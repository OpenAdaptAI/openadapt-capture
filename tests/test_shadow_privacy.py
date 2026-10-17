"""Shadow mining: key lifetime, scrubbing, work scope, notice, and the live tap."""

from __future__ import annotations

import json
import random
import re
import threading
import time

import pytest

from openadapt_capture.live import LiveEvent, LiveEventTap, publish_live
from openadapt_capture.shadow import (
    CollectingNotifier,
    ConsentLedger,
    RecorderShadowBridge,
    ShadowConfig,
    ShadowConsentRequired,
    ShadowEvent,
    ShadowObserver,
    SuppressionList,
    Tokenizer,
    notice,
)
from openadapt_capture.shadow.config import normalize_domain
from openadapt_capture.shadow.consent import NOTICE_VERSION, Acknowledgement, notice_sha256
from openadapt_capture.shadow.events import browser_field_is_secure, native_field_is_secure
from openadapt_capture.shadow.keys import (
    ACTIVE_ACCOUNT,
    KeyringStore,
    MemoryKeyStore,
    load_or_create_keys,
)
from openadapt_capture.shadow.scrub import (
    PLACEHOLDER_ID,
    PLACEHOLDER_LABEL,
    scrub_label,
    scrub_path_segment,
)
from openadapt_capture.shadow.symbols import url_pattern
from tests.shadow_support.streams import SECRET_VALUES, repeated_task_stream

DAY = 24 * 3600.0
ACK = Acknowledgement(NOTICE_VERSION, notice_sha256(), 0.0)
WORK = frozenset({"erp.example.com"})
HEX16 = re.compile(r"\b[0-9a-f]{16}\b")
HEX8 = re.compile(r"(?<![0-9a-z-])[0-9a-f]{8}(?![0-9a-z])")


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _observer(clock, **kw):
    cfg = {"enabled": True, "work_domains": WORK, **kw.pop("cfg", {})}
    return ShadowObserver(ShadowConfig(**cfg), acknowledgement=ACK, clock=clock, **kw)


# ---------------------------------------------------------------------------
# P0a: the key lives at most 24 hours and dies with the buffer
# ---------------------------------------------------------------------------


def test_key_lifetime_is_capped_at_24_hours():
    with pytest.raises(ValueError):
        ShadowConfig(key_lifetime_s=DAY + 1)
    with pytest.raises(ValueError):
        ShadowConfig(max_age_s=DAY + 1)
    with pytest.raises(ValueError):
        load_or_create_keys(MemoryKeyStore(), lifetime_s=DAY * 2)


def test_key_is_reused_within_its_epoch_and_destroyed_after():
    store = MemoryKeyStore()
    first = load_or_create_keys(store, now=1000.0)
    again = load_or_create_keys(store, now=1000.0 + DAY - 1)
    assert again.key_id == first.key_id and again.master == first.master
    later = load_or_create_keys(store, now=1000.0 + DAY)
    assert later.key_id != first.key_id
    assert store.get(f"shadow-key|{first.key_id}") is None
    assert store.get(ACTIVE_ACCOUNT) == later.key_id


def test_a_key_from_the_future_is_not_trusted():
    store = MemoryKeyStore()
    first = load_or_create_keys(store, now=10 * DAY)
    rolled_back = load_or_create_keys(store, now=5 * DAY)
    assert rolled_back.key_id != first.key_id


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service, account):
        return self.values.get((service, account))

    def set_password(self, service, account, value):
        self.values[(service, account)] = value

    def delete_password(self, service, account):
        if (service, account) not in self.values:
            raise type("PasswordDeleteError", (Exception,), {})()
        del self.values[(service, account)]


def test_key_lives_in_the_os_credential_store_never_on_disk(tmp_path):
    backend = FakeKeyring()
    store = KeyringStore(backend=backend)
    clock = Clock(5_000.0)
    obs = _observer(clock, key_store=store, cfg={"store_path": tmp_path / "ring.db"})
    assert obs.keys_persisted
    events, end = repeated_task_stream(random.Random(7), 4, start=clock.now)
    clock.now = end
    obs.observe_all(events)
    assert obs.scan()
    obs.close()
    raw = (tmp_path / "ring.db").read_bytes()
    for (_, account), value in backend.values.items():
        if account != ACTIVE_ACCOUNT:
            secret = json.loads(value)["k"]
            assert secret.encode() not in raw
    # A restart inside the epoch reads the same buffer.
    again = _observer(clock, key_store=store, cfg={"store_path": tmp_path / "ring.db"})
    assert len(again.symbols()) == len(events) - 4  # four typing bursts merged
    again.close()


def test_rotation_purges_the_buffer_and_changes_every_digest(tmp_path):
    clock = Clock(10_000.0)
    store = MemoryKeyStore()
    obs = _observer(clock, key_store=store, cfg={"store_path": tmp_path / "ring.db"})
    old_id = store.get(ACTIVE_ACCOUNT)
    events, end = repeated_task_stream(random.Random(7), 4, start=clock.now)
    clock.now = end
    obs.observe_all(events)
    before = {s.value_digest for s in obs.symbols() if s.value_digest}
    (prompt,) = obs.scan()
    clock.now = 10_000.0 + DAY
    assert obs.symbols() == []
    assert store.get(f"shadow-key|{old_id}") is None
    with pytest.raises(KeyError):
        obs.decide(prompt.motif_id, "review_draft")
    events2, end2 = repeated_task_stream(random.Random(7), 4, start=clock.now)
    clock.now = end2
    obs.observe_all(events2)
    after = {s.value_digest for s in obs.symbols() if s.value_digest}
    assert before and after and not before & after
    obs.close()


def test_an_explicit_key_is_dropped_when_its_epoch_ends():
    clock = Clock(0.0)
    obs = ShadowObserver(
        ShadowConfig(enabled=True), acknowledgement=ACK, digest_key=b"x" * 32, clock=clock
    )
    obs.observe(ShadowEvent(0.0, "type", app="A", role="textfield", label="F", text="123456789"))
    (one,) = obs.symbols()
    clock.now = DAY
    obs.observe(ShadowEvent(DAY, "type", app="A", role="textfield", label="F", text="123456789"))
    (two,) = obs.symbols()
    assert one.value_digest != two.value_digest


def test_export_carries_no_keyed_digest():
    events, end = repeated_task_stream(random.Random(7), 4)
    obs = ShadowObserver(
        ShadowConfig(enabled=True, work_domains=WORK),
        acknowledgement=ACK,
        digest_key=b"k" * 32,
        clock=Clock(end),
    )
    obs.observe_all(events)
    (prompt,) = obs.scan()
    export = obs.decide(prompt.motif_id, "review_draft")
    assert export["schema"] == "openadapt.shadow.episodes/v2"
    digests = set()
    for s in obs.symbols():
        digests |= {s.label_digest, s.value_digest} - {None}
    digests |= {d[:8] for d in digests}
    digests.add(prompt.motif_id)
    blob = json.dumps(export)
    for digest in digests:
        assert digest not in blob
    steps = [step for ep in export["episodes"] for step in ep["steps"]]
    assert all("label_digest" not in s and "value_digest" not in s for s in steps)
    assert all(not HEX8.search(t) for t in export["tokens"])
    refs = {s["value_ref"] for s in steps if s["value_ref"]}
    assert refs and all(re.fullmatch(r"value-[a-z]+", r) for r in refs)
    # The four invoice numbers differ, so each episode's row click has its own ref.
    rows = [s["value_ref"] for s in steps if s["role"] == "cell"]
    assert len(set(rows)) == 4


def test_ignore_survives_key_rotation(tmp_path):
    clock = Clock(10_000.0)
    suppression = SuppressionList(tmp_path / "ignored.json")
    obs = _observer(clock, key_store=MemoryKeyStore(), suppression=suppression)
    events, end = repeated_task_stream(random.Random(7), 4, start=clock.now)
    clock.now = end
    obs.observe_all(events)
    (prompt,) = obs.scan()
    obs.decide(prompt.motif_id, "ignore")
    clock.now = 10_000.0 + DAY + 1
    events2, end2 = repeated_task_stream(random.Random(9), 4, start=clock.now)
    clock.now = end2
    obs.observe_all(events2)
    assert obs.scan() == []


# ---------------------------------------------------------------------------
# P0b: identifiers scrubbed from URL segments and labels before storage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "segment",
    [
        "patient-987654",
        "987654",
        "3f9a0c1e7b",
        "0b8e4f1c-2a3d-4e5f-8a9b-1c2d3e4f5a6b",
        "jane-doe",
        "doe_john",
        "smith",
        "JohnDoe",
        "inv-559017",
    ],
)
def test_identifier_like_path_segments_become_id(segment):
    assert scrub_path_segment(segment) == PLACEHOLDER_ID
    url = f"https://erp.example.com/{segment}/chart?mrn=1234567"
    assert url_pattern(url, WORK) == "https://erp.example.com/<id>/*"


@pytest.mark.parametrize("segment", ["invoices", "new-order", "patients", "settings"])
def test_known_path_words_stay(segment):
    assert scrub_path_segment(segment) == segment


def test_extra_path_words_extend_the_vocabulary():
    assert scrub_path_segment("epic", ["epic"]) == "epic"
    cfg = ShadowConfig(work_domains=WORK, extra_path_words={"Epic"})
    tok = Tokenizer(cfg, digest_key=b"k" * 32)
    (sym,) = tok.feed(ShadowEvent(1, "navigate", app="browser", url="https://erp.example.com/epic"))
    assert sym.url_pattern == "https://erp.example.com/epic"


@pytest.mark.parametrize(
    "label",
    ["Doe, John (12345)", "Jane Doe", "INV-559017", "Pay 1200", "jane@example.com", "Smith"],
)
def test_dynamic_chrome_labels_become_placeholder(label):
    assert scrub_label(label) == PLACEHOLDER_LABEL
    tok = Tokenizer(ShadowConfig(), digest_key=b"k" * 32)
    (sym,) = tok.feed(ShadowEvent(1, "click", app="EHR", role="AXMenuItem", label=label))
    assert sym.display_label == PLACEHOLDER_LABEL
    assert label not in json.dumps(sym.to_dict())


@pytest.mark.parametrize("label", ["Save", "Submit", "New Message", "Attach", "Send"])
def test_common_chrome_labels_stay(label):
    assert scrub_label(label) == label


def test_scrubbing_happens_before_the_buffer(tmp_path):
    clock = Clock(1000.0)
    obs = _observer(clock, key_store=MemoryKeyStore(), cfg={"store_path": tmp_path / "ring.db"})
    obs.observe(ShadowEvent(999, "focus", app="Google Chrome"))
    obs.observe(
        ShadowEvent(
            999.5, "navigate", app="Google Chrome", url="https://erp.example.com/patient-987654"
        )
    )
    obs.observe(ShadowEvent(1000, "click", app="EHR", role="AXButton", label="Doe, John (12345)"))
    (_, nav, click) = obs.symbols()
    assert nav.url_pattern == "https://erp.example.com/<id>"
    assert click.display_label == "<dynamic_label>"
    blob = json.dumps([s.to_dict() for s in obs.symbols()])
    for raw in ("987654", "Doe", "John", "12345"):
        assert raw not in blob
    obs.close()


# ---------------------------------------------------------------------------
# P0c: work-domain allowlist
# ---------------------------------------------------------------------------


def test_domain_allowlist_entries_are_strict():
    assert normalize_domain("*.Example.COM.") == "example.com"
    for bad in ("https://example.com", "example.com/path", "exa*mple.com", "localhost", ""):
        with pytest.raises(ValueError):
            normalize_domain(bad)
    with pytest.raises(TypeError):
        ShadowConfig(work_domains="example.com")


def test_non_work_sites_leave_only_one_marker():
    clock = Clock(100.0)
    obs = _observer(clock, key_store=MemoryKeyStore())
    events = [
        ShadowEvent(1, "focus", app="Google Chrome"),
        ShadowEvent(2, "navigate", app="Google Chrome", url="https://mybank.com/acct/123"),
        ShadowEvent(3, "click", app="Google Chrome", role="button", label="Transfer"),
        ShadowEvent(4, "type", app="Google Chrome", role="textfield", label="Amount", text="900"),
        ShadowEvent(
            5,
            "click",
            app="browser",
            role="link",
            label="Jane Doe",
            url="https://social.example.org/jane",
        ),
        ShadowEvent(6, "navigate", app="Google Chrome", url="https://erp.example.com/invoices"),
        ShadowEvent(7, "click", app="Google Chrome", role="button", label="Submit"),
    ]
    obs.observe_all(events)
    syms = obs.symbols()
    assert [s.token for s in syms] == [
        "focus|Google Chrome",
        "focus|non-work-browser",
        "navigate|Google Chrome|https://erp.example.com/invoices",
        syms[3].token,
    ]
    assert syms[3].display_label == "Submit"
    blob = json.dumps([s.to_dict() for s in syms])
    for raw in ("mybank", "acct", "Transfer", "Amount", "social", "Jane"):
        assert raw not in blob


def test_with_an_empty_allowlist_no_site_is_recorded():
    obs = ShadowObserver(
        ShadowConfig(enabled=True),
        acknowledgement=ACK,
        key_store=MemoryKeyStore(),
        clock=Clock(10.0),
    )
    obs.observe(ShadowEvent(1, "navigate", app="Safari", url="https://erp.example.com/invoices"))
    (sym,) = obs.symbols()
    assert sym.token == "focus|non-work-browser" and sym.url_pattern is None


# ---------------------------------------------------------------------------
# Password-field detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"role": "AXSecureTextField"},
        {"role": "AXTextField", "subrole": "AXSecureTextField"},
        {"role": "Edit", "is_password": True},
        {"role": "Edit", "automation_id": "txtPassword"},
        {"role": "Edit", "class_name": "PinEntryBox"},
    ],
)
def test_native_secret_fields_are_detected(kwargs):
    role = kwargs.pop("role")
    assert native_field_is_secure(role, **kwargs)


def test_ordinary_native_field_is_not_secret():
    assert not native_field_is_secure("AXTextField", automation_id="txtInvoice")


@pytest.mark.parametrize(
    "element",
    [
        {"css_selector": "input[type=password]"},
        {"css_selector": "#login > input", "id": "user-pass"},
        {"type": "password"},
        {"autocomplete": "one-time-code"},
        {"autocomplete": "cc-number"},
        {"name": "Security code"},
        {"class_list": ["field", "ssn-input"]},
    ],
)
def test_browser_secret_fields_are_detected(element):
    assert browser_field_is_secure(element)


@pytest.mark.parametrize("label", ["Password", "PIN", "One-time code", "SSN", "CVV"])
def test_secret_labels_drop_the_value(label):
    tok = Tokenizer(ShadowConfig(), digest_key=b"k" * 32)
    syms = tok.feed(ShadowEvent(1, "type", app="A", role="AXTextField", label=label, text="4321"))
    syms += tok.flush()
    (sym,) = syms
    assert sym.secure and sym.value_digest is None and sym.token.endswith("|secure")


# ---------------------------------------------------------------------------
# P0d: the opt-in notice
# ---------------------------------------------------------------------------


def test_enabling_requires_an_acknowledgement_of_the_current_notice():
    with pytest.raises(ShadowConsentRequired):
        ShadowObserver(ShadowConfig(enabled=True), key_store=MemoryKeyStore())
    stale = Acknowledgement("2000-01-01", "0" * 64, 0.0)
    with pytest.raises(ShadowConsentRequired):
        ShadowObserver(ShadowConfig(enabled=True), acknowledgement=stale)
    # Off needs nothing.
    assert not ShadowObserver(ShadowConfig()).enabled


def test_notice_says_what_the_counsel_review_requires():
    text = notice()["text"]
    for phrase in (
        "What it records",
        "encrypted file on this computer",
        "24 hours",
        "Nothing leaves this computer",
        "can't turn shadow mode on or read the buffer through OpenAdapt",
        "administrator access to this computer",
        "Delete everything and turn off",
        "never",
    ):
        assert phrase in text
    # An OS administrator with access to the device can inspect the buffer
    # while it's on, so the notice must never claim otherwise.
    assert "No administrator" not in text
    assert "can see it" not in text
    assert notice()["sha256"] == notice_sha256()


def test_ledger_records_acknowledgement_time_locally_and_revocation(tmp_path):
    ledger = ConsentLedger(tmp_path / "consent.json")
    assert ledger.current() is None
    with pytest.raises(ShadowConsentRequired):
        ledger.acknowledge("not-the-hash", now=1.0)
    ack = ledger.acknowledge(notice_sha256(), now=1234.5)
    assert ledger.current() == ack and ack.acknowledged_at == 1234.5
    assert oct((tmp_path / "consent.json").stat().st_mode & 0o777) == "0o600"
    ledger.revoke(now=2000.0)
    assert ledger.current() is None
    assert [e["event"] for e in ledger.history()] == ["acknowledged", "revoked"]


def test_purge_and_disable_removes_buffer_key_and_ignores(tmp_path):
    store = MemoryKeyStore()
    clock = Clock(10_000.0)
    suppression = SuppressionList(tmp_path / "ignored.json")
    obs = _observer(
        clock,
        key_store=store,
        suppression=suppression,
        notifier=CollectingNotifier(),
        cfg={"store_path": tmp_path / "ring.db"},
    )
    events, end = repeated_task_stream(random.Random(7), 4, start=clock.now)
    clock.now = end
    obs.observe_all(events)
    (prompt,) = obs.scan()
    obs.decide(prompt.motif_id, "ignore")
    obs.purge_and_disable()
    assert not obs.enabled
    assert not (tmp_path / "ring.db").exists()
    assert store.get(ACTIVE_ACCOUNT) is None and store._values == {}
    assert json.loads((tmp_path / "ignored.json").read_text()) == {"ids": [], "marks": []}
    obs.observe(events[0])
    assert obs.symbols() == [] and obs.scan() == []


# ---------------------------------------------------------------------------
# Live recorder hook
# ---------------------------------------------------------------------------


def _ax(role, name, app="Microsoft Excel"):
    return {
        "provider": "macos_ax",
        "element": {"role": role, "name": name},
        "process": {"process_name": app},
    }


def test_bridge_maps_raw_recorder_events():
    bridge = RecorderShadowBridge(observer=None)
    t = lambda *a: bridge.translate(LiveEvent(*a))  # noqa: E731
    (click,) = t(
        1.0,
        "action",
        {"name": "click", "mouse_pressed": True, "structural_observation": _ax("AXCell", "INV-1")},
    )
    assert (click.kind, click.app, click.role) == ("click", "Microsoft Excel", "AXCell")
    assert t(1.1, "action", {"name": "click", "mouse_pressed": False}) == []
    assert t(2.0, "action", {"name": "press", "key_name": "cmd"}) == []
    (copy,) = t(2.1, "action", {"name": "press", "key_char": "c", "key_name": "c"})
    assert copy.kind == "copy"
    t(2.2, "action", {"name": "release", "key_name": "cmd"})
    field = _ax("AXTextField", "Amount", app="Google Chrome")
    (typed,) = t(3.0, "action", {"name": "press", "key_char": "4", "structural_observation": field})
    assert typed.kind == "type" and typed.text == "4" and not typed.secure
    (blind,) = t(3.1, "action", {"name": "press", "key_char": "5"})
    assert blind.kind == "type" and blind.secure  # no evidence: treat as a secret
    (enter,) = t(4.0, "action", {"name": "press", "key_name": "enter"})
    assert enter.kind == "key" and enter.key == "enter"
    (focus,) = t(5.0, "window", {"title": "Secret doc", "state": {"owner": "Mail"}})
    assert focus.kind == "focus" and focus.app == "Mail" and "Secret" not in repr(focus)
    (nav,) = t(
        6.0,
        "browser",
        {"type": "navigate", "url": "https://x.example/a", "navigation_type": "form_submit"},
    )
    assert nav.kind == "submit"
    (pw,) = t(
        7.0,
        "browser",
        {
            "type": "input",
            "url": "https://x.example/a",
            "data": "hunter2",
            "input_type": "insertText",
            "element": {"role": "textbox", "css_selector": "input[type=password]"},
        },
    )
    assert pw.secure


def test_live_tap_feeds_a_shadow_observer_end_to_end():
    obs = ShadowObserver(
        ShadowConfig(enabled=True, work_domains=WORK),
        acknowledgement=ACK,
        key_store=MemoryKeyStore(),
        clock=Clock(100.0),
    )
    tap = LiveEventTap(RecorderShadowBridge(obs)).start()
    field = _ax("AXTextField", "Amount")
    for i, ch in enumerate("4471"):
        publish_live(
            tap,
            type(
                "E",
                (),
                {
                    "timestamp": 10.0 + i * 0.1,
                    "type": "action",
                    "data": {"name": "press", "key_char": ch, "structural_observation": field},
                },
            )(),
        )
    tap.close()
    (sym,) = obs.symbols()
    assert sym.kind == "type" and sym.value_shape == "digits"
    assert "4471" not in json.dumps(sym.to_dict())
    assert tap.delivered == 4 and tap.failed == 0


def test_live_tap_never_blocks_or_raises():
    gate = threading.Event()
    tap = LiveEventTap(lambda e: gate.wait(5), max_pending=2).start()
    start = time.monotonic()
    for i in range(50):
        tap.publish(float(i), "action", {"name": "click"})
    tap.publish(1.0, "screen", {"pixels": 1})  # frames are never published
    tap.publish(1.0, "action", object())  # not a dict: ignored
    assert time.monotonic() - start < 1.0
    assert tap.dropped >= 40
    gate.set()
    tap.close()


def test_live_tap_close_returns_when_the_subscriber_is_stuck():
    gate = threading.Event()
    tap = LiveEventTap(lambda e: gate.wait(10), max_pending=1).start()
    for i in range(5):
        tap.publish(float(i), "action", {"name": "click"})
    start = time.monotonic()
    tap.close(timeout=0.2)
    assert time.monotonic() - start < 2.0
    gate.set()


def test_live_tap_rejects_frame_types():
    with pytest.raises(ValueError):
        LiveEventTap(lambda e: None, types=frozenset({"screen"}))


def test_secret_values_never_reach_a_live_fed_buffer(tmp_path):
    obs = ShadowObserver(
        ShadowConfig(enabled=True, work_domains=WORK, store_path=tmp_path / "r.db"),
        acknowledgement=ACK,
        key_store=MemoryKeyStore(),
        clock=Clock(100.0),
    )
    bridge = RecorderShadowBridge(obs)
    for i, ch in enumerate(SECRET_VALUES[4]):
        bridge(
            LiveEvent(
                10.0 + i * 0.1,
                "action",
                {
                    "name": "press",
                    "key_char": ch,
                    "structural_observation": _ax("AXTextField", "SSN"),
                },
            )
        )
    obs.symbols()
    obs.close()
    raw = (tmp_path / "r.db").read_bytes().decode("latin-1")
    assert SECRET_VALUES[4] not in raw and "SSN" not in raw


def test_acknowledgement_of_the_old_notice_no_longer_counts(tmp_path):
    # The 2026-10-17 notice claimed no administrator could see the buffer.
    old = Acknowledgement("2026-10-17", notice_sha256(), 1.0)
    assert not old.current
    with pytest.raises(ShadowConsentRequired):
        ShadowObserver(ShadowConfig(enabled=True), acknowledgement=old)
    path = tmp_path / "consent.json"
    path.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "event": "acknowledged",
                        "notice_version": "2026-10-17",
                        "notice_sha256": notice_sha256(),
                        "at": 1.0,
                    }
                ]
            }
        )
    )
    assert ConsentLedger(path).current() is None
