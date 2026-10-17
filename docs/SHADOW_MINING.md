# Shadow-mode pattern mining

Shadow mining notices when you repeat the same task across applications, for
example copying an invoice number from a spreadsheet into a web form and
submitting it, and offers to turn those repeats into a draft for OpenAdapt
Flow. It's off by default. It never runs anything.

This page covers what shadow mining observes, what it stores, how it decides
that something repeated, and what happens when you accept or ignore an offer.
The code is in `openadapt_capture/shadow/`.

## Turn it on

Shadow mining has no command-line switch, environment variable, or remote
setting. The calling application turns it on in code, for one person, after
that person agrees:

```python
from openadapt_capture.shadow import ShadowConfig, ShadowObserver

observer = ShadowObserver(ShadowConfig(enabled=True), notifier=my_tray)
observer.observe(event)        # one ShadowEvent at a time
for prompt in observer.scan(): # call periodically, for example once a minute
    ...
```

With the default `ShadowConfig()`, `observe()` drops every event, `scan()`
returns nothing, no file is created, and `decide()` raises
`ShadowModeDisabled`.

The observer doesn't attach itself to the recorder. Events reach it through
the adapters in `openadapt_capture/shadow/events.py` (`from_capture_event`,
`from_browser_event`, `from_window_event`) or as `ShadowEvent` objects the
caller builds. Wiring a live input source into the observer is a separate
change; see [Not done yet](#not-done-yet).

## What it observes and what it keeps

Each event is reduced to a *symbol* before anything is stored. A symbol names
the kind of action, the application, and the kind of control. The table shows
what happens to each piece of an event.

| Input | What is kept |
|---|---|
| Typed text | A keyed digest (HMAC-SHA256, 64 bits) and a coarse shape such as `digits` or `email`. Never the text or its length. |
| Text in a password or secure field | Nothing. No digest. |
| Label of a button, menu item, tab, check box, or radio button | A keyed digest. If the label is at most 32 characters, at most four words, and has no digits or `@`, the plain text is also kept so you can read the draft. Turn that off with `keep_chrome_labels=False`. |
| Label of a text field or combo box | A keyed digest only. |
| Label of anything else (a table cell, a list row, a link) | Treated as data: a keyed digest of the value, and no label. |
| Application | The process or bundle name, for example `Microsoft Excel`. |
| Window title | Never read. Titles often hold document names, record names, and email subjects. |
| URL | Scheme, host, and the first path segment if it's a short lowercase word. Every later segment becomes `*`. The query string, fragment, credentials, and port are dropped. |
| Clipboard | Never read. Copy and paste are recognized from the key chord (Cmd+C, Ctrl+V). |
| Named keys | Enter, Tab, Escape, arrows, function keys. Any other key becomes `other`. |
| Screenshots, video, audio, mouse coordinates | Not used. |

The digest key is 32 random bytes held in memory for the life of the
observer. Without the key, a stored digest can't be checked against a guess,
which matters for short values such as a member ID or a date. If the caller
passes its own `digest_key` (for example, one kept in the OS keychain), digests
and motif IDs stay stable across restarts.

## Where it's stored

Symbols go into a ring buffer with two limits that both apply:

- **Size.** `max_symbols`, 20,000 by default. When the buffer is full, the
  oldest symbol is overwritten.
- **Age.** `max_age_s`, one day by default. Older symbols are deleted on every
  write and every read.

By default the buffer lives in memory only. With `store_path`, it's a SQLite
file created with owner-only permissions (`0600`, in a `0700` directory), with
`secure_delete` on so deleted rows are overwritten, and with a rollback
journal instead of a write-ahead log so expired rows don't linger in a side
file. `observer.purge()` deletes everything at once.

Capture doesn't encrypt recordings at rest today, so the shadow buffer isn't
encrypted either. It holds only symbols, never raw values.

## How a repeat is detected

The miner works only on symbols. It's deterministic: the same buffer and
settings always give the same result. It calls no model.

1. The stream is split into sessions at gaps longer than `idle_gap_s`
   (five minutes by default). A motif never spans two sessions.
2. A suffix array and its longest-common-prefix array list every repeated
   sequence. Each one is a candidate.
3. A candidate is kept only if:
   - it's between `min_length` (4) and `max_length` (40) symbols long, and
     isn't a shorter unit repeated;
   - it touches at least `min_apps` applications (2, so only cross-application
     tasks are offered);
   - it occurs, without overlap, at least `min_occurrences` times (3) within
     the last `window_s` seconds (one day);
   - its exact repeat count is unlikely by chance. The miner compares the
     count with a Poisson model built from how often each symbol appears in
     the buffer, and corrects for every sequence it could have tested
     (Bonferroni, `significance=1e-3` overall). This is what keeps a busy
     stream of unrelated clicks from producing offers.
4. After a motif passes, near-repeats join it when their similarity reaches
   `similarity_threshold` (0.8, measured with `difflib.SequenceMatcher` over
   symbols). A near-repeat might have one extra click. Near-repeats count
   toward "N times" but not toward the chance test.

## The offer

When a motif passes, the observer calls the notifier with a `MotifPrompt`:

- Title: "OpenAdapt noticed a repeated task"
- Body: "You did this N times today."
- Actions: **Review draft** and **Ignore**

The payload is a fixed template with a count. It never names an application,
a control, or a value, because a notification can appear on a lock screen.
`assert_generic_prompt` rejects any payload that carries more.

Each motif is offered once. It's offered again only if its count grows.

- **Ignore** suppresses the motif. Close variants (Jaccard similarity of 0.6
  or more over hashed symbol pairs) stay suppressed too, so one extra click
  doesn't bring the offer back. Pass a `SuppressionList(path)` to remember
  ignores across restarts; the file holds only motif IDs and hashed pairs.
- **Review draft** returns an `openadapt.shadow.episodes/v1` export: the
  matching episodes as lists of symbols. It doesn't run, compile, or upload
  anything.

`notify.py` is an interface and a stub (`CollectingNotifier`). Capture has no
user interface. Showing the prompt in the OpenAdapt Desktop tray is a
separate change.

## From draft to program

Flow reads the export with
`openadapt_flow.compiler.motif_induction.induce_candidate`, which feeds the
episodes to Flow's existing multi-trace induction. The result is a candidate,
not a program you can run:

- Its anchors are placeholders, because shadow mining keeps no pixels. The
  first item on its record-next worklist is to record the task once with
  Capture.
- Checks it suggests, such as "a file saved from Excel changes", are
  proposals. The episodes that suggested a check can't approve it.
- You admit the program through the usual path: record, `flow compile`,
  `flow induce`, then `flow qualify`.

## Privacy and workplace monitoring

Shadow mining watches what a person does across applications for hours at a
time. Even without values, a symbol stream shows which applications someone
uses, when, and how often. Treat it as activity monitoring.

- **Consent.** Only the person being observed should turn it on, for
  themselves. The API has no remote or policy-driven switch on purpose. Don't
  add one without legal review.
- **Employers.** In many jurisdictions, monitoring employees' computer
  activity requires notice, a lawful basis, or a data protection impact
  assessment (for example, under the GDPR in the EU and UK). In Germany,
  section 87(1) no. 6 of the Works Constitution Act gives the works council a
  co-determination right over technical systems that can monitor employee
  behavior or performance. Austria, France, the Netherlands, and other
  countries have similar rules. A deployment in those settings needs the
  works council's agreement before rollout, not after.
- **Performance data.** "You did this 4 times today" is a count of one
  person's work. Keep it on that person's device. Don't aggregate counts per
  person, export them to a manager, or use them to rate anyone.
- **Retention.** Keep the defaults (one day, 20,000 symbols) unless there's a
  documented reason. Offer an obvious way to turn shadow mining off and purge
  the buffer.
- **Health and other protected data.** Digests and coarse URL patterns lower
  the risk, but a symbol stream from a clinical system is still metadata about
  patient work. Keep the buffer inside the same local boundary as a capture.

## Not done yet

- A live connection from Capture's input observer to `ShadowObserver`. Today
  the caller feeds events in.
- A tray or notification surface in OpenAdapt Desktop.
- Encryption at rest for the buffer, which would follow encryption at rest for
  captures.
- Calibrating thresholds (`min_occurrences`, `significance`,
  `similarity_threshold`) on real activity. The defaults are tuned on
  synthetic streams only.

## Tests

`tests/test_shadow_mining.py` covers detection, near-repeats, single-app
filtering, the time window, no offers on random streams (including a full
20,000-symbol buffer), that typed values never reach symbols, the SQLite file,
or the export, zero network access, the off-by-default state, ring-buffer
expiry and overwrite, suppression after Ignore, and the generic prompt.
