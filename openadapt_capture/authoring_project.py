"""Fail-closed projector from a raw window tree to authoring observe JSON.

The raw accessibility tree may persist on disk for compile. This module is the
only path that shapes that tree for a vendor wire. It never emits field values,
window titles, screenshots, or extra keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openadapt_capture.structural import (
    StructuralBounds,
    StructuralObservation,
    StructuralTreeNode,
)

AUTHORING_OBSERVE_SCHEMA_VERSION = "openadapt.authoring.observe/v1"
MAX_AUTHORING_NODES = 200
MAX_AUTHORING_WIRE_BYTES = 32 * 1024
MAX_AUTHORING_LABEL_LENGTH = 80
NODE_ID_PATTERN = r"^n_[0-9a-f]{8}$"

AuthoringBackend = Literal["macos", "linux", "windows", "web", "rdp", "citrix"]

_AGENT_DRIVE_BACKENDS = frozenset({"macos", "linux", "web"})
_COACH_ONLY_BACKENDS = frozenset({"windows", "rdp", "citrix"})
_EMPTY_TREE_BACKENDS = frozenset({"rdp", "citrix"})
_KNOWN_BACKENDS = frozenset({"macos", "linux", "windows", "web", "rdp", "citrix"})

_PROCESS_NAME = re.compile(r"^[A-Za-z0-9 ._-]{1,64}$")
_SIX_DIGITS = re.compile(r"\d{6,}")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"
)
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")

_logger = logging.getLogger(__name__)


class AuthoringNormalizedBounds(BaseModel):
    """Axis-aligned rectangle normalized to the top-level viewport."""

    model_config = ConfigDict(extra="forbid")

    x: float
    y: float
    w: float
    h: float

    @model_validator(mode="after")
    def validate_normalized(self) -> "AuthoringNormalizedBounds":
        """Reject non-finite or out-of-range overlay coordinates."""
        values = (self.x, self.y, self.w, self.h)
        if not all(math.isfinite(value) for value in values):
            raise ValueError("normalized bounds must be finite")
        if any(value < 0 or value > 1 for value in values):
            raise ValueError("normalized bounds must lie in [0, 1]")
        return self


class AuthoringPixelBounds(BaseModel):
    """Screen-space rectangle for backend clicks. Laptop-only."""

    model_config = ConfigDict(extra="forbid")

    x: float
    y: float
    w: float
    h: float

    @model_validator(mode="after")
    def validate_pixels(self) -> "AuthoringPixelBounds":
        """Reject non-finite or inverted pixel rectangles."""
        values = (self.x, self.y, self.w, self.h)
        if not all(math.isfinite(value) for value in values):
            raise ValueError("pixel bounds must be finite")
        if self.w < 0 or self.h < 0:
            raise ValueError("pixel bounds must not be inverted")
        return self


class AuthoringWireNode(BaseModel):
    """One projected accessibility node on the vendor wire."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(pattern=NODE_ID_PATTERN)
    role: str | None = None
    control_type: str | None = None
    automation_id: str | None = None
    name: str | None = None
    class_name: str | None = None
    enabled: bool | None = None
    focused: bool | None = None
    bounds: AuthoringNormalizedBounds | None = None


class AuthoringWindow(BaseModel):
    """Projected top-level window identity. Titles never appear here."""

    model_config = ConfigDict(extra="forbid")

    process_name: str | None = None
    role: str | None = None
    bounds: AuthoringNormalizedBounds | None = None


class AuthoringObserve(BaseModel):
    """PHI-safe ``openadapt.authoring.observe/v1`` payload."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["openadapt.authoring.observe/v1"] = (
        AUTHORING_OBSERVE_SCHEMA_VERSION
    )
    backend: AuthoringBackend
    provider: str
    mode: Literal["authoring"] = "authoring"
    agent_drive: bool
    coach_only: bool
    recording: bool = False
    window: AuthoringWindow
    tree: list[AuthoringWireNode] = Field(default_factory=list, max_length=MAX_AUTHORING_NODES)
    truncated: bool = False
    node_count: int = Field(default=0, ge=0, le=MAX_AUTHORING_NODES)
    reason: Literal["empty_projection"] | None = None


class AuthoringNodeTableEntry(BaseModel):
    """Laptop-only click table. Never serialized onto the vendor wire."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(pattern=NODE_ID_PATTERN)
    backend_pixels: AuthoringPixelBounds | None = None
    normalized: AuthoringNormalizedBounds | None = None
    provider_runtime_id: str | None = None
    observed_at: int


class AuthoringRawNode(BaseModel):
    """Unprojected accessibility node. May contain PHI. Never send to MCP."""

    model_config = ConfigDict(extra="forbid")

    provider_runtime_id: str | None = None
    automation_id: str | None = None
    role: str | None = None
    control_type: str | None = None
    name: str | None = None
    class_name: str | None = None
    value: str | None = None
    title: str | None = None
    enabled: bool | None = None
    focused: bool | None = None
    bounds: StructuralBounds | None = None
    children: list[AuthoringRawNode] = Field(default_factory=list)


class AuthoringRawWindow(BaseModel):
    """Unprojected window identity. Title is dropped by the projector."""

    model_config = ConfigDict(extra="forbid")

    process_name: str | None = None
    role: str | None = None
    title: str | None = None
    bounds: StructuralBounds | None = None


@dataclass(frozen=True)
class AuthoringProjection:
    """Wire payload plus the laptop-only node table."""

    observe: AuthoringObserve
    node_table: tuple[AuthoringNodeTableEntry, ...]

    def wire_dict(self) -> dict[str, Any]:
        """Return the vendor-wire object with omitted empty optional fields."""
        return self.observe.model_dump(mode="json", exclude_none=True)


def mint_node_id(
    *,
    hmac_key: bytes,
    lease_nonce: bytes,
    provider_runtime_id: str,
) -> str:
    """Mint ``n_`` + 8 hex of HMAC-SHA256(lease_nonce || provider_runtime_id)."""

    if not hmac_key:
        raise ValueError("hmac_key is required")
    if not provider_runtime_id:
        raise ValueError("provider_runtime_id is required")
    digest = hmac.new(
        hmac_key,
        lease_nonce + provider_runtime_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"n_{digest[:8]}"


def project_text(value: str | None) -> str | None:
    """Collapse whitespace and drop labels that fail the coach-hint bar."""

    if not isinstance(value, str):
        return None
    collapsed = " ".join(value.split())
    if not collapsed or len(collapsed) > MAX_AUTHORING_LABEL_LENGTH:
        return None
    if "://" in collapsed or "@" in collapsed:
        return None
    if _SIX_DIGITS.search(collapsed):
        return None
    if _SSN.search(collapsed) or _PHONE.search(collapsed) or _EMAIL.search(collapsed):
        return None
    return collapsed


def project_process_name(value: str | None) -> str | None:
    """Keep a process name only when it matches the closed identifier grammar."""

    if not isinstance(value, str):
        return None
    collapsed = " ".join(value.split())
    if not collapsed or not _PROCESS_NAME.fullmatch(collapsed):
        return None
    return collapsed


def raw_nodes_from_observation(
    observation: StructuralObservation,
) -> list[AuthoringRawNode]:
    """Copy a persisted window tree into projector input."""

    return [_raw_from_structural(node) for node in observation.tree or []]


def raw_window_from_observation(
    observation: StructuralObservation,
) -> AuthoringRawWindow:
    """Copy persisted window identity, including a title that must not go to MCP."""

    window = observation.window
    process_name = None
    if observation.process is not None:
        process_name = observation.process.process_name
    title = None
    bounds = None
    if window is not None:
        title = window.title
        bounds = window.bounds
    return AuthoringRawWindow(
        process_name=process_name,
        role=observation.element.role,
        title=title,
        bounds=bounds,
    )


def project_authoring_observe(
    observation: StructuralObservation | None = None,
    *,
    backend: str,
    hmac_key: bytes,
    lease_nonce: bytes | str,
    provider: str | None = None,
    recording: bool = False,
    raw_tree: list[AuthoringRawNode] | None = None,
    raw_window: AuthoringRawWindow | None = None,
    observed_at_ms: int | None = None,
) -> AuthoringProjection:
    """Project a raw tree to ``openadapt.authoring.observe/v1``.

    Never returns a raw fallback. RDP and Citrix yield an empty coach-only
    tree. Windows native is coach-only but may still carry a projected tree.
    """

    if backend not in _KNOWN_BACKENDS:
        raise ValueError(f"unknown authoring backend: {backend!r}")
    resolved_provider = provider
    if observation is not None:
        resolved_provider = resolved_provider or observation.provider
        if raw_tree is None:
            raw_tree = raw_nodes_from_observation(observation)
        if raw_window is None:
            raw_window = raw_window_from_observation(observation)
        if observed_at_ms is None:
            observed_at_ms = int(observation.observed_at * 1000)
    if not resolved_provider:
        raise ValueError("provider is required")
    nonce = lease_nonce.encode("utf-8") if isinstance(lease_nonce, str) else lease_nonce
    if not nonce:
        raise ValueError("lease_nonce is required")
    if observed_at_ms is None:
        observed_at_ms = 0

    coach_only = backend in _COACH_ONLY_BACKENDS
    agent_drive = backend in _AGENT_DRIVE_BACKENDS
    window = _project_window(raw_window)
    viewport = None if raw_window is None else raw_window.bounds
    raw_truncated = bool(observation.tree_truncated) if observation is not None else False

    tree: list[AuthoringWireNode] = []
    table: list[AuthoringNodeTableEntry] = []
    truncated = raw_truncated
    if backend not in _EMPTY_TREE_BACKENDS:
        tree, table, truncated = _project_tree(
            raw_tree or [],
            hmac_key=hmac_key,
            lease_nonce=nonce,
            viewport=viewport,
            observed_at_ms=observed_at_ms,
            window=window,
            backend=backend,
            provider=resolved_provider,
            agent_drive=agent_drive,
            coach_only=coach_only,
            recording=recording,
            raw_truncated=raw_truncated,
        )

    reason: Literal["empty_projection"] | None = None
    if not tree and backend not in _EMPTY_TREE_BACKENDS:
        reason = "empty_projection"

    observe = AuthoringObserve(
        backend=backend,  # type: ignore[arg-type]
        provider=resolved_provider,
        agent_drive=agent_drive,
        coach_only=coach_only,
        recording=recording,
        window=window,
        tree=tree,
        truncated=truncated,
        node_count=len(tree),
        reason=reason,
    )
    if truncated:
        _logger.info("authoring observe truncated node_count=%s", observe.node_count)
    return AuthoringProjection(observe=observe, node_table=tuple(table))


def _raw_from_structural(node: StructuralTreeNode) -> AuthoringRawNode:
    return AuthoringRawNode(
        provider_runtime_id=node.provider_runtime_id,
        automation_id=node.automation_id,
        role=node.role,
        control_type=node.control_type,
        name=node.name,
        class_name=node.class_name,
        value=node.value,
        enabled=node.enabled,
        focused=node.focused,
        bounds=node.bounds,
        children=[_raw_from_structural(child) for child in node.children or []],
    )


def _project_window(raw_window: AuthoringRawWindow | None) -> AuthoringWindow:
    if raw_window is None:
        return AuthoringWindow()
    bounds = None
    if raw_window.bounds is not None:
        bounds = AuthoringNormalizedBounds(x=0.0, y=0.0, w=1.0, h=1.0)
    return AuthoringWindow(
        process_name=project_process_name(raw_window.process_name),
        role=project_text(raw_window.role),
        bounds=bounds,
    )


def _flatten(nodes: list[AuthoringRawNode]) -> list[AuthoringRawNode]:
    flat: list[AuthoringRawNode] = []
    stack = list(reversed(nodes))
    while stack:
        node = stack.pop()
        flat.append(node)
        stack.extend(reversed(node.children))
    return flat


def _normalize_bounds(
    bounds: StructuralBounds | None,
    viewport: StructuralBounds | None,
) -> AuthoringNormalizedBounds | None:
    if bounds is None or viewport is None:
        return None
    width = viewport.right - viewport.left
    height = viewport.bottom - viewport.top
    if width <= 0 or height <= 0:
        return None
    try:
        return AuthoringNormalizedBounds(
            x=_clamp01((bounds.left - viewport.left) / width),
            y=_clamp01((bounds.top - viewport.top) / height),
            w=_clamp01((bounds.right - bounds.left) / width),
            h=_clamp01((bounds.bottom - bounds.top) / height),
        )
    except (TypeError, ValueError):
        return None


def _pixel_bounds(bounds: StructuralBounds | None) -> AuthoringPixelBounds | None:
    if bounds is None:
        return None
    try:
        return AuthoringPixelBounds(
            x=bounds.left,
            y=bounds.top,
            w=bounds.right - bounds.left,
            h=bounds.bottom - bounds.top,
        )
    except (TypeError, ValueError):
        return None


def _clamp01(value: float) -> float:
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return float(value)


def _has_projected_fields(node: AuthoringWireNode) -> bool:
    return any(
        value is not None
        for value in (
            node.role,
            node.control_type,
            node.automation_id,
            node.name,
            node.class_name,
            node.enabled,
            node.focused,
            node.bounds,
        )
    )


def _wire_size(
    *,
    tree: list[AuthoringWireNode],
    window: AuthoringWindow,
    backend: str,
    provider: str,
    agent_drive: bool,
    coach_only: bool,
    recording: bool,
    truncated: bool,
) -> int:
    payload = {
        "schema_version": AUTHORING_OBSERVE_SCHEMA_VERSION,
        "backend": backend,
        "provider": provider,
        "mode": "authoring",
        "agent_drive": agent_drive,
        "coach_only": coach_only,
        "recording": recording,
        "window": window.model_dump(mode="json", exclude_none=True),
        "tree": [node.model_dump(mode="json", exclude_none=True) for node in tree],
        "truncated": truncated,
        "node_count": len(tree),
    }
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _project_tree(
    raw_tree: list[AuthoringRawNode],
    *,
    hmac_key: bytes,
    lease_nonce: bytes,
    viewport: StructuralBounds | None,
    observed_at_ms: int,
    window: AuthoringWindow,
    backend: str,
    provider: str,
    agent_drive: bool,
    coach_only: bool,
    recording: bool,
    raw_truncated: bool,
) -> tuple[list[AuthoringWireNode], list[AuthoringNodeTableEntry], bool]:
    tree: list[AuthoringWireNode] = []
    table: list[AuthoringNodeTableEntry] = []
    truncated = raw_truncated
    for index, raw in enumerate(_flatten(raw_tree)):
        runtime_id = raw.provider_runtime_id or f"anon:{index}"
        node = AuthoringWireNode(
            node_id=mint_node_id(
                hmac_key=hmac_key,
                lease_nonce=lease_nonce,
                provider_runtime_id=runtime_id,
            ),
            role=project_text(raw.role),
            control_type=project_text(raw.control_type),
            automation_id=project_text(raw.automation_id),
            name=project_text(raw.name),
            class_name=project_text(raw.class_name),
            enabled=raw.enabled,
            focused=raw.focused,
            bounds=_normalize_bounds(raw.bounds, viewport),
        )
        if not _has_projected_fields(node):
            continue
        candidate_tree = [*tree, node]
        if len(candidate_tree) > MAX_AUTHORING_NODES:
            truncated = True
            break
        size = _wire_size(
            tree=candidate_tree,
            window=window,
            backend=backend,
            provider=provider,
            agent_drive=agent_drive,
            coach_only=coach_only,
            recording=recording,
            truncated=True,
        )
        if size > MAX_AUTHORING_WIRE_BYTES:
            truncated = True
            break
        tree = candidate_tree
        table.append(
            AuthoringNodeTableEntry(
                node_id=node.node_id,
                backend_pixels=_pixel_bounds(raw.bounds),
                normalized=node.bounds,
                provider_runtime_id=raw.provider_runtime_id,
                observed_at=observed_at_ms,
            )
        )
    return tree, table, truncated


__all__ = [
    "AUTHORING_OBSERVE_SCHEMA_VERSION",
    "AuthoringBackend",
    "AuthoringNodeTableEntry",
    "AuthoringNormalizedBounds",
    "AuthoringObserve",
    "AuthoringPixelBounds",
    "AuthoringProjection",
    "AuthoringRawNode",
    "AuthoringRawWindow",
    "AuthoringWindow",
    "AuthoringWireNode",
    "MAX_AUTHORING_LABEL_LENGTH",
    "MAX_AUTHORING_NODES",
    "MAX_AUTHORING_WIRE_BYTES",
    "mint_node_id",
    "project_authoring_observe",
    "project_process_name",
    "project_text",
    "raw_nodes_from_observation",
    "raw_window_from_observation",
]
