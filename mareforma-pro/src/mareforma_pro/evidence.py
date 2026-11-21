"""Evidence records and receipt-facing values for the rootless collector.

The collector records *read intent* and, when the parser can bind a syscall to
the fd path, actual successful reads. A successful ``open(..., O_RDONLY)`` is
not renamed into proof that bytes were consumed: the receipt carries
``opened_only`` separately and the verdict builder treats it as a blind spot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import posixpath
import time
from typing import Any, Iterable, Mapping


RECEIPT_SCHEMA = "mareforma_pro.rootless_receipt/v1"
RECEIPT_DOMAIN = b"mareforma_pro.rootless_receipt/v1\n"

# Diagnostic codes used by the rootless path. The first six are the stable
# vocabulary from the plan; ``open_only`` is an additional fail-closed marker
# needed when a file was opened for reading but no read syscall was observed.
OPAQUE_UNMAPPED_TMPFS = "unmapped_tmpfs"
OPAQUE_UNMAPPED_SANDBOX = "unmapped_sandbox_path"
OPAQUE_TRACE_INCOMPLETE = "trace_incomplete"
OPAQUE_EXTERNAL_MCP = "external_mcp"
OPAQUE_UNSIGNED_DECLARED = "unsigned_declared"
OPAQUE_STATIC_BINARY_UNTRACED = "static_binary_untraced"
OPAQUE_OPEN_ONLY = "open_only"
OPAQUE_SOCKET_UNBOUND = "socket_event_unbound"
OPAQUE_NO_CITED_SOURCE = "no_cited_source"
OPAQUE_REASONS = frozenset(
    {
        OPAQUE_UNMAPPED_TMPFS,
        OPAQUE_UNMAPPED_SANDBOX,
        OPAQUE_TRACE_INCOMPLETE,
        OPAQUE_EXTERNAL_MCP,
        OPAQUE_UNSIGNED_DECLARED,
        OPAQUE_STATIC_BINARY_UNTRACED,
        OPAQUE_OPEN_ONLY,
        OPAQUE_SOCKET_UNBOUND,
        OPAQUE_NO_CITED_SOURCE,
    }
)


def normalize_path(value: str | os.PathLike[str]) -> str:
    """Normalize a local path without requiring it to exist.

    Existing paths are realpath'd so a symlinked data directory compares the
    same way as the core observer's citations. Non-existing paths use lexical
    normalization; this keeps a missing citation from silently matching a
    different path.
    """
    raw = os.fspath(value)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not raw:
        return ""
    # URLs and sha256 content addresses are not filesystem paths.
    if "://" in raw or raw.startswith("sha256:"):
        return raw
    try:
        if os.path.lexists(raw):
            return os.path.realpath(raw)
    except OSError:
        pass
    return posixpath.normpath(raw)


def normalize_many(values: Iterable[str]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        norm = normalize_path(value)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return tuple(out)


def normalize_mount_map(mount_map: Mapping[str, str] | None) -> dict[str, str]:
    if not mount_map:
        return {}
    out: dict[str, str] = {}
    for sandbox, host in mount_map.items():
        sbx = posixpath.normpath(os.fspath(sandbox))
        hst = posixpath.normpath(os.fspath(host))
        if not sbx.startswith("/") or not hst.startswith("/"):
            raise ValueError("mount_map entries must use absolute paths")
        out[sbx] = hst
    return out


@dataclass(frozen=True)
class ScopeRegistration:
    """The deterministic inputs that define one observed execution scope."""

    scope_id: str
    mount_map: Mapping[str, str] = field(default_factory=dict)
    tmpfs_mounts: tuple[str, ...] = ()
    root_passthrough: bool = False
    traceparent: str | None = None
    parent_scope_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    evidence_level: str = "USER_TRACE"
    read_semantics: str = "READ_INTENT"
    coverage_roots: tuple[str, ...] = ()
    collector_mode: str | None = None

    def __post_init__(self) -> None:
        if not self.scope_id:
            raise ValueError("scope_id must not be empty")
        object.__setattr__(self, "mount_map", normalize_mount_map(self.mount_map))
        object.__setattr__(
            self,
            "tmpfs_mounts",
            tuple(posixpath.normpath(os.fspath(path)) for path in self.tmpfs_mounts),
        )
        coverage_roots = (
            (self.coverage_roots,) if isinstance(self.coverage_roots, str) else self.coverage_roots
        )
        object.__setattr__(self, "coverage_roots", normalize_many(coverage_roots))


@dataclass(frozen=True)
class ScopeEvidence:
    """A signed, collector-produced observation record.

    ``observed_files`` are paths for which a successful read syscall was seen
    (or, for application hooks, an explicit read event was reported).
    ``opened_only`` are paths opened for reading but not observed being read.
    The distinction is intentionally part of the wire format.
    """

    scope_id: str
    observed_files: tuple[str, ...] = ()
    observed_dirs: tuple[str, ...] = ()
    opened_only: tuple[str, ...] = ()
    unmapped_paths: tuple[str, ...] = ()
    opaque_reasons: tuple[str, ...] = ()
    payload_digests: tuple[str, ...] = ()
    processes: tuple[Mapping[str, Any], ...] = ()
    socket_events: tuple[str, ...] = ()
    opened_at: float = 0.0
    closed_at: float = 0.0
    expires_at: float = 0.0
    schema_version: str = RECEIPT_SCHEMA
    collector_mode: str = "strace_seccomp_bpf"
    evidence_level: str = "USER_TRACE"
    read_semantics: str = "READ_INTENT"
    collector_id: str = "rootless"
    traceparent: str | None = None
    parent_scope_id: str | None = None
    # Host paths this backend can observe. Empty means the legacy scope-wide
    # contract (for example a root_passthrough strace run).
    coverage_roots: tuple[str, ...] = ()
    hmac_signature: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "observed_files",
            "observed_dirs",
            "opened_only",
            "unmapped_paths",
            "opaque_reasons",
            "payload_digests",
            "socket_events",
            "coverage_roots",
        ):
            object.__setattr__(self, name, tuple(dict.fromkeys(getattr(self, name) or ())))
        object.__setattr__(self, "processes", tuple(self.processes or ()))

    def to_receipt_dict(self) -> dict[str, Any]:
        """Return a fresh JSON-compatible mapping, including the signature."""
        receipt = {
            "schema_version": self.schema_version,
            "scope_id": self.scope_id,
            "collector_id": self.collector_id,
            "collector_mode": self.collector_mode,
            "evidence_level": self.evidence_level,
            "read_semantics": self.read_semantics,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "expires_at": self.expires_at,
            "observed_files": list(self.observed_files),
            "observed_dirs": list(self.observed_dirs),
            "opened_only": list(self.opened_only),
            "unmapped_paths": list(self.unmapped_paths),
            "opaque_reasons": list(self.opaque_reasons),
            "payload_digests": list(self.payload_digests),
            "processes": [dict(p) for p in self.processes],
            "socket_events": list(self.socket_events),
            "traceparent": self.traceparent,
            "parent_scope_id": self.parent_scope_id,
            "hmac_signature": self.hmac_signature,
        }
        # Keep older receipts byte-identical when no coverage bound was
        # recorded. A non-empty root list is signed as part of the receipt.
        if self.coverage_roots:
            receipt["coverage_roots"] = list(self.coverage_roots)
        return receipt

    @classmethod
    def from_receipt_dict(cls, receipt: Mapping[str, Any]) -> "ScopeEvidence":
        if not isinstance(receipt, Mapping):
            raise TypeError("receipt must be a mapping")
        return cls(
            scope_id=str(receipt.get("scope_id", "")),
            observed_files=tuple(receipt.get("observed_files") or ()),
            observed_dirs=tuple(receipt.get("observed_dirs") or ()),
            opened_only=tuple(receipt.get("opened_only") or ()),
            unmapped_paths=tuple(receipt.get("unmapped_paths") or ()),
            opaque_reasons=tuple(receipt.get("opaque_reasons") or ()),
            payload_digests=tuple(receipt.get("payload_digests") or ()),
            processes=tuple(dict(p) for p in receipt.get("processes") or ()),
            socket_events=tuple(receipt.get("socket_events") or ()),
            opened_at=float(receipt.get("opened_at", 0.0)),
            closed_at=float(receipt.get("closed_at", 0.0)),
            expires_at=float(receipt.get("expires_at", 0.0)),
            schema_version=str(receipt.get("schema_version", RECEIPT_SCHEMA)),
            collector_mode=str(receipt.get("collector_mode", "strace_seccomp_bpf")),
            evidence_level=str(receipt.get("evidence_level", "USER_TRACE")),
            read_semantics=str(receipt.get("read_semantics", "READ_INTENT")),
            collector_id=str(receipt.get("collector_id", "rootless")),
            traceparent=receipt.get("traceparent"),
            parent_scope_id=receipt.get("parent_scope_id"),
            coverage_roots=tuple(receipt.get("coverage_roots") or ()),
            hmac_signature=receipt.get("hmac_signature"),
        )


@dataclass(frozen=True)
class VerifiedScopeEvidence:
    """Evidence that has passed the local HMAC verification gate."""

    evidence: ScopeEvidence
    verified_at: float = field(default_factory=time.time)

    @property
    def receipt(self) -> dict[str, Any]:
        return self.evidence.to_receipt_dict()
