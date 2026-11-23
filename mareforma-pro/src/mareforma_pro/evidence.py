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
from urllib.parse import urlsplit


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
OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE = "computed_no_external_source"
OPAQUE_CONCURRENT_CALL_OVERLAP = "concurrent_call_overlap"
OPAQUE_EGRESS_PROXY_BYPASSED = "egress_proxy_bypassed"
OPAQUE_EGRESS_UNINSPECTED = "egress_uninspected"
OPAQUE_DB_UNINSPECTED = "db_uninspected"
OPAQUE_HTTPS_PATH_OPAQUE = "https_path_opaque"
OPAQUE_HTTP_BODY_UNOBSERVED = "http_body_unobserved"

# Whether this observation was expected to read an external source. Most scopes
# default to ``required``. A pure computation can explicitly say that no external
# source exists; the verdict remains OPAQUE, but names a different reason so a
# product layer does not confuse it with a missing citation for data work.
SOURCE_REQUIRED = "required"
SOURCE_NOT_APPLICABLE = "not_applicable"
SOURCE_REQUIREMENTS = frozenset({SOURCE_REQUIRED, SOURCE_NOT_APPLICABLE})
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
        OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE,
        OPAQUE_CONCURRENT_CALL_OVERLAP,
        OPAQUE_EGRESS_PROXY_BYPASSED,
        OPAQUE_EGRESS_UNINSPECTED,
        OPAQUE_DB_UNINSPECTED,
        OPAQUE_HTTPS_PATH_OPAQUE,
        OPAQUE_HTTP_BODY_UNOBSERVED,
    }
)


def normalize_path(value: str | os.PathLike[str]) -> str:
    """Normalize a local path or URL without requiring the target to exist.

    Existing paths are realpath'd so a symlinked data directory compares the
    same way as the core observer's citations. Non-existing paths use lexical
    normalization; this keeps a missing citation from silently matching a
    different path. URLs are reduced to ``scheme://host[:port]/path``: userinfo,
    query strings, and fragments are dropped before they can enter a signed
    receipt, because those often carry credentials or presigned secrets.
    """
    raw = os.fspath(value)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not raw:
        return ""
    if raw.startswith("sha256:"):
        return raw
    if "://" in raw:
        return _normalize_url(raw)
    try:
        if os.path.lexists(raw):
            return os.path.realpath(raw)
    except OSError:
        pass
    return posixpath.normpath(raw)


def _normalize_url(raw: str) -> str:
    """Return a credential-free URL identity, or the stripped input otherwise."""
    try:
        parts = urlsplit(raw)
        if parts.scheme == "file" and parts.path:
            return posixpath.normpath(parts.path)
        if not parts.scheme or not parts.netloc:
            return raw.strip()
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        try:
            port = f":{parts.port}" if parts.port else ""
        except ValueError:
            port = ""
        return f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"
    except (TypeError, ValueError):
        return raw.strip()


def normalize_many(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        values = (values,)
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
    source_requirement: str = SOURCE_REQUIRED

    def __post_init__(self) -> None:
        if not self.scope_id:
            raise ValueError("scope_id must not be empty")
        if self.source_requirement not in SOURCE_REQUIREMENTS:
            raise ValueError(
                "source_requirement must be one of: "
                + ", ".join(sorted(SOURCE_REQUIREMENTS))
            )
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
    ``observed_urls`` are application-reported URL reads, never kernel network
    evidence. They are carried only when an application adapter explicitly says
    the response bytes arrived for that URL. ``opened_only`` are paths opened for
    reading but not observed being read. The distinction is intentionally part
    of the wire format.
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
    # Append-only wire fields. Keep them after every pre-existing positional
    # field so a caller constructing ScopeEvidence positionally keeps its
    # meaning across the 0.1 -> 0.2 transition.
    observed_urls: tuple[str, ...] = ()
    source_requirement: str = SOURCE_REQUIRED
    internal_temp_files: tuple[str, ...] = ()
    observed_egress_urls: tuple[str, ...] = ()
    observed_db_queries: tuple[Mapping[str, Any], ...] = ()
    # Worker-mode fields. These are optional so existing scope receipts keep
    # their old signed shape and byte-identical serialization when absent.
    task_id: str | None = None
    worker_id: str | None = None
    attempt: str | None = None
    execution_id: str | None = None
    read_bytes: int = 0
    observed_http: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "observed_files",
            "observed_urls",
            "observed_dirs",
            "opened_only",
            "unmapped_paths",
            "opaque_reasons",
            "payload_digests",
            "socket_events",
            "coverage_roots",
            "internal_temp_files",
            "observed_egress_urls",
        ):
            object.__setattr__(self, name, tuple(dict.fromkeys(getattr(self, name) or ())))
        object.__setattr__(self, "processes", tuple(self.processes or ()))
        normalized_db_queries: list[Mapping[str, Any]] = []
        seen_db_queries: set[str] = set()
        for item in self.observed_db_queries or ():
            if not isinstance(item, Mapping):
                raise ValueError("observed_db_queries entries must be mappings")
            row = dict(item)
            key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
            if key not in seen_db_queries:
                seen_db_queries.add(key)
                normalized_db_queries.append(row)
        object.__setattr__(self, "observed_db_queries", tuple(normalized_db_queries))
        normalized_http: list[Mapping[str, Any]] = []
        seen_http: set[str] = set()
        for item in self.observed_http or ():
            if not isinstance(item, Mapping):
                raise ValueError("observed_http entries must be mappings")
            row = dict(item)
            key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
            if key not in seen_http:
                seen_http.add(key)
                normalized_http.append(row)
        object.__setattr__(self, "observed_http", tuple(normalized_http))
        if self.source_requirement not in SOURCE_REQUIREMENTS:
            raise ValueError(
                "source_requirement must be one of: "
                + ", ".join(sorted(SOURCE_REQUIREMENTS))
            )

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
        if self.observed_urls:
            receipt["observed_urls"] = list(self.observed_urls)
        if self.source_requirement != SOURCE_REQUIRED:
            receipt["source_requirement"] = self.source_requirement
        # Keep older receipts byte-identical when no coverage bound was
        # recorded. A non-empty root list is signed as part of the receipt.
        if self.coverage_roots:
            receipt["coverage_roots"] = list(self.coverage_roots)
        if self.internal_temp_files:
            receipt["internal_temp_files"] = list(self.internal_temp_files)
        if self.observed_egress_urls:
            receipt["observed_egress_urls"] = list(self.observed_egress_urls)
        if self.observed_db_queries:
            receipt["observed_db_queries"] = [dict(row) for row in self.observed_db_queries]
        if self.observed_http:
            receipt["observed_http"] = [dict(row) for row in self.observed_http]
        if self.task_id:
            receipt["task_id"] = self.task_id
        if self.worker_id:
            receipt["worker_id"] = self.worker_id
        if self.attempt:
            receipt["attempt"] = self.attempt
        if self.execution_id:
            receipt["execution_id"] = self.execution_id
        if self.read_bytes:
            receipt["read_bytes"] = int(self.read_bytes)
        return receipt

    @classmethod
    def from_receipt_dict(cls, receipt: Mapping[str, Any]) -> "ScopeEvidence":
        if not isinstance(receipt, Mapping):
            raise TypeError("receipt must be a mapping")
        return cls(
            scope_id=str(receipt.get("scope_id", "")),
            observed_files=tuple(receipt.get("observed_files") or ()),
            observed_urls=tuple(receipt.get("observed_urls") or ()),
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
            source_requirement=str(
                receipt.get("source_requirement", SOURCE_REQUIRED)
            ),
            internal_temp_files=tuple(receipt.get("internal_temp_files") or ()),
            observed_egress_urls=tuple(receipt.get("observed_egress_urls") or ()),
            observed_db_queries=tuple(
                dict(row)
                for row in receipt.get("observed_db_queries") or ()
                if isinstance(row, Mapping)
            ),
            observed_http=tuple(
                dict(row)
                for row in receipt.get("observed_http") or ()
                if isinstance(row, Mapping)
            ),
            task_id=receipt.get("task_id"),
            worker_id=receipt.get("worker_id"),
            attempt=receipt.get("attempt"),
            execution_id=receipt.get("execution_id"),
            read_bytes=int(receipt.get("read_bytes") or 0),
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
