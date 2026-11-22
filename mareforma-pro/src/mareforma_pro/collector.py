"""In-process rootless collector: parse, aggregate, sign, and verify."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time
from typing import Any, Iterable, Mapping

from .errors import ScopeError
from .evidence import (
    RECEIPT_SCHEMA,
    OPAQUE_TRACE_INCOMPLETE,
    SOURCE_REQUIRED,
    SOURCE_REQUIREMENTS,
    ScopeEvidence,
    VerifiedScopeEvidence,
    normalize_many,
)
from .paths import MountResolver
from .receipt import sign_receipt, verify_scope_receipt
from .strace import ParsedStrace, parse_strace
from .store import ReceiptStore


@dataclass
class ScopeRecord:
    scope_id: str
    resolver: MountResolver
    opened_at: float = field(default_factory=time.time)
    observed_files: set[str] = field(default_factory=set)
    observed_urls: set[str] = field(default_factory=set)
    observed_egress_urls: set[str] = field(default_factory=set)
    observed_dirs: set[str] = field(default_factory=set)
    opened_only: set[str] = field(default_factory=set)
    unmapped_paths: set[str] = field(default_factory=set)
    internal_temp_files: set[str] = field(default_factory=set)
    observed_db_queries: list[dict[str, Any]] = field(default_factory=list)
    opaque_reasons: set[str] = field(default_factory=set)
    payload_digests: set[str] = field(default_factory=set)
    processes: list[dict[str, Any]] = field(default_factory=list)
    socket_events: set[str] = field(default_factory=set)
    traceparent: str | None = None
    parent_scope_id: str | None = None
    evidence_level: str = "USER_TRACE"
    read_semantics: str = "READ_INTENT"
    collector_mode: str | None = None
    coverage_roots: set[str] = field(default_factory=set)
    source_requirement: str = SOURCE_REQUIRED
    trace_complete: bool = True

    def merge(self, parsed: ParsedStrace) -> None:
        self.observed_files.update(parsed.observed_files)
        self.observed_dirs.update(parsed.observed_dirs)
        self.opened_only.update(parsed.opened_only)
        self.internal_temp_files.update(getattr(parsed, "internal_temp_files", ()))
        self.unmapped_paths.update(parsed.unmapped_paths)
        self.opaque_reasons.update(parsed.opaque_reasons)
        self.processes.extend(parsed.processes)
        self.socket_events.update(parsed.socket_events)
        # A path that has ever produced a non-empty read is proven-read, even
        # if the same path is opened again later without a read. Keep the
        # receipt categories disjoint so a reader never has to guess which
        # line wins.
        self.opened_only.difference_update(self.observed_files)


class RootlessCollector:
    """The local trust center for rootless receipts.

    The HMAC secret belongs to the SDK/collector process and must not be placed
    in the target process's environment. The runner uses ``bwrap --clearenv``
    by default for exactly that reason.
    """

    def __init__(
        self,
        secret: str | bytes,
        *,
        collector_id: str = "rootless",
        receipt_ttl: float = 300.0,
        store: ReceiptStore | None = None,
        span_exporter: object | None = None,
        clock=time.time,
    ) -> None:
        if not secret:
            raise ValueError("HMAC secret must not be empty")
        self._secret = secret
        self.collector_id = collector_id
        self.receipt_ttl = float(receipt_ttl)
        self.store = store
        self.span_exporter = span_exporter
        self._clock = clock
        self._scopes: dict[str, ScopeRecord] = {}
        self._closed: dict[str, ScopeEvidence] = {}

    def open_scope(
        self,
        scope_id: str,
        resolver: MountResolver | None = None,
        *,
        mount_map: Mapping[str, str] | None = None,
        tmpfs_mounts: Iterable[str] = (),
        root_passthrough: bool = False,
        traceparent: str | None = None,
        parent_scope_id: str | None = None,
        evidence_level: str = "USER_TRACE",
        read_semantics: str = "READ_INTENT",
        collector_mode: str | None = None,
        coverage_roots: Iterable[str] = (),
        source_requirement: str = SOURCE_REQUIRED,
    ) -> None:
        if not scope_id:
            raise ScopeError("scope_id must not be empty")
        if scope_id in self._scopes:
            raise ScopeError(f"scope already open: {scope_id}")
        if scope_id in self._closed:
            raise ScopeError(f"scope already closed: {scope_id}")
        if source_requirement not in SOURCE_REQUIREMENTS:
            raise ScopeError(
                "source_requirement must be one of: "
                + ", ".join(sorted(SOURCE_REQUIREMENTS))
            )
        if resolver is None:
            resolver = MountResolver.from_mounts(
                mount_map or {},
                tmpfs_mounts=tmpfs_mounts,
                root_passthrough=root_passthrough,
            )
        coverage = (coverage_roots,) if isinstance(coverage_roots, str) else coverage_roots
        self._scopes[scope_id] = ScopeRecord(
            scope_id=scope_id,
            resolver=resolver,
            opened_at=float(self._clock()),
            traceparent=traceparent,
            parent_scope_id=parent_scope_id,
            evidence_level=evidence_level,
            read_semantics=read_semantics,
            collector_mode=collector_mode,
            coverage_roots=set(normalize_many(coverage)),
            source_requirement=source_requirement,
        )

    def _record(self, scope_id: str) -> ScopeRecord:
        try:
            return self._scopes[scope_id]
        except KeyError as exc:
            raise ScopeError(f"unknown open scope: {scope_id}") from exc

    def ingest_strace_lines(self, scope_id: str, lines: Iterable[str]) -> ParsedStrace:
        record = self._record(scope_id)
        parsed = parse_strace(lines, record.resolver)
        record.merge(parsed)
        return parsed

    def ingest_strace_path(self, scope_id: str, path: str | Path) -> ParsedStrace:
        record = self._record(scope_id)
        trace_path = Path(path)
        if not trace_path.is_file() or trace_path.stat().st_size == 0:
            record.trace_complete = False
            record.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
            return ParsedStrace(opaque_reasons={OPAQUE_TRACE_INCOMPLETE})
        try:
            with trace_path.open("r", encoding="utf-8", errors="replace") as handle:
                return self.ingest_strace_lines(scope_id, handle)
        except OSError:
            record.trace_complete = False
            record.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
            return ParsedStrace(opaque_reasons={OPAQUE_TRACE_INCOMPLETE})

    def ingest_events(
        self,
        scope_id: str,
        *,
        observed_files: Iterable[str] = (),
        observed_urls: Iterable[str] = (),
        observed_egress_urls: Iterable[str] = (),
        observed_dirs: Iterable[str] = (),
        opened_only: Iterable[str] = (),
        internal_temp_files: Iterable[str] = (),
        observed_db_queries: Iterable[Mapping[str, Any]] = (),
        payload_digests: Iterable[str] = (),
        opaque_reasons: Iterable[str] = (),
    ) -> None:
        record = self._record(scope_id)
        files = normalize_many(observed_files)
        urls = normalize_many(observed_urls)
        egress_urls = normalize_many(observed_egress_urls)
        dirs = normalize_many(observed_dirs)
        opened = normalize_many(opened_only)
        temp_files = normalize_many(internal_temp_files)
        record.observed_files.update(files)
        record.observed_urls.update(urls)
        record.observed_egress_urls.update(egress_urls)
        record.observed_dirs.update(dirs)
        record.opened_only.update(opened)
        record.internal_temp_files.update(temp_files)
        record.opened_only.difference_update(record.observed_files)
        record.opened_only.difference_update(record.observed_urls)
        for item in observed_db_queries:
            if not isinstance(item, Mapping):
                raise ValueError("observed_db_queries entries must be mappings")
            row = dict(item)
            if row not in record.observed_db_queries:
                record.observed_db_queries.append(row)
        record.payload_digests.update(str(value) for value in payload_digests if value)
        record.opaque_reasons.update(str(value) for value in opaque_reasons if value)

    def close_scope(self, scope_id: str) -> ScopeEvidence:
        record = self._record(scope_id)
        closed_at = float(self._clock())
        evidence = ScopeEvidence(
            scope_id=scope_id,
            observed_files=tuple(sorted(record.observed_files)),
            observed_urls=tuple(sorted(record.observed_urls)),
            observed_egress_urls=tuple(sorted(record.observed_egress_urls)),
            observed_dirs=tuple(sorted(record.observed_dirs)),
            opened_only=tuple(sorted(record.opened_only)),
            internal_temp_files=tuple(sorted(record.internal_temp_files)),
            observed_db_queries=tuple(
                sorted(record.observed_db_queries, key=lambda row: repr(sorted(row.items())))
            ),
            unmapped_paths=tuple(sorted(record.unmapped_paths)),
            opaque_reasons=tuple(sorted(record.opaque_reasons)),
            payload_digests=tuple(sorted(record.payload_digests)),
            processes=tuple(
                sorted(record.processes, key=lambda p: (int(p.get("pid", 0)), str(p.get("syscall", ""))))
            ),
            socket_events=tuple(sorted(record.socket_events)),
            opened_at=float(record.opened_at),
            closed_at=closed_at,
            expires_at=closed_at + self.receipt_ttl,
            schema_version=RECEIPT_SCHEMA,
            collector_mode=record.collector_mode
            or {
                "APPLICATION_PYTHON_AUDIT": "application_python_audit",
                "APPLICATION_MCP": "application_mcp",
                "USER_FUSE": "fuse_read_proxy",
            }.get(record.evidence_level, "strace_seccomp_bpf"),
            evidence_level=record.evidence_level,
            read_semantics=record.read_semantics,
            collector_id=self.collector_id,
            traceparent=record.traceparent,
            parent_scope_id=record.parent_scope_id,
            coverage_roots=tuple(sorted(record.coverage_roots)),
            source_requirement=record.source_requirement,
        )
        unsigned = evidence.to_receipt_dict()
        signed = sign_receipt(unsigned, self._secret)
        evidence = ScopeEvidence.from_receipt_dict({**unsigned, "hmac_signature": signed})
        self._scopes.pop(scope_id, None)
        self._closed[scope_id] = evidence
        if self.store is not None:
            self.store.save(evidence.to_receipt_dict())
        self._export_spans(evidence)
        return evidence

    def _export_spans(self, evidence: ScopeEvidence) -> None:
        """Send a non-authoritative span projection after a scope closes.

        Telemetry is deliberately after signing and persistence, and every
        failure is swallowed: an exporter that raises or a full queue must not
        change the receipt or the grounding verdict.
        """
        exporter = self.span_exporter
        if exporter is None:
            return
        try:
            from .otel import process_spans_from_evidence

            spans = process_spans_from_evidence(evidence)
        except Exception:
            return
        for span in spans:
            try:
                exporter.export(span)  # type: ignore[attr-defined]
            except Exception:
                continue

    def verify(self, receipt: Mapping[str, Any] | ScopeEvidence, *, now: float | None = None) -> VerifiedScopeEvidence:
        if isinstance(receipt, ScopeEvidence):
            payload = receipt.to_receipt_dict()
        else:
            payload = receipt
        return verify_scope_receipt(payload, self._secret, now=now)

    @property
    def open_scope_count(self) -> int:
        return len(self._scopes)

    def receipt(self, scope_id: str) -> ScopeEvidence | None:
        return self._closed.get(scope_id)

    def get_receipt(self, scope_id: str) -> dict[str, Any] | None:
        evidence = self._closed.get(scope_id)
        if evidence is not None:
            return evidence.to_receipt_dict()
        if self.store is not None:
            return self.store.load(scope_id)
        return None
