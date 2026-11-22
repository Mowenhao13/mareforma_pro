"""Non-authoritative OTel projection of rootless receipts.

Telemetry never changes a grounding verdict. This module only builds a compact
span projection and provides a stdlib asynchronous JSONL exporter, so the
collector works without the OpenTelemetry SDK.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
from pathlib import Path
from typing import Any, Mapping

from .evidence import ScopeEvidence
from .mcp_receipts import CallReceipt, SessionReceipt


def _trace_id(traceparent: str | None, seed: str) -> str:
    if traceparent:
        parts = traceparent.split("-")
        if len(parts) >= 4 and len(parts[1]) == 32:
            return parts[1].lower()
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _span_id(seed: str) -> str:
    return hashlib.sha256(("span:" + seed).encode("utf-8")).hexdigest()[:16]


def scope_span_from_evidence(
    evidence: ScopeEvidence,
    *,
    verdict: str | None = None,
    parent_span_id: str | None = None,
) -> dict[str, Any]:
    """Project a signed evidence record into a deterministic span mapping."""
    trace_id = _trace_id(evidence.traceparent, evidence.scope_id)
    span_id = _span_id(evidence.scope_id)
    attributes: dict[str, Any] = {
        "mareforma.scope_id": evidence.scope_id,
        "mareforma.collector_id": evidence.collector_id,
        "mareforma.collector_mode": evidence.collector_mode,
        "mareforma.evidence_level": evidence.evidence_level,
        "mareforma.read_semantics": evidence.read_semantics,
        "mareforma.coverage_roots": list(evidence.coverage_roots),
        "mareforma.observed_files": list(evidence.observed_files),
        "mareforma.observed_urls": list(evidence.observed_urls),
        "mareforma.observed_egress_urls": list(evidence.observed_egress_urls),
        "mareforma.internal_temp_files": list(evidence.internal_temp_files),
        "mareforma.observed_db_queries": [dict(row) for row in evidence.observed_db_queries],
        "mareforma.opened_only": list(evidence.opened_only),
        "mareforma.opaque_reasons": list(evidence.opaque_reasons),
        "mareforma.payload_digests": list(evidence.payload_digests),
        "mareforma.socket_events": list(evidence.socket_events),
        "mareforma.processes": [dict(p) for p in evidence.processes],
        "mareforma.source_requirement": evidence.source_requirement,
    }
    if verdict is not None:
        attributes["mareforma.grounding"] = verdict
    if evidence.parent_scope_id:
        attributes["mareforma.parent_scope_id"] = evidence.parent_scope_id
    span: dict[str, Any] = {
        "name": "mareforma.scope",
        "trace_id": trace_id,
        "span_id": span_id,
        "start_time_unix_nano": int(evidence.opened_at * 1_000_000_000),
        "end_time_unix_nano": int(evidence.closed_at * 1_000_000_000),
        "attributes": attributes,
    }
    links = []
    if evidence.parent_scope_id:
        links.append({"trace_id": trace_id, "span_id": _span_id(evidence.parent_scope_id)})
    if parent_span_id:
        links.append({"trace_id": trace_id, "span_id": parent_span_id})
    if links:
        span["links"] = links
    return span


def process_spans_from_evidence(
    evidence: ScopeEvidence,
    *,
    verdict: str | None = None,
) -> tuple[dict[str, Any], ...]:
    """Project the exec/clone process tree as deterministic child spans.

    The root span is first. Every distinct pid becomes one child span, keyed by
    the same trace id and parented to the process that cloned it (or to the
    scope span when the clone edge is absent). The projection deliberately keeps
    the raw ``execve``/``clone`` data on the scope span as attributes too: a
    backend that cannot consume nested spans still loses no evidence.
    """
    root = scope_span_from_evidence(evidence, verdict=verdict)
    process_rows: dict[int, dict[str, Any]] = {}
    for raw in evidence.processes:
        try:
            pid = int(raw.get("pid", 0))
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        row = process_rows.setdefault(
            pid,
            {"pid": pid, "parent_pid": None, "syscalls": set(), "binary": None},
        )
        parent = raw.get("parent_pid")
        if parent is not None:
            try:
                row["parent_pid"] = int(parent)
            except (TypeError, ValueError):
                pass
        syscall = raw.get("syscall")
        if isinstance(syscall, str) and syscall:
            row["syscalls"].add(syscall)
        binary = raw.get("binary")
        if isinstance(binary, str) and binary:
            row["binary"] = binary

    span_ids = {
        row["pid"]: _span_id(f"{evidence.scope_id}:process:{row['pid']}")
        for row in process_rows.values()
    }
    spans: list[dict[str, Any]] = [root]
    for pid in sorted(process_rows):
        row = process_rows[pid]
        parent_pid = row["parent_pid"]
        parent_span_id = (
            span_ids.get(parent_pid, root["span_id"]) if parent_pid else root["span_id"]
        )
        name = f"process {row['binary']}" if row["binary"] else f"process {pid}"
        attributes: dict[str, Any] = {
            "mareforma.scope_id": evidence.scope_id,
            "mareforma.process.pid": pid,
            "mareforma.process.syscalls": sorted(row["syscalls"]),
        }
        if parent_pid:
            attributes["mareforma.process.parent_pid"] = parent_pid
        if row["binary"]:
            attributes["mareforma.process.binary"] = row["binary"]
        spans.append(
            {
                "name": name,
                "trace_id": root["trace_id"],
                "span_id": span_ids[pid],
                "parent_span_id": parent_span_id,
                "start_time_unix_nano": root["start_time_unix_nano"],
                "end_time_unix_nano": root["end_time_unix_nano"],
                "attributes": attributes,
            }
        )
    return tuple(spans)


def call_span_from_receipt(
    receipt: CallReceipt,
    *,
    parent_span_id: str | None = None,
) -> dict[str, Any]:
    """Project a long-running MCP CallReceipt into one OTel-shaped span."""
    trace_id = _trace_id(receipt.traceparent, receipt.call_id)
    span_id = _span_id(receipt.call_id)
    attributes: dict[str, Any] = {
        "mareforma.receipt.kind": "call",
        "mareforma.call_id": receipt.call_id,
        "mareforma.scope_id": receipt.scope_id,
        "mareforma.session_id": receipt.session_id,
        "mareforma.method": receipt.method,
        "mareforma.request_id": receipt.request_id,
        "mareforma.http_status": receipt.http_status,
        "mareforma.observed_files": list(receipt.observed_files),
        "mareforma.internal_temp_files": list(receipt.internal_temp_files),
        "mareforma.observed_urls": list(receipt.observed_urls),
        "mareforma.observed_egress_urls": list(receipt.observed_egress_urls),
        "mareforma.observed_db_queries": [dict(row) for row in receipt.observed_db_queries],
        "mareforma.opened_only": list(receipt.opened_only),
        "mareforma.unmapped_paths": list(receipt.unmapped_paths),
        "mareforma.opaque_reasons": list(receipt.opaque_reasons),
        "mareforma.payload_digests": list(receipt.payload_digests),
        "mareforma.socket_events": list(receipt.socket_events),
        "mareforma.collector_mode": receipt.collector_mode,
        "mareforma.evidence_level": receipt.evidence_level,
    }
    if receipt.parent_scope_id:
        attributes["mareforma.parent_scope_id"] = receipt.parent_scope_id
    event_attributes: list[dict[str, Any]] = []
    for path in receipt.observed_files:
        event_attributes.append({"name": "file.read", "attributes": {"path": path}})
    for path in receipt.internal_temp_files:
        event_attributes.append(
            {"name": "temp.internal_read", "attributes": {"path": path}}
        )
    for url in receipt.observed_egress_urls:
        event_attributes.append({"name": "egress.url", "attributes": {"url": url}})
    for row in receipt.observed_db_queries:
        event_attributes.append({"name": "db.query", "attributes": dict(row)})
    span: dict[str, Any] = {
        "name": "mareforma.mcp.call",
        "trace_id": trace_id,
        "span_id": span_id,
        "start_time_unix_nano": int(receipt.started_at * 1_000_000_000),
        "end_time_unix_nano": int(receipt.closed_at * 1_000_000_000),
        "attributes": attributes,
    }
    if parent_span_id:
        span["parent_span_id"] = parent_span_id
    if event_attributes:
        span["events"] = event_attributes
    if receipt.parent_scope_id:
        span["links"] = [{"trace_id": trace_id, "span_id": _span_id(receipt.parent_scope_id)}]
    return span


def session_span_from_receipt(
    receipt: SessionReceipt,
    *,
    call_receipts: tuple[CallReceipt, ...] = (),
) -> dict[str, Any]:
    """Project a SessionReceipt and link it to its per-call spans."""
    trace_id = _trace_id(None, receipt.session_id)
    span_id = _span_id("session:" + receipt.session_id)
    attributes: dict[str, Any] = {
        "mareforma.receipt.kind": "session",
        "mareforma.session_id": receipt.session_id,
        "mareforma.scope_ids": list(receipt.scope_ids),
        "mareforma.call_ids": list(receipt.call_ids),
        "mareforma.call_receipt_digests": list(receipt.call_receipt_digests),
        "mareforma.observed_files": list(receipt.observed_files),
        "mareforma.internal_temp_files": list(receipt.internal_temp_files),
        "mareforma.observed_egress_urls": list(receipt.observed_egress_urls),
        "mareforma.observed_db_queries": [dict(row) for row in receipt.observed_db_queries],
        "mareforma.opaque_reasons": list(receipt.opaque_reasons),
        "mareforma.collector_mode": receipt.collector_mode,
    }
    span: dict[str, Any] = {
        "name": "mareforma.mcp.session",
        "trace_id": trace_id,
        "span_id": span_id,
        "start_time_unix_nano": int(receipt.opened_at * 1_000_000_000),
        "end_time_unix_nano": int(receipt.closed_at * 1_000_000_000),
        "attributes": attributes,
    }
    links = [
        {"trace_id": _trace_id(call.traceparent, call.call_id), "span_id": _span_id(call.call_id)}
        for call in call_receipts
    ]
    if links:
        span["links"] = links
    return span


class AsyncJsonlSpanExporter:
    """Write spans on a bounded background queue without affecting grounding.

    A full queue drops telemetry rather than delaying the collector. Call
    ``close()`` at shutdown to flush queued spans.
    """

    def __init__(self, path: str | Path, *, max_queue: int = 1024) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=max_queue)
        self._thread = threading.Thread(target=self._run, name="mareforma-otel-jsonl", daemon=True)
        self._thread.start()

    def export(self, span: Mapping[str, Any]) -> None:
        try:
            self._queue.put_nowait(dict(span))
        except queue.Full:
            return

    def _run(self) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            while True:
                item = self._queue.get()
                if item is None:
                    return
                try:
                    handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
                    handle.flush()
                except OSError:
                    # Telemetry is non-authoritative by construction.
                    continue

    def close(self, *, timeout: float = 5.0) -> None:
        try:
            self._queue.put(None, timeout=timeout)
        except queue.Full:
            return
        self._thread.join(timeout=timeout)


# The plan names an OTLP adapter as an optional stage-4 addition. Keep the
# importable name useful without forcing the OpenTelemetry SDK into core deps.
class OTLPSpanExporterAdapter:
    """Optional OTLP/HTTP adapter using the optional extra if installed."""

    def __init__(self, endpoint: str, *, service_name: str = "mareforma") -> None:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "OTLP export requires the 'otel' extra (opentelemetry-sdk and "
                "opentelemetry-exporter-otlp-proto-http)"
            ) from exc
        provider = TracerProvider(resource=None)
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        self._provider = provider
        self._tracer = provider.get_tracer(service_name)

    def export(self, span: Mapping[str, Any]) -> None:
        otel_span = self._tracer.start_span(str(span.get("name", "mareforma.scope")))
        for key, value in (span.get("attributes") or {}).items():
            otel_span.set_attribute(str(key), value)
        otel_span.end()

    def shutdown(self) -> None:
        self._provider.shutdown()
