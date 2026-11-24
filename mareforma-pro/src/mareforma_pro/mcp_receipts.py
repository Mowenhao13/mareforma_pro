"""Signed Call and Session receipts for the long-running MCP supervisor.

The short-task collector signs one ``ScopeEvidence`` per process lifetime. A
long-running MCP server has a different shape: one process can serve many
sessions and calls. These receipts keep the same HMAC discipline while making
the two lifecycles explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import time
from typing import Any, Iterable, Mapping

from .evidence import normalize_many, normalize_path
from .errors import ReceiptError
from .receipt import canonical_bytes, sign_payload, verify_payload, verify_scope_receipt

CALL_RECEIPT_SCHEMA = "mareforma_pro.mcp_call_receipt/v1"
SESSION_RECEIPT_SCHEMA = "mareforma_pro.mcp_session_receipt/v1"
TASK_CHAIN_VERDICT_SCHEMA = "mareforma_pro.task_chain_verdict/v1"
CALL_RECEIPT_DOMAIN = b"mareforma_pro.mcp_call_receipt/v1\n"
SESSION_RECEIPT_DOMAIN = b"mareforma_pro.mcp_session_receipt/v1\n"

# Statuses for the two-link MCP -> worker chain. Only ``LINKED`` is positive;
# every other value is an explicit refusal to infer a parent relationship.
TASK_CHAIN_LINKED = "LINKED"
TASK_CHAIN_CALL_RECEIPT_INVALID = "CALL_RECEIPT_INVALID"
TASK_CHAIN_WORKER_RECEIPT_INVALID = "WORKER_RECEIPT_INVALID"
TASK_CHAIN_MISSING_GATEWAY_TASK_ID = "MISSING_GATEWAY_TASK_ID"
TASK_CHAIN_MISSING_WORKER_TASK_ID = "MISSING_WORKER_TASK_ID"
TASK_CHAIN_MISSING_WORKER_PARENT_SCOPE = "MISSING_WORKER_PARENT_SCOPE"
TASK_CHAIN_TASK_ID_MISMATCH = "TASK_ID_MISMATCH"
TASK_CHAIN_PARENT_SCOPE_MISMATCH = "PARENT_SCOPE_MISMATCH"


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values if value))


def _db_rows(values: Iterable[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    rows: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping):
            continue
        row = dict(value)
        key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
        if key not in seen:
            seen.add(key)
            rows.append(row)
    return tuple(rows)


def receipt_digest(payload: Mapping[str, Any]) -> str:
    """Return a content digest of the signed payload without its MAC."""
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class CallReceipt:
    """The evidence for one MCP HTTP call.

    The OS-level fields are deliberately the same vocabulary as the rootless
    scope receipt. ``observed_egress_urls`` is proxy/application evidence about
    outbound traffic; it is not a claim that the response body was read.
    """

    call_id: str
    scope_id: str
    session_id: str | None = None
    method: str | None = None
    request_id: str | None = None
    started_at: float = 0.0
    closed_at: float = 0.0
    expires_at: float = 0.0
    http_status: int | None = None
    observed_files: tuple[str, ...] = ()
    internal_temp_files: tuple[str, ...] = ()
    observed_urls: tuple[str, ...] = ()
    observed_egress_urls: tuple[str, ...] = ()
    observed_db_queries: tuple[Mapping[str, Any], ...] = ()
    opened_only: tuple[str, ...] = ()
    unmapped_paths: tuple[str, ...] = ()
    opaque_reasons: tuple[str, ...] = ()
    payload_digests: tuple[str, ...] = ()
    socket_events: tuple[str, ...] = ()
    processes: tuple[Mapping[str, Any], ...] = ()
    traceparent: str | None = None
    parent_scope_id: str | None = None
    evidence_level: str = "USER_TRACE"
    collector_mode: str = "mcp_process_supervisor"
    schema_version: str = CALL_RECEIPT_SCHEMA
    hmac_signature: str | None = None
    # Append-only field for the signed gateway half of a two-link task chain.
    # It is omitted from the wire shape when empty so pre-existing receipts
    # remain byte-identical.
    dispatched_task_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "observed_files",
            "internal_temp_files",
            "observed_urls",
            "observed_egress_urls",
            "opened_only",
            "unmapped_paths",
            "opaque_reasons",
            "payload_digests",
            "socket_events",
            "dispatched_task_ids",
        ):
            object.__setattr__(self, name, _dedupe(getattr(self, name) or ()))
        object.__setattr__(self, "observed_db_queries", _db_rows(self.observed_db_queries))
        object.__setattr__(self, "processes", tuple(dict(row) for row in self.processes or ()))

    def to_receipt_dict(self) -> dict[str, Any]:
        receipt = {
            "schema_version": self.schema_version,
            "call_id": self.call_id,
            "scope_id": self.scope_id,
            "session_id": self.session_id,
            "method": self.method,
            "request_id": self.request_id,
            "started_at": self.started_at,
            "closed_at": self.closed_at,
            "expires_at": self.expires_at,
            "http_status": self.http_status,
            "observed_files": list(self.observed_files),
            "internal_temp_files": list(self.internal_temp_files),
            "observed_urls": list(self.observed_urls),
            "observed_egress_urls": list(self.observed_egress_urls),
            "observed_db_queries": [dict(row) for row in self.observed_db_queries],
            "opened_only": list(self.opened_only),
            "unmapped_paths": list(self.unmapped_paths),
            "opaque_reasons": list(self.opaque_reasons),
            "payload_digests": list(self.payload_digests),
            "socket_events": list(self.socket_events),
            "processes": [dict(row) for row in self.processes],
            "traceparent": self.traceparent,
            "parent_scope_id": self.parent_scope_id,
            "evidence_level": self.evidence_level,
            "collector_mode": self.collector_mode,
            "hmac_signature": self.hmac_signature,
        }
        if self.dispatched_task_ids:
            receipt["dispatched_task_ids"] = list(self.dispatched_task_ids)
        return receipt

    @classmethod
    def from_receipt_dict(cls, payload: Mapping[str, Any]) -> "CallReceipt":
        if not isinstance(payload, Mapping):
            raise TypeError("call receipt must be a mapping")
        return cls(
            schema_version=str(payload.get("schema_version", CALL_RECEIPT_SCHEMA)),
            call_id=str(payload.get("call_id", "")),
            scope_id=str(payload.get("scope_id", "")),
            session_id=payload.get("session_id"),
            method=payload.get("method"),
            request_id=payload.get("request_id"),
            started_at=float(payload.get("started_at", 0.0)),
            closed_at=float(payload.get("closed_at", 0.0)),
            expires_at=float(payload.get("expires_at", 0.0)),
            http_status=payload.get("http_status"),
            observed_files=tuple(payload.get("observed_files") or ()),
            internal_temp_files=tuple(payload.get("internal_temp_files") or ()),
            observed_urls=tuple(payload.get("observed_urls") or ()),
            observed_egress_urls=tuple(payload.get("observed_egress_urls") or ()),
            observed_db_queries=tuple(payload.get("observed_db_queries") or ()),
            opened_only=tuple(payload.get("opened_only") or ()),
            unmapped_paths=tuple(payload.get("unmapped_paths") or ()),
            opaque_reasons=tuple(payload.get("opaque_reasons") or ()),
            payload_digests=tuple(payload.get("payload_digests") or ()),
            socket_events=tuple(payload.get("socket_events") or ()),
            processes=tuple(payload.get("processes") or ()),
            traceparent=payload.get("traceparent"),
            parent_scope_id=payload.get("parent_scope_id"),
            evidence_level=str(payload.get("evidence_level", "USER_TRACE")),
            collector_mode=str(payload.get("collector_mode", "mcp_process_supervisor")),
            hmac_signature=payload.get("hmac_signature"),
            dispatched_task_ids=tuple(payload.get("dispatched_task_ids") or ()),
        )


@dataclass(frozen=True)
class SessionReceipt:
    """A signed roll-up of all calls in one MCP session (or one call)."""

    session_id: str
    opened_at: float = 0.0
    closed_at: float = 0.0
    expires_at: float = 0.0
    scope_ids: tuple[str, ...] = ()
    call_ids: tuple[str, ...] = ()
    call_receipt_digests: tuple[str, ...] = ()
    observed_files: tuple[str, ...] = ()
    internal_temp_files: tuple[str, ...] = ()
    observed_egress_urls: tuple[str, ...] = ()
    observed_db_queries: tuple[Mapping[str, Any], ...] = ()
    opened_only: tuple[str, ...] = ()
    unmapped_paths: tuple[str, ...] = ()
    opaque_reasons: tuple[str, ...] = ()
    schema_version: str = SESSION_RECEIPT_SCHEMA
    collector_mode: str = "mcp_process_supervisor"
    hmac_signature: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "scope_ids",
            "call_ids",
            "call_receipt_digests",
            "observed_files",
            "internal_temp_files",
            "observed_egress_urls",
            "opened_only",
            "unmapped_paths",
            "opaque_reasons",
        ):
            object.__setattr__(self, name, _dedupe(getattr(self, name) or ()))
        object.__setattr__(self, "observed_db_queries", _db_rows(self.observed_db_queries))

    def to_receipt_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "expires_at": self.expires_at,
            "scope_ids": list(self.scope_ids),
            "call_ids": list(self.call_ids),
            "call_receipt_digests": list(self.call_receipt_digests),
            "observed_files": list(self.observed_files),
            "internal_temp_files": list(self.internal_temp_files),
            "observed_egress_urls": list(self.observed_egress_urls),
            "observed_db_queries": [dict(row) for row in self.observed_db_queries],
            "opened_only": list(self.opened_only),
            "unmapped_paths": list(self.unmapped_paths),
            "opaque_reasons": list(self.opaque_reasons),
            "collector_mode": self.collector_mode,
            "hmac_signature": self.hmac_signature,
        }

    @classmethod
    def from_receipt_dict(cls, payload: Mapping[str, Any]) -> "SessionReceipt":
        if not isinstance(payload, Mapping):
            raise TypeError("session receipt must be a mapping")
        return cls(
            schema_version=str(payload.get("schema_version", SESSION_RECEIPT_SCHEMA)),
            session_id=str(payload.get("session_id", "")),
            opened_at=float(payload.get("opened_at", 0.0)),
            closed_at=float(payload.get("closed_at", 0.0)),
            expires_at=float(payload.get("expires_at", 0.0)),
            scope_ids=tuple(payload.get("scope_ids") or ()),
            call_ids=tuple(payload.get("call_ids") or ()),
            call_receipt_digests=tuple(payload.get("call_receipt_digests") or ()),
            observed_files=tuple(payload.get("observed_files") or ()),
            internal_temp_files=tuple(payload.get("internal_temp_files") or ()),
            observed_egress_urls=tuple(payload.get("observed_egress_urls") or ()),
            observed_db_queries=tuple(payload.get("observed_db_queries") or ()),
            opened_only=tuple(payload.get("opened_only") or ()),
            unmapped_paths=tuple(payload.get("unmapped_paths") or ()),
            opaque_reasons=tuple(payload.get("opaque_reasons") or ()),
            collector_mode=str(payload.get("collector_mode", "mcp_process_supervisor")),
            hmac_signature=payload.get("hmac_signature"),
        )


def sign_call_receipt(receipt: CallReceipt, secret: str | bytes) -> CallReceipt:
    unsigned = receipt.to_receipt_dict()
    unsigned.pop("hmac_signature", None)
    return replace(receipt, hmac_signature=sign_payload(unsigned, secret, domain=CALL_RECEIPT_DOMAIN))


def verify_call_receipt(
    payload: Mapping[str, Any], secret: str | bytes, *, now: float | None = None
) -> CallReceipt:
    if not isinstance(payload, Mapping):
        raise TypeError("call receipt must be a mapping")
    if payload.get("schema_version") != CALL_RECEIPT_SCHEMA:
        raise ReceiptError("unsupported call receipt schema")
    if not verify_payload(payload, secret, domain=CALL_RECEIPT_DOMAIN):
        raise ReceiptError("call receipt HMAC verification failed")
    receipt = CallReceipt.from_receipt_dict(payload)
    if not receipt.call_id or not receipt.scope_id:
        raise ReceiptError("call receipt has an empty identity")
    check_at = time.time() if now is None else float(now)
    if receipt.expires_at and check_at > receipt.expires_at:
        raise ReceiptError("call receipt has expired")
    return receipt


@dataclass(frozen=True)
class TaskChainVerdict:
    """The result of checking one signed gateway half against one worker half.

    The verdict is unsigned derived state. It names the two receipt digests it
    was computed from, so a caller can retain it as an audit note without
    mistaking it for a third signature.
    """

    status: str
    call_scope_id: str | None = None
    call_task_ids: tuple[str, ...] = ()
    worker_scope_id: str | None = None
    worker_task_id: str | None = None
    worker_parent_scope_id: str | None = None
    execution_id: str | None = None
    attempt: str | None = None
    call_receipt_digest: str | None = None
    worker_receipt_digest: str | None = None
    detail: str = ""
    schema_version: str = TASK_CHAIN_VERDICT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(self, "call_task_ids", _dedupe(self.call_task_ids or ()))

    @property
    def linked(self) -> bool:
        return self.status == TASK_CHAIN_LINKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "linked": self.linked,
            "call_scope_id": self.call_scope_id,
            "call_task_ids": list(self.call_task_ids),
            "worker_scope_id": self.worker_scope_id,
            "worker_task_id": self.worker_task_id,
            "worker_parent_scope_id": self.worker_parent_scope_id,
            "execution_id": self.execution_id,
            "attempt": self.attempt,
            "call_receipt_digest": self.call_receipt_digest,
            "worker_receipt_digest": self.worker_receipt_digest,
            "detail": self.detail,
        }


def _mapping_digest(payload: Mapping[str, Any]) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    try:
        return receipt_digest(payload)
    except (TypeError, ValueError):
        return None


def verify_task_chain(
    call_receipt: Mapping[str, Any],
    worker_receipt: Mapping[str, Any],
    secret: str | bytes,
    *,
    worker_secret: str | bytes | None = None,
    now: float | None = None,
) -> TaskChainVerdict:
    """Verify a gateway-to-worker parent chain without using a time window.

    The gateway ``CallReceipt`` must carry a signed ``dispatched_task_ids``
    entry supplied by the MCP response. The worker ``ScopeEvidence`` receipt
    must carry the same signed ``task_id`` and a signed ``parent_scope_id``
    equal to the gateway receipt's ``scope_id``. Both HMACs are verified before
    either relation is considered.

    ``secret`` verifies the gateway receipt. Pass ``worker_secret`` only when
    the worker collector was configured with a different secret. A missing
    field, a bad signature, or a mismatch returns an explicit non-linked
    status; this function never raises those conditions into a positive link.
    Use :attr:`TaskChainVerdict.linked` as the single positive test.
    """
    call_digest = _mapping_digest(call_receipt)
    worker_digest = _mapping_digest(worker_receipt)
    try:
        call = verify_call_receipt(call_receipt, secret, now=now)
    except (ReceiptError, TypeError, ValueError) as exc:
        return TaskChainVerdict(
            status=TASK_CHAIN_CALL_RECEIPT_INVALID,
            call_receipt_digest=call_digest,
            worker_receipt_digest=worker_digest,
            detail=str(exc)[:500],
        )
    selected_worker_secret = secret if worker_secret is None else worker_secret
    try:
        verified_worker = verify_scope_receipt(
            worker_receipt, selected_worker_secret, now=now
        )
    except (ReceiptError, TypeError, ValueError) as exc:
        return TaskChainVerdict(
            status=TASK_CHAIN_WORKER_RECEIPT_INVALID,
            call_scope_id=call.scope_id,
            call_task_ids=call.dispatched_task_ids,
            call_receipt_digest=call_digest,
            worker_receipt_digest=worker_digest,
            detail=str(exc)[:500],
        )

    worker = verified_worker.evidence
    fields = {
        "call_scope_id": call.scope_id,
        "call_task_ids": call.dispatched_task_ids,
        "worker_scope_id": worker.scope_id,
        "worker_task_id": worker.task_id,
        "worker_parent_scope_id": worker.parent_scope_id,
        "execution_id": worker.execution_id,
        "attempt": worker.attempt,
        "call_receipt_digest": call_digest,
        "worker_receipt_digest": worker_digest,
    }
    if not call.dispatched_task_ids:
        return TaskChainVerdict(
            status=TASK_CHAIN_MISSING_GATEWAY_TASK_ID,
            detail="the signed CallReceipt carries no dispatched task id",
            **fields,
        )
    if not worker.task_id:
        return TaskChainVerdict(
            status=TASK_CHAIN_MISSING_WORKER_TASK_ID,
            detail="the signed worker receipt carries no task_id",
            **fields,
        )
    if not worker.parent_scope_id:
        return TaskChainVerdict(
            status=TASK_CHAIN_MISSING_WORKER_PARENT_SCOPE,
            detail="the signed worker receipt carries no parent_scope_id",
            **fields,
        )
    if worker.task_id not in call.dispatched_task_ids:
        return TaskChainVerdict(
            status=TASK_CHAIN_TASK_ID_MISMATCH,
            detail="the worker task_id is not in the CallReceipt dispatched set",
            **fields,
        )
    if worker.parent_scope_id != call.scope_id:
        return TaskChainVerdict(
            status=TASK_CHAIN_PARENT_SCOPE_MISMATCH,
            detail="the worker parent_scope_id does not equal the CallReceipt scope_id",
            **fields,
        )
    return TaskChainVerdict(status=TASK_CHAIN_LINKED, **fields)


def build_call_receipt(
    *,
    call_id: str,
    scope_id: str,
    secret: str | bytes,
    session_id: str | None = None,
    method: str | None = None,
    request_id: str | None = None,
    started_at: float | None = None,
    closed_at: float | None = None,
    ttl: float = 300.0,
    http_status: int | None = None,
    observed_files: Iterable[str] = (),
    internal_temp_files: Iterable[str] = (),
    observed_urls: Iterable[str] = (),
    observed_egress_urls: Iterable[str] = (),
    observed_db_queries: Iterable[Mapping[str, Any]] = (),
    opened_only: Iterable[str] = (),
    unmapped_paths: Iterable[str] = (),
    opaque_reasons: Iterable[str] = (),
    payload_digests: Iterable[str] = (),
    socket_events: Iterable[str] = (),
    processes: Iterable[Mapping[str, Any]] = (),
    traceparent: str | None = None,
    parent_scope_id: str | None = None,
    evidence_level: str = "USER_TRACE",
    collector_mode: str = "mcp_process_supervisor",
    dispatched_task_ids: Iterable[str] = (),
) -> CallReceipt:
    start = time.time() if started_at is None else float(started_at)
    end = time.time() if closed_at is None else float(closed_at)
    receipt = CallReceipt(
        call_id=call_id,
        scope_id=scope_id,
        session_id=session_id,
        method=method,
        request_id=request_id,
        started_at=start,
        closed_at=end,
        expires_at=end + float(ttl),
        http_status=http_status,
        observed_files=tuple(normalize_path(value) for value in observed_files if value),
        internal_temp_files=tuple(normalize_path(value) for value in internal_temp_files if value),
        observed_urls=tuple(normalize_path(value) for value in observed_urls if value),
        observed_egress_urls=tuple(normalize_path(value) for value in observed_egress_urls if value),
        observed_db_queries=tuple(observed_db_queries),
        opened_only=tuple(normalize_path(value) for value in opened_only if value),
        unmapped_paths=tuple(normalize_path(value) for value in unmapped_paths if value),
        opaque_reasons=tuple(opaque_reasons),
        payload_digests=tuple(payload_digests),
        socket_events=tuple(socket_events),
        processes=tuple(processes),
        traceparent=traceparent,
        parent_scope_id=parent_scope_id,
        evidence_level=evidence_level,
        collector_mode=collector_mode,
        dispatched_task_ids=tuple(dispatched_task_ids),
    )
    return sign_call_receipt(receipt, secret)


def build_session_receipt(
    *,
    session_id: str,
    calls: Iterable[CallReceipt],
    secret: str | bytes,
    opened_at: float | None = None,
    closed_at: float | None = None,
    ttl: float = 300.0,
) -> SessionReceipt:
    call_list = tuple(calls)
    start = min((call.started_at for call in call_list), default=time.time())
    end = time.time() if closed_at is None else float(closed_at)
    receipt = SessionReceipt(
        session_id=session_id,
        opened_at=float(start if opened_at is None else opened_at),
        closed_at=end,
        expires_at=end + float(ttl),
        scope_ids=tuple(call.scope_id for call in call_list),
        call_ids=tuple(call.call_id for call in call_list),
        call_receipt_digests=tuple(receipt_digest(call.to_receipt_dict()) for call in call_list),
        observed_files=tuple(value for call in call_list for value in call.observed_files),
        internal_temp_files=tuple(value for call in call_list for value in call.internal_temp_files),
        observed_egress_urls=tuple(value for call in call_list for value in call.observed_egress_urls),
        observed_db_queries=tuple(row for call in call_list for row in call.observed_db_queries),
        opened_only=tuple(value for call in call_list for value in call.opened_only),
        unmapped_paths=tuple(value for call in call_list for value in call.unmapped_paths),
        opaque_reasons=tuple(value for call in call_list for value in call.opaque_reasons),
    )
    unsigned = receipt.to_receipt_dict()
    unsigned.pop("hmac_signature", None)
    return replace(receipt, hmac_signature=sign_payload(unsigned, secret, domain=SESSION_RECEIPT_DOMAIN))


def verify_session_receipt(
    payload: Mapping[str, Any], secret: str | bytes, *, now: float | None = None
) -> SessionReceipt:
    if not isinstance(payload, Mapping):
        raise TypeError("session receipt must be a mapping")
    if payload.get("schema_version") != SESSION_RECEIPT_SCHEMA:
        raise ReceiptError("unsupported session receipt schema")
    if not verify_payload(payload, secret, domain=SESSION_RECEIPT_DOMAIN):
        raise ReceiptError("session receipt HMAC verification failed")
    receipt = SessionReceipt.from_receipt_dict(payload)
    if not receipt.session_id:
        raise ReceiptError("session receipt has an empty session_id")
    check_at = time.time() if now is None else float(now)
    if receipt.expires_at and check_at > receipt.expires_at:
        raise ReceiptError("session receipt has expired")
    return receipt
