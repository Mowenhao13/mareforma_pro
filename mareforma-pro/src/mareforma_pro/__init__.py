"""Rootless, no-sudo observation extension for Mareforma."""

__version__ = "0.5.0"

from .backend import CollectorBackend, EvidenceBackend, InProcessBackend
from .collector import RootlessCollector
from .errors import (
    FuseMountError,
    MareformaProError,
    ReceiptError,
    RootlessRunError,
    RootlessUnavailableError,
    ScopeError,
)
from .evidence import (
    OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE,
    OPAQUE_CONCURRENT_CALL_OVERLAP,
    OPAQUE_DB_UNINSPECTED,
    OPAQUE_EGRESS_PROXY_BYPASSED,
    OPAQUE_EGRESS_UNINSPECTED,
    OPAQUE_HTTPS_PATH_OPAQUE,
    OPAQUE_HTTP_BODY_UNOBSERVED,
    SOURCE_NOT_APPLICABLE,
    SOURCE_REQUIRED,
    ScopeEvidence,
    ScopeRegistration,
    VerifiedScopeEvidence,
)
from .fuse import FuseReadOnlyProxy
from .http import record_url_read
from .egress import EgressObservation, EgressProxy
from .dbproxy import DatabaseObservation, LocalTCPRelay, engine_for_port, parse_relay_targets, rewrite_database_env
from .jupyter import JupyterCellResult, JupyterScopeHook, audit_scope
from .mcp import (
    MCPApplicationMiddleware,
    MCPContext,
    MCPObservation,
    inject_meta,
    payload_digest,
    record_mcp_payload,
)
from .observe import (
    ReceiptVerifier,
    RootlessObservation,
    assert_claim_from_receipt,
    observe,
    verdict_from_evidence,
    verdict_or_opaque,
    verify_and_verdict,
)
from .otel import (
    AsyncJsonlSpanExporter,
    OTLPSpanExporterAdapter,
    call_span_from_receipt,
    process_spans_from_evidence,
    scope_span_from_evidence,
    session_span_from_receipt,
)
from .paths import MountResolver
from .receipt import sign_receipt, verify_scope_receipt, verify_signature
from .runner import FuseRunResult, RootlessBwrapRunner, RootlessFuseRunner, RunResult
from .server import CollectorClient, CollectorServer
from .mcp_receipts import (
    CALL_RECEIPT_DOMAIN,
    CALL_RECEIPT_SCHEMA,
    SESSION_RECEIPT_DOMAIN,
    SESSION_RECEIPT_SCHEMA,
    CallReceipt,
    SessionReceipt,
    build_call_receipt,
    build_session_receipt,
    receipt_digest,
    sign_call_receipt,
    sign_payload,
    verify_call_receipt,
    verify_session_receipt,
)
from .supervisor import MCPProcessSupervisor, WorkerConfig, rewrite_command_port
from .worker import WorkerProcessObserver
from .store import ReceiptStore
from .strace import (
    SUPERVISOR_TRACE_EXPR,
    TRACE_EXPR,
    ParsedStrace,
    StraceEvent,
    StraceParser,
    parse_strace,
)

__all__ = [
    "AsyncJsonlSpanExporter",
    "call_span_from_receipt",
    "CALL_RECEIPT_DOMAIN",
    "CALL_RECEIPT_SCHEMA",
    "CallReceipt",
    "CollectorBackend",
    "CollectorClient",
    "CollectorServer",
    "EgressObservation",
    "EgressProxy",
    "DatabaseObservation",
    "LocalTCPRelay",
    "EvidenceBackend",
    "FuseMountError",
    "FuseReadOnlyProxy",
    "FuseRunResult",
    "InProcessBackend",
    "JupyterCellResult",
    "JupyterScopeHook",
    "MCPApplicationMiddleware",
    "MCPContext",
    "MCPObservation",
    "MCPProcessSupervisor",
    "MareformaProError",
    "MountResolver",
    "OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE",
    "OPAQUE_CONCURRENT_CALL_OVERLAP",
    "OPAQUE_DB_UNINSPECTED",
    "OPAQUE_EGRESS_PROXY_BYPASSED",
    "OPAQUE_EGRESS_UNINSPECTED",
    "OPAQUE_HTTPS_PATH_OPAQUE",
    "OPAQUE_HTTP_BODY_UNOBSERVED",
    "OTLPSpanExporterAdapter",
    "ParsedStrace",
    "ReceiptError",
    "ReceiptStore",
    "RootlessBwrapRunner",
    "RootlessCollector",
    "RootlessFuseRunner",
    "ReceiptVerifier",
    "RootlessObservation",
    "RootlessRunError",
    "RootlessUnavailableError",
    "RunResult",
    "ScopeError",
    "ScopeEvidence",
    "ScopeRegistration",
    "SOURCE_NOT_APPLICABLE",
    "SOURCE_REQUIRED",
    "SESSION_RECEIPT_DOMAIN",
    "SESSION_RECEIPT_SCHEMA",
    "SessionReceipt",
    "StraceEvent",
    "StraceParser",
    "TRACE_EXPR",
    "SUPERVISOR_TRACE_EXPR",
    "WorkerConfig",
    "WorkerProcessObserver",
    "VerifiedScopeEvidence",
    "assert_claim_from_receipt",
    "audit_scope",
    "inject_meta",
    "build_call_receipt",
    "build_session_receipt",
    "observe",
    "parse_strace",
    "parse_relay_targets",
    "process_spans_from_evidence",
    "payload_digest",
    "record_mcp_payload",
    "record_url_read",
    "engine_for_port",
    "rewrite_database_env",
    "receipt_digest",
    "rewrite_command_port",
    "sign_call_receipt",
    "sign_payload",
    "scope_span_from_evidence",
    "session_span_from_receipt",
    "sign_receipt",
    "verdict_from_evidence",
    "verdict_or_opaque",
    "verify_call_receipt",
    "verify_session_receipt",
    "verify_and_verdict",
    "verify_scope_receipt",
    "verify_signature",
]
