"""Rootless, no-sudo observation extension for Mareforma."""

__version__ = "0.1.0"

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
from .evidence import ScopeEvidence, ScopeRegistration, VerifiedScopeEvidence
from .fuse import FuseReadOnlyProxy
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
    process_spans_from_evidence,
    scope_span_from_evidence,
)
from .paths import MountResolver
from .receipt import sign_receipt, verify_scope_receipt, verify_signature
from .runner import FuseRunResult, RootlessBwrapRunner, RootlessFuseRunner, RunResult
from .server import CollectorClient, CollectorServer
from .store import ReceiptStore
from .strace import TRACE_EXPR, ParsedStrace, StraceParser, parse_strace

__all__ = [
    "AsyncJsonlSpanExporter",
    "CollectorBackend",
    "CollectorClient",
    "CollectorServer",
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
    "MareformaProError",
    "MountResolver",
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
    "StraceParser",
    "TRACE_EXPR",
    "VerifiedScopeEvidence",
    "assert_claim_from_receipt",
    "audit_scope",
    "inject_meta",
    "observe",
    "parse_strace",
    "process_spans_from_evidence",
    "payload_digest",
    "record_mcp_payload",
    "scope_span_from_evidence",
    "sign_receipt",
    "verdict_from_evidence",
    "verdict_or_opaque",
    "verify_and_verdict",
    "verify_scope_receipt",
    "verify_signature",
]
