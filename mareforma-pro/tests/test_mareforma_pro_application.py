"""Application hooks: Jupyter and MCP stay explicitly application-level."""

from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import sys
import threading

from mareforma.observe import ObservedGrounding
from mareforma_pro.collector import RootlessCollector
from mareforma_pro.evidence import (
    OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE,
    OPAQUE_SOCKET_UNBOUND,
    OPAQUE_STATIC_BINARY_UNTRACED,
    OPAQUE_TRACE_INCOMPLETE,
    SOURCE_NOT_APPLICABLE,
)
from mareforma_pro.jupyter import JupyterScopeHook, _native_import, audit_scope
from mareforma_pro.mcp import (
    MCPApplicationMiddleware,
    MCPContext,
    inject_meta,
    payload_digest,
)


class _Events:
    def __init__(self) -> None:
        self.handlers: dict[str, object] = {}

    def register(self, name, callback):
        self.handlers[name] = callback

    def unregister(self, name, callback):
        if self.handlers.get(name) is callback:
            self.handlers.pop(name, None)


class _IPython:
    def __init__(self) -> None:
        self.events = _Events()


def test_jupyter_cell_hook_records_python_open(tmp_path: Path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    ipython = _IPython()
    hook = JupyterScopeHook(ipython, collector, cites=str(data)).install()
    hook.pre_run_cell()
    data.read_text()
    hook.post_run_cell()
    assert hook.last is not None
    assert hook.last.verdict.grounding is ObservedGrounding.GROUNDED
    assert hook.last.evidence.evidence.evidence_level == "APPLICATION_PYTHON_AUDIT"
    assert hook.last.evidence.evidence.read_semantics == "OPEN_INTENT"
    assert hook.last.evidence.evidence.collector_mode == "application_python_audit"
    assert hook.last.verdict.reason.startswith("an application-level read-open")
    assert hook.last.verdict.reads[0].kind == "application-open"
    hook.uninstall()
    assert not ipython.events.handlers


def test_mcp_context_injection_round_trip():
    context = MCPContext(
        scope_id="scp_1",
        traceparent="00-aa11223344556677889900aabbcc0001-1000000000000001-01",
        parent_scope_id="tool-7",
    )
    params = inject_meta({"name": "read", "arguments": {}}, context)
    assert params["_meta"]["mareforma_scope_id"] == "scp_1"
    parsed = MCPContext.from_meta(params["_meta"])
    assert parsed == context


def test_mcp_self_hosted_hook_reads_file(tmp_path: Path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    middleware = MCPApplicationMiddleware(collector, cites=str(data))
    result = middleware({"name": "read"}, lambda: data.read_text())
    assert result == "x\n"
    assert middleware.last is not None
    assert middleware.last.verdict.grounding is ObservedGrounding.GROUNDED
    assert middleware.last.evidence.evidence.evidence_level == "APPLICATION_MCP"
    assert middleware.last.evidence.evidence.collector_mode == "application_mcp"


def test_mcp_self_hosted_hook_accepts_an_explicit_url_manifest():
    url = "https://api.example.org/v1/protein?token=secret"
    collector = RootlessCollector("secret")
    middleware = MCPApplicationMiddleware(
        collector,
        cites="https://api.example.org/v1/protein",
        observed_urls=[url],
    )
    result = middleware({"name": "http_read"}, lambda: {"protein": "TP53"})
    assert result == {"protein": "TP53"}
    assert middleware.last is not None
    assert middleware.last.verdict.grounding is ObservedGrounding.GROUNDED
    assert middleware.last.evidence.evidence.observed_urls == (
        "https://api.example.org/v1/protein",
    )


def test_external_mcp_stays_opaque(tmp_path: Path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    middleware = MCPApplicationMiddleware(collector, cites=str(data), external=True)
    result = middleware({"name": "remote"}, lambda: {"value": 1})
    assert result == {"value": 1}
    assert middleware.last is not None
    assert middleware.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert "external_mcp" in middleware.last.verdict.opaque_reasons


def test_external_mcp_url_manifest_stays_opaque():
    url = "https://api.example.org/v1/protein"
    collector = RootlessCollector("secret")
    middleware = MCPApplicationMiddleware(
        collector,
        cites=url,
        external=True,
        observed_urls=[url],
    )
    middleware({"name": "remote_http"}, lambda: {"protein": "TP53"})
    assert middleware.last is not None
    assert middleware.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert "external_mcp" in middleware.last.verdict.opaque_reasons
    assert middleware.last.evidence.evidence.observed_urls == (url,)


def test_payload_digest_is_stable_across_key_order():
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})

def test_audit_scope_records_process_thread_and_socket_boundaries():
    cases = (
        ("subprocess", lambda: subprocess.run([sys.executable, "-c", "pass"], check=True), OPAQUE_STATIC_BINARY_UNTRACED),
        ("thread", lambda: threading.Thread(target=lambda: None).start(), OPAQUE_TRACE_INCOMPLETE),
        ("socket", lambda: socket.socket().connect_ex(("127.0.0.1", 1)), OPAQUE_SOCKET_UNBOUND),
    )
    for name, action, expected in cases:
        collector = RootlessCollector("secret")
        scope_id = "audit_" + name
        collector.open_scope(scope_id)
        with audit_scope(collector, scope_id):
            action()
        evidence = collector.close_scope(scope_id)
        assert expected in evidence.opaque_reasons


def test_jupyter_missing_cited_file_is_opaque_not_grounded(tmp_path: Path):
    data = tmp_path / "missing.csv"
    collector = RootlessCollector("secret")
    hook = JupyterScopeHook(_IPython(), collector, cites=str(data)).install()
    hook.pre_run_cell()
    try:
        data.read_text()
    except FileNotFoundError:
        pass
    hook.post_run_cell()
    assert hook.last is not None
    assert hook.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert "open_only" in hook.last.verdict.opaque_reasons
    hook.uninstall()


def test_jupyter_native_load_is_an_explicit_blind_spot():
    collector = RootlessCollector("secret")
    hook = JupyterScopeHook(_IPython(), collector).install()
    hook.pre_run_cell()
    try:
        # CDLL(None) emits ctypes.dlopen even when ctypes was imported earlier in
        # the test process. It exercises the native boundary without assuming a
        # particular extension module is installed.
        import ctypes

        ctypes.CDLL(None).getpid()
    finally:
        hook.post_run_cell()
    assert hook.last is not None
    assert hook.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert OPAQUE_STATIC_BINARY_UNTRACED in hook.last.verdict.opaque_reasons
    hook.uninstall()


def test_jupyter_computation_only_scope_uses_the_distinct_reason():
    collector = RootlessCollector("secret")
    hook = JupyterScopeHook(
        _IPython(),
        collector,
        source_requirement=SOURCE_NOT_APPLICABLE,
    ).install()
    hook.pre_run_cell()
    hook.post_run_cell()
    assert hook.last is not None
    assert hook.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE in hook.last.verdict.opaque_reasons
    assert "no_cited_source" not in hook.last.verdict.opaque_reasons
    hook.uninstall()


def test_native_import_suffix_detection():
    assert _native_import(("numpy.core._multiarray_umath", "/opt/venv/numpy/_multiarray_umath.cpython-313-x86_64-linux-gnu.so"))
    assert _native_import(("pydantic_core", "C:/venv/pydantic_core/_pydantic_core.pyd"))
    assert not _native_import(("json", "/usr/lib/python3.13/json/__init__.py"))
    assert not _native_import(("builtin_extension", None))


def test_mcp_computation_only_scope_uses_the_distinct_reason():
    collector = RootlessCollector("secret")
    middleware = MCPApplicationMiddleware(
        collector,
        source_requirement=SOURCE_NOT_APPLICABLE,
    )
    middleware({"name": "compute"}, lambda: {"value": 1})
    assert middleware.last is not None
    assert middleware.last.verdict.grounding is ObservedGrounding.OPAQUE
    assert OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE in middleware.last.verdict.opaque_reasons
