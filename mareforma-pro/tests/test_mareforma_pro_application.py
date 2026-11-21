"""Application hooks: Jupyter and MCP stay explicitly application-level."""

from __future__ import annotations

from pathlib import Path

from mareforma.observe import ObservedGrounding
from mareforma_pro.collector import RootlessCollector
from mareforma_pro.jupyter import JupyterScopeHook
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


def test_payload_digest_is_stable_across_key_order():
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})

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

