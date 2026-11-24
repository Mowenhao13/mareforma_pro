"""Regression tests for the 0.4 long-running MCP supervisor primitives."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mareforma_pro.egress import EgressProxy
from mareforma_pro.errors import ReceiptError
from mareforma_pro.collector import RootlessCollector
from mareforma_pro.evidence import (
    OPAQUE_DB_UNINSPECTED,
    OPAQUE_UNMAPPED_TMPFS,
)
from mareforma_pro.mcp_receipts import (
    TASK_CHAIN_CALL_RECEIPT_INVALID,
    TASK_CHAIN_LINKED,
    TASK_CHAIN_MISSING_GATEWAY_TASK_ID,
    TASK_CHAIN_MISSING_WORKER_TASK_ID,
    TASK_CHAIN_MISSING_WORKER_PARENT_SCOPE,
    TASK_CHAIN_PARENT_SCOPE_MISMATCH,
    TASK_CHAIN_TASK_ID_MISMATCH,
    build_call_receipt,
    build_session_receipt,
    verify_call_receipt,
    verify_session_receipt,
    verify_task_chain,
)
from mareforma_pro.paths import MountResolver
from mareforma_pro.strace import parse_strace
from mareforma_pro.stream import CallEvidence
from mareforma_pro.supervisor import (
    DEFAULT_INTERNAL_PORT,
    DEFAULT_PUBLIC_PORT,
    MCPProcessSupervisor,
    MCPWorker,
    WorkerConfig,
    WorkerPool,
    _body_has_scope,
    _extract_dispatched_task_ids,
    _inject_mcp_metadata,
    rewrite_command_port,
)


def test_rewrite_command_port_uses_placeholders_and_common_flag():
    assert rewrite_command_port(
        ["python", "server.py", "--port", "18000"],
        external_port=18000,
        internal_port=18100,
    )[-1] == "18100"
    assert rewrite_command_port(
        ["python", "server.py", "--port={external_port}"],
        external_port=18000,
        internal_port=18100,
    )[-1] == "--port=18100"
    assert rewrite_command_port(
        ["python", "server.py", "--port", "{internal_port}"],
        external_port=18000,
        internal_port=18100,
    )[-1] == "18100"


def test_supervisor_defaults_keep_fixed_server_on_18000():
    supervisor = MCPProcessSupervisor(
        ["python", "server.py"],
        secret="secret",
    )
    assert DEFAULT_PUBLIC_PORT == 18100
    assert DEFAULT_INTERNAL_PORT == 18000
    assert supervisor.port == 18100
    assert supervisor.internal_port == 18000
    assert rewrite_command_port(
        ["python", "server.py", "--port", "18000"],
        external_port=supervisor.port,
        internal_port=supervisor.internal_port,
    )[-1] == "18000"


def test_supervisor_rejects_public_internal_port_collision():
    with pytest.raises(ValueError, match="must differ"):
        MCPProcessSupervisor(
            ["python", "server.py"],
            secret="secret",
            port=18000,
            internal_port=18000,
        )
    with pytest.raises(ValueError, match="specific external bind address"):
        MCPProcessSupervisor(
            ["python", "server.py"],
            secret="secret",
            host="0.0.0.0",
            port=18000,
            internal_port=18000,
        )


def test_supervisor_allows_same_port_on_distinct_bind_addresses():
    supervisor = MCPProcessSupervisor(
        ["python", "server.py"],
        secret="secret",
        host="10.12.112.230",
        internal_host="127.0.0.1",
        port=18000,
        internal_port=18000,
    )
    assert supervisor.port == supervisor.internal_port == 18000
    assert supervisor.host != supervisor.internal_host


def test_worker_environment_pins_the_internal_host_and_port():
    worker = MCPWorker(
        WorkerConfig(
            index=0,
            host="127.0.0.1",
            port=18000,
            external_port=18100,
            command=("python", "server.py"),
            secret="secret",
        )
    )
    env = worker._env()
    assert env["HOST"] == "127.0.0.1"
    assert env["MCP_HOST"] == "127.0.0.1"
    assert env["UVICORN_HOST"] == "127.0.0.1"
    assert env["MCP_SERVER_HOST"] == "127.0.0.1"
    assert env["PORT"] == "18000"
    assert "MAREFORMA_HMAC_SECRET" not in env

    rewrite = MCPWorker(
        WorkerConfig(
            index=0,
            host="127.0.0.1",
            port=18100,
            external_port=18000,
            command=("python", "server.py"),
            secret="secret",
            bind_rewrite_port=18000,
        )
    )
    rewrite_env = rewrite._env()
    assert rewrite_env["MAREFORMA_REWRITE_BIND_FROM"] == "18000"
    assert rewrite_env["MAREFORMA_REWRITE_BIND_TO_HOST"] == "127.0.0.1"
    assert rewrite_env["MAREFORMA_REWRITE_BIND_TO_PORT"] == "18100"


def test_autohook_rewrites_a_fixed_python_bind_port():
    import mareforma_pro

    autohook = Path(mareforma_pro.__file__).parent / "autohook"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(autohook) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    env["MAREFORMA_REWRITE_BIND_FROM"] = "65000"
    env["MAREFORMA_REWRITE_BIND_TO_HOST"] = "127.0.0.1"
    env["MAREFORMA_REWRITE_BIND_TO_PORT"] = "0"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import socket\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.bind(('0.0.0.0', 65000))\n"
                "print(s.getsockname()[0], s.getsockname()[1])\n"
                "s.close()\n"
            ),
        ],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    host, port = result.stdout.split()
    assert host == "127.0.0.1"
    assert int(port) != 65000


def test_temp_semantics_distinguish_write_then_read_from_foreign_temp():
    resolver = MountResolver.from_mounts({}, root_passthrough=True)
    lines = [
        '10 openat(AT_FDCWD, "/tmp/mf-owned", O_WRONLY|O_CREAT, 0600) = 3</tmp/mf-owned>\n',
        '10 write(3</tmp/mf-owned>, "x", 1) = 1\n',
        '10 openat(AT_FDCWD, "/tmp/mf-owned", O_RDONLY) = 4</tmp/mf-owned>\n',
        '10 read(4</tmp/mf-owned>, "x", 1) = 1\n',
        '10 openat(AT_FDCWD, "/tmp/mf-foreign", O_RDONLY) = 5</tmp/mf-foreign>\n',
        '10 read(5</tmp/mf-foreign>, "y", 1) = 1\n',
    ]
    result = parse_strace(
        lines,
        resolver,
        track_temp_semantics=True,
    )
    assert "/tmp/mf-owned" in result.internal_temp_files
    assert "/tmp/mf-foreign" in result.unmapped_paths
    assert OPAQUE_UNMAPPED_TMPFS in result.opaque_reasons


def test_call_and_session_receipts_verify_and_reject_tamper():
    call = build_call_receipt(
        call_id="call-1",
        scope_id="scope-1",
        session_id="session-1",
        secret="secret",
        method="tools/call",
        request_id="1",
        observed_files=["/data/a.csv"],
        internal_temp_files=["/tmp/owned"],
        observed_egress_urls=["https://api.example.org/v1"],
        observed_db_queries=[{"engine": "sqlite", "database": "/data/a.db"}],
        payload_digests=["sha256:" + "a" * 64],
    )
    assert verify_call_receipt(call.to_receipt_dict(), "secret").call_id == "call-1"
    assert "dispatched_task_ids" not in call.to_receipt_dict()
    tampered = call.to_receipt_dict()
    tampered["observed_files"].append("/data/fake.csv")
    with pytest.raises(ReceiptError):
        verify_call_receipt(tampered, "secret")
    session = build_session_receipt(
        session_id="session-1",
        calls=[call],
        secret="secret",
    )
    assert verify_session_receipt(session.to_receipt_dict(), "secret").call_ids == ("call-1",)
    bad = session.to_receipt_dict()
    bad["opaque_reasons"].append("fake")
    with pytest.raises(ReceiptError):
        verify_session_receipt(bad, "secret")


def _worker_receipt(
    *,
    task_id: str = "task-1",
    parent_scope_id: str | None = "scope-1",
    secret: str = "secret",
) -> dict:
    collector = RootlessCollector(secret, receipt_ttl=3600.0)
    scope_id = f"wrk:{task_id}"
    collector.open_scope(
        scope_id,
        root_passthrough=True,
        parent_scope_id=parent_scope_id,
        task_id=task_id,
        worker_id="worker-1",
        execution_id="exec-1",
        attempt="attempt-1",
    )
    return collector.close_scope(scope_id).to_receipt_dict()


def test_dispatched_task_id_is_signed_into_the_call_receipt():
    call = build_call_receipt(
        call_id="call-task-1",
        scope_id="scope-1",
        secret="secret",
        method="tools/call",
        dispatched_task_ids=["task-1"],
    )
    payload = call.to_receipt_dict()
    assert payload["dispatched_task_ids"] == ["task-1"]
    assert verify_call_receipt(payload, "secret").dispatched_task_ids == ("task-1",)

    tampered = dict(payload)
    tampered["dispatched_task_ids"] = ["task-2"]
    with pytest.raises(ReceiptError):
        verify_call_receipt(tampered, "secret")


def test_extract_dispatched_task_ids_reads_mcp_response_shapes():
    task_id = "267da66a-eb78-4502-9f9b-9ddc80b358cd"
    response = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"protocol": "biomni.task.v1", "task_id": task_id}),
                }
            ],
            "structuredContent": {"task_id": task_id, "status": "queued"},
            "isError": False,
        },
    }
    assert _extract_dispatched_task_ids(json.dumps(response).encode()) == (task_id,)

    conflicting = json.loads(json.dumps(response))
    conflicting["result"]["content"][0]["text"] = json.dumps({"task_id": "task-other"})
    assert _extract_dispatched_task_ids(json.dumps(conflicting).encode()) == ()

    failed = json.loads(json.dumps(response))
    failed["result"]["isError"] = True
    assert _extract_dispatched_task_ids(json.dumps(failed).encode()) == ()
    assert _extract_dispatched_task_ids(b"not-json") == ()
    assert _extract_dispatched_task_ids(b"x" * (4 * 1024 * 1024 + 1)) == ()


def test_supervisor_injects_scope_metadata_without_overwriting_client_values():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "protein.query", "arguments": {}},
    }
    injected = _inject_mcp_metadata(
        json.dumps(request).encode(),
        scope_id="mcp_generated",
        traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )
    meta = json.loads(injected)["params"]["_meta"]
    assert meta["mareforma_scope_id"] == "mcp_generated"
    assert meta["traceparent"].startswith("00-4bf92f")
    assert _body_has_scope(injected, "mcp_generated")

    client_scoped = {
        **request,
        "params": {
            **request["params"],
            "_meta": {"mareforma_scope_id": "mcp_client", "keep": "yes"},
        },
    }
    preserved = _inject_mcp_metadata(
        json.dumps(client_scoped).encode(),
        scope_id="mcp_generated",
    )
    preserved_meta = json.loads(preserved)["params"]["_meta"]
    assert preserved_meta == {"mareforma_scope_id": "mcp_client", "keep": "yes"}

    not_a_tool_call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    original = json.dumps(not_a_tool_call).encode()
    assert _inject_mcp_metadata(original, scope_id="mcp_generated") == original


def test_supervisor_signs_the_task_id_it_returns_to_the_client(tmp_path):
    task_id = "267da66a-eb78-4502-9f9b-9ddc80b358cd"
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            payload = json.loads(self.rfile.read(length) or b"{}")
            received.append(payload)
            if payload.get("method") != "tools/call":
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"protocol": "biomni.task.v1", "task_id": task_id}
                                ),
                            }
                        ],
                        "structuredContent": {
                            "protocol": "biomni.task.v1",
                            "task_id": task_id,
                            "status": "queued",
                        },
                        "isError": False,
                    },
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    upstream.daemon_threads = True
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    supervisor = MCPProcessSupervisor(
        [sys.executable, "-c", "pass"],
        secret="secret",
        host="127.0.0.1",
        port=0,
        internal_host="127.0.0.1",
        internal_port=upstream.server_address[1],
        use_strace=False,
        trace_dir=tmp_path / "trace",
        receipt_log=tmp_path / "mcp-receipts.jsonl",
    )
    supervisor.workers[0].start = lambda: None  # type: ignore[method-assign]
    supervisor.start()
    try:
        public_port = supervisor._httpd.server_address[1]  # type: ignore[union-attr]
        conn = http.client.HTTPConnection("127.0.0.1", public_port, timeout=5)
        try:
            conn.request(
                "POST",
                "/mcp",
                body=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {
                            "name": "biomni_invoke_tool",
                            "arguments": {"tool_name": "protein.query"},
                        },
                    }
                ),
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            response.read()
            assert response.status == 200
            response_scope = response.getheader("X-Mareforma-Scope-Id")
        finally:
            conn.close()
        assert response_scope is not None
        assert received[0]["params"]["_meta"]["mareforma_scope_id"] == response_scope
        with supervisor._session_lock:
            call = next(
                receipt
                for receipts in supervisor._sessions.values()
                for receipt in receipts
                if receipt.scope_id == response_scope
            )
        assert call.dispatched_task_ids == (task_id,)
        worker = _worker_receipt(task_id=task_id, parent_scope_id=response_scope)
        assert verify_task_chain(call.to_receipt_dict(), worker, "secret").linked
    finally:
        supervisor.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_task_chain_requires_both_signatures_and_matching_ids():
    call = build_call_receipt(
        call_id="call-task-1",
        scope_id="scope-1",
        secret="secret",
        method="tools/call",
        dispatched_task_ids=["task-1"],
    )
    worker = _worker_receipt(task_id="task-1", parent_scope_id="scope-1")
    linked = verify_task_chain(call.to_receipt_dict(), worker, "secret")
    assert linked.status == TASK_CHAIN_LINKED
    assert linked.linked is True
    assert linked.call_scope_id == "scope-1"
    assert linked.call_task_ids == ("task-1",)
    assert linked.worker_parent_scope_id == "scope-1"
    assert linked.to_dict()["linked"] is True

    no_gateway_task = build_call_receipt(
        call_id="call-task-2",
        scope_id="scope-1",
        secret="secret",
        method="tools/call",
    )
    verdict = verify_task_chain(no_gateway_task.to_receipt_dict(), worker, "secret")
    assert verdict.status == TASK_CHAIN_MISSING_GATEWAY_TASK_ID
    assert verdict.linked is False

    verdict = verify_task_chain(
        call.to_receipt_dict(),
        _worker_receipt(task_id="task-1", parent_scope_id=None),
        "secret",
    )
    assert verdict.status == TASK_CHAIN_MISSING_WORKER_PARENT_SCOPE

    collector = RootlessCollector("secret", receipt_ttl=3600.0)
    collector.open_scope("wrk:no-task", parent_scope_id="scope-1")
    no_worker_task = collector.close_scope("wrk:no-task").to_receipt_dict()
    verdict = verify_task_chain(call.to_receipt_dict(), no_worker_task, "secret")
    assert verdict.status == TASK_CHAIN_MISSING_WORKER_TASK_ID

    verdict = verify_task_chain(
        call.to_receipt_dict(), _worker_receipt(task_id="task-2"), "secret"
    )
    assert verdict.status == TASK_CHAIN_TASK_ID_MISMATCH

    verdict = verify_task_chain(
        call.to_receipt_dict(),
        _worker_receipt(task_id="task-1", parent_scope_id="scope-other"),
        "secret",
    )
    assert verdict.status == TASK_CHAIN_PARENT_SCOPE_MISMATCH

    tampered_call = call.to_receipt_dict()
    tampered_call["dispatched_task_ids"] = ["task-1", "task-2"]
    verdict = verify_task_chain(tampered_call, worker, "secret")
    assert verdict.status == TASK_CHAIN_CALL_RECEIPT_INVALID

    tampered_worker = dict(worker)
    tampered_worker["parent_scope_id"] = "scope-other"
    verdict = verify_task_chain(call.to_receipt_dict(), tampered_worker, "secret")
    assert verdict.status.startswith("WORKER_RECEIPT_INVALID")


def test_task_chain_can_verify_two_distinct_hmac_domains():
    call = build_call_receipt(
        call_id="call-task-1",
        scope_id="scope-1",
        secret="gateway-secret",
        method="tools/call",
        dispatched_task_ids=["task-1"],
    )
    worker = _worker_receipt(
        task_id="task-1", parent_scope_id="scope-1", secret="worker-secret"
    )
    assert verify_task_chain(
        call.to_receipt_dict(), worker, "gateway-secret", worker_secret="worker-secret"
    ).linked
    assert verify_task_chain(call.to_receipt_dict(), worker, "gateway-secret").status == (
        "WORKER_RECEIPT_INVALID"
    )


def test_call_evidence_records_connect_and_embedded_db():
    evidence = CallEvidence()
    evidence.add_connect_endpoint("tcp:10.0.0.1:5432")
    evidence.add_strace_event(
        type("E", (), {
            "kind": "read",
            "path": "/tmp/query.db",
            "resolved_path": "/tmp/query.db",
            "bytes": 4096,
            "is_dir": False,
        })()
    )
    values = evidence.finalize(egress_proxy_enabled=False, db_hook_enabled=False)
    assert OPAQUE_DB_UNINSPECTED in values["opaque_reasons"]
    assert any(row.get("database") == "/tmp/query.db" for row in values["observed_db_queries"])


def test_egress_proxy_observes_http_url(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    seen = []
    proxy = EgressProxy(seen.append)
    proxy.start()
    try:
        import socket

        request = (
            f"GET http://127.0.0.1:{target.server_address[1]}/api?token=secret HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\nConnection: close\r\n\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=3) as sock:
            sock.sendall(request)
            while sock.recv(65536):
                pass
    finally:
        proxy.stop()
        target.shutdown()
        target.server_close()
    assert seen
    assert seen[0].url == f"http://127.0.0.1:{target.server_address[1]}/api"


def test_database_relay_rewrites_matching_environment():
    from mareforma_pro.dbproxy import LocalTCPRelay, rewrite_database_env

    seen = []
    relay = LocalTCPRelay("db.internal", 5432, seen.append)
    relay.start()
    relay_port = relay.port
    try:
        env = rewrite_database_env(
            {
                "DATABASE_URL": "postgresql://user:pass@db.internal:5432/app?sslmode=require",
                "PGHOST": "db.internal",
                "PGPORT": "5432",
            },
            {relay.target: relay},
        )
    finally:
        relay.stop()
    assert f"127.0.0.1:{relay_port}" in env["DATABASE_URL"]
    assert env["PGHOST"] == "127.0.0.1"
    assert env["PGPORT"] == str(relay_port)
    assert "sslmode=require" in env["DATABASE_URL"]

class _DummyPoolWorker:
    def __init__(self) -> None:
        self._reserved = False
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True


def test_worker_pool_affinity_and_anonymous_never_share_a_reserved_worker():
    """Regression for the 502 race under concurrent MCP initialize calls.

    The old queue-backed pool left an affinity-acquired worker in the idle
    queue. An anonymous request could then remove the same worker while it was
    still handling the first request, and ``begin_call`` correctly refused with
    "worker already has an active call".
    """
    worker = _DummyPoolWorker()
    pool = WorkerPool([worker])
    first = pool.acquire("session-a")
    assert first is worker
    assert worker._reserved is True

    results: dict[str, object] = {}

    def anonymous() -> None:
        try:
            results["anonymous"] = pool.acquire(None, timeout=0.2)
        except TimeoutError as exc:
            results["anonymous_error"] = str(exc)

    thread = threading.Thread(target=anonymous)
    thread.start()
    thread.join(timeout=1.0)
    assert results.get("anonymous_error") == "no idle MCP worker"
    assert "anonymous" not in results

    pool.release(first)
    second = pool.acquire(None, timeout=0.2)
    assert second is worker


def test_worker_pool_pinned_session_waits_for_its_own_worker():
    worker = _DummyPoolWorker()
    pool = WorkerPool([worker])
    pool.bind_session("session-b", worker)
    held = pool.acquire("session-b")
    assert held is worker
    results: dict[str, object] = {}

    def waiter() -> None:
        try:
            results["worker"] = pool.acquire("session-b", timeout=1.0)
        except TimeoutError as exc:
            results["error"] = str(exc)

    thread = threading.Thread(target=waiter)
    thread.start()
    time.sleep(0.05)
    pool.release(held)
    thread.join(timeout=2.0)
    assert results.get("worker") is worker


def test_worker_pool_uses_distinct_workers_for_concurrent_anonymous_calls():
    workers = [_DummyPoolWorker(), _DummyPoolWorker()]
    pool = WorkerPool(workers)
    first = pool.acquire(None, timeout=0.2)
    second = pool.acquire(None, timeout=0.2)
    assert first is not second
    assert {first, second} == set(workers)
    with pytest.raises(TimeoutError, match="no idle MCP worker"):
        pool.acquire(None, timeout=0.05)



def test_supervisor_get_stream_does_not_starve_post_calls(tmp_path):
    """The MCP SDK's long-lived GET /mcp must not reserve the only worker.

    The official Streamable HTTP client starts a GET SSE stream after
    ``notifications/initialized`` and keeps it open.  A GET is transport, not
    a tool call; reserving the worker for its lifetime would make the next
    ``tools/list`` time out and return 503.  This fake upstream reproduces the
    same sequence and asserts that POST continues while GET is open.
    """
    import http.client

    get_started = threading.Event()
    release_get = threading.Event()
    delete_seen = threading.Event()
    session = "session-stream-1"

    class FakeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            return

        def _send_json(self, status, value, extra_headers=()):
            data = json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for key, header_value in extra_headers:
                self.send_header(key, header_value)
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            payload = json.loads(self.rfile.read(length) or b"{}")
            method = payload.get("method")
            if method == "initialize":
                self._send_json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "serverInfo": {"name": "fake", "version": "0"},
                        },
                    },
                    extra_headers=(("Mcp-Session-Id", session),),
                )
            elif method == "notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif method == "tools/list":
                self._send_json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": payload.get("id"),
                        "result": {"tools": [{"name": "echo"}]},
                    },
                )
            else:
                self._send_json(
                    400,
                    {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601}},
                )

        def do_GET(self):
            get_started.set()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            event = b'event: message\ndata: {}\n\n'
            self.wfile.write(f"{len(event):X}\r\n".encode("ascii") + event + b"\r\n")
            self.wfile.flush()
            release_get.wait(10)
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                pass

        def do_DELETE(self):
            delete_seen.set()
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeHandler)
    upstream.daemon_threads = True
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    supervisor = MCPProcessSupervisor(
        [sys.executable, "-c", "pass"],
        secret="secret",
        host="127.0.0.1",
        port=0,
        internal_host="127.0.0.1",
        internal_port=upstream.server_address[1],
        use_strace=False,
        trace_dir=tmp_path / "trace",
        receipt_log=tmp_path / "receipts.jsonl",
    )
    # Keep the fake upstream thread as the worker process.  The real worker
    # startup/port check is covered elsewhere; this test isolates HTTP routing.
    supervisor.workers[0].start = lambda: None  # type: ignore[method-assign]
    supervisor.start()
    public_port = supervisor._httpd.server_address[1]  # type: ignore[union-attr]

    def post(payload, *, sid=None):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if sid:
            headers["Mcp-Session-Id"] = sid
        conn = http.client.HTTPConnection("127.0.0.1", public_port, timeout=5)
        try:
            conn.request("POST", "/mcp", body=json.dumps(payload), headers=headers)
            response = conn.getresponse()
            response_body = response.read()
            return response.status, response.getheader("Mcp-Session-Id"), response_body
        finally:
            conn.close()

    get_conn = None
    try:
        status, sid, body = post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "stream-test", "version": "0"},
                },
            }
        )
        assert status == 200 and sid == session
        status, _, _ = post(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            sid=sid,
        )
        assert status == 202

        get_conn = http.client.HTTPConnection("127.0.0.1", public_port, timeout=5)
        get_conn.request(
            "GET",
            "/mcp",
            headers={"Mcp-Session-Id": session, "Accept": "text/event-stream"},
        )
        get_response = get_conn.getresponse()
        assert get_response.status == 200
        assert get_response.read(1) == b"e"
        assert get_started.wait(2), "GET did not reach the upstream worker"

        # The decisive assertion: a POST on the same session must complete
        # while the GET stream is still open.
        status, _, tools_body = post(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            sid=sid,
        )
        assert status == 200
        assert json.loads(tools_body)["result"]["tools"] == [{"name": "echo"}]

        deadline = time.monotonic() + 3
        tool_receipt = None
        while time.monotonic() < deadline:
            with supervisor._session_lock:
                receipts = list(supervisor._sessions.get(session, ()))
            tool_receipt = next(
                (call for call in receipts if call.method == "tools/list"), None
            )
            if tool_receipt is not None:
                break
            time.sleep(0.02)
        assert tool_receipt is not None
        assert "concurrent_call_overlap" in tool_receipt.opaque_reasons

        conn = http.client.HTTPConnection("127.0.0.1", public_port, timeout=5)
        try:
            conn.request("DELETE", "/mcp", headers={"Mcp-Session-Id": session})
            delete_response = conn.getresponse()
            delete_response.read()
            assert delete_response.status == 204
        finally:
            conn.close()
        assert delete_seen.wait(2), "DELETE did not reach the upstream worker"
    finally:
        release_get.set()
        if get_conn is not None:
            get_conn.close()
        supervisor.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_worker_pool_stream_route_does_not_take_a_call_reservation():
    worker = _DummyPoolWorker()
    pool = WorkerPool([worker])
    pool.bind_session("session-stream", worker)
    held = pool.acquire("session-stream", timeout=0.2)
    assert held is worker
    assert pool.worker_for_session("session-stream") is worker
    with pytest.raises(TimeoutError, match="no idle MCP worker"):
        pool.acquire(None, timeout=0.05)
    pool.release(held)
