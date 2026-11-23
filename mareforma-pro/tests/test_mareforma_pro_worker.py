"""Task-scoped worker observation and Python autohook tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mareforma_pro.evidence import (
    OPAQUE_HTTP_BODY_UNOBSERVED,
    OPAQUE_TRACE_INCOMPLETE,
)
from mareforma_pro.receipt import verify_scope_receipt
from mareforma_pro.worker import WorkerProcessObserver


class _HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/stream"):
            body = b"0123456789" * 100
        else:
            body = b'{"protein":"P04637","length":393}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@contextmanager
def _http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _event_receiver(tmp_path: Path):
    path = tmp_path / "events.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(str(path))
    sock.settimeout(0.1)
    events: list[dict] = []
    stopped = threading.Event()

    def receive() -> None:
        while not stopped.is_set():
            try:
                raw, _ = sock.recvfrom(256 * 1024)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        yield path, events
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stopped.set()
        thread.join(timeout=2)
        sock.close()


def _autohook_env(
    event_socket: Path,
    *,
    extra_path: Path | None = None,
    task_context: dict[str, str] | None = None,
) -> dict[str, str]:
    autohook = Path(__file__).parents[1] / "src" / "mareforma_pro" / "autohook"
    paths = [str(autohook)]
    if extra_path is not None:
        paths.insert(0, str(extra_path))
    env = dict(os.environ)
    old = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(paths + ([old] if old else []))
    env["MAREFORMA_AUTOHOOK_SOCKET"] = str(event_socket)
    env["MAREFORMA_AUTOHOOK_WORKER"] = "test-worker"
    env["MAREFORMA_AUTOHOOK_AUDIT"] = "1"
    env.pop("MAREFORMA_AUTOHOOK_OWNER_PID", None)
    for name in (
        "MAREFORMA_TASK_ID",
        "MAREFORMA_EXECUTION_ID",
        "MAREFORMA_ATTEMPT",
        "MAREFORMA_ATTEMPT_DIR",
        "MAREFORMA_EXECUTION_EPOCH",
        "MAREFORMA_PARENT_SCOPE_ID",
        "MAREFORMA_TRACEPARENT",
    ):
        env.pop(name, None)
    if task_context is None:
        env.pop("MAREFORMA_AUTOHOOK_TASK_CONTEXT", None)
    else:
        env["MAREFORMA_AUTOHOOK_TASK_CONTEXT"] = json.dumps(task_context)
    return env


def _run_python(script: str, env: dict[str, str], *, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def test_autohook_task_boundaries_ignore_child_processes(tmp_path):
    with _event_receiver(tmp_path) as (event_socket, events):
        env = _autohook_env(event_socket)
        script = """
import os, subprocess, sys
os.environ["MAREFORMA_TASK_ID"] = "task-main"
os.environ["MAREFORMA_EXECUTION_ID"] = "exec-main"
os.environ["MAREFORMA_ATTEMPT_DIR"] = "/tmp/attempt-2"
subprocess.run(
    [sys.executable, "-c", "import os; assert os.environ['MAREFORMA_TASK_ID'] == 'task-main'"],
    check=True,
)
os.environ.pop("MAREFORMA_TASK_ID")
"""
        completed = _run_python(script, env)
        assert completed.returncode == 0, completed.stderr

    boundaries = [
        event for event in events if event.get("kind") in {"task_start", "task_end"}
    ]
    assert [event["kind"] for event in boundaries] == ["task_start", "task_end"]
    assert all(event["process_role"] == "main" for event in boundaries)
    assert boundaries[0]["task_id"] == "task-main"
    context = [event for event in events if event.get("kind") == "task_context"]
    assert context
    assert context[-1]["execution_id"] == "exec-main"
    assert context[-1]["attempt"] == "attempt-2"


def test_autohook_does_not_infer_an_unmapped_application_task_variable(tmp_path):
    with _event_receiver(tmp_path) as (event_socket, events):
        env = _autohook_env(event_socket)
        script = """
import os
os.environ["APPLICATION_TASK_ID"] = "application-task"
os.environ["APPLICATION_TASK_ID"] = "application-task-2"
os.environ.pop("APPLICATION_TASK_ID")
"""
        completed = _run_python(script, env)
        assert completed.returncode == 0, completed.stderr

    assert not [
        event for event in events if event.get("kind") in {"task_start", "task_end"}
    ]


def test_autohook_uses_an_explicit_application_task_variable_mapping(tmp_path):
    with _event_receiver(tmp_path) as (event_socket, events):
        env = _autohook_env(
            event_socket,
            task_context={
                "task_id": "APPLICATION_TASK_ID",
                "execution_id": "APPLICATION_EXECUTION_ID",
                "attempt": "APPLICATION_ATTEMPT",
                "attempt_dir": "APPLICATION_ATTEMPT_DIR",
                "execution_epoch": "APPLICATION_EXECUTION_EPOCH",
                "parent_scope_id": "APPLICATION_PARENT_SCOPE_ID",
                "traceparent": "APPLICATION_TRACEPARENT",
            },
        )
        script = """
import os
os.environ["APPLICATION_TASK_ID"] = "mapped-task"
os.environ["APPLICATION_EXECUTION_ID"] = "mapped-exec"
os.environ["APPLICATION_ATTEMPT"] = "mapped-attempt"
os.environ["APPLICATION_PARENT_SCOPE_ID"] = "parent-scope"
os.environ["APPLICATION_TRACEPARENT"] = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
os.environ.pop("APPLICATION_TASK_ID")
"""
        completed = _run_python(script, env)
        assert completed.returncode == 0, completed.stderr

    boundaries = [
        event for event in events if event.get("kind") in {"task_start", "task_end"}
    ]
    assert [event["kind"] for event in boundaries] == ["task_start", "task_end"]
    assert boundaries[0]["task_id"] == "mapped-task"
    contexts = [event for event in events if event.get("kind") == "task_context"]
    assert contexts
    assert contexts[-1]["execution_id"] == "mapped-exec"
    assert contexts[-1]["attempt"] == "mapped-attempt"
    assert contexts[-1]["parent_scope_id"] == "parent-scope"
    assert contexts[-1]["traceparent"].startswith("00-")


def test_autohook_requests_stream_records_body_digest_with_a_private_query(tmp_path):
    fake = tmp_path / "fake-python"
    package = fake / "requests"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        """
class Response:
    status_code = 200
    url = "https://example.org/data?token=secret"
    def __init__(self):
        self._content = False
        self.closed = False
    def iter_content(self, chunk_size=1):
        yield b"hello-"
        yield b"world"
    def close(self):
        self.closed = True

class Session:
    def request(self, method, url, **kwargs):
        return Response()
""",
        encoding="utf-8",
    )
    with _event_receiver(tmp_path) as (event_socket, events):
        env = _autohook_env(event_socket, extra_path=fake)
        script = """
import os
os.environ["MAREFORMA_TASK_ID"] = "task-requests"
import requests
response = requests.Session().request("GET", "https://example.org/data?token=secret")
assert b"".join(response.iter_content()) == b"hello-world"
response.close()
os.environ.pop("MAREFORMA_TASK_ID")
"""
        completed = _run_python(script, env)
        assert completed.returncode == 0, completed.stderr

    http_events = [event for event in events if event.get("kind") == "http"]
    assert len(http_events) == 2
    assert http_events[0]["pending"] is True
    final = http_events[-1]
    assert final["body_observed"] is True
    assert final["body_bytes"] == 11
    assert final["body_digest"] == "sha256:" + hashlib.sha256(b"hello-world").hexdigest()
    assert final["url"] == "https://example.org/data"
    assert final["query_keys"] == ["token"]
    assert final["query_digest"] == "sha256:" + hashlib.sha256(b"token=secret").hexdigest()
    assert "secret" not in json.dumps(final)


def test_autohook_psycopg_and_redis_commands_are_application_events(tmp_path):
    fake = tmp_path / "fake-python"
    psycopg = fake / "psycopg"
    psycopg.mkdir(parents=True)
    (psycopg / "__init__.py").write_text(
        """
class _Info:
    host = "127.0.0.1"
    port = 5432
    dbname = "science"

class _Connection:
    info = _Info()

class Cursor:
    connection = _Connection()
    def execute(self, query, *args, **kwargs):
        return None

class AsyncCursor(Cursor):
    async def execute(self, query, *args, **kwargs):
        return None
""",
        encoding="utf-8",
    )
    redis = fake / "redis"
    redis.mkdir(parents=True)
    (redis / "__init__.py").write_text(
        """
class Redis:
    connection_pool = type("Pool", (), {"connection_kwargs": {"host": "127.0.0.1", "port": 6379, "db": 0}})()
    def execute_command(self, *args, **kwargs):
        return None
""",
        encoding="utf-8",
    )
    (redis / "client.py").write_text(
        """
from redis import Redis

class Pipeline(Redis):
    pass
""",
        encoding="utf-8",
    )
    asyncio_pkg = redis / "asyncio"
    asyncio_pkg.mkdir()
    (asyncio_pkg / "__init__.py").write_text(
        """
class Redis:
    connection_pool = type("Pool", (), {"connection_kwargs": {"host": "127.0.0.1", "port": 6379, "db": 1}})()
    async def execute_command(self, *args, **kwargs):
        return None
""",
        encoding="utf-8",
    )
    (asyncio_pkg / "client.py").write_text(
        """
class Pipeline(Redis):
    pass
""",
        encoding="utf-8",
    )
    with _event_receiver(tmp_path) as (event_socket, events):
        env = _autohook_env(event_socket, extra_path=fake)
        env["MAREFORMA_DB_QUERY_TEXT"] = "1"
        script = """
import os
os.environ["MAREFORMA_TASK_ID"] = "task-db"
import psycopg
psycopg.Cursor().execute("select * from proteins where id = %s", (1,))
from redis import Redis
Redis().execute_command("GET", "protein:P04637")
os.environ.pop("MAREFORMA_TASK_ID")
"""
        completed = _run_python(script, env)
        assert completed.returncode == 0, completed.stderr

    db_events = [event for event in events if event.get("kind") == "db"]
    assert [event["engine"] for event in db_events] == ["postgresql", "redis"]
    assert db_events[0]["query"] == "select * from proteins where id = %s"
    assert db_events[0]["database"] == "postgresql://127.0.0.1:5432/science"
    assert db_events[1]["query"] == "GET protein:P04637"
    assert db_events[1]["database"] == "redis://127.0.0.1:6379/0"


def test_worker_observer_signs_one_receipt_per_task_with_http_files_and_db(tmp_path):
    if not shutil.which("strace"):
        pytest.skip("strace is required")
    data_a = tmp_path / "data-a.csv"
    data_a.write_text("gene,value\nTP53,1\n", encoding="utf-8")
    data_b = tmp_path / "data-b.csv"
    data_b.write_text("gene,value\nEGFR,2\n", encoding="utf-8")
    worker_script = tmp_path / "worker.py"
    receipt_log = tmp_path / "worker-receipts.jsonl"
    trace_dir = tmp_path / "trace"
    secret_probe = tmp_path / "secret-probe.json"
    with _http_server() as base_url:
        worker_script.write_text(
            f"""
import json, os, sqlite3, time
from pathlib import Path
import httpx

probe = {{
    "hmac": "MAREFORMA_HMAC_SECRET" in os.environ,
    "pro": "MAREFORMA_PRO_SECRET" in os.environ,
    "secret": "MAREFORMA_SECRET" in os.environ,
}}
Path({str(secret_probe)!r}).write_text(json.dumps(probe), encoding="utf-8")

os.environ["MAREFORMA_TASK_ID"] = "task-a"
os.environ["MAREFORMA_EXECUTION_ID"] = "exec-a"
os.environ["MAREFORMA_ATTEMPT_DIR"] = "/tmp/attempt-1"
Path({str(data_a)!r}).read_text(encoding="utf-8")
db = sqlite3.connect({str(tmp_path / "science.db")!r})
db.execute("create table if not exists protein (id text)").fetchall()
db.execute("insert into protein values (?)", ("P04637",)).fetchall()
db.close()
response = httpx.get({base_url!r} + "/protein/P04637?format=json")
assert response.status_code == 200
os.environ.pop("MAREFORMA_TASK_ID")
time.sleep(0.15)

os.environ["MAREFORMA_TASK_ID"] = "task-b"
os.environ["MAREFORMA_EXECUTION_ID"] = "exec-b"
os.environ["MAREFORMA_ATTEMPT_DIR"] = "/tmp/attempt-2"
Path({str(data_b)!r}).read_text(encoding="utf-8")
with httpx.Client() as client:
    with client.stream("GET", {base_url!r} + "/stream?format=json") as response:
        assert len(b"".join(response.iter_bytes())) == 1000
os.environ.pop("MAREFORMA_TASK_ID")
""",
            encoding="utf-8",
        )
        observer = WorkerProcessObserver(
            [sys.executable, str(worker_script)],
            secret="worker-secret",
            worker_id="11",
            receipt_log=receipt_log,
            trace_dir=trace_dir,
            drain_timeout=2.0,
        )
        returncode = observer.run_forever()

    assert returncode == 0
    assert observer.receipt_count == 2
    rows = [json.loads(line) for line in receipt_log.read_text(encoding="utf-8").splitlines()]
    assert [row["task_id"] for row in rows] == ["task-a", "task-b"]
    assert json.loads(secret_probe.read_text(encoding="utf-8")) == {
        "hmac": False,
        "pro": False,
        "secret": False,
    }

    by_task = {row["task_id"]: row["receipt"] for row in rows}
    first = by_task["task-a"]
    second = by_task["task-b"]
    assert first["worker_id"] == "11"
    assert first["execution_id"] == "exec-a"
    assert first["attempt"] == "attempt-1"
    # A pre-existing file under /tmp is intentionally fail-closed: strace saw
    # the read, but it is not a writer-owned temporary file with a known source.
    assert str(data_a) in first["unmapped_paths"]
    assert "unmapped_tmpfs" in first["opaque_reasons"]
    assert first["observed_http"][0]["method"] == "GET"
    assert first["observed_http"][0]["status"] == 200
    assert first["observed_http"][0]["body_bytes"] == 33
    assert first["observed_http"][0]["body_digest"].startswith("sha256:")
    assert first["observed_http"][0]["url"].endswith("/protein/P04637")
    assert any(row.get("engine") == "sqlite3" for row in first["observed_db_queries"])
    assert any(
        row.get("query") == "insert into protein values ('P04637')"
        for row in first["observed_db_queries"]
    )

    assert second["execution_id"] == "exec-b"
    assert str(data_b) in second["unmapped_paths"]
    assert second["observed_http"][0]["body_bytes"] == 1000
    assert second["observed_http"][0]["body_observed"] is True
    assert OPAQUE_HTTP_BODY_UNOBSERVED not in second.get("opaque_reasons", ())

    for receipt in (first, second):
        verified = verify_scope_receipt(receipt, "worker-secret")
        assert verified.evidence.task_id == receipt["task_id"]
        assert verified.evidence.read_bytes > 0


def test_worker_observer_marks_no_strace_as_trace_incomplete(tmp_path):
    receipt_log = tmp_path / "receipts.jsonl"
    worker_script = tmp_path / "worker.py"
    worker_script.write_text(
        """
import os
os.environ["MAREFORMA_TASK_ID"] = "compute-only"
os.environ.pop("MAREFORMA_TASK_ID")
""",
        encoding="utf-8",
    )
    observer = WorkerProcessObserver(
        [sys.executable, str(worker_script)],
        secret="worker-secret",
        receipt_log=receipt_log,
        trace_dir=tmp_path / "trace",
        use_strace=False,
    )
    assert observer.run_forever() == 0
    receipt = json.loads(receipt_log.read_text(encoding="utf-8"))["receipt"]
    assert OPAQUE_TRACE_INCOMPLETE in receipt["opaque_reasons"]
    assert receipt["task_id"] == "compute-only"
    assert receipt["collector_mode"] == "worker_python_audit"


def test_worker_unfinished_http_stream_is_opaque_but_keeps_the_attempt(tmp_path):
    receipt_log = tmp_path / "receipts.jsonl"
    observer = WorkerProcessObserver(
        ["/bin/true"],
        secret="worker-secret",
        receipt_log=receipt_log,
        trace_dir=tmp_path / "trace",
        use_strace=False,
    )
    observer._on_event(
        {
            "kind": "task_start",
            "task_id": "task-stream",
            "execution_id": "exec-stream",
            "process_role": "main",
            "pid": 123,
        }
    )
    observer._on_event(
        {
            "kind": "http",
            "task_id": "task-stream",
            "execution_id": "exec-stream",
            "process_role": "main",
            "pid": 123,
            "request_id": "request-1",
            "url": "https://api.example.org/data?token=secret",
            "method": "GET",
            "status": 200,
            "body_unobserved": True,
            "pending": True,
            "query_digest": "sha256:" + hashlib.sha256(b"token=secret").hexdigest(),
            "query_keys": ["token"],
        }
    )
    observer._on_event(
        {
            "kind": "task_end",
            "task_id": "task-stream",
            "process_role": "main",
            "pid": 123,
        }
    )
    receipt = json.loads(receipt_log.read_text(encoding="utf-8"))["receipt"]
    assert OPAQUE_HTTP_BODY_UNOBSERVED in receipt["opaque_reasons"]
    assert receipt["observed_egress_urls"] == ["https://api.example.org/data"]
    assert "observed_urls" not in receipt
    assert receipt["observed_http"] == [
        {
            "request_id": "request-1",
            "url": "https://api.example.org/data",
            "method": "GET",
            "status": 200,
            "body_observed": False,
            "query_digest": "sha256:" + hashlib.sha256(b"token=secret").hexdigest(),
            "query_keys": ["token"],
            "error": "no_completion_event",
        }
    ]


def test_worker_routes_strace_events_by_wall_clock_task_boundary(tmp_path):
    from mareforma_pro.strace import StraceEvent

    receipt_log = tmp_path / "receipts.jsonl"
    observer = WorkerProcessObserver(
        ["/bin/true"],
        secret="worker-secret",
        receipt_log=receipt_log,
        trace_dir=tmp_path / "trace",
        use_strace=False,
    )
    observer._on_event(
        {
            "kind": "task_start",
            "task_id": "task-clock",
            "process_role": "main",
            "pid": 123,
            "ts": 100.0,
        }
    )
    # A late line from an earlier task is buffered, not charged to this task.
    observer._on_strace_event(
        StraceEvent(
            syscall="read",
            pid=123,
            kind="read",
            path="/srv/before.csv",
            resolved_path="/srv/before.csv",
            bytes=5,
            timestamp=99.0,
        )
    )
    observer._on_strace_event(
        StraceEvent(
            syscall="read",
            pid=123,
            kind="read",
            path="/srv/inside.csv",
            resolved_path="/srv/inside.csv",
            bytes=7,
            timestamp=101.0,
        )
    )
    observer._on_event(
        {
            "kind": "task_end",
            "task_id": "task-clock",
            "process_role": "main",
            "pid": 123,
            "ts": 102.0,
        }
    )
    receipt = json.loads(receipt_log.read_text(encoding="utf-8"))["receipt"]
    assert receipt["observed_files"] == ["/srv/inside.csv"]
    assert receipt["read_bytes"] == 7
