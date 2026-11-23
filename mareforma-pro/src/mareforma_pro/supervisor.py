"""Long-running, rootless MCP process supervisor.

The supervisor owns the public HTTP port, starts one or more unchanged MCP
server processes under streaming ``strace``, serializes requests per process,
and signs one :class:`CallReceipt` per HTTP request. It is intentionally a
user-space reverse gate: no server source changes, no sudo, no eBPF.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from .egress import EgressObservation, EgressProxy
from .dbproxy import (
    DatabaseObservation,
    LocalTCPRelay,
    engine_for_port,
    rewrite_database_env,
)
from .evidence import (
    OPAQUE_CONCURRENT_CALL_OVERLAP,
    OPAQUE_EGRESS_PROXY_BYPASSED,
    OPAQUE_TRACE_INCOMPLETE,
)
from .mcp_receipts import (
    CallReceipt,
    SessionReceipt,
    build_call_receipt,
    build_session_receipt,
)
from .paths import MountResolver
from .strace import SUPERVISOR_TRACE_EXPR, StraceEvent
from .stream import CallEvidence, StraceStream

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# The original MCP server commonly hard-codes 18000. Keep that port for the
# child process and put the observing public gate on a separate port so the
# supervisor can run without modifying or rebinding the server configuration.
DEFAULT_PUBLIC_PORT = 18100
DEFAULT_INTERNAL_PORT = 18000


def _json_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _extract_mcp_metadata(body: bytes) -> dict[str, Any]:
    """Extract request id, JSON-RPC method, scope and traceparent from a body."""
    result: dict[str, Any] = {}
    if not body:
        return result
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return result
    items = payload if isinstance(payload, list) else [payload]
    methods: list[str] = []
    ids: list[str] = []
    scopes: list[str] = []
    traces: list[str] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        method = item.get("method")
        if isinstance(method, str):
            methods.append(method)
        request_id = item.get("id")
        if request_id is not None:
            text = _json_value(request_id)
            if text is not None:
                ids.append(text)
        params = item.get("params")
        if isinstance(params, Mapping):
            meta = params.get("_meta")
            if isinstance(meta, Mapping):
                scope = meta.get("mareforma_scope_id") or meta.get("mareforma.scope_id")
                if isinstance(scope, str) and scope:
                    scopes.append(scope)
                trace = meta.get("traceparent")
                if isinstance(trace, str) and trace:
                    traces.append(trace)
    if methods:
        result["method"] = methods[0] if len(methods) == 1 else "batch"
        result["methods"] = tuple(methods)
    if ids:
        result["request_id"] = ids[0] if len(ids) == 1 else ",".join(ids)
    if scopes:
        result["scope_id"] = scopes[0]
    if traces:
        result["traceparent"] = traces[0]
    return result


def rewrite_command_port(
    command: Sequence[str], *, external_port: int, internal_port: int
) -> list[str]:
    """Point an unchanged server command at the internal port.

    Placeholders are the least ambiguous option: ``{internal_port}`` and
    ``{external_port}``. For existing commands we also rewrite the common
    ``--port <external_port>`` / ``--port=<external_port>`` shape.
    Environment variables are set by :class:`MCPWorker` as a fallback for
    servers that read PORT/MCP_PORT.
    """
    out: list[str] = []
    external = str(external_port)
    internal = str(internal_port)
    previous = ""
    for token in command:
        value = str(token).replace("{external_port}", external).replace("{internal_port}", internal)
        if previous == "--port" and value == external:
            value = internal
        elif value == f"--port={external}":
            value = f"--port={internal}"
        out.append(value)
        previous = value
    return out


@dataclass
class WorkerConfig:
    index: int
    host: str = "127.0.0.1"
    port: int = DEFAULT_INTERNAL_PORT
    external_port: int = DEFAULT_PUBLIC_PORT
    command: Sequence[str] = ()
    secret: str | bytes = b""
    egress_proxy: bool = False
    db_hook: bool = False
    db_relays: tuple[tuple[str, int], ...] = ()
    use_strace: bool = True
    strace_binary: str | None = None
    bind_rewrite_port: int | None = None
    ready_timeout: float = 30.0
    receipt_ttl: float = 300.0
    drain_timeout: float = 2.0
    trace_dir: str | Path | None = None


@dataclass
class _SessionState:
    calls: list[CallReceipt] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    written_files: set[str] = field(default_factory=set)


class JsonlReceiptJournal:
    """Thread-safe append-only JSONL journal for call/session receipts."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, kind: str, receipt: Mapping[str, Any]) -> None:
        row = {"kind": kind, **dict(receipt)}
        line = json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())


class MCPWorker:
    """One internal MCP server process and its exclusive evidence pipeline."""

    def __init__(self, config: WorkerConfig) -> None:
        self.config = config
        self.host = config.host
        self.port = config.port
        self.proc: subprocess.Popen[Any] | None = None
        self.stream: StraceStream | None = None
        self.egress: EgressProxy | None = None
        self._db_relays: dict[str, LocalTCPRelay] = {}
        self._trace_dir = Path(config.trace_dir) if config.trace_dir else Path(
            tempfile.mkdtemp(prefix="mf_mcp_supervisor_")
        )
        self._owns_trace_dir = config.trace_dir is None
        self._trace_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._trace_dir.chmod(0o700)
        except OSError:
            pass
        self._fifo = self._trace_dir / f"worker-{config.index}.fifo"
        self._stderr_path = self._trace_dir / f"worker-{config.index}.log"
        self._event_socket_path = self._trace_dir / f"events-{config.index}.sock"
        self._event_socket: socket.socket | None = None
        self._event_thread: threading.Thread | None = None
        self._active: CallEvidence | None = None
        self._active_started: float = 0.0
        self._active_session: str | None = None
        self._active_scope: str | None = None
        self._active_method: str | None = None
        self._active_request_id: str | None = None
        self._active_traceparent: str | None = None
        self._active_parent_scope_id: str | None = None
        self._event_lock = threading.Lock()
        self._event_condition = threading.Condition(self._event_lock)
        self._last_aux_event_at = time.monotonic()
        self._stopping = threading.Event()
        self._sessions: dict[str, _SessionState] = {}
        self._sessions_lock = threading.Lock()
        self._reserved = False
        self._ready = False
        # GET /mcp is the MCP Streamable HTTP server-notification stream.  It
        # deliberately does not reserve the worker: it is a long-lived
        # transport connection, not a tool call, and reserving the only worker
        # until the client closes it would deadlock every later POST.  Count
        # live streams so a POST that overlaps one is explicitly OPAQUE rather
        # than falsely treating interleaved process events as call evidence.
        self._stream_count = 0

    @property
    def fifo_path(self) -> Path:
        return self._fifo

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def proxy_endpoints(self) -> tuple[str, ...]:
        return (self.egress.endpoint,) if self.egress is not None else ()

    @property
    def session(self) -> dict[str, Any]:
        with self._sessions_lock:
            return dict(self._sessions)

    def _event_socket_start(self) -> None:
        if not self.config.db_hook:
            return
        if self._event_socket is not None:
            return
        try:
            if self._event_socket_path.exists():
                self._event_socket_path.unlink()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(str(self._event_socket_path))
            try:
                self._event_socket_path.chmod(0o600)
            except OSError:
                pass
            sock.settimeout(0.5)
            self._event_socket = sock
            self._event_thread = threading.Thread(
                target=self._event_loop, name=f"mareforma-autohook-{self.config.index}", daemon=True
            )
            self._event_thread.start()
        except OSError:
            self._event_socket = None

    def _event_loop(self) -> None:
        sock = self._event_socket
        if sock is None:
            return
        while not self._stopping.is_set():
            try:
                raw, _ = sock.recvfrom(256 * 1024)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, Mapping):
                self._on_application_event(event)

    def _on_application_event(self, event: Mapping[str, Any]) -> None:
        with self._event_condition:
            self._last_aux_event_at = time.monotonic()
            self._event_condition.notify_all()
            if self._active is not None:
                self._active.add_application_event(event)

    def _on_egress(self, observation: EgressObservation) -> None:
        with self._event_condition:
            self._last_aux_event_at = time.monotonic()
            self._event_condition.notify_all()
            if self._active is None:
                return
            self._active.add_url(observation.url, path_opaque=observation.path_opaque)

    def _on_database(self, observation: DatabaseObservation) -> None:
        with self._event_condition:
            self._last_aux_event_at = time.monotonic()
            self._event_condition.notify_all()
            if self._active is None:
                return
            try:
                target_port = int(observation.target.rsplit(":", 1)[-1])
            except (ValueError, IndexError):
                target_port = 0
            self._active.add_application_event(
                {
                    "kind": "db",
                    "engine": engine_for_port(target_port),
                    "database": observation.target,
                    "operation": observation.operation,
                    "source": "local_tcp_relay",
                }
            )

    def _on_strace_event(self, event: StraceEvent) -> None:
        with self._event_condition:
            if self._active is not None:
                self._active.add_strace_event(event)

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        # The target must not be able to mint or read the supervisor's HMAC
        # key. The explicit argument is passed to the worker object, never to
        # the child environment.
        for name in (
            "MAREFORMA_HMAC_SECRET",
            "MAREFORMA_PRO_SECRET",
            "MAREFORMA_SECRET",
        ):
            env.pop(name, None)
        env["PORT"] = str(self.port)
        env["MCP_PORT"] = str(self.port)
        env["UVICORN_PORT"] = str(self.port)
        env["MCP_SERVER_PORT"] = str(self.port)
        env["HOST"] = self.host
        env["MCP_HOST"] = self.host
        env["UVICORN_HOST"] = self.host
        env["MCP_SERVER_HOST"] = self.host
        env["PYTHONUNBUFFERED"] = "1"
        if self.config.db_hook or self.config.bind_rewrite_port is not None:
            path = Path(__file__).with_name("autohook")
            old = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(path) + (os.pathsep + old if old else "")
        if self.config.db_hook:
            env["MAREFORMA_AUTOHOOK_SOCKET"] = str(self._event_socket_path)
            env["MAREFORMA_AUTOHOOK_WORKER"] = str(self.config.index)
        if self.config.bind_rewrite_port is not None:
            env["MAREFORMA_REWRITE_BIND_FROM"] = str(self.config.bind_rewrite_port)
            env["MAREFORMA_REWRITE_BIND_TO_HOST"] = self.host
            env["MAREFORMA_REWRITE_BIND_TO_PORT"] = str(self.port)
        if self.config.egress_proxy and self.egress is not None:
            proxy = self.egress.proxy_url
            env["HTTP_PROXY"] = proxy
            env["HTTPS_PROXY"] = proxy
            env["ALL_PROXY"] = proxy
            env["NO_PROXY"] = "127.0.0.1,localhost,::1"
            env["http_proxy"] = proxy
            env["https_proxy"] = proxy
            env["all_proxy"] = proxy
            env["no_proxy"] = "127.0.0.1,localhost,::1"
        if self._db_relays:
            env = rewrite_database_env(env, self._db_relays)
        return env

    def start(self) -> None:
        if self.proc is not None:
            return
        self._assert_internal_port_free()
        self._event_socket_start()
        for host, port in self.config.db_relays:
            relay = LocalTCPRelay(host, port, self._on_database)
            relay.start()
            self._db_relays[relay.target] = relay
        if self.config.egress_proxy:
            self.egress = EgressProxy(self._on_egress, host="127.0.0.1")
            self.egress.start()
        if self.config.use_strace:
            try:
                if self._fifo.exists():
                    self._fifo.unlink()
                os.mkfifo(self._fifo, 0o600)
            except OSError as exc:
                self._shutdown_resources()
                raise RuntimeError(f"cannot create strace FIFO: {exc}") from exc
            self.stream = StraceStream(
                self._fifo,
                MountResolver.from_mounts({}, root_passthrough=True),
                track_temp_semantics=True,
                event_sink=self._on_strace_event,
            )
            self.stream.start()
        command = rewrite_command_port(
            self.config.command,
            external_port=self.config.external_port,
            internal_port=self.port,
        )
        if self.config.use_strace:
            strace = self.config.strace_binary or shutil.which("strace")
            if not strace:
                self._shutdown_resources()
                raise RuntimeError("strace is not installed")
            argv = [
                strace,
                "--seccomp-bpf",
                "-f",
                "-yy",
                "-qq",
                "-s",
                "0",
                "-e",
                f"trace={SUPERVISOR_TRACE_EXPR}",
                "-o",
                str(self._fifo),
                "--",
                *command,
            ]
        else:
            argv = list(command)
        log_handle = self._stderr_path.open("ab")
        try:
            self.proc = subprocess.Popen(
                argv,
                env=self._env(),
                cwd=None,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except BaseException:
            log_handle.close()
            self._shutdown_resources()
            raise
        finally:
            try:
                log_handle.close()
            except Exception:
                pass
        try:
            self._wait_ready()
            if self.stream is not None:
                # Consume startup opens before a request can claim the worker;
                # those events belong to process initialization, not a tool
                # call, and must not leak into the first CallReceipt.
                self.stream.wait_drained(quiet_seconds=0.1, timeout=self.config.drain_timeout)
        except BaseException:
            self._stop_process()
            self._shutdown_resources()
            raise

    def _assert_internal_port_free(self) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((self.host, self.port))
        except OSError as exc:
            raise RuntimeError(
                f"internal MCP port {self.endpoint} is already in use"
            ) from exc
        finally:
            probe.close()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + max(0.1, float(self.config.ready_timeout))
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError(
                    f"internal MCP worker {self.config.index} exited with "
                    f"{self.proc.returncode}; see {self._stderr_path}"
                )
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    # A stale process may still own the internal port. Check
                    # that the child we just launched survived the probe before
                    # declaring it ready.
                    time.sleep(0.05)
                    if self.proc is not None and self.proc.poll() is not None:
                        raise RuntimeError(
                            f"internal MCP worker {self.config.index} exited with "
                            f"{self.proc.returncode}; see {self._stderr_path}"
                        )
                    self._ready = True
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(
            f"internal MCP worker {self.config.index} did not listen on "
            f"{self.endpoint} within {self.config.ready_timeout}s"
        )

    def begin_call(
        self,
        *,
        scope_id: str,
        session_id: str | None,
        method: str | None,
        request_id: str | None,
        traceparent: str | None,
        parent_scope_id: str | None = None,
    ) -> CallEvidence:
        if not self._reserved:
            raise RuntimeError("worker was not reserved")
        with self._sessions_lock:
            state = self._sessions.setdefault(session_id or "__anonymous__", _SessionState())
            state.last_seen = time.time()
            written = set(state.written_files)
        with self._event_lock:
            if self._active is not None:
                raise RuntimeError("worker already has an active call")
            evidence = CallEvidence(written_files=written)
            if self._stream_count:
                evidence.opaque_reasons.add(OPAQUE_CONCURRENT_CALL_OVERLAP)
            self._active = evidence
            self._active_started = time.time()
            self._active_session = session_id
            self._active_scope = scope_id
            self._active_method = method
            self._active_request_id = request_id
            self._active_traceparent = traceparent
            self._active_parent_scope_id = parent_scope_id
        return evidence

    def open_stream(self) -> None:
        """Register a long-lived GET/SSE stream without reserving the worker."""
        with self._event_lock:
            self._stream_count += 1
            if self._active is not None:
                self._active.opaque_reasons.add(OPAQUE_CONCURRENT_CALL_OVERLAP)
            self._event_condition.notify_all()

    def close_stream(self) -> None:
        with self._event_lock:
            if self._stream_count > 0:
                self._stream_count -= 1
            self._event_condition.notify_all()

    def finish_call(
        self,
        *,
        http_status: int | None,
        response_digest: str | None = None,
        session_id: str | None = None,
        forced_opaque: Iterable[str] = (),
    ) -> CallReceipt:
        drained = True
        if self.stream is not None:
            drained = self.stream.wait_drained(timeout=self.config.drain_timeout)
        aux_drained = True
        if self.config.db_hook or self.config.egress_proxy:
            deadline = time.monotonic() + self.config.drain_timeout
            with self._event_condition:
                while time.monotonic() - self._last_aux_event_at < 0.05:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        aux_drained = False
                        break
                    self._event_condition.wait(min(0.05, remaining))
        with self._event_condition:
            evidence = self._active
            if evidence is None:
                raise RuntimeError("worker has no active call")
            if (
                self.stream is None
                or not drained
                or not aux_drained
                or self.stream.error is not None
            ):
                evidence.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
            evidence.opaque_reasons.update(forced_opaque)
            if response_digest:
                evidence.payload_digests.add(response_digest)
            session = session_id or self._active_session
            kwargs = evidence.finalize(
                egress_proxy_enabled=self.config.egress_proxy,
                egress_proxy_endpoints=self.proxy_endpoints,
                db_hook_enabled=self.config.db_hook,
            )
            with self._sessions_lock:
                state = self._sessions.setdefault(session or "__anonymous__", _SessionState())
                state.written_files.update(evidence.written_files)
                state.last_seen = time.time()
            call = build_call_receipt(
                call_id=str(uuid4()),
                scope_id=self._active_scope or f"mcp:{uuid4().hex}",
                secret=self.config.secret,
                session_id=session,
                method=self._active_method,
                request_id=self._active_request_id,
                started_at=self._active_started,
                closed_at=time.time(),
                ttl=self.config.receipt_ttl,
                http_status=http_status,
                traceparent=self._active_traceparent,
                parent_scope_id=self._active_parent_scope_id,
                **kwargs,
            )
            with self._sessions_lock:
                state = self._sessions.setdefault(session or "__anonymous__", _SessionState())
                state.calls.append(call)
            self._active = None
            self._active_session = None
            self._active_scope = None
        return call

    def session_receipts(self, *, ttl: float) -> list[SessionReceipt]:
        with self._sessions_lock:
            states = list(self._sessions.items())
            self._sessions.clear()
        out: list[SessionReceipt] = []
        for session_id, state in states:
            if state.calls:
                out.append(
                    build_session_receipt(
                        session_id=session_id,
                        calls=state.calls,
                        secret=self.config.secret,
                        ttl=ttl,
                    )
                )
        return out

    def _shutdown_resources(self) -> None:
        self._stopping.set()
        if self.stream is not None:
            self.stream.stop()
            self.stream = None
        if self.egress is not None:
            self.egress.stop()
            self.egress = None
        for relay in self._db_relays.values():
            relay.stop()
        self._db_relays.clear()
        if self._event_socket is not None:
            try:
                self._event_socket.close()
            except OSError:
                pass
            self._event_socket = None
        try:
            self._event_socket_path.unlink()
        except OSError:
            pass
        try:
            self._fifo.unlink()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop_process()
        self._shutdown_resources()
        if self._owns_trace_dir:
            try:
                shutil.rmtree(self._trace_dir)
            except OSError:
                pass

    def _stop_process(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is not None:
            try:
                # strace is the process-group leader and the MCP server is its
                # child. Terminating only strace would leave the server bound
                # to the internal port. Kill the whole supervised group.
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                try:
                    proc.terminate()
                except OSError:
                    pass


class WorkerPool:
    """Deterministic idle-worker reservation with session affinity.

    A single condition protects both the idle state and the affinity map.
    Updating ``_reserved`` and removing a worker from the available set must be
    one atomic operation: otherwise an affinity request and an anonymous
    request can both observe the same worker as idle, which surfaced as
    ``worker already has an active call`` and a 502 under concurrent clients.
    """

    def __init__(self, workers: Iterable[MCPWorker]) -> None:
        self.workers = tuple(workers)
        self._affinity: dict[str, MCPWorker] = {}
        self._condition = threading.Condition()
        self._closed = False

    def _idle_locked(self) -> MCPWorker | None:
        for worker in self.workers:
            if not worker._reserved:
                return worker
        return None

    def acquire(self, session_id: str | None, *, timeout: float = 30.0) -> MCPWorker:
        deadline = time.monotonic() + max(0.1, timeout)
        with self._condition:
            while True:
                if self._closed:
                    raise RuntimeError("worker pool is closed")
                if session_id:
                    pinned = self._affinity.get(session_id)
                    if pinned is not None:
                        if not pinned._reserved:
                            pinned._reserved = True
                            return pinned
                    else:
                        worker = self._idle_locked()
                        if worker is not None:
                            worker._reserved = True
                            return worker
                else:
                    worker = self._idle_locked()
                    if worker is not None:
                        worker._reserved = True
                        return worker
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if session_id and self._affinity.get(session_id) is not None:
                        raise TimeoutError(f"session worker busy: {session_id}")
                    raise TimeoutError("no idle MCP worker")
                self._condition.wait(remaining)

    def bind_session(self, session_id: str | None, worker: MCPWorker) -> None:
        if not session_id:
            return
        with self._condition:
            self._affinity.setdefault(session_id, worker)

    def worker_for_session(self, session_id: str | None) -> MCPWorker:
        """Return the worker for a stream/termination request without reserving it.

        A GET/SSE stream must be forwarded even while the same worker is
        reserved for a POST.  The upstream MCP server handles those HTTP
        connections concurrently; only the evidence pipeline is serialized.
        For an unknown session, prefer an idle worker and otherwise fall back
        to the first worker.  In the normal Streamable HTTP flow, initialize
        has already bound the session to its worker.
        """
        with self._condition:
            if self._closed:
                raise RuntimeError("worker pool is closed")
            if session_id:
                pinned = self._affinity.get(session_id)
                if pinned is not None:
                    return pinned
            worker = self._idle_locked()
            if worker is not None:
                return worker
            if not self.workers:
                raise RuntimeError("no MCP worker is configured")
            return self.workers[0]

    def release(self, worker: MCPWorker) -> None:
        with self._condition:
            if worker._reserved:
                worker._reserved = False
                self._condition.notify_all()

    def shutdown(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        for worker in self.workers:
            worker.stop()


class _SupervisorHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, supervisor: "MCPProcessSupervisor"):
        self.supervisor = supervisor
        super().__init__(address, handler)


class _MCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mareforma-pro-supervisor/0.5.0"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the server user's stderr available for their own logs, but do
        # not duplicate every MCP request into the supervisor log.
        return

    def _handle(self) -> None:
        self.server.supervisor.handle(self)  # type: ignore[attr-defined]

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle
    do_HEAD = _handle


class MCPProcessSupervisor:
    """Public HTTP gate plus one unchanged MCP process per worker."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        secret: str | bytes,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PUBLIC_PORT,
        internal_host: str = "127.0.0.1",
        internal_port: int = DEFAULT_INTERNAL_PORT,
        workers: int = 1,
        egress_proxy: bool = False,
        db_hook: bool = False,
        db_relays: Iterable[tuple[str, int]] = (),
        use_strace: bool = True,
        strace_binary: str | None = None,
        bind_rewrite_port: int | None = None,
        ready_timeout: float = 30.0,
        receipt_ttl: float = 300.0,
        session_idle_timeout: float = 300.0,
        drain_timeout: float = 2.0,
        trace_dir: str | Path | None = None,
        receipt_log: str | Path | None = None,
        span_exporter: object | None = None,
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        if not secret:
            raise ValueError("secret must not be empty")
        if workers < 1:
            raise ValueError("workers must be >= 1")
        self.command = tuple(str(item) for item in command)
        self.secret = secret
        self.host = host
        self.port = int(port)
        self.internal_host = internal_host
        self.internal_port = int(internal_port)
        if self.port == self.internal_port:
            wildcard_hosts = {"", "0.0.0.0", "::", "[::]", "*"}
            if self.host in wildcard_hosts:
                raise ValueError(
                    "when public and internal ports match, --host must name a "
                    "specific external bind address; wildcard binding would "
                    f"conflict with {self.internal_host}:{self.internal_port}"
                )
            if self.host == self.internal_host:
                raise ValueError(
                    "when public and internal ports match, the public and "
                    "internal bind hosts must differ"
                )
        self.receipt_ttl = float(receipt_ttl)
        self.session_idle_timeout = float(session_idle_timeout)
        self.trace_dir = trace_dir
        self.receipt_log = Path(receipt_log) if receipt_log else None
        self.journal = JsonlReceiptJournal(self.receipt_log) if self.receipt_log else None
        self.span_exporter = span_exporter
        self._httpd: _SupervisorHTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._sessions: dict[str, list[CallReceipt]] = {}
        self._session_last_seen: dict[str, float] = {}
        self._session_lock = threading.Lock()
        self._idle_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        configs = [
            WorkerConfig(
                index=index,
                host=internal_host,
                port=self.internal_port + index,
                external_port=self.port,
                command=self.command,
                secret=secret,
                egress_proxy=egress_proxy,
                db_hook=db_hook,
                db_relays=tuple(db_relays),
                use_strace=use_strace,
                strace_binary=strace_binary,
                bind_rewrite_port=bind_rewrite_port,
                ready_timeout=ready_timeout,
                receipt_ttl=receipt_ttl,
                drain_timeout=drain_timeout,
                trace_dir=trace_dir,
            )
            for index in range(workers)
        ]
        self.workers = tuple(MCPWorker(config) for config in configs)
        self.pool = WorkerPool(self.workers)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._httpd is not None:
            return
        started: list[MCPWorker] = []
        try:
            for worker in self.workers:
                worker.start()
                started.append(worker)
            self._httpd = _SupervisorHTTPServer(
                (self.host, self.port), _MCPHandler, self
            )
            self._http_thread = threading.Thread(
                target=self._httpd.serve_forever,
                name="mareforma-mcp-supervisor",
                daemon=True,
            )
            self._http_thread.start()
        except BaseException:
            for worker in reversed(started):
                worker.stop()
            self._httpd = None
            raise
        self._idle_thread = threading.Thread(
            target=self._idle_loop, name="mareforma-session-idle", daemon=True
        )
        self._idle_thread.start()

    def _idle_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            self._close_idle_sessions()

    def _close_idle_sessions(self) -> None:
        now = time.time()
        with self._session_lock:
            expired = [
                session_id
                for session_id, last_seen in self._session_last_seen.items()
                if now - last_seen >= self.session_idle_timeout
            ]
        for session_id in expired:
            self.finalize_session(session_id)

    def _remember_call(self, call: CallReceipt) -> None:
        session_id = call.session_id or "__anonymous__"
        with self._session_lock:
            self._sessions.setdefault(session_id, []).append(call)
            self._session_last_seen[session_id] = time.time()
        if self.journal is not None:
            self.journal.append("call", call.to_receipt_dict())
        if self.span_exporter is not None:
            try:
                from .otel import call_span_from_receipt

                self.span_exporter.export(call_span_from_receipt(call))  # type: ignore[attr-defined]
            except Exception:
                pass

    def finalize_session(self, session_id: str) -> SessionReceipt | None:
        with self._session_lock:
            calls = self._sessions.pop(session_id, [])
            self._session_last_seen.pop(session_id, None)
        if not calls:
            return None
        receipt = build_session_receipt(
            session_id=session_id,
            calls=calls,
            secret=self.secret,
            ttl=self.receipt_ttl,
        )
        if self.journal is not None:
            self.journal.append("session", receipt.to_receipt_dict())
        if self.span_exporter is not None:
            try:
                from .otel import session_span_from_receipt

                self.span_exporter.export(  # type: ignore[attr-defined]
                    session_span_from_receipt(receipt, call_receipts=tuple(calls))
                )
            except Exception:
                pass
        return receipt

    def _request_headers(self, handler: BaseHTTPRequestHandler) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in handler.headers.items():
            headers[key] = value
        return headers

    def _request_body(self, handler: BaseHTTPRequestHandler) -> bytes:
        length_text = handler.headers.get("Content-Length")
        transfer = (handler.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer:
            chunks: list[bytes] = []
            while True:
                line = handler.rfile.readline(65536)
                if not line:
                    break
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    break
                if size == 0:
                    while handler.rfile.readline(65536) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                chunks.append(handler.rfile.read(size))
                handler.rfile.read(2)
            return b"".join(chunks)
        if not length_text:
            return b""
        try:
            length = int(length_text)
        except ValueError:
            return b""
        if length < 0 or length > 64 * 1024 * 1024:
            return b""
        return handler.rfile.read(length)

    def _upstream_headers(
        self,
        handler: BaseHTTPRequestHandler,
        worker: MCPWorker,
        body: bytes,
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in handler.headers.items():
            lower = key.lower()
            if lower in _HOP_BY_HOP or lower in {"host", "content-length"}:
                continue
            headers[key] = value
        headers["Host"] = f"{worker.host}:{worker.port}"
        headers["X-Forwarded-For"] = handler.client_address[0]
        headers["X-Forwarded-Proto"] = "http"
        if body:
            headers["Content-Length"] = str(len(body))
        return headers

    def _request_target(self, handler: BaseHTTPRequestHandler) -> str:
        target = urlsplit(handler.path)
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        return path

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        body = self._request_body(handler)
        meta = _extract_mcp_metadata(body)
        header_scope = handler.headers.get("X-Mareforma-Scope-Id")
        header_trace = handler.headers.get("traceparent")
        header_session = handler.headers.get("Mcp-Session-Id") or handler.headers.get(
            "X-MCP-Session-Id"
        )
        if handler.command in {"GET", "DELETE"}:
            self._handle_stream(handler, body=body, session_id=header_session)
            return
        scope_id = str(meta.get("scope_id") or header_scope or f"mcp:{uuid4().hex}")
        traceparent = str(meta.get("traceparent") or header_trace or "") or None
        session_id = header_session or f"mcp-anon:{uuid4().hex}"
        method = str(meta.get("method") or handler.command or "")
        request_id = meta.get("request_id")
        worker: MCPWorker | None = None
        call_started = False
        status: int | None = None
        try:
            worker = self.pool.acquire(session_id)
            worker.begin_call(
                scope_id=scope_id,
                session_id=session_id,
                method=method,
                request_id=str(request_id) if request_id is not None else None,
                traceparent=traceparent,
            )
            call_started = True
            upstream_headers = self._upstream_headers(handler, worker, body)
            status, response_digest, response_session = self._forward(
                handler, worker, upstream_headers, body
            )
            if response_session:
                session_id = response_session
                self.pool.bind_session(session_id, worker)
            call = worker.finish_call(
                http_status=status,
                response_digest=response_digest,
                session_id=session_id,
            )
            self._remember_call(call)
        except TimeoutError as exc:
            self._error_response(handler, 503, str(exc))
            if worker is not None and call_started:
                try:
                    call = worker.finish_call(
                        http_status=503,
                        forced_opaque=(OPAQUE_TRACE_INCOMPLETE,),
                        session_id=session_id,
                    )
                    self._remember_call(call)
                except Exception:
                    pass
        except (OSError, ValueError, RuntimeError) as exc:
            self._error_response(handler, 502, str(exc))
            if worker is not None and call_started:
                try:
                    call = worker.finish_call(
                        http_status=502,
                        forced_opaque=(OPAQUE_TRACE_INCOMPLETE,),
                        session_id=session_id,
                    )
                    self._remember_call(call)
                except Exception:
                    pass
        finally:
            if worker is not None:
                self.pool.release(worker)

    def _handle_stream(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        body: bytes,
        session_id: str | None,
    ) -> None:
        """Forward GET/SSE and DELETE without taking the serial call slot.

        The official MCP Streamable HTTP client opens ``GET /mcp`` after
        ``notifications/initialized`` and keeps it open for server-initiated
        messages.  Holding the sole worker reservation across that connection
        made the next ``tools/list`` wait until the supervisor's acquire
        timeout and return 503.  GET/DELETE are transport/session operations,
        not tool calls; forwarding them directly preserves protocol
        compatibility.  A POST that overlaps a live GET is marked
        ``concurrent_call_overlap`` so its process evidence is not treated as
        fully attributable.
        """
        worker: MCPWorker | None = None
        stream_open = False
        try:
            worker = self.pool.worker_for_session(session_id)
            upstream_headers = self._upstream_headers(handler, worker, body)
            if handler.command == "GET":
                worker.open_stream()
                stream_open = True
            self._forward(handler, worker, upstream_headers, body)
            if handler.command == "DELETE" and session_id:
                self.finalize_session(session_id)
        except (OSError, ValueError, RuntimeError) as exc:
            self._error_response(handler, 502, str(exc))
        finally:
            if stream_open and worker is not None:
                worker.close_stream()

    def _forward(
        self,
        handler: BaseHTTPRequestHandler,
        worker: MCPWorker,
        headers: Mapping[str, str],
        body: bytes,
    ) -> tuple[int, str, str | None]:
        conn = http.client.HTTPConnection(worker.host, worker.port, timeout=600)
        try:
            conn.request(handler.command, self._request_target(handler), body=body, headers=dict(headers))
            response = conn.getresponse()
            status = int(response.status)
            response_headers = response.getheaders()
            response_session = response.getheader("Mcp-Session-Id") or response.getheader(
                "X-MCP-Session-Id"
            )
            content_length = response.getheader("Content-Length")
            send_chunked = content_length is None and handler.command != "HEAD"
            handler.send_response_only(status, response.reason)
            for key, value in response_headers:
                lower = key.lower()
                if lower in _HOP_BY_HOP or lower == "content-length":
                    continue
                handler.send_header(key, value)
            if content_length is not None:
                handler.send_header("Content-Length", content_length)
            elif send_chunked:
                handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("Connection", "close")
            handler.end_headers()
            digest = hashlib.sha256()
            sent = 0
            while True:
                # read1() returns as soon as some decoded bytes are available.
                # read(n) may wait until n bytes or EOF and would buffer the
                # long-lived MCP GET /mcp SSE stream instead of forwarding it.
                chunk = response.read1(65536)
                if not chunk:
                    break
                digest.update(chunk)
                if handler.command == "HEAD":
                    continue
                if send_chunked:
                    handler.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                else:
                    handler.wfile.write(chunk)
                handler.wfile.flush()
                sent += len(chunk)
            if send_chunked:
                handler.wfile.write(b"0\r\n\r\n")
                handler.wfile.flush()
            return status, "sha256:" + digest.hexdigest(), response_session
        finally:
            conn.close()

    def _error_response(self, handler: BaseHTTPRequestHandler, status: int, detail: str) -> None:
        try:
            body = json.dumps({"error": detail, "supervisor": "mareforma-pro"}).encode("utf-8")
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.send_header("Connection", "close")
            handler.end_headers()
            if handler.command != "HEAD":
                handler.wfile.write(body)
                handler.wfile.flush()
        except OSError:
            pass

    def stop(self) -> None:
        if self._stop_event.is_set() and self._httpd is None and not self.workers:
            return
        self._stop_event.set()
        httpd, thread = self._httpd, self._http_thread
        self._httpd = None
        self._http_thread = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=3)
        # Finalize sessions before stopping workers so their in-memory calls
        # are not lost. The journal is append-only and remains readable after
        # the supervisor exits.
        with self._session_lock:
            session_ids = list(self._sessions)
        for session_id in session_ids:
            self.finalize_session(session_id)
        self.pool.shutdown()
        self.workers = ()
        self.pool = WorkerPool(())

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop_event.wait(1.0):
                pass
        finally:
            self.stop()
