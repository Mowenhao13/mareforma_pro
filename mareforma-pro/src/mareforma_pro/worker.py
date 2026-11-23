"""Long-running, task-scoped observer for rootless worker processes.

This module is the worker counterpart of :mod:`mareforma_pro.supervisor`. The
supervisor observes one HTTP MCP gateway; a worker is a separate, long-running
process that executes tasks sequentially. The worker is started as a child of
``strace``, and a tiny ``sitecustomize`` hook reports application events tagged
with ``BIOMNI_TASK_ID``. The parent process is the only component that holds
the HMAC secret and signs receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

from .collector import RootlessCollector
from .evidence import (
    OPAQUE_HTTP_BODY_UNOBSERVED,
    OPAQUE_HTTPS_PATH_OPAQUE,
    OPAQUE_TRACE_INCOMPLETE,
    SOURCE_REQUIRED,
    normalize_path,
)
from .paths import MountResolver
from .stream import CallEvidence, StraceStream
from .strace import SUPERVISOR_TRACE_EXPR, StraceEvent
from .supervisor import JsonlReceiptJournal


@dataclass
class _TaskState:
    task_id: str
    execution_id: str | None = None
    attempt: str | None = None
    traceparent: str | None = None
    parent_scope_id: str | None = None
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    evidence: CallEvidence = field(default_factory=CallEvidence)
    observed_urls: set[str] = field(default_factory=set)
    observed_egress_urls: set[str] = field(default_factory=set)
    observed_db_queries: list[dict[str, Any]] = field(default_factory=list)
    payload_digests: set[str] = field(default_factory=set)
    opaque_reasons: set[str] = field(default_factory=set)
    http_requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    extra_read_bytes: int = 0
    has_evidence: bool = True
    _db_rows: set[str] = field(default_factory=set, init=False, repr=False)
    _observed_http_reads: set[str] = field(default_factory=set, init=False, repr=False)


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _event_task_id(event: Mapping[str, Any]) -> str | None:
    return _string(event.get("task_id"))


def _number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class WorkerProcessObserver:
    """Run one worker under ``strace`` and sign per-task receipts.

    The observer starts a new worker; it cannot attach to an already-running
    systemd unit. Replace the unit's ``ExecStart`` with
    ``mareforma-pro worker supervise ... -- <original worker command>``.

    Task boundaries are emitted by the worker-side ``sitecustomize`` hook when
    ``BIOMNI_TASK_ID`` changes. The worker remains source-unmodified when that
    variable is already managed by its runtime, as in the Biomni worker.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        secret: str | bytes,
        worker_id: str = "0",
        collector_id: str | None = None,
        use_strace: bool = True,
        strace_binary: str | None = None,
        drain_timeout: float = 2.0,
        receipt_ttl: float = 300.0,
        receipt_log: str | Path | None = None,
        trace_dir: str | Path | None = None,
        event_socket: str | Path | None = None,
        coverage_roots: Iterable[str] = (),
        source_requirement: str = SOURCE_REQUIRED,
        record_query_text: bool = True,
        record_http_query_text: bool = False,
    ) -> None:
        if not command:
            raise ValueError("command must not be empty")
        if not secret:
            raise ValueError("secret must not be empty")
        if not worker_id:
            raise ValueError("worker_id must not be empty")
        self.command = tuple(str(item) for item in command)
        self.secret = secret
        self.worker_id = str(worker_id)
        self.collector_id = collector_id or f"worker-{self.worker_id}"
        self.use_strace = bool(use_strace)
        self.strace_binary = strace_binary
        self.drain_timeout = float(drain_timeout)
        self.receipt_ttl = float(receipt_ttl)
        self.receipt_log = Path(receipt_log).expanduser() if receipt_log else None
        self.journal = JsonlReceiptJournal(self.receipt_log) if self.receipt_log else None
        self._owns_trace_dir = trace_dir is None
        self._trace_dir = Path(trace_dir).expanduser() if trace_dir else Path(
            tempfile.mkdtemp(prefix="mf_worker_supervisor_")
        )
        self._trace_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._trace_dir.chmod(0o700)
        except OSError:
            pass
        self._fifo = self._trace_dir / "worker.fifo"
        self._event_socket_path = (
            Path(event_socket).expanduser()
            if event_socket
            else self._trace_dir / "worker-events.sock"
        )
        self._coverage_roots = tuple(str(item) for item in coverage_roots if str(item))
        self.source_requirement = str(source_requirement)
        self.record_query_text = bool(record_query_text)
        self.record_http_query_text = bool(record_http_query_text)

        self.proc: subprocess.Popen[Any] | None = None
        self.stream: StraceStream | None = None
        self._event_socket: socket.socket | None = None
        self._event_thread: threading.Thread | None = None
        self._event_lock = threading.Lock()
        self._event_condition = threading.Condition(self._event_lock)
        self._active: _TaskState | None = None
        self._closing: _TaskState | None = None
        self._pending_strace: list[StraceEvent] = []
        self._pending_strace_overflow = False
        self._stopping = threading.Event()
        self._last_aux_event_at = time.monotonic()
        self._receipt_count = 0

    @property
    def trace_dir(self) -> Path:
        return self._trace_dir

    @property
    def event_socket_path(self) -> Path:
        return self._event_socket_path

    @property
    def receipt_count(self) -> int:
        return self._receipt_count

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        for name in (
            "MAREFORMA_HMAC_SECRET",
            "MAREFORMA_PRO_SECRET",
            "MAREFORMA_SECRET",
            "MAREFORMA_AUTOHOOK_OWNER_PID",
        ):
            env.pop(name, None)
        autohook = Path(__file__).with_name("autohook")
        old = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(autohook) + (os.pathsep + old if old else "")
        env["MAREFORMA_AUTOHOOK_SOCKET"] = str(self._event_socket_path)
        env["MAREFORMA_AUTOHOOK_WORKER"] = self.worker_id
        env["MAREFORMA_AUTOHOOK_AUDIT"] = "1"
        env["MAREFORMA_DB_QUERY_TEXT"] = "1" if self.record_query_text else "0"
        env["MAREFORMA_HTTP_QUERY_TEXT"] = "1" if self.record_http_query_text else "0"
        env["PYTHONUNBUFFERED"] = "1"
        return env

    def _event_socket_start(self) -> None:
        if self._event_socket is not None:
            return
        path = self._event_socket_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(str(path))
            try:
                path.chmod(0o600)
            except OSError:
                pass
            sock.settimeout(0.5)
            self._event_socket = sock
            self._event_thread = threading.Thread(
                target=self._event_loop,
                name=f"mareforma-worker-events-{self.worker_id}",
                daemon=True,
            )
            self._event_thread.start()
        except OSError as exc:
            raise RuntimeError(f"cannot create worker event socket: {exc}") from exc

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
                self._on_event(event)

    def _on_event(self, event: Mapping[str, Any]) -> None:
        with self._event_condition:
            self._last_aux_event_at = time.monotonic()
            self._event_condition.notify_all()
        kind = str(event.get("kind") or "")
        task_id = _event_task_id(event)
        role = _string(event.get("process_role"))
        main_process = role in (None, "main")
        if kind == "task_start":
            if task_id and main_process:
                self._start_task(event)
            return
        if kind == "task_end":
            if task_id and main_process:
                with self._event_lock:
                    active = self._active
                if active is not None and active.task_id == task_id:
                    self._close_active(ended_at=_number(event.get("ts")))
            return
        if kind == "task_context":
            if task_id and main_process:
                with self._event_lock:
                    active = self._active
                if active is not None and active.task_id == task_id:
                    self._merge_task_context(active, event)
            return
        if not task_id:
            return
        with self._event_lock:
            state = self._active
        # A task_start event owns the scope boundary. An ordinary event must
        # never mint a task of its own; that is how a child process or a late
        # post-task write would become a phantom receipt.
        if state is None or state.task_id != task_id:
            return
        self._merge_event(state, event)

    def _task_identity(self, event: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
        return (
            _event_task_id(event),
            _string(event.get("execution_id")),
            _string(event.get("attempt")),
        )

    def _same_task(self, state: _TaskState, event: Mapping[str, Any]) -> bool:
        task_id, execution_id, attempt = self._task_identity(event)
        if state.task_id != task_id:
            return False
        if execution_id is not None and state.execution_id is not None:
            if state.execution_id != execution_id:
                return False
        if attempt is not None and state.attempt is not None:
            if state.attempt != attempt:
                return False
        return True

    def _merge_task_context(self, state: _TaskState, event: Mapping[str, Any]) -> None:
        execution_id = _string(event.get("execution_id"))
        attempt = _string(event.get("attempt"))
        traceparent = _string(event.get("traceparent"))
        parent_scope_id = _string(
            event.get("parent_scope_id") or event.get("mareforma_parent_scope_id")
        )
        if execution_id:
            state.execution_id = execution_id
        if attempt:
            state.attempt = attempt
        if traceparent:
            state.traceparent = traceparent
        if parent_scope_id:
            state.parent_scope_id = parent_scope_id

    def _start_task(self, event: Mapping[str, Any]) -> _TaskState | None:
        task_id = _event_task_id(event)
        if not task_id:
            return None
        with self._event_lock:
            active = self._active
        if active is not None and self._same_task(active, event):
            self._merge_task_context(active, event)
            return active
        if active is not None:
            self._close_active(ended_at=_number(event.get("ts")))
        started_at = _number(event.get("ts")) or time.time()
        state = _TaskState(
            task_id=task_id,
            execution_id=_string(event.get("execution_id")),
            attempt=_string(event.get("attempt")),
            traceparent=_string(event.get("traceparent")),
            parent_scope_id=_string(
                event.get("parent_scope_id") or event.get("mareforma_parent_scope_id")
            ),
            started_at=started_at,
        )
        pid = event.get("pid")
        if isinstance(pid, int):
            process = {
                "pid": pid,
                "ppid": event.get("ppid"),
                "syscall": "task_start",
                "kind": "worker_process",
                "role": "main",
            }
            state.evidence.processes.append(
                {key: value for key, value in process.items() if value is not None}
            )
        with self._event_lock:
            self._active = state
            buffered = self._pending_strace
            self._pending_strace = []
            overflow = self._pending_strace_overflow
            self._pending_strace_overflow = False
            for buffered_event in buffered:
                if (
                    buffered_event.timestamp is None
                    or buffered_event.timestamp >= state.started_at
                ):
                    state.evidence.add_strace_event(buffered_event)
            if overflow:
                state.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
        return state

    def _http_row(self, event: Mapping[str, Any], key: str) -> dict[str, Any] | None:
        url = _string(event.get("url"))
        if not url:
            return None
        url = normalize_path(url)
        final_url = _string(event.get("final_url"))
        if final_url:
            final_url = normalize_path(final_url)
        body_observed = bool(event.get("body_observed") or event.get("observed"))
        pending = bool(event.get("pending"))
        try:
            body_bytes = int(event.get("body_bytes") or 0)
        except (TypeError, ValueError):
            body_bytes = 0
        try:
            status = int(event["status"]) if event.get("status") is not None else None
        except (TypeError, ValueError):
            status = None
        row: dict[str, Any] = {
            "request_id": key,
            "url": url,
            "method": _string(event.get("method")),
            "status": status,
            "final_url": final_url if final_url and final_url != url else None,
            "body_bytes": body_bytes,
            "body_digest": _string(event.get("body_digest")),
            "body_observed": body_observed,
            "pending": pending,
            "partial": bool(event.get("partial")),
            "query": _string(event.get("query")),
            "query_digest": _string(event.get("query_digest")),
            "query_keys": tuple(str(item) for item in event.get("query_keys") or ()),
            "error": _string(event.get("error")),
        }
        return {
            key: value
            for key, value in row.items()
            if value not in (None, "", (), [], False) or key == "body_observed"
        }

    def _refresh_http_opaque(self, state: _TaskState) -> None:
        if any(not row.get("body_observed") for row in state.http_requests.values()):
            state.opaque_reasons.add(OPAQUE_HTTP_BODY_UNOBSERVED)
        else:
            state.opaque_reasons.discard(OPAQUE_HTTP_BODY_UNOBSERVED)

    def _merge_event(self, state: _TaskState, event: Mapping[str, Any]) -> None:
        kind = str(event.get("kind") or "")
        if kind in {"http", "http_url"}:
            raw_url = _string(event.get("url"))
            if not raw_url:
                return
            url = normalize_path(raw_url)
            final_url = _string(event.get("final_url"))
            final_identity = normalize_path(final_url) if final_url else None
            state.observed_egress_urls.add(url)
            if final_identity:
                state.observed_egress_urls.add(final_identity)
            if event.get("path_opaque"):
                state.opaque_reasons.add(OPAQUE_HTTPS_PATH_OPAQUE)
            key = _string(event.get("request_id")) or (
                f"{url}|{event.get('method') or ''}|{event.get('status') or ''}"
            )
            previous = state.http_requests.get(key, {})
            row = self._http_row(event, key)
            if row is None:
                return
            body_observed = bool(row.get("body_observed"))
            was_observed = bool(previous.get("body_observed"))
            pending = bool(row.get("pending"))
            if body_observed:
                state.observed_urls.add(url)
                if final_identity:
                    state.observed_urls.add(final_identity)
                digest = _string(row.get("body_digest"))
                if digest:
                    state.payload_digests.add(digest)
                if key not in state._observed_http_reads:
                    state._observed_http_reads.add(key)
                    try:
                        state.extra_read_bytes += int(row.get("body_bytes") or 0)
                    except (TypeError, ValueError):
                        pass
                row.pop("pending", None)
                row.pop("error", None)
                state.http_requests[key] = row
                self._refresh_http_opaque(state)
            elif pending:
                if was_observed:
                    return
                state.http_requests[key] = row
            else:
                if was_observed:
                    return
                row.pop("pending", None)
                state.http_requests[key] = row
                self._refresh_http_opaque(state)
            state.has_evidence = True
            return
        if kind in {"db", "db_query"}:
            row = {
                "engine": str(event.get("engine") or "unknown"),
                "database": str(event.get("database") or ""),
                "operation": str(event.get("operation") or "query"),
                "query": event.get("query"),
                "query_digest": event.get("query_digest"),
                "source": str(event.get("db_source") or "python_autohook"),
            }
            row = {key: value for key, value in row.items() if value not in (None, "")}
            key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
            if key not in state._db_rows:
                state._db_rows.add(key)
                state.observed_db_queries.append(row)
            state.has_evidence = True
            return
        if kind == "audit":
            # Audit events are hints. With strace active, the syscall stream is
            # the authoritative byte-level path. Without strace, the scope is
            # already forced to trace_incomplete at close.
            state.has_evidence = True
            return
        if kind == "opaque":
            reason = _string(event.get("reason"))
            if reason:
                state.opaque_reasons.add(reason)
                state.has_evidence = True

    def _on_strace_event(self, event: StraceEvent) -> None:
        with self._event_lock:
            timestamp = event.timestamp
            active = self._active
            closing = self._closing
            if active is not None and (
                timestamp is None or timestamp >= active.started_at
            ):
                active.evidence.add_strace_event(event)
                active.has_evidence = True
                return
            if closing is not None and (
                timestamp is None
                or closing.ended_at is None
                or timestamp <= closing.ended_at
            ):
                closing.evidence.add_strace_event(event)
                closing.has_evidence = True
                return
            self._pending_strace.append(event)
            if len(self._pending_strace) > 20_000:
                del self._pending_strace[:10_000]
                self._pending_strace_overflow = True

    def _open_strace(self) -> None:
        if not self.use_strace:
            return
        try:
            if self._fifo.exists():
                self._fifo.unlink()
            os.mkfifo(self._fifo, 0o600)
        except OSError as exc:
            raise RuntimeError(f"cannot create worker strace FIFO: {exc}") from exc
        self.stream = StraceStream(
            self._fifo,
            MountResolver.from_mounts({}, root_passthrough=True),
            track_temp_semantics=True,
            event_sink=self._on_strace_event,
        )
        self.stream.start()

    def start(self) -> None:
        if self.proc is not None:
            return
        self._stopping.clear()
        self._event_socket_start()
        self._open_strace()
        command = list(self.command)
        if self.use_strace:
            strace = self.strace_binary or shutil.which("strace")
            if not strace:
                self._shutdown_resources()
                raise RuntimeError("strace is not installed")
            argv = [
                strace,
                "--seccomp-bpf",
                "-f",
                "-ttt",
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
            argv = command
        try:
            self.proc = subprocess.Popen(
                argv,
                env=self._env(),
                stdout=None,
                stderr=None,
                start_new_session=True,
            )
        except BaseException:
            self._shutdown_resources()
            raise

    def _close_active(self, *, ended_at: float | None = None) -> None:
        with self._event_lock:
            state = self._active
            self._active = None
            if state is not None:
                state.ended_at = ended_at
                self._closing = state
        if state is not None:
            self._close_task(state)

    def _final_http_rows(self, state: _TaskState) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for row in state.http_requests.values():
            cleaned = dict(row)
            if cleaned.get("pending") or not cleaned.get("body_observed"):
                if cleaned.get("pending"):
                    state.opaque_reasons.add(OPAQUE_HTTP_BODY_UNOBSERVED)
                    cleaned["error"] = cleaned.get("error") or "no_completion_event"
                cleaned["body_observed"] = False
                cleaned.pop("pending", None)
            else:
                cleaned.pop("pending", None)
                cleaned.pop("error", None)
            if cleaned.get("partial") is False:
                cleaned.pop("partial", None)
            # Preserve body_bytes=0 on a fully observed empty response. It is
            # materially different from "no body observation at all".
            if cleaned.get("body_observed") and "body_bytes" not in cleaned:
                cleaned["body_bytes"] = 0
            rows.append(cleaned)
        if any(not row.get("body_observed") for row in rows):
            state.opaque_reasons.add(OPAQUE_HTTP_BODY_UNOBSERVED)
        else:
            state.opaque_reasons.discard(OPAQUE_HTTP_BODY_UNOBSERVED)
        rows.sort(
            key=lambda row: (
                str(row.get("url") or ""),
                str(row.get("method") or ""),
                int(row.get("status") or 0),
                str(row.get("request_id") or ""),
            )
        )
        return rows

    def _close_task(self, state: _TaskState) -> None:
        if self.stream is not None:
            drained = self.stream.wait_drained(timeout=self.drain_timeout)
        else:
            drained = not self.use_strace
        if self.stream is not None and (not drained or self.stream.error is not None):
            state.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
        if not self.use_strace:
            state.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
        observed_http = self._final_http_rows(state)
        with self._event_lock:
            values = state.evidence.finalize(
                egress_proxy_enabled=False,
                db_hook_enabled=True,
                skip_network_reconciliation=True,
            )
            if self._closing is state:
                self._closing = None
        # The worker hook is the authority for URL/DB events. Keep the file
        # fields from the strace evidence and add the application manifest.
        observed_db = list(values.get("observed_db_queries", ()))
        known_db = {
            repr(sorted(dict(row).items(), key=lambda pair: str(pair[0])))
            for row in observed_db
        }
        for row in state.observed_db_queries:
            key = repr(sorted(dict(row).items(), key=lambda pair: str(pair[0])))
            if key not in known_db:
                known_db.add(key)
                observed_db.append(row)
        opaque_reasons = set(values.get("opaque_reasons", ())) | state.opaque_reasons
        payload_digests = set(values.get("payload_digests", ())) | state.payload_digests
        read_bytes = int(state.evidence.read_bytes) + state.extra_read_bytes
        scope_id = f"wrk:{state.task_id}"
        if state.execution_id:
            scope_id += f":{state.execution_id}"
        if state.attempt:
            scope_id += f":{state.attempt}"
        collector = RootlessCollector(
            self.secret,
            collector_id=self.collector_id,
            receipt_ttl=self.receipt_ttl,
        )
        collector.open_scope(
            scope_id,
            root_passthrough=True,
            traceparent=state.traceparent,
            parent_scope_id=state.parent_scope_id,
            evidence_level="APPLICATION_PYTHON_AUDIT",
            read_semantics="READ_BYTES",
            collector_mode=(
                "worker_process_supervisor" if self.use_strace else "worker_python_audit"
            ),
            coverage_roots=self._coverage_roots,
            source_requirement=self.source_requirement,
            task_id=state.task_id,
            worker_id=self.worker_id,
            attempt=state.attempt,
            execution_id=state.execution_id,
            opened_at=state.started_at,
        )
        collector.ingest_events(
            scope_id,
            observed_files=values.get("observed_files", ()),
            observed_dirs=values.get("observed_dirs", ()),
            internal_temp_files=values.get("internal_temp_files", ()),
            observed_urls=state.observed_urls,
            observed_egress_urls=state.observed_egress_urls,
            unmapped_paths=values.get("unmapped_paths", ()),
            opened_only=values.get("opened_only", ()),
            observed_db_queries=observed_db,
            observed_http=observed_http,
            payload_digests=payload_digests,
            opaque_reasons=opaque_reasons,
            socket_events=state.evidence.socket_events,
            processes=state.evidence.processes,
            read_bytes=read_bytes,
        )
        receipt = collector.close_scope(scope_id)
        verified = collector.verify(receipt)
        if self.journal is not None:
            self.journal.append(
                "worker_task",
                {
                    "task_id": state.task_id,
                    "worker_id": self.worker_id,
                    "execution_id": state.execution_id,
                    "attempt": state.attempt,
                    "receipt": verified.receipt,
                },
            )
        self._receipt_count += 1

    def _shutdown_resources(self) -> None:
        self._stopping.set()
        if self.stream is not None:
            self.stream.stop()
            self.stream = None
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

    def _stop_process(self) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass

    def stop(self) -> None:
        self._stopping.set()
        # Stop the producer first so the final syscalls are in the FIFO before
        # an interrupted task is sealed. If the worker already exited, this is
        # a no-op and any active task state still receives its final receipt.
        self._stop_process()
        self._close_active()
        self._shutdown_resources()
        if self._owns_trace_dir:
            try:
                shutil.rmtree(self._trace_dir)
            except OSError:
                pass

    def run_forever(self) -> int:
        self.start()
        previous = None
        returncode = 0
        try:
            previous = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGTERM, lambda _signum, _frame: self._stopping.set())
        except (ValueError, OSError):
            previous = None
        try:
            while not self._stopping.wait(0.5):
                proc = self.proc
                if proc is not None and proc.poll() is not None:
                    returncode = int(proc.returncode or 0)
                    break
        finally:
            self.stop()
            if previous is not None:
                try:
                    signal.signal(signal.SIGTERM, previous)
                except (ValueError, OSError):
                    pass
        return returncode
