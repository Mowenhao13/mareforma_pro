"""Streaming strace consumption for long-running MCP processes.

``RootlessBwrapRunner`` parses a completed trace file. The supervisor cannot
wait for process exit: it needs events while a call is active. This module
wraps the same :class:`StraceParser` in a FIFO reader thread and provides a
call-window accumulator plus a quiet drain barrier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Iterable, Mapping

from .evidence import (
    OPAQUE_DB_UNINSPECTED,
    OPAQUE_EGRESS_PROXY_BYPASSED,
    OPAQUE_EGRESS_UNINSPECTED,
    OPAQUE_HTTPS_PATH_OPAQUE,
    OPAQUE_TRACE_INCOMPLETE,
    OPAQUE_UNMAPPED_TMPFS,
    normalize_path,
)
from .paths import MountResolver
from .strace import StraceEvent, StraceParser, is_temp_path

_DB_PORTS = frozenset({1433, 1521, 3306, 5432, 6379, 27017})
_SYSTEM_PREFIXES = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev")
_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".duckdb", ".db-wal", ".db-shm", ".db-journal")


def _is_system_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _SYSTEM_PREFIXES)


def _is_db_path(path: str) -> bool:
    return path.endswith(_DB_SUFFIXES)


@dataclass
class CallEvidence:
    """Mutable evidence bucket for one serialized MCP call."""

    observed_files: set[str] = field(default_factory=set)
    internal_temp_files: set[str] = field(default_factory=set)
    observed_urls: set[str] = field(default_factory=set)
    observed_egress_urls: set[str] = field(default_factory=set)
    observed_db_queries: list[dict[str, Any]] = field(default_factory=list)
    opened_readable: set[str] = field(default_factory=set)
    opened_only: set[str] = field(default_factory=set)
    unmapped_paths: set[str] = field(default_factory=set)
    opaque_reasons: set[str] = field(default_factory=set)
    payload_digests: set[str] = field(default_factory=set)
    socket_events: set[str] = field(default_factory=list)
    connect_endpoints: set[str] = field(default_factory=set)
    processes: list[dict[str, Any]] = field(default_factory=list)
    written_files: set[str] = field(default_factory=set)
    _db_rows: set[str] = field(default_factory=set, init=False, repr=False)

    def add_application_event(self, event: Mapping[str, Any]) -> None:
        """Merge an optional Python-autohook event."""
        kind = str(event.get("kind") or "")
        if kind in {"db", "db_query"}:
            row = {
                "engine": str(event.get("engine") or "unknown"),
                "database": str(event.get("database") or ""),
                "operation": str(event.get("operation") or "query"),
                "query": event.get("query"),
                "query_digest": event.get("query_digest"),
                "source": "python_autohook",
            }
            row = {key: value for key, value in row.items() if value not in (None, "")}
            key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
            if key not in self._db_rows:
                self._db_rows.add(key)
                self.observed_db_queries.append(row)
            return
        if kind in {"http", "http_url"}:
            url = event.get("url")
            if url:
                self.observed_egress_urls.add(normalize_path(str(url)))
            path_opaque = bool(event.get("path_opaque"))
            if path_opaque:
                self.opaque_reasons.add(OPAQUE_HTTPS_PATH_OPAQUE)
            return
        if kind == "opaque":
            reason = event.get("reason")
            if reason:
                self.opaque_reasons.add(str(reason))

    def add_connect_endpoint(self, endpoint: str) -> None:
        self.connect_endpoints.add(endpoint)
        self.socket_events.append(f"connect:{endpoint}")

    def add_url(self, url: str, *, path_opaque: bool = False) -> None:
        self.observed_egress_urls.add(normalize_path(url))
        if path_opaque:
            self.opaque_reasons.add(OPAQUE_HTTPS_PATH_OPAQUE)

    def add_strace_event(self, event: StraceEvent) -> None:
        if event.kind in {"exec", "clone"}:
            if event.kind == "exec":
                self.processes.append(
                    {"pid": event.pid, "syscall": event.syscall, "binary": event.path or "<unknown>"}
                )
            return
        if event.kind == "connect":
            if event.endpoint:
                self.add_connect_endpoint(event.endpoint)
            return
        path = event.resolved_path or event.path
        if event.kind in {"open", "open_write"}:
            if not path:
                return
            if event.is_dir or _is_system_path(path):
                return
            if event.kind == "open_write":
                self.written_files.add(path)
                return
            self.opened_readable.add(path)
            return
        if event.kind == "write":
            if path and not _is_system_path(path):
                self.written_files.add(path)
            return
        if event.kind != "read" or not path or event.bytes <= 0:
            return
        if _is_system_path(path):
            return
        db_path = path if _is_db_path(path) else None
        if db_path is not None:
            self.observed_files.add(path)
            row = {
                "engine": "embedded",
                "database": path,
                "operation": "read",
                "evidence": "openat+read",
                "source": "strace",
            }
            key = repr(sorted(row.items(), key=lambda pair: str(pair[0])))
            if key not in self._db_rows:
                self._db_rows.add(key)
                self.observed_db_queries.append(row)
        elif is_temp_path(path):
            if path in self.written_files:
                self.internal_temp_files.add(path)
            else:
                self.unmapped_paths.add(path)
                self.opaque_reasons.add(OPAQUE_UNMAPPED_TMPFS)
        else:
            self.observed_files.add(path)
        self.opened_readable.discard(path)

    def finalize(
        self,
        *,
        egress_proxy_enabled: bool = False,
        egress_proxy_endpoints: Iterable[str] = (),
        db_hook_enabled: bool = False,
    ) -> dict[str, Any]:
        """Return keyword arguments for :func:`build_call_receipt`."""
        self.opened_only = set(self.opened_readable)
        self.opened_only.difference_update(self.observed_files)
        self.opened_only.difference_update(self.internal_temp_files)
        proxy_endpoints = set(egress_proxy_endpoints)
        for endpoint in self.connect_endpoints:
            if not endpoint.startswith("tcp:"):
                continue
            try:
                host, port_text = endpoint[4:].rsplit(":", 1)
                port = int(port_text)
            except (ValueError, IndexError):
                continue
            db_target = f"{host}:{port}"
            if port in _DB_PORTS:
                covered = any(
                    db_target in str(row.get("database", "")) or row.get("target") == db_target
                    for row in self.observed_db_queries
                )
                if not covered:
                    self.opaque_reasons.add(OPAQUE_DB_UNINSPECTED)
            if host in {"127.0.0.1", "::1", "localhost"} or port == 53:
                continue
            if endpoint in proxy_endpoints:
                continue
            if egress_proxy_enabled:
                self.opaque_reasons.add(OPAQUE_EGRESS_PROXY_BYPASSED)
            else:
                self.opaque_reasons.add(OPAQUE_EGRESS_UNINSPECTED)
        if self.opened_only:
            # The caller decides whether an open-only path is relevant to the
            # cited finding. Keep the same diagnostic vocabulary as 0.2.0.
            self.opaque_reasons.add("open_only")
        return {
            "observed_files": tuple(sorted(self.observed_files)),
            "internal_temp_files": tuple(sorted(self.internal_temp_files)),
            "observed_urls": tuple(sorted(self.observed_urls)),
            "observed_egress_urls": tuple(sorted(self.observed_egress_urls)),
            "observed_db_queries": tuple(self.observed_db_queries),
            "opened_only": tuple(sorted(self.opened_only)),
            "unmapped_paths": tuple(sorted(self.unmapped_paths)),
            "opaque_reasons": tuple(sorted(self.opaque_reasons)),
            "payload_digests": tuple(sorted(self.payload_digests)),
            "socket_events": tuple(sorted(set(self.socket_events))),
            "processes": tuple(self.processes),
        }


class StraceStream:
    """Read a FIFO fed by ``strace -f -y -o FIFO`` and parse it live."""

    def __init__(
        self,
        fifo_path: str | Path,
        resolver: MountResolver,
        *,
        track_temp_semantics: bool = True,
        event_sink: Callable[[StraceEvent], None] | None = None,
    ) -> None:
        self.fifo_path = Path(fifo_path)
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_event_at = time.monotonic()
        self._event_count = 0
        self._error: BaseException | None = None
        self._external_sink = event_sink
        self.parser = StraceParser(
            resolver,
            track_temp_semantics=track_temp_semantics,
            event_sink=self._handle_event,
        )

    def _handle_event(self, event: StraceEvent) -> None:
        self._on_event(event)
        if self._external_sink is not None:
            self._external_sink(event)

    def _on_event(self, _event: StraceEvent) -> None:
        with self._condition:
            self._last_event_at = time.monotonic()
            self._event_count += 1
            self._condition.notify_all()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="mareforma-strace-fifo", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            with self.fifo_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    self.parser.feed_line(line)
                    if self._stop.is_set():
                        break
        except BaseException as exc:  # noqa: BLE001 - surfaced through stop/status
            self._error = exc
        finally:
            with self._condition:
                self._condition.notify_all()

    def wait_drained(self, *, quiet_seconds: float = 0.05, timeout: float = 2.0) -> bool:
        """Wait until no new trace event has arrived for a quiet interval.

        The worker is serialized, so the next request cannot start until this
        method returns. A timeout is not silently ignored: the caller adds
        ``trace_incomplete`` to the call receipt.
        """
        deadline = time.monotonic() + max(0.0, float(timeout))
        quiet = max(0.0, float(quiet_seconds))
        with self._condition:
            while True:
                now = time.monotonic()
                if now - self._last_event_at >= quiet:
                    return True
                if now >= deadline:
                    return False
                self._condition.wait(timeout=min(quiet, deadline - now))

    @property
    def error(self) -> BaseException | None:
        return self._error

    def stop(self) -> None:
        self._stop.set()
        # A FIFO reader blocks in open() until a writer appears. Open and close
        # a non-blocking writer solely to unblock shutdown when strace failed
        # before starting.
        try:
            fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=3)
