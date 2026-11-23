"""Deterministic parsing of ``strace --seccomp-bpf -f -y`` output.

The parser tracks successful read-open and read syscalls separately. An open is
not silently promoted to a read: if the fd is never observed being read, its
resolved path lands in ``opened_only`` and the verdict layer can fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import posixpath
import re
from typing import Callable, Iterable, Mapping

from .evidence import (
    OPAQUE_OPEN_ONLY,
    OPAQUE_TRACE_INCOMPLETE,
    OPAQUE_UNMAPPED_SANDBOX,
    OPAQUE_UNMAPPED_TMPFS,
)
from .paths import MountResolver

# Read syscalls are included deliberately. The plan's fast path can still use
# only open*; this parser also understands read* when a caller enables it.
TRACE_SYSCALLS = (
    "open",
    "openat",
    "openat2",
    "read",
    "pread64",
    "readv",
    "preadv",
    "preadv2",
    "execve",
    "execveat",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "connect",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "sendmmsg",
    "recvmmsg",
)
TRACE_EXPR = ",".join(TRACE_SYSCALLS)

# The long-running supervisor enables a wider trace than the short-task
# runner. In particular, writes are needed to tell a request-created temp file
# from a pre-existing temp file that arrived from outside the request.
SUPERVISOR_TRACE_SYSCALLS = TRACE_SYSCALLS + (
    "write",
    "pwrite64",
    "writev",
    "pwritev",
    "pwritev2",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "memfd_create",
    "mmap",
)
SUPERVISOR_TRACE_EXPR = ",".join(SUPERVISOR_TRACE_SYSCALLS)

OPEN_CALLS = frozenset({"open", "openat", "openat2"})
READ_CALLS = frozenset({"read", "pread64", "readv", "preadv", "preadv2"})
EXEC_CALLS = frozenset({"execve", "execveat"})
CLONE_CALLS = frozenset({"clone", "clone3", "fork", "vfork"})
SOCKET_CALLS = frozenset(
    {"connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
)
WRITE_CALLS = frozenset({"write", "pwrite64", "writev", "pwritev", "pwritev2"})
MMAP_CALLS = frozenset({"mmap"})

_LINE = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+(?:(\d+(?:\.\d+)?)\s+)?(.*)$")
_UNFINISHED = re.compile(r"^([A-Za-z0-9_]+)\((.*)<unfinished \.\.\.>$")
_RESUMED = re.compile(r"^<\.\.\.\s+([A-Za-z0-9_]+)\s+resumed>(.*)$")
_CALL = re.compile(r"^([A-Za-z0-9_]+)\((.*)\)\s*=\s*(-?\d+.*)$")
_QUOTED = re.compile(r'"((?:\\.|[^"\\])*)"')
_FD_PATH = re.compile(r"^(\d+)<([^>]*)>(?:\s*)$")
_READ_FD = re.compile(r"^\s*(\d+)<([^>]*)>")
_READ_FD_PLAIN = re.compile(r"^\s*(\d+)\s*,")
_FLAG_WRITE = re.compile(r"\bO_WRONLY\b")
_FLAG_RDWR = re.compile(r"\bO_RDWR\b")
_FLAG_DIR = re.compile(r"\bO_DIRECTORY\b")
_FLAG_PATH = re.compile(r"\bO_PATH\b")
_INET4 = re.compile(
    r"sin_port=htons\((?P<port>\d+)\).*?sin_addr=inet_addr\(\"(?P<addr>[^\"]+)\"\)"
)
_INET6 = re.compile(
    r"sin6_port=htons\((?P<port>\d+)\).*?sin6_addr=inet_pton\(AF_INET6,\s*\"(?P<addr>[^\"]+)\"\)"
)
_UNIX_SOCK = re.compile(r"sun_path=\"(?P<path>[^\"]+)\"")

TEMP_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "/run/user")


def _decode_quoted(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except json.JSONDecodeError:
        return value


def _last_quoted(args: str) -> tuple[str | None, int]:
    last = None
    end = -1
    for match in _QUOTED.finditer(args):
        last = match
        end = match.end()
    if last is None:
        return None, -1
    return _decode_quoted(last.group(1)), end


def _connect_endpoint(args: str) -> str | None:
    """Best-effort stable endpoint identity from a connect(2) argument."""
    match = _INET6.search(args)
    if match is not None:
        return f"tcp:[{match.group('addr')}]:{match.group('port')}"
    match = _INET4.search(args)
    if match is not None:
        return f"tcp:{match.group('addr')}:{match.group('port')}"
    match = _UNIX_SOCK.search(args)
    if match is not None:
        return f"unix:{match.group('path')}"
    return None


def _is_temp_path(path: str | None) -> bool:
    if not path or not path.startswith("/"):
        return False
    norm = posixpath.normpath(path)
    return any(norm == prefix or norm.startswith(prefix + "/") for prefix in TEMP_PREFIXES)


def is_temp_path(path: str | None) -> bool:
    return _is_temp_path(path)


def _is_write_open(flags: str) -> bool:
    return bool(
        _FLAG_WRITE.search(flags)
        or _FLAG_RDWR.search(flags)
        or re.search(r"\bO_TRUNC\b|\bO_APPEND\b|\bO_CREAT\b", flags)
    )


@dataclass(frozen=True)
class StraceEvent:
    """One deterministic event delivered to the long-running supervisor.

    The legacy parser aggregates events into :class:`ParsedStrace`. The stream
    path also needs the ordered event stream so a call can be sealed without
    guessing from a process-wide aggregate.
    """

    syscall: str
    pid: int
    kind: str
    path: str | None = None
    resolved_path: str | None = None
    fd: int | None = None
    bytes: int = 0
    endpoint: str | None = None
    success: bool = True
    is_dir: bool = False
    # Wall-clock completion time when the trace used ``strace -ttt``. The
    # worker observer uses it to attribute a late FIFO line to the task that
    # was active when the syscall completed, not to the task being processed
    # when the line happened to arrive.
    timestamp: float | None = None


def _first_quoted(args: str) -> str | None:
    match = _QUOTED.search(args)
    return _decode_quoted(match.group(1)) if match is not None else None


def _fd_from_result(result: str) -> tuple[int | None, str | None]:
    match = _FD_PATH.match(result.strip())
    if match is None:
        # ``-y`` may be unavailable or may omit a path for an anonymous fd.
        plain = re.match(r"^(\d+)\s*$", result.strip())
        return (int(plain.group(1)), None) if plain else (None, None)
    return int(match.group(1)), match.group(2) or None


def _fd_from_read(args: str) -> tuple[int | None, str | None]:
    match = _READ_FD.match(args)
    if match is not None:
        return int(match.group(1)), match.group(2) or None
    match = _READ_FD_PLAIN.match(args)
    if match is not None:
        return int(match.group(1)), None
    return None, None


@dataclass
class ParsedStrace:
    observed_files: set[str] = field(default_factory=set)
    observed_dirs: set[str] = field(default_factory=set)
    opened_readable: set[str] = field(default_factory=set)
    opened_only: set[str] = field(default_factory=set)
    unmapped_paths: set[str] = field(default_factory=set)
    opaque_reasons: set[str] = field(default_factory=set)
    processes: list[dict[str, object]] = field(default_factory=list)
    socket_events: list[str] = field(default_factory=list)
    connect_events: list[str] = field(default_factory=list)
    internal_temp_files: set[str] = field(default_factory=set)
    written_files: set[str] = field(default_factory=set)
    observed_db_queries: list[dict[str, object]] = field(default_factory=list)
    events: list[StraceEvent] = field(default_factory=list)
    pids: set[int] = field(default_factory=set)
    read_bytes: int = 0
    opened_readable_events: int = 0
    stitched_lines: int = 0
    skipped_writes: int = 0


@dataclass
class _OpenRecord:
    namespace_path: str
    resolved_path: str | None
    is_dir: bool
    unmapped_reason: str | None
    readable: bool = False
    writable: bool = False


class StraceParser:
    """Stateful parser for one interleaved ``strace -f`` log."""

    def __init__(
        self,
        resolver: MountResolver,
        *,
        track_temp_semantics: bool = False,
        event_sink: Callable[[StraceEvent], None] | None = None,
    ) -> None:
        self.resolver = resolver
        self.track_temp_semantics = track_temp_semantics
        self.event_sink = event_sink
        self.result = ParsedStrace()
        # pending unfinished call prefix keyed by pid
        self._pending: dict[str, tuple[str, str, float | None]] = {}
        # fd -> open metadata keyed by (pid, fd)
        self._fd: dict[tuple[int, int], _OpenRecord] = {}
        self._current_timestamp: float | None = None

    def _emit(self, event: StraceEvent) -> None:
        if event.timestamp is None and self._current_timestamp is not None:
            event = replace(event, timestamp=self._current_timestamp)
        self.result.events.append(event)
        if self.event_sink is None:
            return
        try:
            self.event_sink(event)
        except Exception:
            # A streaming consumer must never tear down the target trace. The
            # receipt will disclose an incomplete trace instead.
            self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)

    def feed(self, lines: Iterable[str]) -> ParsedStrace:
        for raw in lines:
            self.feed_line(raw)
        self.finish()
        return self.result

    def feed_line(self, raw_line: str) -> None:
        line = raw_line.rstrip("\r\n")
        if not line or line.startswith("+++ exited with"):
            return
        line_match = _LINE.match(line)
        if line_match is None:
            return
        pid_text = line_match.group(1) or line_match.group(2)
        assert pid_text is not None
        pid = int(pid_text)
        self.result.pids.add(pid)
        timestamp_text = line_match.group(3)
        try:
            self._current_timestamp = (
                float(timestamp_text) if timestamp_text else None
            )
        except ValueError:
            self._current_timestamp = None
        body = line_match.group(4).strip()

        unfinished = _UNFINISHED.match(body)
        if unfinished is not None:
            self._pending[pid_text] = (
                unfinished.group(1),
                f"{unfinished.group(1)}({unfinished.group(2)}",
                self._current_timestamp,
            )
            return

        resumed = _RESUMED.match(body)
        if resumed is not None:
            syscall, suffix = resumed.group(1), resumed.group(2)
            pending = self._pending.pop(pid_text, None)
            if pending is None or pending[0] != syscall:
                self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
                return
            # Prefer the resumed line's completion time. If the producer did not
            # timestamp the resumed fragment, fall back to the entry timestamp
            # rather than losing task attribution entirely.
            if self._current_timestamp is None:
                self._current_timestamp = pending[2]
            body = pending[1] + suffix
            self.result.stitched_lines += 1

        call = _CALL.match(body)
        if call is None:
            return
        syscall, args, result = call.group(1), call.group(2), call.group(3).strip()

        if syscall in EXEC_CALLS:
            if result.startswith("0"):
                binary = _first_quoted(args)
                self.result.processes.append(
                    {
                        "pid": pid,
                        "syscall": syscall,
                        "binary": binary or "<unknown>",
                    }
                )
                self._emit(
                    StraceEvent(
                        syscall=syscall,
                        pid=pid,
                        kind="exec",
                        path=binary,
                        resolved_path=binary,
                    )
                )
            return

        if syscall in CLONE_CALLS:
            if result.startswith("0"):
                # In strace -f the parent sees a positive child pid; the child
                # sees 0, which does not identify a new pid.
                return
            try:
                child = int(result.split()[0])
            except (ValueError, IndexError):
                return
            if child > 0:
                self.result.processes.append(
                    {"pid": child, "parent_pid": pid, "syscall": syscall}
                )
                self._emit(
                    StraceEvent(
                        syscall=syscall,
                        pid=pid,
                        kind="clone",
                        bytes=child,
                    )
                )
            return

        if syscall in SOCKET_CALLS:
            if result != "-1":
                self.result.socket_events.append(syscall)
                endpoint = _connect_endpoint(args) if syscall == "connect" else None
                if endpoint is not None:
                    self.result.connect_events.append(endpoint)
                    self._emit(
                        StraceEvent(
                            syscall=syscall,
                            pid=pid,
                            kind="connect",
                            endpoint=endpoint,
                        )
                    )
            return

        if syscall in OPEN_CALLS:
            self._handle_open(pid, args, result)
            return

        if syscall in READ_CALLS:
            self._handle_read(pid, args, result)
            return

        if syscall in WRITE_CALLS:
            self._handle_write(pid, args, result)
            return

        if syscall in MMAP_CALLS:
            # A readable mmap is a genuine data path that ordinary read(2)
            # tracing cannot validate. Preserve the fact instead of reporting a
            # clean absence later.
            if result != "-1" and "PROT_READ" in args:
                self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
            return

    def _handle_open(self, pid: int, args: str, result: str) -> None:
        fd, annotated_path = _fd_from_result(result)
        if fd is None:
            return
        path, quote_end = _last_quoted(args)
        if path is None:
            return
        flags_segment = args[quote_end:] if quote_end >= 0 else args
        if _FLAG_PATH.search(flags_segment):
            return
        writable = _is_write_open(flags_segment)
        readable = not (_FLAG_WRITE.search(flags_segment) and not _FLAG_RDWR.search(flags_segment))
        if writable and not readable:
            self.result.skipped_writes += 1

        is_dir = bool(_FLAG_DIR.search(flags_segment))
        # Prefer the path argument.  ``-y`` can print an fd path that includes a
        # process-relative cwd; the open argument is the namespace path the
        # mount resolver knows how to translate.
        namespace_path = annotated_path if annotated_path and annotated_path.startswith("/") else path
        resolution = self.resolver.resolve(namespace_path)
        record = _OpenRecord(
            namespace_path=namespace_path,
            resolved_path=resolution.resolved,
            is_dir=is_dir,
            unmapped_reason=resolution.opaque_reason,
            readable=readable,
            writable=writable,
        )
        self._fd[(pid, fd)] = record
        if writable and resolution.resolved is not None:
            self.result.written_files.add(resolution.resolved)
        self._emit(
            StraceEvent(
                syscall="openat",
                pid=pid,
                kind="open_write" if writable and not readable else "open",
                path=namespace_path,
                resolved_path=resolution.resolved,
                fd=fd,
                success=resolution.resolved is not None,
                is_dir=is_dir,
            )
        )
        if not readable:
            return
        self.result.opened_readable_events += 1

        if resolution.ignored:
            return
        if resolution.opaque_reason is not None:
            if resolution.opaque_reason in (OPAQUE_UNMAPPED_TMPFS, OPAQUE_UNMAPPED_SANDBOX):
                self.result.unmapped_paths.add(namespace_path)
                self.result.opaque_reasons.add(resolution.opaque_reason)
            return
        if resolution.resolved is None:
            return
        if is_dir:
            self.result.observed_dirs.add(resolution.resolved)
            # A directory can be read with getdents, but that does not prove a
            # cited data file's bytes flowed. Keep it out of read/open-only.
            return
        self.result.opened_readable.add(resolution.resolved)

    def _handle_read(self, pid: int, args: str, result: str) -> None:
        fd, annotated_path = _fd_from_read(args)
        if fd is None:
            return
        try:
            count = int(result.split()[0])
        except (ValueError, IndexError):
            return
        if count <= 0:
            return
        record = self._fd.get((pid, fd))
        path = annotated_path
        if path and not path.startswith("/"):
            # A read on a socket/pipe/anon fd is not a file read, but it is a
            # real seam: bytes can enter from outside the trace. Record the
            # non-file channel so a missing cited read fails closed instead of
            # looking like an honest absence.
            kind = path.split(":", 1)[0]
            if kind in {"socket", "pipe"}:
                self.result.socket_events.append(f"read:{kind}")
            return
        resolution = self.resolver.resolve(path) if path else None
        if record is not None:
            if record.resolved_path is None or record.is_dir:
                return
            resolved = record.resolved_path
        elif resolution is not None:
            resolved = resolution.resolved
        else:
            self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
            return
        if resolved is None:
            if resolution is not None and resolution.opaque_reason is not None:
                if not (
                    self.track_temp_semantics
                    and _is_temp_path(path)
                    and path in self.result.written_files
                ):
                    self.result.unmapped_paths.add(path or "<unknown>")
                    self.result.opaque_reasons.add(resolution.opaque_reason)
            return
        temp = _is_temp_path(resolved)
        if temp and self.track_temp_semantics:
            if resolved in self.result.written_files:
                self.result.internal_temp_files.add(resolved)
            else:
                self.result.unmapped_paths.add(resolved)
                self.result.opaque_reasons.add(OPAQUE_UNMAPPED_TMPFS)
        self.result.observed_files.add(resolved)
        self.result.read_bytes += count
        self._emit(
            StraceEvent(
                syscall="read",
                pid=pid,
                kind="read",
                path=path,
                resolved_path=resolved,
                fd=fd,
                bytes=count,
            )
        )
        if temp and self.track_temp_semantics and resolved in self.result.written_files:
            self.result.internal_temp_files.add(resolved)
        if resolved.endswith((".db", ".sqlite", ".sqlite3", ".duckdb")):
            self.result.observed_db_queries.append(
                {
                    "engine": "embedded",
                    "database": resolved,
                    "operation": "read",
                    "query": None,
                    "evidence": "openat+read",
                }
            )
        # A file that was opened readable and then read is no longer open-only.
        self.result.opened_readable.discard(resolved)

    def _handle_write(self, pid: int, args: str, result: str) -> None:
        fd, annotated_path = _fd_from_read(args)
        if fd is None:
            return
        try:
            count = int(result.split()[0])
        except (ValueError, IndexError):
            return
        if count <= 0:
            return
        record = self._fd.get((pid, fd))
        path = record.namespace_path if record is not None else annotated_path
        resolved = record.resolved_path if record is not None else None
        if resolved is None and path:
            resolution = self.resolver.resolve(path)
            resolved = resolution.resolved
        if resolved is None:
            return
        self.result.written_files.add(resolved)
        self._emit(
            StraceEvent(
                syscall="write",
                pid=pid,
                kind="write",
                path=path,
                resolved_path=resolved,
                fd=fd,
                bytes=count,
            )
        )

    def finish(self) -> None:
        for syscall, _prefix, _timestamp in self._pending.values():
            if syscall in OPEN_CALLS or syscall in READ_CALLS or syscall in WRITE_CALLS:
                self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
        self.result.opened_only = set(self.result.opened_readable)
        if self.result.opened_only:
            # Keep a named diagnostic even when the caller does not cite the
            # path; verdict_from_evidence decides whether it is relevant.
            self.result.opaque_reasons.add(OPAQUE_OPEN_ONLY)
        # Stable ordering makes receipts reproducible for the same trace.
        self.result.processes = sorted(
            self.result.processes,
            key=lambda item: (int(item.get("pid", 0)), str(item.get("syscall", ""))),
        )
        self.result.socket_events = sorted(set(self.result.socket_events))


def parse_strace(
    lines: Iterable[str],
    resolver: MountResolver,
    *,
    track_temp_semantics: bool = False,
    event_sink: Callable[[StraceEvent], None] | None = None,
) -> ParsedStrace:
    return StraceParser(
        resolver,
        track_temp_semantics=track_temp_semantics,
        event_sink=event_sink,
    ).feed(lines)
