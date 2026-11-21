"""Deterministic parsing of ``strace --seccomp-bpf -f -y`` output.

The parser tracks successful read-open and read syscalls separately. An open is
not silently promoted to a read: if the fd is never observed being read, its
resolved path lands in ``opened_only`` and the verdict layer can fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Iterable

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

OPEN_CALLS = frozenset({"open", "openat", "openat2"})
READ_CALLS = frozenset({"read", "pread64", "readv", "preadv", "preadv2"})
EXEC_CALLS = frozenset({"execve", "execveat"})
CLONE_CALLS = frozenset({"clone", "clone3", "fork", "vfork"})
SOCKET_CALLS = frozenset(
    {"connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
)

_LINE = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+(.*)$")
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


class StraceParser:
    """Stateful parser for one interleaved ``strace -f`` log."""

    def __init__(self, resolver: MountResolver) -> None:
        self.resolver = resolver
        self.result = ParsedStrace()
        # pending unfinished call prefix keyed by pid
        self._pending: dict[str, tuple[str, str]] = {}
        # fd -> open metadata keyed by (pid, fd)
        self._fd: dict[tuple[int, int], _OpenRecord] = {}

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
        body = line_match.group(3).strip()

        unfinished = _UNFINISHED.match(body)
        if unfinished is not None:
            self._pending[pid_text] = (unfinished.group(1), f"{unfinished.group(1)}({unfinished.group(2)}")
            return

        resumed = _RESUMED.match(body)
        if resumed is not None:
            syscall, suffix = resumed.group(1), resumed.group(2)
            pending = self._pending.pop(pid_text, None)
            if pending is None or pending[0] != syscall:
                self.result.opaque_reasons.add(OPAQUE_TRACE_INCOMPLETE)
                return
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
            return

        if syscall in SOCKET_CALLS:
            if result != "-1":
                self.result.socket_events.append(syscall)
            return

        if syscall in OPEN_CALLS:
            self._handle_open(pid, args, result)
            return

        if syscall in READ_CALLS:
            self._handle_read(pid, args, result)

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
        if _FLAG_WRITE.search(flags_segment) and not _FLAG_RDWR.search(flags_segment):
            self.result.skipped_writes += 1
            return

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
        )
        self._fd[(pid, fd)] = record
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
                self.result.unmapped_paths.add(path or "<unknown>")
                self.result.opaque_reasons.add(resolution.opaque_reason)
            return
        self.result.observed_files.add(resolved)
        self.result.read_bytes += count
        # A file that was opened readable and then read is no longer open-only.
        self.result.opened_readable.discard(resolved)

    def finish(self) -> None:
        for syscall, _prefix in self._pending.values():
            if syscall in OPEN_CALLS or syscall in READ_CALLS:
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


def parse_strace(lines: Iterable[str], resolver: MountResolver) -> ParsedStrace:
    return StraceParser(resolver).feed(lines)
