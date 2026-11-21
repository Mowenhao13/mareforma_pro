"""Rootless command runners: ``strace`` + ``bwrap`` and FUSE + ``bwrap``.

The default route uses no cgroup, eBPF, setuid helper, or privileged daemon.
Every strace run gets a private trace file and a generated scope id, so
concurrent executions cannot share a parser stream. The optional FUSE route
uses the user-facing ``fusermount3`` helper only to ask the kernel for an
unprivileged mount; it needs no sudo and no ptrace permission.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Mapping, Sequence

from .collector import RootlessCollector
from .errors import RootlessRunError, RootlessUnavailableError
from .evidence import OPAQUE_TRACE_INCOMPLETE, ScopeEvidence
from .fuse import FuseReadOnlyProxy
from .paths import MountResolver
from .strace import TRACE_EXPR


@dataclass(frozen=True)
class RunResult:
    process: subprocess.CompletedProcess[str]
    evidence: ScopeEvidence
    trace_path: Path


@dataclass(frozen=True)
class FuseRunResult:
    """A command run against a rootless FUSE read-only view."""

    process: subprocess.CompletedProcess[str]
    evidence: ScopeEvidence


class RootlessBwrapRunner:
    """Run a command in a non-setuid bwrap sandbox under strace."""

    def __init__(
        self,
        collector: RootlessCollector,
        *,
        strace_binary: str | None = None,
        bwrap_binary: str | None = None,
        log_dir: str | Path | None = None,
        seccomp_bpf: bool = True,
    ) -> None:
        self.collector = collector
        self.strace_binary = strace_binary or shutil.which("strace")
        self.bwrap_binary = bwrap_binary or shutil.which("bwrap")
        self.log_dir = Path(log_dir) if log_dir is not None else None
        self.seccomp_bpf = seccomp_bpf

    def _require_strace(self) -> str:
        if not self.strace_binary:
            raise RootlessUnavailableError("strace is required for the rootless collector")
        return self.strace_binary

    def _require_bwrap(self) -> str:
        if not self.bwrap_binary:
            raise RootlessUnavailableError("bwrap is required for the rootless runner")
        return self.bwrap_binary

    def _require_tools(self) -> tuple[str, str]:
        return self._require_strace(), self._require_bwrap()

    def _private_log(self, scope_id: str) -> tuple[Path, Path | None]:
        created: Path | None = None
        if self.log_dir is None:
            created = Path(tempfile.mkdtemp(prefix="mf_rootless_"))
            created.chmod(0o700)
            directory = created
        else:
            directory = self.log_dir
            directory.mkdir(parents=True, exist_ok=True)
        safe_scope = "".join(
            char if char.isalnum() or char in "_-" else "_"
            for char in scope_id
        )
        path = directory / f"mf_trace_{safe_scope}.log"
        # Pre-create mode 0600. strace -o truncates the existing file without
        # widening its mode; a target sharing the UID still has less room to
        # replace it before the collector reads it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)
        return path, created

    def build_bwrap_command(
        self,
        command: Sequence[str],
        *,
        ro_binds: Mapping[str, str] | None = None,
        rw_binds: Mapping[str, str] | None = None,
        tmpfs_mounts: Sequence[str] = ("/tmp",),
        ro_bind_root: bool = True,
        unshare_pid: bool = True,
        clearenv: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> tuple[list[str], dict[str, str], MountResolver]:
        if not command:
            raise ValueError("command must not be empty")
        bwrap = self._require_bwrap()
        mount_map: dict[str, str] = {}
        argv: list[str] = [bwrap]
        if ro_bind_root:
            argv.extend(["--ro-bind", "/", "/"])
        argv.extend(["--dev", "/dev", "--proc", "/proc"])
        for path in tmpfs_mounts:
            if not str(path).startswith("/"):
                raise ValueError("tmpfs mount paths must be absolute")
            argv.extend(["--tmpfs", str(path)])
        for host, sandbox in (ro_binds or {}).items():
            argv.extend(["--ro-bind", str(host), str(sandbox)])
            mount_map[str(sandbox)] = os.path.abspath(str(host))
        for host, sandbox in (rw_binds or {}).items():
            argv.extend(["--bind", str(host), str(sandbox)])
            mount_map[str(sandbox)] = os.path.abspath(str(host))
        if unshare_pid:
            argv.append("--unshare-pid")
        if clearenv:
            argv.append("--clearenv")
        for key, value in (env or {}).items():
            if clearenv:
                argv.extend(["--setenv", str(key), str(value)])
        argv.append("--")
        argv.extend(str(part) for part in command)
        resolver = MountResolver.from_mounts(
            mount_map,
            tmpfs_mounts=tmpfs_mounts,
            root_passthrough=ro_bind_root,
        )
        return argv, mount_map, resolver

    def run_in_bwrap(
        self,
        command: Sequence[str],
        *,
        scope_id: str | None = None,
        ro_binds: Mapping[str, str] | None = None,
        rw_binds: Mapping[str, str] | None = None,
        tmpfs_mounts: Sequence[str] = ("/tmp",),
        ro_bind_root: bool = True,
        unshare_pid: bool = True,
        clearenv: bool = True,
        env: Mapping[str, str] | None = None,
        timeout_sec: float = 60.0,
        keep_log: bool = False,
        traceparent: str | None = None,
        parent_scope_id: str | None = None,
    ) -> RunResult:
        strace = self._require_strace()
        self._require_bwrap()
        scope_id = scope_id or _new_scope_id()
        trace_path, private_dir = self._private_log(scope_id)
        bwrap_argv, _, resolver = self.build_bwrap_command(
            command,
            ro_binds=ro_binds,
            rw_binds=rw_binds,
            tmpfs_mounts=tmpfs_mounts,
            ro_bind_root=ro_bind_root,
            unshare_pid=unshare_pid,
            clearenv=clearenv,
            env=env,
        )
        trace_args = [strace]
        if self.seccomp_bpf:
            trace_args.append("--seccomp-bpf")
        trace_args.extend(
            [
                "-f",
                "-y",
                "-qq",
                "-e",
                f"trace={TRACE_EXPR}",
                "-o",
                str(trace_path),
                "--",
                *bwrap_argv,
            ]
        )
        self.collector.open_scope(
            scope_id,
            resolver,
            traceparent=traceparent,
            parent_scope_id=parent_scope_id,
        )
        error: BaseException | None = None
        proc: subprocess.CompletedProcess[str] | None = None
        try:
            try:
                proc = subprocess.run(
                    trace_args,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                    check=False,
                )
            except BaseException as exc:  # noqa: BLE001 - close and sign below
                error = exc
            self.collector.ingest_strace_path(scope_id, trace_path)
            evidence = self.collector.close_scope(scope_id)
        finally:
            if not keep_log and trace_path.exists():
                try:
                    trace_path.unlink()
                except OSError:
                    pass
            if private_dir is not None:
                try:
                    private_dir.rmdir()
                except OSError:
                    pass
        if error is not None:
            raise RootlessRunError(
                f"rootless command failed before completion: {error}",
                evidence=evidence,
            ) from error
        assert proc is not None
        return RunResult(process=proc, evidence=evidence, trace_path=trace_path)


class RootlessFuseRunner:
    """Run a command under bwrap against a FUSE read-only data view.

    This route needs no ``strace`` and no ptrace permission.  The FUSE server
    is the observer: a command that reads a file through the view produces a
    ``READ_BYTES`` record for the corresponding host path.  Data outside the
    supplied source root is not visible through the view and cannot make a
    cited read ``GROUNDED``.
    """

    def __init__(
        self,
        collector: RootlessCollector,
        *,
        bwrap_binary: str | None = None,
        fusermount_binary: str | None = None,
        mount_parent: str | Path | None = None,
        mount_timeout: float = 10.0,
    ) -> None:
        self.collector = collector
        self.bwrap_binary = bwrap_binary or shutil.which("bwrap")
        self.fusermount_binary = fusermount_binary or shutil.which("fusermount3") or shutil.which("fusermount")
        self.mount_parent = Path(mount_parent) if mount_parent is not None else None
        self.mount_timeout = float(mount_timeout)

    def _require_tools(self) -> tuple[str, str]:
        if not self.bwrap_binary:
            raise RootlessUnavailableError("bwrap is required for the rootless FUSE runner")
        if not self.fusermount_binary:
            raise RootlessUnavailableError("fusermount3 is required for the rootless FUSE runner")
        return self.bwrap_binary, self.fusermount_binary

    def run_in_bwrap(
        self,
        command: Sequence[str],
        *,
        source_root: str | Path,
        sandbox_path: str = "/tmp/mareforma-data",
        hide_source_root: bool = True,
        scope_id: str | None = None,
        tmpfs_mounts: Sequence[str] = ("/tmp",),
        ro_bind_root: bool = True,
        unshare_pid: bool = True,
        clearenv: bool = True,
        env: Mapping[str, str] | None = None,
        timeout_sec: float = 60.0,
        traceparent: str | None = None,
        parent_scope_id: str | None = None,
    ) -> FuseRunResult:
        if not command:
            raise ValueError("command must not be empty")
        if not str(sandbox_path).startswith("/"):
            raise ValueError("sandbox_path must be absolute")
        if hide_source_root and os.path.realpath(source_root) == os.sep:
            raise ValueError("hide_source_root cannot hide the host root; use a narrower source_root")
        bwrap, fusermount = self._require_tools()
        scope_id = scope_id or _new_scope_id()
        bwrap_runner = RootlessBwrapRunner(
            self.collector,
            bwrap_binary=bwrap,
        )
        proxy = FuseReadOnlyProxy(
            self.collector,
            scope_id,
            source_root,
            mount_parent=self.mount_parent,
            fusermount_binary=fusermount,
            mount_timeout=self.mount_timeout,
        )
        self.collector.open_scope(
            scope_id,
            MountResolver.from_mounts({}),
            traceparent=traceparent,
            parent_scope_id=parent_scope_id,
            evidence_level="USER_FUSE",
            read_semantics="READ_BYTES",
            collector_mode="fuse_read_proxy",
            coverage_roots=(str(proxy.source_root),),
        )
        error: BaseException | None = None
        proc: subprocess.CompletedProcess[str] | None = None
        evidence: ScopeEvidence | None = None
        try:
            try:
                proxy.start()
                bwrap_argv, _, _ = bwrap_runner.build_bwrap_command(
                    command,
                    ro_binds={str(proxy.mountpoint): sandbox_path},
                    tmpfs_mounts=_with_hidden_root(
                        tmpfs_mounts,
                        str(proxy.source_root) if hide_source_root else None,
                    ),
                    ro_bind_root=ro_bind_root,
                    unshare_pid=unshare_pid,
                    clearenv=clearenv,
                    env=env,
                )
                proc = subprocess.run(
                    bwrap_argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                    check=False,
                )
            except BaseException as exc:  # noqa: BLE001 - always sign what was observed
                error = exc
        finally:
            proxy.stop()
            if proxy.errors or proxy.premature_exit or error is not None:
                try:
                    self.collector.ingest_events(
                        scope_id,
                        opaque_reasons=(OPAQUE_TRACE_INCOMPLETE,),
                    )
                except BaseException:
                    pass
            evidence = self.collector.close_scope(scope_id)
        if error is not None:
            raise RootlessRunError(
                f"rootless FUSE command failed before completion: {error}",
                evidence=evidence,
            ) from error
        assert proc is not None and evidence is not None
        return FuseRunResult(process=proc, evidence=evidence)


def _new_scope_id() -> str:
    from uuid import uuid4

    return "scp_" + uuid4().hex[:16]


def _with_hidden_root(tmpfs_mounts: Sequence[str], source_root: str | None) -> tuple[str, ...]:
    """Add a tmpfs over the host source path so the FUSE copy is the only view.

    The FUSE backend can only certify reads through its mount. If bwrap's
    root bind still exposed the original host directory, a command could read
    that path directly and the receipt would have no event for it. Shadowing
    the source makes the documented sandbox path the only route to the data.
    """
    mounts = list(dict.fromkeys(str(path) for path in tmpfs_mounts))
    if source_root is None:
        return tuple(mounts)
    for existing in mounts:
        if source_root == existing or source_root.startswith(existing.rstrip("/") + "/"):
            return tuple(mounts)
    mounts.append(source_root)
    return tuple(mounts)
