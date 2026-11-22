"""Rootless Jupyter cell hook using Python's audit events.

This is application evidence: it sees Python-level opens and selected audit
boundaries, not the bytes a C extension or the kernel reads. The hook now marks
native extension loads, ctypes calls, process/thread creation, and socket
connections as blind spots rather than pretending it is eBPF.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
import sys
from typing import Any, Iterable

from .collector import RootlessCollector
from .errors import ScopeError
from .evidence import (
    OPAQUE_SOCKET_UNBOUND,
    OPAQUE_STATIC_BINARY_UNTRACED,
    OPAQUE_TRACE_INCOMPLETE,
    SOURCE_REQUIRED,
)
from .observe import verdict_from_evidence


@dataclass(frozen=True)
class JupyterCellResult:
    scope_id: str
    evidence: Any
    verdict: Any

    @property
    def receipt(self) -> dict[str, Any]:
        return self.evidence.receipt


_ACTIVE: ContextVar[tuple[RootlessCollector, str] | None] = ContextVar(
    "mareforma_pro_jupyter_scope", default=None
)
_HOOK_INSTALLED = False


# Native code and child processes can read bytes without emitting a Python
# ``open`` event. ``import`` carries the resolved extension-module path on
# CPython; ``ctypes`` events cover explicit shared-library loads even when no
# Python module import is involved. These stay named as a static-binary blind
# spot instead of being promoted to evidence.
_PROCESS_BOUNDARY_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
    }
)
_THREAD_BOUNDARY_EVENTS = frozenset(
    {
        "_thread.start_new_thread",
        "_thread.start_joinable_thread",
    }
)
_SOCKET_BOUNDARY_EVENTS = frozenset({"socket.connect"})
_NATIVE_LOAD_EVENTS = frozenset(
    {
        "ctypes.dlopen",
        "ctypes.dlsym",
        "ctypes.dlsym/handle",
    }
)
_NATIVE_SUFFIXES = (".so", ".pyd", ".dylib", ".dll")


def _native_import(args: tuple[Any, ...]) -> bool:
    """Whether an ``import`` audit event loaded a native extension module."""
    filename = args[1] if len(args) > 1 else None
    if not isinstance(filename, str):
        return False
    return filename.casefold().endswith(_NATIVE_SUFFIXES)


def _mark_boundary(
    collector: RootlessCollector,
    scope_id: str,
    reason: str,
) -> None:
    collector.ingest_events(scope_id, opaque_reasons=[reason])


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    active = _ACTIVE.get()
    if active is None:
        return
    collector, scope_id = active
    try:
        if event == "open":
            path = args[0] if args else None
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            if not isinstance(path, (str, bytes, os.PathLike)):
                return
            read = False
            if isinstance(mode, str):
                read = "r" in mode or "+" in mode
            elif isinstance(flags, int):
                if flags & getattr(os, "O_PATH", 0):
                    read = False
                else:
                    read = (flags & os.O_ACCMODE) != os.O_WRONLY
            if not read:
                return
            target = os.path.realpath(os.fspath(path))
            # The audit event fires before the open completes and carries no
            # result. Only a readable regular file can be treated as an
            # application read-open; a missing path or directory stays
            # ``opened_only`` and the verdict fails closed.
            readable = os.path.isfile(target) and os.access(target, os.R_OK)
            collector.ingest_events(
                scope_id,
                observed_files=[target] if readable else (),
                opened_only=[] if readable else [target],
            )
            return
        if event in _PROCESS_BOUNDARY_EVENTS:
            _mark_boundary(collector, scope_id, OPAQUE_STATIC_BINARY_UNTRACED)
            return
        if event in _THREAD_BOUNDARY_EVENTS:
            _mark_boundary(collector, scope_id, OPAQUE_TRACE_INCOMPLETE)
            return
        if event in _SOCKET_BOUNDARY_EVENTS:
            _mark_boundary(collector, scope_id, OPAQUE_SOCKET_UNBOUND)
            return
        if event in _NATIVE_LOAD_EVENTS or (event == "import" and _native_import(args)):
            _mark_boundary(collector, scope_id, OPAQUE_STATIC_BINARY_UNTRACED)
    except (OSError, ScopeError, ValueError):
        return
    except BaseException:
        # A PEP-578 hook that raises would break the observed call. If our own
        # bookkeeping fails, retain an honest blind spot instead of letting the
        # exception escape or silently treating the scope as complete.
        try:
            _mark_boundary(collector, scope_id, OPAQUE_TRACE_INCOMPLETE)
        except BaseException:
            pass


def install_audit_hook() -> None:
    """Install the process-wide audit hook once."""
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_audit_hook)
        _HOOK_INSTALLED = True


@contextmanager
def audit_scope(collector: RootlessCollector, scope_id: str):
    install_audit_hook()
    token = _ACTIVE.set((collector, scope_id))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


class JupyterScopeHook:
    """Bind one collector scope to each IPython cell.

    ``ipython`` only needs the tiny event surface used by IPython:
    ``events.register(name, callback)`` and ``events.unregister(name, callback)``.
    The hook deliberately does not require IPython as a runtime dependency.
    """

    def __init__(
        self,
        ipython: Any,
        collector: RootlessCollector,
        *,
        cites: str | Iterable[str] | None = None,
        mount_map: dict[str, str] | None = None,
        tmpfs_mounts: tuple[str, ...] = (),
        root_passthrough: bool = True,
        source_requirement: str = SOURCE_REQUIRED,
    ) -> None:
        self.ipython = ipython
        self.collector = collector
        self.cites = cites
        self.mount_map = mount_map or {}
        self.tmpfs_mounts = tmpfs_mounts
        self.root_passthrough = root_passthrough
        self.source_requirement = source_requirement
        self.last: JupyterCellResult | None = None
        self._scope_id: str | None = None
        self._context: Any = None
        self._pre_callback = self.pre_run_cell
        self._post_callback = self.post_run_cell

    def install(self) -> "JupyterScopeHook":
        self.ipython.events.register("pre_run_cell", self._pre_callback)
        self.ipython.events.register("post_run_cell", self._post_callback)
        return self

    def uninstall(self) -> None:
        self.ipython.events.unregister("pre_run_cell", self._pre_callback)
        self.ipython.events.unregister("post_run_cell", self._post_callback)

    def pre_run_cell(self, info: Any = None) -> None:
        from uuid import uuid4

        if self._scope_id is not None:
            # A nested cell is not a safe attribution edge; finish the previous
            # scope before starting another one.
            self.post_run_cell(None)
        scope_id = "cell_" + uuid4().hex[:16]
        self.collector.open_scope(
            scope_id,
            mount_map=self.mount_map,
            tmpfs_mounts=self.tmpfs_mounts,
            root_passthrough=self.root_passthrough,
            evidence_level="APPLICATION_PYTHON_AUDIT",
            read_semantics="OPEN_INTENT",
            source_requirement=self.source_requirement,
        )
        self._scope_id = scope_id
        self._context = audit_scope(self.collector, scope_id)
        self._context.__enter__()

    def post_run_cell(self, result: Any = None) -> None:
        scope_id = self._scope_id
        if scope_id is None:
            return
        context = self._context
        self._scope_id = None
        self._context = None
        if context is not None:
            context.__exit__(None, None, None)
        error = getattr(result, "error_in_exec", None) if result is not None else None
        if error is not None:
            self.collector.ingest_events(scope_id, opaque_reasons=["trace_incomplete"])
        try:
            evidence = self.collector.close_scope(scope_id)
            verified = self.collector.verify(evidence)
            verdict = verdict_from_evidence(verified, cites=self.cites)
            self.last = JupyterCellResult(scope_id=scope_id, evidence=verified, verdict=verdict)
        except Exception:
            # A failed close is still a failed observation; leave ``last`` unset
            # rather than manufacturing a successful cell verdict.
            self.last = None

    @property
    def current_scope_id(self) -> str | None:
        """The scope id a tool can use with ``record_url_read`` in this cell."""
        return self._scope_id
