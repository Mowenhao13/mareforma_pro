"""A small local Unix-socket control plane for the rootless collector."""

from __future__ import annotations

from pathlib import Path
import hmac
import json
import os
import socket
import socketserver
import struct
import threading
from typing import Any, Mapping

from .collector import RootlessCollector
from .errors import ScopeError


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int] | None:
    """Return Linux ``SO_PEERCRED`` as ``(pid, uid, gid)`` when available.

    Unix-domain sockets are local, but another local user may still connect to
    a world-writable path. The collector socket is created ``0600``; this check
    makes the same-UID boundary explicit rather than relying on filesystem
    permissions alone.
    """
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, option, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", raw)
    except OSError:
        return None
    return pid, uid, gid


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        peer_rejection = getattr(self.server, "peer_rejection", None)
        if peer_rejection is not None:
            rejection = peer_rejection(self.connection)
            if rejection is not None:
                self._send({"ok": False, "error": rejection})
                return
        raw = self.rfile.readline(1_048_577)
        if not raw or len(raw) > 1_048_576:
            self._send({"ok": False, "error": "request_too_large_or_empty"})
            return
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send({"ok": False, "error": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send({"ok": False, "error": "request_must_be_an_object"})
            return
        self._send(self.server.dispatch(request))  # type: ignore[attr-defined]

    def _send(self, payload: Mapping[str, Any]) -> None:
        self.wfile.write(
            (json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        )
        self.wfile.flush()


class _ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class CollectorServer:
    """Serve ``open_scope``/``ingest_strace``/``ingest_events``/``close_scope``.

    The wire protocol is one JSON object per line over a Unix domain socket.
    This is intentionally smaller than a general HTTP server, but preserves the
    four operations and keeps the collector local to the user.
    """

    def __init__(
        self,
        socket_path: str | Path,
        collector: RootlessCollector,
        *,
        auth_token: str | None = None,
        require_same_uid: bool = True,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.collector = collector
        self.auth_token = auth_token
        self.require_same_uid = require_same_uid
        self._lock = threading.Lock()
        self._server: _ThreadedUnixServer | None = None
        self._thread: threading.Thread | None = None

    def _authenticated(self, request: Mapping[str, Any]) -> bool:
        if self.auth_token is None:
            return True
        supplied = request.get("token")
        return isinstance(supplied, str) and hmac.compare_digest(supplied, self.auth_token)

    def _peer_rejection(self, connection: socket.socket) -> str | None:
        if not self.require_same_uid:
            return None
        credentials = _peer_credentials(connection)
        if credentials is None:
            return "peer_uid_unavailable"
        _pid, uid, _gid = credentials
        if uid != os.getuid():
            return "peer_uid_mismatch"
        return None

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if not self._authenticated(request):
            return {"ok": False, "error": "unauthorized"}
        op = request.get("op")
        try:
            with self._lock:
                if op == "open_scope":
                    scope_id = str(request.get("scope_id", ""))
                    self.collector.open_scope(
                        scope_id,
                        mount_map=request.get("mount_map") or {},
                        tmpfs_mounts=request.get("tmpfs_mounts") or (),
                        root_passthrough=bool(request.get("root_passthrough", False)),
                        traceparent=request.get("traceparent"),
                        parent_scope_id=request.get("parent_scope_id"),
                        evidence_level=str(request.get("evidence_level", "USER_TRACE")),
                        read_semantics=str(request.get("read_semantics", "READ_INTENT")),
                        collector_mode=request.get("collector_mode"),
                        coverage_roots=request.get("coverage_roots") or (),
                    )
                    return {"ok": True, "scope_id": scope_id}
                if op == "ingest_strace":
                    scope_id = str(request.get("scope_id", ""))
                    path = request.get("path")
                    if isinstance(path, str):
                        parsed = self.collector.ingest_strace_path(scope_id, path)
                    else:
                        parsed = self.collector.ingest_strace_lines(
                            scope_id, request.get("lines") or ()
                        )
                    return {
                        "ok": True,
                        "observed_files": sorted(parsed.observed_files),
                        "opaque_reasons": sorted(parsed.opaque_reasons),
                    }
                if op == "ingest_events":
                    scope_id = str(request.get("scope_id", ""))
                    self.collector.ingest_events(
                        scope_id,
                        observed_files=request.get("observed_files") or (),
                        observed_dirs=request.get("observed_dirs") or (),
                        opened_only=request.get("opened_only") or (),
                        payload_digests=request.get("payload_digests") or (),
                        opaque_reasons=request.get("opaque_reasons") or (),
                    )
                    return {"ok": True, "scope_id": scope_id}
                if op == "close_scope":
                    scope_id = str(request.get("scope_id", ""))
                    return {"ok": True, "receipt": self.collector.close_scope(scope_id).to_receipt_dict()}
                if op == "health":
                    return {
                        "ok": True,
                        "collector_id": self.collector.collector_id,
                        "open_scopes": self.collector.open_scope_count,
                    }
                return {"ok": False, "error": f"unknown operation: {op!r}"}
        except (AttributeError, ScopeError, TypeError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def serve_in_thread(self) -> None:
        if self._thread is not None:
            return
        if self.socket_path.exists():
            self.socket_path.unlink()
        previous_umask = os.umask(0o077)
        try:
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
            server = _ThreadedUnixServer(str(self.socket_path), _Handler)
        finally:
            os.umask(previous_umask)
        server.dispatch = self.dispatch  # type: ignore[attr-defined]
        server.peer_rejection = self._peer_rejection  # type: ignore[attr-defined]
        try:
            self.socket_path.chmod(0o600)
        except OSError:
            pass
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="mareforma-collector", daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def __enter__(self) -> "CollectorServer":
        self.serve_in_thread()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()


class CollectorClient:
    """Minimal client for tests and local SDK integrations."""

    def __init__(self, socket_path: str | Path, *, token: str | None = None, timeout: float = 5.0) -> None:
        self.socket_path = Path(socket_path)
        self.token = token
        self.timeout = timeout

    def request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        import socket

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
            data = dict(payload)
            if self.token is not None:
                data["token"] = self.token
            sock.sendall((json.dumps(data, sort_keys=True) + "\n").encode("utf-8"))
            file = sock.makefile("rb")
            try:
                line = file.readline()
            finally:
                file.close()
        if not line:
            raise RuntimeError("collector returned no response")
        result = json.loads(line.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("collector returned a non-object response")
        return result
