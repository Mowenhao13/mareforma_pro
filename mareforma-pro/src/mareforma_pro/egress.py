"""Small user-space forward proxy for observed MCP egress.

The proxy deliberately does not claim TLS path visibility. HTTPS requests are
reported at the ``CONNECT host:port`` authority level and carry
``https_path_opaque``; plain HTTP requests expose their full, query-stripped URL.
An optional TLS-terminating mode can be layered on later without changing the
receipt vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
import select
import socket
import socketserver
import ssl
import threading
from typing import Callable
from urllib.parse import urlsplit

from .evidence import normalize_path


@dataclass(frozen=True)
class EgressObservation:
    url: str
    method: str
    target: str
    path_opaque: bool = False
    https: bool = False
    status: int | None = None


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, *, observer: Callable[[EgressObservation], None]):
        self.observer = observer
        super().__init__(address, _ProxyHandler)


class _ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 30.0

    def _read_headers(self, *, limit: int = 65536) -> tuple[str, list[tuple[str, str]]] | None:
        line = self.rfile.readline(limit + 1)
        if not line:
            return None
        if len(line) > limit:
            return None
        try:
            request_line = line.decode("latin-1").rstrip("\r\n")
        except UnicodeDecodeError:
            return None
        headers: list[tuple[str, str]] = []
        total = len(line)
        while True:
            raw = self.rfile.readline(limit + 1)
            if not raw:
                break
            total += len(raw)
            if total > limit:
                return None
            if raw in (b"\r\n", b"\n"):
                break
            try:
                text = raw.decode("latin-1").rstrip("\r\n")
            except UnicodeDecodeError:
                return None
            if ":" in text:
                name, value = text.split(":", 1)
                headers.append((name.strip(), value.strip()))
        return request_line, headers

    @staticmethod
    def _header(headers: list[tuple[str, str]], name: str) -> str | None:
        wanted = name.lower()
        for key, value in headers:
            if key.lower() == wanted:
                return value
        return None

    def handle(self) -> None:
        parsed = self._read_headers()
        if parsed is None:
            return
        request_line, headers = parsed
        try:
            method, target, version = request_line.split(" ", 2)
        except ValueError:
            self._plain(400, b"bad proxy request\n")
            return
        if method.upper() == "CONNECT":
            self._handle_connect(target)
            return
        self._handle_http(method, target, version, headers)

    def _plain(self, status: int, body: bytes) -> None:
        reason = {400: "Bad Request", 502: "Bad Gateway"}.get(status, "Error")
        self.wfile.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n"
            "Content-Type: text/plain\r\nConnection: close\r\n\r\n".encode("ascii")
            + body
        )
        self.wfile.flush()

    def _handle_connect(self, authority: str) -> None:
        try:
            host, port_text = authority.rsplit(":", 1)
            port = int(port_text)
        except (ValueError, TypeError):
            self._plain(400, b"invalid CONNECT authority\n")
            return
        url = normalize_path(f"https://{host}:{port}/")
        self.server.observer(
            EgressObservation(
                url=url,
                method="CONNECT",
                target=authority,
                path_opaque=True,
                https=True,
            )
        )
        try:
            upstream = socket.create_connection((host, port), timeout=self.timeout)
        except OSError:
            self._plain(502, b"upstream unavailable\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        client = self.connection
        try:
            sockets = [client, upstream]
            while sockets:
                readable, _, _ = select.select(sockets, [], [], self.timeout)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(data)
        except (OSError, ValueError):
            return
        finally:
            upstream.close()

    def _handle_http(
        self,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
    ) -> None:
        if "://" not in target:
            host = self._header(headers, "Host")
            if not host:
                self._plain(400, b"missing Host header\n")
                return
            target = f"http://{host}{target}"
        parts = urlsplit(target)
        if parts.scheme not in {"http", ""} or not parts.hostname:
            self._plain(400, b"only plain HTTP proxy requests are supported\n")
            return
        port = parts.port or 80
        origin = parts.path or "/"
        if parts.query:
            origin += "?" + parts.query
        url = normalize_path(target)
        self.server.observer(
            EgressObservation(
                url=url,
                method=method,
                target=target,
                path_opaque=False,
                https=False,
            )
        )
        body = self._read_request_body(headers)
        outgoing = [f"{method} {origin} {version or 'HTTP/1.1'}"]
        skipped = {"proxy-connection", "connection", "transfer-encoding"}
        for key, value in headers:
            if key.lower() not in skipped:
                outgoing.append(f"{key}: {value}")
        outgoing.append("Connection: close")
        if body is not None:
            outgoing.append(f"Content-Length: {len(body)}")
        raw = ("\r\n".join(outgoing) + "\r\n\r\n").encode("latin-1") + (body or b"")
        try:
            upstream = socket.create_connection((parts.hostname, port), timeout=self.timeout)
        except OSError:
            self._plain(502, b"upstream unavailable\n")
            return
        try:
            upstream.sendall(raw)
            response = b""
            while b"\r\n\r\n" not in response and len(response) <= 65536:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                response += chunk
            if b"\r\n\r\n" not in response:
                self._plain(502, b"invalid upstream response\n")
                return
            head, rest = response.split(b"\r\n\r\n", 1)
            self.wfile.write(head + b"\r\n\r\n")
            self.wfile.flush()
            if rest:
                self.wfile.write(rest)
                self.wfile.flush()
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, BrokenPipeError):
            return
        finally:
            upstream.close()

    def _read_request_body(self, headers: list[tuple[str, str]]) -> bytes | None:
        transfer = (self._header(headers, "Transfer-Encoding") or "").lower()
        if "chunked" in transfer:
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline(65536)
                if not line:
                    break
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    break
                if size == 0:
                    # Consume trailers through the blank line.
                    while self.rfile.readline(65536) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        raw_length = self._header(headers, "Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except ValueError:
            return b""
        if length < 0 or length > 64 * 1024 * 1024:
            return b""
        return self.rfile.read(length) if length else b""


class EgressProxy:
    """A local forward proxy with an in-process observation callback."""

    def __init__(
        self,
        observer: Callable[[EgressObservation], None],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        https_mode: str = "opaque",
    ) -> None:
        if https_mode != "opaque":
            raise ValueError("the stdlib proxy currently supports https_mode='opaque' only")
        self.observer = observer
        self.host = host
        self.requested_port = int(port)
        self.https_mode = https_mode
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            return self.requested_port
        return int(self._server.server_address[1])

    @property
    def endpoint(self) -> str:
        return f"tcp:{self.host}:{self.port}"

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._server is not None:
            return
        server = _ProxyServer((self.host, self.requested_port), observer=self.observer)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="mareforma-egress-proxy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)

    def __enter__(self) -> "EgressProxy":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
