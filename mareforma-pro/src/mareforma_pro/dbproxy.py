"""Optional user-space TCP relay for database connection-pool visibility.

The relay does not decrypt a database protocol and does not invent SQL text. It
does give a deterministic answer to "this call sent traffic to which database
endpoint", including a connection created before the call by a long-lived pool.
"""

from __future__ import annotations

from dataclasses import dataclass
import select
import socket
import socketserver
import threading
from typing import Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {
    "postgres": 5432,
    "postgresql": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "redis": 6379,
    "mongodb": 27017,
}

_DB_ENV_VARS = (
    "DATABASE_URL",
    "POSTGRES_URL",
    "POSTGRESQL_URL",
    "MYSQL_URL",
    "MARIADB_URL",
    "REDIS_URL",
    "MONGO_URL",
    "MONGODB_URI",
)


@dataclass(frozen=True)
class DatabaseObservation:
    target: str
    operation: str = "traffic"
    direction: str | None = None
    bytes: int = 0


def engine_for_port(port: int) -> str:
    for engine, default_port in _DEFAULT_PORTS.items():
        if port == default_port:
            return engine
    return "tcp"


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        relay: LocalTCPRelay = self.server.relay  # type: ignore[attr-defined]
        try:
            upstream = socket.create_connection(
                (relay.target_host, relay.target_port), timeout=relay.timeout
            )
        except OSError:
            return
        client = self.request
        relay.observer(
            DatabaseObservation(
                target=relay.target,
                operation="connect",
                direction="connect",
            )
        )
        try:
            sockets = [client, upstream]
            while sockets:
                readable, _, _ = select.select(sockets, [], [], relay.timeout)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    if source is client:
                        direction = "to_database"
                    else:
                        direction = "from_database"
                    relay.observer(
                        DatabaseObservation(
                            target=relay.target,
                            operation="traffic",
                            direction=direction,
                            bytes=len(data),
                        )
                    )
                    destination = upstream if source is client else client
                    destination.sendall(data)
        except (OSError, ValueError):
            return
        finally:
            upstream.close()


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, *, relay: "LocalTCPRelay"):
        self.relay = relay
        super().__init__(address, _RelayHandler)


class LocalTCPRelay:
    """Forward one local TCP endpoint to one configured database endpoint."""

    def __init__(
        self,
        target_host: str,
        target_port: int,
        observer: Callable[[DatabaseObservation], None],
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        timeout: float = 30.0,
    ) -> None:
        self.target_host = target_host
        self.target_port = int(target_port)
        self.target = f"{target_host}:{self.target_port}"
        self.observer = observer
        self.host = host
        self.requested_port = int(port)
        self.timeout = float(timeout)
        self._server: _RelayServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            return self.requested_port
        return int(self._server.server_address[1])

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def start(self) -> None:
        if self._server is not None:
            return
        server = _RelayServer((self.host, self.requested_port), relay=self)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="mareforma-db-relay", daemon=True)
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


def _split_target(value: str) -> tuple[str, int]:
    host, sep, port_text = value.rpartition(":")
    if not sep or not host:
        raise ValueError(f"database relay target must be HOST:PORT, got {value!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"database relay target has invalid port: {value!r}") from exc
    if not (0 < port < 65536):
        raise ValueError(f"database relay target port is out of range: {value!r}")
    return host, port


def rewrite_database_env(
    env: Mapping[str, str], relays: Mapping[str, LocalTCPRelay]
) -> dict[str, str]:
    """Point common DB URL/host environment variables at local relays.

    The rewrite is opt-in and only touches a variable when its target endpoint
    matches a configured relay. Unmatched variables are left byte-identical.
    """
    out = dict(env)
    if not relays:
        return out
    by_target = {relay.target: relay for relay in relays.values()}
    for name in _DB_ENV_VARS:
        raw = out.get(name)
        if not raw:
            continue
        try:
            parts = urlsplit(raw)
        except ValueError:
            continue
        scheme = parts.scheme.lower()
        if not parts.hostname:
            continue
        default_port = _DEFAULT_PORTS.get(scheme, 0)
        try:
            port = parts.port or default_port
        except ValueError:
            continue
        if not port:
            continue
        target = f"{parts.hostname}:{port}"
        relay = by_target.get(target)
        if relay is None:
            continue
        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username
            if parts.password is not None:
                userinfo += ":" + parts.password
            userinfo += "@"
        netloc = userinfo + relay.endpoint
        out[name] = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    # Common separate host/port variables. Match only when the configured
    # target is unambiguous so a generic PGHOST is not silently redirected.
    pairs = (
        ("PGHOST", "PGPORT", 5432),
        ("MYSQL_HOST", "MYSQL_PORT", 3306),
        ("REDIS_HOST", "REDIS_PORT", 6379),
        ("MONGO_HOST", "MONGO_PORT", 27017),
    )
    for host_var, port_var, default_port in pairs:
        host = out.get(host_var)
        if not host:
            continue
        try:
            port = int(out.get(port_var, str(default_port)))
        except ValueError:
            continue
        relay = by_target.get(f"{host}:{port}")
        if relay is None:
            continue
        local_host, local_port = relay.endpoint.rsplit(":", 1)
        out[host_var] = local_host
        out[port_var] = local_port
    return out


def parse_relay_targets(values: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
    return tuple(_split_target(value) for value in values)
