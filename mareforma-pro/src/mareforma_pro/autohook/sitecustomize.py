"""Opt-in Python autohook for a supervised MCP process.

The supervisor prepends this directory to ``PYTHONPATH`` when ``--db-hook`` or
``--bind-rewrite-port`` is enabled. Python imports ``sitecustomize`` before the
application starts. Every event is a best-effort datagram to the supervisor; a
missing socket or a library that cannot be patched never changes the server's
normal behaviour.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import socket
import threading
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SOCKET_PATH = os.environ.get("MAREFORMA_AUTOHOOK_SOCKET", "")
_WORKER_ID = os.environ.get("MAREFORMA_AUTOHOOK_WORKER", "")
_TEXT_QUERIES = os.environ.get("MAREFORMA_DB_QUERY_TEXT", "") == "1"
_SEND_LOCK = threading.Lock()
_PATCHED: set[str] = set()
_PATCHING = False


def _optional_int(name: str) -> int | None:
    value = os.environ.get(name, "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


_REWRITE_BIND_FROM = _optional_int("MAREFORMA_REWRITE_BIND_FROM")
_REWRITE_BIND_TO_PORT = _optional_int("MAREFORMA_REWRITE_BIND_TO_PORT")
_REWRITE_BIND_TO_HOST = os.environ.get("MAREFORMA_REWRITE_BIND_TO_HOST", "")


def _emit(kind: str, **fields: Any) -> None:
    if not _SOCKET_PATH:
        return
    payload = {"kind": kind, "worker_id": _WORKER_ID, **fields}
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        with _SEND_LOCK:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                sock.sendto(raw, _SOCKET_PATH)
            finally:
                sock.close()
    except Exception:
        return


def _safe_url(value: Any) -> str | None:
    if value is None:
        return None
    try:
        parts = urlsplit(str(value))
        if not parts.scheme or not parts.netloc:
            return None
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port else ""
        return urlunsplit((parts.scheme.lower(), host + port, parts.path or "/", "", ""))
    except Exception:
        return None


def _query_digest(query: Any) -> str:
    return "sha256:" + hashlib.sha256(str(query).encode("utf-8", "replace")).hexdigest()


def _emit_db(engine: str, database: Any, query: Any) -> None:
    text = str(query) if query is not None else ""
    _emit(
        "db",
        engine=engine,
        database=str(database or ""),
        operation="query",
        query_digest=_query_digest(text),
        query=text[:4096] if _TEXT_QUERIES else None,
    )


def _patch_sqlite3() -> None:
    try:
        import sqlite3
    except Exception:
        return
    if "sqlite3" in _PATCHED:
        return
    _PATCHED.add("sqlite3")
    original = sqlite3.connect

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        database = args[0] if args else kwargs.get("database", ":memory:")
        try:
            connection.set_trace_callback(lambda query: _emit_db("sqlite3", database, query))
        except Exception:
            pass
        return connection

    try:
        sqlite3.connect = connect
    except Exception:
        pass


def _patch_urllib() -> None:
    try:
        import urllib.request as urllib_request
    except Exception:
        return
    if "urllib.request" in _PATCHED:
        return
    _PATCHED.add("urllib.request")
    original = urllib_request.urlopen

    def urlopen(url, *args, **kwargs):
        safe = _safe_url(url)
        if safe:
            _emit("http", url=safe, path_opaque=False)
        return original(url, *args, **kwargs)

    try:
        urllib_request.urlopen = urlopen
    except Exception:
        pass


def _patch_requests() -> None:
    try:
        import requests
    except Exception:
        return
    if "requests" in _PATCHED:
        return
    _PATCHED.add("requests")
    original = requests.Session.request

    def request(self, method, url, *args, **kwargs):
        safe = _safe_url(url)
        if safe:
            _emit("http", url=safe, path_opaque=False)
        return original(self, method, url, *args, **kwargs)

    try:
        requests.Session.request = request
    except Exception:
        pass


def _patch_httpx() -> None:
    try:
        import httpx
    except Exception:
        return
    if "httpx" in _PATCHED:
        return
    _PATCHED.add("httpx")
    original_client = httpx.Client.request
    original_async = httpx.AsyncClient.request

    def request(self, method, url, *args, **kwargs):
        safe = _safe_url(url)
        if safe:
            _emit("http", url=safe, path_opaque=False)
        return original_client(self, method, url, *args, **kwargs)

    async def async_request(self, method, url, *args, **kwargs):
        safe = _safe_url(url)
        if safe:
            _emit("http", url=safe, path_opaque=False)
        return await original_async(self, method, url, *args, **kwargs)

    try:
        httpx.Client.request = request
        httpx.AsyncClient.request = async_request
    except Exception:
        pass


def _install_bind_rewrite() -> None:
    """Redirect one fixed IPv4 bind() without touching other sockets."""
    if (
        _REWRITE_BIND_FROM is None
        or _REWRITE_BIND_TO_PORT is None
        or not _REWRITE_BIND_TO_HOST
        or getattr(socket.socket.bind, "_mareforma_rewrite", False)
    ):
        return
    original = socket.socket.bind

    def bind(sock, address):
        if sock.family == socket.AF_INET and isinstance(address, tuple) and len(address) >= 2:
            try:
                port = int(address[1])
            except (TypeError, ValueError):
                port = -1
            if port == _REWRITE_BIND_FROM:
                address = (_REWRITE_BIND_TO_HOST, _REWRITE_BIND_TO_PORT)
        return original(sock, address)

    bind._mareforma_rewrite = True  # type: ignore[attr-defined]
    try:
        socket.socket.bind = bind
    except Exception:
        pass


_TARGETS = {
    "sqlite3": _patch_sqlite3,
    "urllib": _patch_urllib,
    "urllib.request": _patch_urllib,
    "requests": _patch_requests,
    "httpx": _patch_httpx,
}


def _patch_module(name: str) -> None:
    global _PATCHING
    if _PATCHING:
        return
    root = name.split(".", 1)[0]
    patcher = _TARGETS.get(name) or _TARGETS.get(root)
    if patcher is None:
        return
    _PATCHING = True
    try:
        patcher()
    finally:
        _PATCHING = False


_ORIGINAL_IMPORT = builtins.__import__


def _import(name, globals=None, locals=None, fromlist=(), level=0):
    module = _ORIGINAL_IMPORT(name, globals, locals, fromlist, level)
    try:
        _patch_module(name)
    except Exception:
        pass
    return module


try:
    builtins.__import__ = _import
except Exception:
    pass

try:
    _install_bind_rewrite()
except Exception:
    pass

# These modules are loaded before most MCP applications import their optional
# dependencies, so patch them immediately as well.
for _name in ("sqlite3", "urllib", "urllib.request"):
    try:
        _patch_module(_name)
    except Exception:
        pass
