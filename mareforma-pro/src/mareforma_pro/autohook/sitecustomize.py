"""Opt-in Python autohook for a supervised process.

The worker observer prepends this directory to ``PYTHONPATH``. Python imports
``sitecustomize`` before the application starts. Events are best-effort
datagrams to the parent collector; a missing socket or a library that cannot be
patched never changes the application's normal behaviour.

The hook is deliberately split into two evidence classes:

* application hooks see Python-level HTTP, DB commands, task context, and
  process/native boundary hints;
* the parent ``strace`` process sees the kernel-level file/network/process
  boundary that native code and child processes can cross.

The autohook never receives an HMAC secret, so it cannot mint a receipt.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import socket
import sys
import threading
import time
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_SOCKET_PATH = os.environ.get("MAREFORMA_AUTOHOOK_SOCKET", "")
_WORKER_ID = os.environ.get("MAREFORMA_AUTOHOOK_WORKER", "")
_DB_QUERY_TEXT = os.environ.get("MAREFORMA_DB_QUERY_TEXT", "") == "1"
_HTTP_QUERY_TEXT = os.environ.get("MAREFORMA_HTTP_QUERY_TEXT", "") == "1"
_AUDIT_ENABLED = os.environ.get("MAREFORMA_AUTOHOOK_AUDIT", "") == "1"
_SEND_LOCK = threading.Lock()
_PATCHED: set[str] = set()
_PATCHING = False
_AUDIT_DEPTH = threading.local()
_TASK_LOCK = threading.Lock()
_LAST_TASK_ID: str | None = None

_PROCESS_PID = os.getpid()
_PROCESS_PPID = os.getppid()
_INHERITED_OWNER = os.environ.get("MAREFORMA_AUTOHOOK_OWNER_PID", "").strip()
if _INHERITED_OWNER:
    try:
        _TASK_OWNER_PID = int(_INHERITED_OWNER)
    except ValueError:
        _TASK_OWNER_PID = _PROCESS_PID
    _PROCESS_ROLE = "main" if _TASK_OWNER_PID == _PROCESS_PID else "child"
else:
    _TASK_OWNER_PID = _PROCESS_PID
    _PROCESS_ROLE = "main"
    try:
        # A child Python process inherits this marker. At import time its PID
        # differs from the owner, so it cannot open or close the task scope.
        os.environ["MAREFORMA_AUTOHOOK_OWNER_PID"] = str(_TASK_OWNER_PID)
    except Exception:
        pass

_DEFAULT_TASK_CONTEXT = {
    "task_id": "MAREFORMA_TASK_ID",
    "execution_id": "MAREFORMA_EXECUTION_ID",
    "attempt": "MAREFORMA_ATTEMPT",
    "attempt_dir": "MAREFORMA_ATTEMPT_DIR",
    "execution_epoch": "MAREFORMA_EXECUTION_EPOCH",
    "parent_scope_id": "MAREFORMA_PARENT_SCOPE_ID",
    "traceparent": "MAREFORMA_TRACEPARENT",
}


def _load_task_context_names() -> dict[str, str]:
    raw = os.environ.get("MAREFORMA_AUTOHOOK_TASK_CONTEXT", "")
    supplied: dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                supplied = parsed
        except (TypeError, ValueError):
            supplied = {}
    out: dict[str, str] = {}
    for key, default in _DEFAULT_TASK_CONTEXT.items():
        value = supplied.get(key, default)
        if value is None:
            continue
        name = str(value).strip()
        if name:
            out[key] = name
    # The parent validates this mapping before launch. Keep a usable fallback
    # for a direct import of this hook during development.
    out.setdefault("task_id", _DEFAULT_TASK_CONTEXT["task_id"])
    return out


_TASK_CONTEXT_NAMES = _load_task_context_names()
_TASK_ID_KEY = _TASK_CONTEXT_NAMES["task_id"]
_EXECUTION_ID_KEY = _TASK_CONTEXT_NAMES.get("execution_id")
_ATTEMPT_KEY = _TASK_CONTEXT_NAMES.get("attempt")
_ATTEMPT_DIR_KEY = _TASK_CONTEXT_NAMES.get("attempt_dir")
_EXECUTION_EPOCH_KEY = _TASK_CONTEXT_NAMES.get("execution_epoch")
_PARENT_SCOPE_ID_KEY = _TASK_CONTEXT_NAMES.get("parent_scope_id")
_TRACEPARENT_KEY = _TASK_CONTEXT_NAMES.get("traceparent")
_TASK_CONTEXT_KEYS = frozenset(
    name
    for name in (
        _EXECUTION_ID_KEY,
        _EXECUTION_EPOCH_KEY,
        _ATTEMPT_KEY,
        _ATTEMPT_DIR_KEY,
        _PARENT_SCOPE_ID_KEY,
        _TRACEPARENT_KEY,
    )
    if name and name != _TASK_ID_KEY
)


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


def _attempt_name() -> str | None:
    if _ATTEMPT_KEY:
        explicit = os.environ.get(_ATTEMPT_KEY, "").strip()
        if explicit:
            return explicit
    if _ATTEMPT_DIR_KEY:
        attempt_dir = os.environ.get(_ATTEMPT_DIR_KEY, "").strip()
        if attempt_dir:
            return os.path.basename(attempt_dir.rstrip("/")) or None
    return None


def _task_fields() -> dict[str, str]:
    out: dict[str, str] = {}
    task_id = os.environ.get(_TASK_ID_KEY, "").strip()
    if task_id:
        out["task_id"] = task_id
    if _EXECUTION_ID_KEY:
        execution_id = os.environ.get(_EXECUTION_ID_KEY, "").strip()
        if execution_id:
            out["execution_id"] = execution_id
    if _EXECUTION_EPOCH_KEY:
        epoch = os.environ.get(_EXECUTION_EPOCH_KEY, "").strip()
        if epoch:
            out["execution_epoch"] = epoch
    if _PARENT_SCOPE_ID_KEY:
        parent_scope_id = os.environ.get(_PARENT_SCOPE_ID_KEY, "").strip()
        if parent_scope_id:
            out["parent_scope_id"] = parent_scope_id
    if _TRACEPARENT_KEY:
        traceparent = os.environ.get(_TRACEPARENT_KEY, "").strip()
        if traceparent:
            out["traceparent"] = traceparent
    attempt = _attempt_name()
    if attempt:
        out["attempt"] = attempt
    return out


def _emit(kind: str, **fields: Any) -> None:
    if not _SOCKET_PATH:
        return
    current_pid = os.getpid()
    payload = {
        "kind": kind,
        "worker_id": _WORKER_ID,
        "source": "mareforma_autohook",
        "ts": time.time(),
        "pid": current_pid,
        "ppid": os.getppid(),
        "process_role": "main" if current_pid == _TASK_OWNER_PID else "child",
        "task_owner_pid": _TASK_OWNER_PID,
    }
    payload.update(_task_fields())
    payload.update(fields)
    payload = {key: value for key, value in payload.items() if value is not None}
    try:
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        with _SEND_LOCK:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                sock.sendto(raw, _SOCKET_PATH)
            finally:
                sock.close()
    except Exception:
        return


def _announce_task_change(
    old: str | None,
    new: str | None,
    *,
    old_context: dict[str, str] | None = None,
    new_context: dict[str, str] | None = None,
) -> None:
    """Emit task boundaries when the root worker changes task context."""
    global _LAST_TASK_ID
    if os.getpid() != _TASK_OWNER_PID:
        return
    old_value = str(old) if old else None
    new_value = str(new) if new else None
    with _TASK_LOCK:
        if old_value == new_value:
            _LAST_TASK_ID = new_value
            return
        previous = _LAST_TASK_ID
        _LAST_TASK_ID = new_value
    if previous and previous != old_value:
        old_value = previous
    if old_value:
        fields = dict(old_context or {})
        fields["task_id"] = old_value
        _emit("task_end", **fields)
    if new_value:
        fields = dict(new_context or {})
        fields["task_id"] = new_value
        _emit("task_start", **fields)


def _install_task_context() -> None:
    """Observe the configured task-id environment transitions without changing worker code.

    Only the root process owns task boundaries. A child Python process inherits
    the same task id and emits ordinary evidence into that scope, but it cannot
    create a second scope for the task it inherited.
    """
    global _LAST_TASK_ID
    _LAST_TASK_ID = os.environ.get(_TASK_ID_KEY) or None
    if _PROCESS_ROLE != "main":
        return
    environment_type = getattr(os, "_Environ", None)
    if environment_type is None or getattr(
        environment_type, "_mareforma_task_tracking", False
    ):
        if _LAST_TASK_ID:
            _emit("task_start", **_task_fields())
        return
    original_set = environment_type.__setitem__
    original_del = environment_type.__delitem__

    def setitem(self, key, value):
        old_context = _task_fields() if key in {_TASK_ID_KEY, *_TASK_CONTEXT_KEYS} else None
        old = self.get(key)
        result = original_set(self, key, value)
        if key == _TASK_ID_KEY:
            try:
                _announce_task_change(
                    old,
                    value,
                    old_context=old_context,
                    new_context=_task_fields(),
                )
            except Exception:
                pass
        elif key in _TASK_CONTEXT_KEYS and os.environ.get(_TASK_ID_KEY):
            try:
                _emit("task_context", **_task_fields())
            except Exception:
                pass
        return result

    def delitem(self, key):
        old_context = _task_fields() if key in {_TASK_ID_KEY, *_TASK_CONTEXT_KEYS} else None
        old = self.get(key)
        result = original_del(self, key)
        if key == _TASK_ID_KEY:
            try:
                _announce_task_change(
                    old,
                    None,
                    old_context=old_context,
                    new_context=None,
                )
            except Exception:
                pass
        elif key in _TASK_CONTEXT_KEYS and os.environ.get(_TASK_ID_KEY):
            try:
                _emit("task_context", **_task_fields())
            except Exception:
                pass
        return result

    setitem._mareforma_task_tracking = True  # type: ignore[attr-defined]
    try:
        environment_type.__setitem__ = setitem
        environment_type.__delitem__ = delitem
        environment_type._mareforma_task_tracking = True  # type: ignore[attr-defined]
        if _LAST_TASK_ID:
            _emit("task_start", **_task_fields())
    except Exception:
        pass


def _safe_url(value: Any) -> str | None:
    """Return the credential-free URL identity signed into receipts."""
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


def _url_fields(value: Any) -> dict[str, Any] | None:
    """URL identity plus a non-secret query digest and key set.

    Query values are omitted by default because they routinely carry credentials
    and presigned secrets. ``MAREFORMA_HTTP_QUERY_TEXT=1`` opts into the text.
    """
    safe = _safe_url(value)
    if not safe:
        return None
    fields: dict[str, Any] = {"url": safe}
    try:
        query = urlsplit(str(value)).query
    except Exception:
        query = ""
    if query:
        fields["query_digest"] = _digest_text(query)
        try:
            fields["query_keys"] = sorted(
                {key for key, _value in parse_qsl(query, keep_blank_values=True)}
            )
        except Exception:
            pass
        if _HTTP_QUERY_TEXT:
            fields["query"] = query[:4096]
    return fields


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_text(value: Any) -> str:
    return _digest_bytes(str(value).encode("utf-8", "replace"))


def _query_digest(query: Any) -> str:
    return _digest_text(query)


def _emit_db(
    engine: str,
    database: Any,
    query: Any,
    *,
    operation: str = "query",
    source: str = "python_autohook",
) -> None:
    text = str(query) if query is not None else ""
    _emit(
        "db",
        engine=engine,
        database=str(database or ""),
        operation=operation,
        query_digest=_query_digest(text),
        query=text[:4096] if _DB_QUERY_TEXT else None,
        db_source=source,
    )


def _body_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def _response_body(response: Any) -> bytes | None:
    """Return an already-buffered response body without triggering a read."""
    content = _body_bytes(getattr(response, "_content", None))
    if content is not None:
        return content
    try:
        if getattr(response, "is_stream_consumed", False):
            return _body_bytes(getattr(response, "content", None))
    except Exception:
        pass
    return None


def _status_code(response: Any) -> int | None:
    for name in ("status_code", "status"):
        try:
            value = getattr(response, name, None)
        except Exception:
            value = None
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    return None


def _final_url(response: Any, requested: Any) -> str | None:
    try:
        value = getattr(response, "url", None)
        return str(value) if value else str(requested)
    except Exception:
        return str(requested) if requested else None


def _emit_http_result(
    request_id: str,
    url: Any,
    *,
    method: str | None = None,
    status: int | None = None,
    final_url: Any = None,
    body: bytes | None = None,
    observed_bytes: int | None = None,
    observed_digest: str | None = None,
    body_observed: bool | None = None,
    body_unobserved: bool = False,
    pending: bool = False,
    partial: bool = False,
    error: str | None = None,
) -> None:
    fields = _url_fields(url)
    if fields is None:
        return
    if final_url is not None:
        final = _safe_url(final_url)
        if final and final != fields["url"]:
            fields["final_url"] = final
    if body is not None:
        body_observed = True if body_observed is None else bool(body_observed)
    observed = bool(body_observed)
    digest = _digest_bytes(body) if body is not None else observed_digest
    if body is not None:
        body_length: int | None = len(body)
    else:
        body_length = observed_bytes
    _emit(
        "http",
        request_id=request_id,
        method=method,
        status=status,
        body_bytes=body_length,
        body_digest=digest,
        body_observed=observed,
        observed=observed,
        body_unobserved=bool(body_unobserved or not observed),
        pending=bool(pending),
        partial=bool(partial),
        path_opaque=False,
        error=error,
        **fields,
    )


class _HttpCapture:
    """Accumulate a streamed response body and emit one final HTTP event."""

    def __init__(
        self,
        response: Any,
        url: Any,
        method: str | None,
        request_id: str | None = None,
    ) -> None:
        self.request_id = request_id or uuid.uuid4().hex
        self.response = response
        self.url = url
        self.method = method
        self.status = _status_code(response)
        self.final_url = _final_url(response, url)
        self._digest = hashlib.sha256()
        self._bytes = 0
        self._finished = False
        self._closed = False
        self._active_readers = 0
        self._lock = threading.Lock()

    @property
    def finished(self) -> bool:
        return self._finished

    def reader_started(self) -> None:
        with self._lock:
            self._active_readers += 1

    def reader_finished(self, *, complete: bool) -> None:
        with self._lock:
            if self._active_readers > 0:
                self._active_readers -= 1
            deferred = self._active_readers == 0 and self._closed
        if complete:
            self.finish()
        elif deferred:
            self.abandon()
        else:
            self.finish(complete=False)

    def note_close(self, reason: str = "stream_closed_unread") -> None:
        with self._lock:
            self._closed = True
            active = self._active_readers > 0
        if not active:
            self.abandon(reason)

    def emit_pending(self) -> None:
        _emit_http_result(
            self.request_id,
            self.url,
            method=self.method,
            status=self.status,
            final_url=self.final_url,
            body_unobserved=True,
            pending=True,
        )

    def feed(self, chunk: Any) -> None:
        data = _body_bytes(chunk)
        if not data:
            return
        with self._lock:
            if self._finished:
                return
            self._digest.update(data)
            self._bytes += len(data)

    def finish(self, *, complete: bool = True) -> None:
        with self._lock:
            if self._finished:
                return
            self._finished = True
            body_bytes = self._bytes
            digest = "sha256:" + self._digest.hexdigest()
        _emit_http_result(
            self.request_id,
            self.url,
            method=self.method,
            status=self.status,
            final_url=self.final_url,
            observed_bytes=body_bytes,
            observed_digest=digest,
            body_observed=complete,
            body_unobserved=not complete,
            pending=False,
            partial=(not complete and body_bytes > 0),
            error=None if complete else "stream_not_fully_consumed",
        )

    def abandon(self, reason: str = "stream_closed_unread") -> None:
        with self._lock:
            if self._finished:
                return
            self._finished = True
            body_bytes = self._bytes
            digest = "sha256:" + self._digest.hexdigest()
        _emit_http_result(
            self.request_id,
            self.url,
            method=self.method,
            status=self.status,
            final_url=self.final_url,
            observed_bytes=body_bytes,
            observed_digest=digest,
            body_observed=False,
            body_unobserved=True,
            pending=False,
            partial=body_bytes > 0,
            error=reason,
        )


class _ObservedUrllibResponse:
    """Transparent urllib response proxy that hashes bytes as they are read."""

    def __init__(self, response: Any, capture: _HttpCapture) -> None:
        self._response = response
        self._capture = capture

    def _feed(self, chunk: Any) -> None:
        self._capture.feed(chunk)

    def read(self, *args: Any, **kwargs: Any) -> Any:
        data = self._response.read(*args, **kwargs)
        self._feed(data)
        # read(), read(None), and read(-1) consume to EOF. read(n) may not.
        if not data or not args or args[0] in (None, -1):
            self._capture.finish()
        return data

    def read1(self, *args: Any, **kwargs: Any) -> Any:
        method = getattr(self._response, "read1", None)
        if method is None:
            return self.read(*args, **kwargs)
        data = method(*args, **kwargs)
        self._feed(data)
        if not data:
            self._capture.finish()
        return data

    def readline(self, *args: Any, **kwargs: Any) -> Any:
        data = self._response.readline(*args, **kwargs)
        self._feed(data)
        if not data:
            self._capture.finish()
        return data

    def readlines(self, *args: Any, **kwargs: Any) -> Any:
        lines = self._response.readlines(*args, **kwargs)
        for line in lines:
            self._feed(line)
        self._capture.finish()
        return lines

    def __iter__(self):
        try:
            for line in self._response:
                self._feed(line)
                yield line
        finally:
            self._capture.finish()

    def close(self) -> Any:
        try:
            if not self._capture.finished:
                self._capture.finish(complete=False)
        finally:
            return self._response.close()

    def __enter__(self):
        enter = getattr(self._response, "__enter__", None)
        if enter is not None:
            enter()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        exit_method = getattr(self._response, "__exit__", None)
        if exit_method is not None:
            return exit_method(exc_type, exc, tb)
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)


def _emit_http_error(
    request_id: str,
    url: Any,
    *,
    method: str | None,
    error: str,
) -> None:
    _emit_http_result(
        request_id,
        url,
        method=method,
        body_unobserved=True,
        pending=False,
        error=error,
    )


def _observe_requests_stream(response: Any, capture: _HttpCapture) -> None:
    original_iter = getattr(response, "iter_content", None)
    if callable(original_iter) and not getattr(original_iter, "_mareforma_hooked", False):
        def iter_content(*args, **kwargs):
            try:
                for chunk in original_iter(*args, **kwargs):
                    capture.feed(chunk)
                    yield chunk
            except BaseException as exc:
                capture.finish(complete=False)
                raise
            else:
                capture.finish()

        iter_content._mareforma_hooked = True  # type: ignore[attr-defined]
        try:
            response.iter_content = iter_content
        except Exception:
            pass
    original_close = getattr(response, "close", None)
    if callable(original_close) and not getattr(original_close, "_mareforma_hooked", False):
        def close(*args, **kwargs):
            try:
                return original_close(*args, **kwargs)
            finally:
                if not capture.finished:
                    capture.abandon()

        close._mareforma_hooked = True  # type: ignore[attr-defined]
        try:
            response.close = close
        except Exception:
            pass


def _observe_httpx_stream(response: Any, capture: _HttpCapture) -> None:
    original_iter = getattr(response, "iter_bytes", None)
    if callable(original_iter) and not getattr(original_iter, "_mareforma_hooked", False):
        def iter_bytes(*args, **kwargs):
            completed = False
            capture.reader_started()
            try:
                for chunk in original_iter(*args, **kwargs):
                    capture.feed(chunk)
                    yield chunk
                completed = True
            finally:
                capture.reader_finished(complete=completed)

        iter_bytes._mareforma_hooked = True  # type: ignore[attr-defined]
        try:
            response.iter_bytes = iter_bytes
        except Exception:
            pass
    original_aiter = getattr(response, "aiter_bytes", None)
    if callable(original_aiter) and not getattr(original_aiter, "_mareforma_hooked", False):
        async def aiter_bytes(*args, **kwargs):
            completed = False
            capture.reader_started()
            try:
                async for chunk in original_aiter(*args, **kwargs):
                    capture.feed(chunk)
                    yield chunk
                completed = True
            finally:
                capture.reader_finished(complete=completed)

        aiter_bytes._mareforma_hooked = True  # type: ignore[attr-defined]
        try:
            response.aiter_bytes = aiter_bytes
        except Exception:
            pass
    for name in ("close", "aclose"):
        original_close = getattr(response, name, None)
        if not callable(original_close) or getattr(original_close, "_mareforma_hooked", False):
            continue
        if name == "aclose":
            async def aclose(*args, _original=original_close, **kwargs):
                try:
                    return await _original(*args, **kwargs)
                finally:
                    capture.note_close()

            aclose._mareforma_hooked = True  # type: ignore[attr-defined]
            replacement = aclose
        else:
            def close(*args, _original=original_close, **kwargs):
                try:
                    return _original(*args, **kwargs)
                finally:
                    capture.note_close()

            close._mareforma_hooked = True  # type: ignore[attr-defined]
            replacement = close
        try:
            setattr(response, name, replacement)
        except Exception:
            pass


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
            connection.set_trace_callback(
                lambda query: _emit_db("sqlite3", database, query)
            )
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
        method = "GET"
        get_method = getattr(url, "get_method", None)
        if callable(get_method):
            try:
                method = str(get_method())
            except Exception:
                pass
        request_id = uuid.uuid4().hex
        try:
            response = original(url, *args, **kwargs)
        except Exception as exc:
            _emit_http_error(
                request_id,
                url,
                method=method,
                error=type(exc).__name__,
            )
            raise
        capture = _HttpCapture(response, url, method, request_id=request_id)
        capture.emit_pending()
        return _ObservedUrllibResponse(response, capture)

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
        request_id = uuid.uuid4().hex
        try:
            response = original(self, method, url, *args, **kwargs)
        except Exception as exc:
            _emit_http_error(
                request_id,
                url,
                method=str(method),
                error=type(exc).__name__,
            )
            raise
        body = _response_body(response)
        if body is not None:
            _emit_http_result(
                request_id,
                url,
                method=str(method),
                status=_status_code(response),
                final_url=_final_url(response, url),
                body=body,
            )
        else:
            capture = _HttpCapture(response, url, str(method), request_id=request_id)
            capture.emit_pending()
            _observe_requests_stream(response, capture)
        return response

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
    # ``Client.get/post/request`` all funnel through ``send``; patching send
    # also covers the ``Client.stream(...)`` path, which bypasses request().
    original_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send

    def request_meta(request: Any) -> tuple[Any, str | None]:
        try:
            url = request.url
        except Exception:
            url = None
        try:
            method = str(request.method)
        except Exception:
            method = None
        return url, method

    def handle_response(
        request_id: str,
        url: Any,
        method: str | None,
        response: Any,
    ) -> None:
        body = _response_body(response)
        if body is not None:
            _emit_http_result(
                request_id,
                url,
                method=method,
                status=_status_code(response),
                final_url=_final_url(response, url),
                body=body,
            )
        else:
            capture = _HttpCapture(response, url, method, request_id=request_id)
            capture.emit_pending()
            _observe_httpx_stream(response, capture)

    def send(self, request, *args, **kwargs):
        request_id = uuid.uuid4().hex
        url, method = request_meta(request)
        try:
            response = original_send(self, request, *args, **kwargs)
        except Exception as exc:
            _emit_http_error(
                request_id,
                url,
                method=method,
                error=type(exc).__name__,
            )
            raise
        handle_response(request_id, url, method, response)
        return response

    async def async_send(self, request, *args, **kwargs):
        request_id = uuid.uuid4().hex
        url, method = request_meta(request)
        try:
            response = await original_async_send(self, request, *args, **kwargs)
        except Exception as exc:
            _emit_http_error(
                request_id,
                url,
                method=method,
                error=type(exc).__name__,
            )
            raise
        handle_response(request_id, url, method, response)
        return response

    try:
        httpx.Client.send = send
        httpx.AsyncClient.send = async_send
    except Exception:
        pass


def _postgres_target(connection: Any) -> str:
    info = getattr(connection, "info", None)
    if info is None:
        return ""
    values = []
    for name in ("host", "port", "dbname"):
        try:
            value = getattr(info, name, None)
        except Exception:
            value = None
        if value:
            values.append(str(value))
    if len(values) >= 3:
        return f"postgresql://{values[0]}:{values[1]}/{values[2]}"
    return "postgresql://" + "/".join(values)


def _patch_psycopg2() -> None:
    try:
        import psycopg2.extensions as extensions
    except Exception:
        return
    cursor_type = getattr(extensions, "cursor", None)
    if cursor_type is None:
        # ``psycopg2.extensions`` can be imported while the package is still
        # initialising. Do not record a false "patched" marker; the completed
        # top-level import gets another chance.
        return
    for name in ("execute", "executemany"):
        original = getattr(cursor_type, name, None)
        if original is None or getattr(original, "_mareforma_hooked", False):
            continue

        def make_wrapper(original_method, operation):
            def wrapper(self, query, *args, **kwargs):
                try:
                    _emit_db(
                        "postgresql",
                        _postgres_target(getattr(self, "connection", None)),
                        query,
                        operation=operation,
                        source="python_autohook_psycopg2",
                    )
                except Exception:
                    pass
                return original_method(self, query, *args, **kwargs)

            wrapper._mareforma_hooked = True  # type: ignore[attr-defined]
            return wrapper

        try:
            setattr(cursor_type, name, make_wrapper(original, name))
        except Exception:
            pass
    _PATCHED.add("psycopg2.extensions")


def _patch_psycopg() -> None:
    try:
        import psycopg
        from psycopg import AsyncCursor, Cursor
    except Exception:
        return
    if "psycopg" in _PATCHED:
        return
    _PATCHED.add("psycopg")

    def wrapper_for(cls, name, operation, *, async_method=False):
        original = getattr(cls, name, None)
        if original is None or getattr(original, "_mareforma_hooked", False):
            return
        if async_method:
            async def wrapper(self, query, *args, **kwargs):
                try:
                    _emit_db(
                        "postgresql",
                        _postgres_target(getattr(self, "connection", None)),
                        query,
                        operation=operation,
                        source="python_autohook_psycopg",
                    )
                except Exception:
                    pass
                return await original(self, query, *args, **kwargs)
        else:
            def wrapper(self, query, *args, **kwargs):
                try:
                    _emit_db(
                        "postgresql",
                        _postgres_target(getattr(self, "connection", None)),
                        query,
                        operation=operation,
                        source="python_autohook_psycopg",
                    )
                except Exception:
                    pass
                return original(self, query, *args, **kwargs)
        wrapper._mareforma_hooked = True  # type: ignore[attr-defined]
        try:
            setattr(cls, name, wrapper)
        except Exception:
            pass

    for name in ("execute", "executemany"):
        wrapper_for(Cursor, name, name)
        wrapper_for(AsyncCursor, name, name, async_method=True)


def _redis_database(connection: Any, command: Any, args: tuple[Any, ...]) -> str:
    pool = getattr(connection, "connection_pool", None)
    kwargs = getattr(pool, "connection_kwargs", None) or {}
    if isinstance(kwargs, dict):
        host = kwargs.get("host")
        port = kwargs.get("port")
        db = kwargs.get("db")
        pieces = []
        if host:
            pieces.append(str(host))
        if port:
            pieces.append(str(port))
        target = ":".join(pieces)
        if db is not None:
            target += f"/{db}"
        if target:
            return "redis://" + target
    return "redis://"


def _emit_redis(connection: Any, command: Any, args: tuple[Any, ...]) -> None:
    text = " ".join([str(command), *[str(item) for item in args]])
    _emit(
        "db",
        engine="redis",
        database=_redis_database(connection, command, args),
        operation="command",
        query_digest=_query_digest(text),
        query=text[:4096] if _DB_QUERY_TEXT else None,
        db_source="python_autohook_redis",
    )


def _patch_redis_execute(cls: type, *, async_method: bool) -> None:
    original = getattr(cls, "execute_command", None)
    if original is None or getattr(original, "_mareforma_hooked", False):
        return
    if async_method:
        async def execute_command(self, *args, **kwargs):
            try:
                if args:
                    _emit_redis(self, args[0], tuple(args[1:]))
            except Exception:
                pass
            return await original(self, *args, **kwargs)
    else:
        def execute_command(self, *args, **kwargs):
            try:
                if args:
                    _emit_redis(self, args[0], tuple(args[1:]))
            except Exception:
                pass
            return original(self, *args, **kwargs)
    execute_command._mareforma_hooked = True  # type: ignore[attr-defined]
    try:
        setattr(cls, "execute_command", execute_command)
    except Exception:
        pass


def _patch_redis() -> None:
    try:
        import redis as redis_module
    except Exception:
        return
    redis_type = getattr(redis_module, "Redis", None)
    if redis_type is not None:
        _patch_redis_execute(redis_type, async_method=False)
        try:
            from redis.client import Pipeline
        except Exception:
            Pipeline = None
        if Pipeline is not None:
            _patch_redis_execute(Pipeline, async_method=False)
        _PATCHED.add("redis")
    try:
        import redis.asyncio as redis_asyncio
    except Exception:
        return
    async_type = getattr(redis_asyncio, "Redis", None)
    if async_type is None:
        return
    _patch_redis_execute(async_type, async_method=True)
    try:
        from redis.asyncio.client import Pipeline as AsyncPipeline
    except Exception:
        AsyncPipeline = None
    if AsyncPipeline is not None:
        _patch_redis_execute(AsyncPipeline, async_method=True)
    _PATCHED.add("redis.asyncio")


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


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    """Emit Python-level boundary hints; strace remains the byte-level judge."""
    if not _AUDIT_ENABLED or not _SOCKET_PATH or getattr(_AUDIT_DEPTH, "active", False):
        return
    try:
        _AUDIT_DEPTH.active = True
        if event in {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.spawn",
            "os.fork",
            "os.forkpty",
        }:
            _emit("audit", category="process", event=event)
        elif event in {"ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle"}:
            _emit("audit", category="native", event=event)
        elif event == "socket.connect":
            _emit("audit", category="socket", event=event)
        elif event == "import" and len(args) > 1 and isinstance(args[1], str):
            if args[1].casefold().endswith((".so", ".pyd", ".dylib", ".dll")):
                _emit("audit", category="native", event=event)
    except Exception:
        return
    finally:
        _AUDIT_DEPTH.active = False


def _install_audit_hook() -> None:
    if not _AUDIT_ENABLED or getattr(sys, "_mareforma_worker_audit", False):
        return
    try:
        sys.addaudithook(_audit_hook)
        sys._mareforma_worker_audit = True  # type: ignore[attr-defined]
    except Exception:
        pass


_TARGETS = {
    "sqlite3": _patch_sqlite3,
    "urllib": _patch_urllib,
    "urllib.request": _patch_urllib,
    "requests": _patch_requests,
    "httpx": _patch_httpx,
    "psycopg": _patch_psycopg,
    "psycopg2": _patch_psycopg2,
    "psycopg2.extensions": _patch_psycopg2,
    "redis": _patch_redis,
    "redis.asyncio": _patch_redis,
}


def _patch_module(name: str) -> None:
    global _PATCHING
    if _PATCHING:
        return
    # Do not map a submodule import back to its package: during a package's
    # own first import that target is only partially initialised. The import
    # hook runs again for the completed top-level module, where the classes
    # the patcher needs actually exist.
    patcher = _TARGETS.get(name)
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

for _install in (_install_bind_rewrite, _install_task_context, _install_audit_hook):
    try:
        _install()
    except Exception:
        pass

# These modules are loaded before most applications import their optional
# dependencies, so patch them immediately as well.
for _name in ("sqlite3", "urllib", "urllib.request"):
    try:
        _patch_module(_name)
    except Exception:
        pass
