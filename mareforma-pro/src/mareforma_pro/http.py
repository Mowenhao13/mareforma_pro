"""Explicit application-level URL read evidence.

PEP-578 ``socket.connect`` events prove that a connection happened, not which
URL was requested or which response bytes arrived. A Python audit hook therefore
cannot, by itself, ground a URL citation. This module provides the narrow bridge
an application adapter can call *after* it has received a successful response:

    digest = record_url_read(collector, scope_id, url, response)

The collector signs the URL identity and the response digest. The verdict keeps
the distinction explicit: this is application evidence, not kernel network
proof, and an external MCP call that has no local receipt still stays OPAQUE.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from .evidence import normalize_path


def _payload_bytes(payload: Any) -> bytes | None:
    """Return raw response bytes when the object exposes them safely.

    ``requests.Response`` / ``httpx.Response`` expose ``.content``; a plain
    ``str`` or bytes-like body is accepted directly. The function never calls
    ``read()`` on a response object, because doing so would consume a stream the
    caller still needs.
    """
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, (bytearray, memoryview)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if payload is None:
        return None
    try:
        content = getattr(payload, "content", None)
    except Exception:  # noqa: BLE001 - a property may raise on an exhausted stream
        content = None
    if isinstance(content, bytes):
        return content
    if isinstance(content, (bytearray, memoryview)):
        return bytes(content)
    try:
        text = getattr(payload, "text", None)
    except Exception:  # noqa: BLE001
        text = None
    if isinstance(text, str):
        return text.encode("utf-8")
    return None


def _payload_digest(payload: Any) -> str:
    raw = _payload_bytes(payload)
    if raw is not None:
        return "sha256:" + hashlib.sha256(raw).hexdigest()
    # JSON-ish objects are common tool outputs; reuse the stable canonical
    # digest from the MCP adapter rather than repr() of an object address.
    from .mcp import payload_digest

    return payload_digest(payload)


def _validate_url(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise ValueError("url must be a non-empty string")
    parsed = urlsplit(url)
    if (
        parsed.scheme.lower() not in {"http", "https", "ftp"}
        or not parsed.netloc
        or not parsed.hostname
    ):
        raise ValueError("url must be an absolute http, https, or ftp URL")
    normalized = normalize_path(url)
    if "://" not in normalized:
        raise ValueError("url could not be normalized to an absolute URL")
    return normalized


def record_url_read(
    collector: Any,
    scope_id: str,
    url: str,
    payload: Any = None,
    *,
    digest: str | None = None,
    nonempty: bool | None = None,
) -> str:
    """Record one successful application URL read and return its payload digest.

    Call this only after the HTTP client has completed a request and the caller
    has the response (or an already-computed digest). It records a URL identity
    with credentials/query/fragment removed and a SHA-256 over the response
    bytes, then lets the normal collector/verdict path decide whether the cited
    URL matched.

    ``nonempty=False`` records the URL as an open-only event. That deliberately
    fails closed: a URL opened but returning no bytes must not ground a finding.
    For a streamed or otherwise opaque response object, pass the digest explicitly
    and let ``nonempty`` state whether bytes arrived; when in doubt, leave it True
    only if the caller has verified the body was non-empty.
    """
    if payload is None and digest is None:
        raise ValueError("payload or digest is required for a URL read")
    canonical_url = _validate_url(url)
    if digest is None:
        digest = _payload_digest(payload)
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("digest must be a sha256: content digest")

    if nonempty is None:
        raw = _payload_bytes(payload)
        if raw is not None:
            nonempty = bool(raw)
        elif payload is None:
            nonempty = True
        elif isinstance(payload, (Mapping, list, tuple, set, frozenset)):
            nonempty = bool(payload)
        else:
            # The caller supplied a successful response object. Its body is not
            # inspectable without consuming it; the documented contract is that
            # this helper is called after a non-empty response.
            nonempty = True
    if nonempty:
        collector.ingest_events(
            scope_id,
            observed_urls=[canonical_url],
            payload_digests=[digest],
        )
    else:
        # ``opened_only`` is the existing fail-closed category for a source that
        # was opened but produced no bytes. A cited URL in this list makes the
        # verdict OPAQUE(open_only) rather than allowing a false GROUNDED.
        collector.ingest_events(
            scope_id,
            opened_only=[canonical_url],
            payload_digests=[digest],
        )
    return digest


__all__ = ["record_url_read"]
