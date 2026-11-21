"""Canonical HMAC receipts for the rootless collector."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Mapping

from .errors import ReceiptError
from .evidence import (
    RECEIPT_DOMAIN,
    RECEIPT_SCHEMA,
    ScopeEvidence,
    VerifiedScopeEvidence,
)

_REQUIRED = (
    "schema_version",
    "scope_id",
    "collector_id",
    "collector_mode",
    "evidence_level",
    "read_semantics",
    "opened_at",
    "closed_at",
    "expires_at",
    "observed_files",
    "observed_dirs",
    "opened_only",
    "unmapped_paths",
    "opaque_reasons",
    "payload_digests",
    "processes",
    "socket_events",
    "hmac_signature",
)


def _secret_bytes(secret: str | bytes) -> bytes:
    value = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not isinstance(value, (bytes, bytearray)) or not value:
        raise ValueError("HMAC secret must be a non-empty str or bytes")
    return bytes(value)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "hmac_signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(payload: Mapping[str, Any], secret: str | bytes) -> str:
    digest = hmac.new(_secret_bytes(secret), RECEIPT_DOMAIN + canonical_bytes(payload), hashlib.sha256)
    return "hmac-sha256:" + digest.hexdigest()


def verify_signature(payload: Mapping[str, Any], secret: str | bytes) -> bool:
    provided = payload.get("hmac_signature") if isinstance(payload, Mapping) else None
    if not isinstance(provided, str) or not provided.startswith("hmac-sha256:"):
        return False
    try:
        expected = sign_receipt(payload, secret)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, provided)


def verify_scope_receipt(
    receipt: Mapping[str, Any],
    secret: str | bytes,
    *,
    now: float | None = None,
) -> VerifiedScopeEvidence:
    """Verify and decode a collector receipt, failing closed on every error."""
    if not isinstance(receipt, Mapping):
        raise ReceiptError("receipt must be a mapping")
    missing = [key for key in _REQUIRED if key not in receipt]
    if missing:
        raise ReceiptError(f"receipt is missing fields: {', '.join(missing)}")
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ReceiptError("unsupported receipt schema")
    if not verify_signature(receipt, secret):
        raise ReceiptError("receipt HMAC verification failed")
    try:
        evidence = ScopeEvidence.from_receipt_dict(receipt)
    except (TypeError, ValueError) as exc:
        raise ReceiptError(f"receipt could not be decoded: {exc}") from exc
    if not evidence.scope_id:
        raise ReceiptError("receipt has an empty scope_id")
    if evidence.closed_at < evidence.opened_at:
        raise ReceiptError("receipt closes before it opens")
    check_at = time.time() if now is None else float(now)
    if evidence.expires_at and check_at > evidence.expires_at:
        raise ReceiptError("receipt has expired")
    return VerifiedScopeEvidence(evidence=evidence, verified_at=check_at)
