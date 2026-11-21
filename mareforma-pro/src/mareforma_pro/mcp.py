"""MCP correlation and application-layer observations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable, Mapping

from .collector import RootlessCollector
from .evidence import OPAQUE_EXTERNAL_MCP, OPAQUE_STATIC_BINARY_UNTRACED
from .jupyter import audit_scope
from .observe import verdict_from_evidence


def payload_digest(payload: Any) -> str:
    """Canonical SHA-256 for a JSON response, with a stable repr fallback."""
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        data = raw.encode("utf-8")
    except (TypeError, ValueError):
        data = repr(payload).encode("utf-8", "replace")
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class MCPContext:
    scope_id: str
    traceparent: str | None = None
    parent_scope_id: str | None = None

    def meta(self) -> dict[str, str]:
        out = {"mareforma_scope_id": self.scope_id}
        if self.traceparent:
            out["traceparent"] = self.traceparent
        if self.parent_scope_id:
            out["mareforma_parent_scope_id"] = self.parent_scope_id
        return out

    @classmethod
    def from_meta(cls, meta: Mapping[str, Any] | None) -> "MCPContext | None":
        if not isinstance(meta, Mapping):
            return None
        scope_id = meta.get("mareforma_scope_id")
        if not isinstance(scope_id, str) or not scope_id:
            return None
        traceparent = meta.get("traceparent")
        parent = meta.get("mareforma_parent_scope_id")
        return cls(
            scope_id=scope_id,
            traceparent=traceparent if isinstance(traceparent, str) else None,
            parent_scope_id=parent if isinstance(parent, str) else None,
        )


def inject_meta(params: Mapping[str, Any], context: MCPContext) -> dict[str, Any]:
    """Return a copy of MCP params with Mareforma metadata in ``_meta``."""
    out = dict(params)
    existing = out.get("_meta")
    merged = dict(existing) if isinstance(existing, Mapping) else {}
    merged.update(context.meta())
    out["_meta"] = merged
    return out


def record_mcp_payload(
    collector: RootlessCollector,
    scope_id: str,
    response: Any,
    *,
    external: bool = True,
) -> str:
    digest = payload_digest(response)
    reasons = [OPAQUE_EXTERNAL_MCP] if external else []
    collector.ingest_events(
        scope_id,
        payload_digests=[digest],
        opaque_reasons=reasons,
    )
    return digest


@dataclass
class MCPObservation:
    scope_id: str
    evidence: Any
    verdict: Any

    @property
    def receipt(self) -> dict[str, Any]:
        return self.evidence.receipt


class MCPApplicationMiddleware:
    """Wrap one MCP tool operation and sign an application receipt.

    The wrapper never turns an external server into local kernel evidence. For
    ``external=True`` the resulting verdict stays OPAQUE via ``external_mcp``;
    callers can still compare the response digest on the client side.
    """

    def __init__(
        self,
        collector: RootlessCollector,
        *,
        cites: str | list[str] | None = None,
        external: bool = False,
        mount_map: dict[str, str] | None = None,
        root_passthrough: bool = True,
    ) -> None:
        self.collector = collector
        self.cites = cites
        self.external = external
        self.mount_map = mount_map or {}
        self.root_passthrough = root_passthrough
        self.last: MCPObservation | None = None

    def __call__(
        self,
        params: Mapping[str, Any],
        handler: Callable[[], Any],
    ) -> Any:
        context = MCPContext.from_meta(params.get("_meta") if isinstance(params, Mapping) else None)
        if context is None:
            from uuid import uuid4

            context = MCPContext(scope_id="mcp_" + uuid4().hex[:16])
        scope_id = context.scope_id
        self.collector.open_scope(
            scope_id,
            mount_map=self.mount_map,
            root_passthrough=self.root_passthrough,
            traceparent=context.traceparent,
            parent_scope_id=context.parent_scope_id,
            evidence_level="APPLICATION_MCP",
            read_semantics="OPEN_INTENT",
        )
        try:
            with audit_scope(self.collector, scope_id):
                result = handler()
            record_mcp_payload(self.collector, scope_id, result, external=self.external)
            if self.external:
                self.collector.ingest_events(scope_id, opaque_reasons=[OPAQUE_EXTERNAL_MCP])
            evidence = self.collector.close_scope(scope_id)
            verified = self.collector.verify(evidence)
            self.last = MCPObservation(
                scope_id=scope_id,
                evidence=verified,
                verdict=verdict_from_evidence(verified, cites=self.cites),
            )
            return result
        except Exception:
            # Always close a scope opened by this wrapper, then re-raise the
            # caller's error; no receipt is presented as a successful call.
            try:
                self.collector.close_scope(scope_id)
            except Exception:
                pass
            raise
