"""Backend abstraction for in-process and rootless evidence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Mapping

from .collector import RootlessCollector
from .evidence import ScopeRegistration, VerifiedScopeEvidence


class EvidenceBackend(ABC):
    """The small seam the core observer needs for external evidence."""

    @abstractmethod
    def open_scope(self, registration: ScopeRegistration) -> None:
        """Open a scope before the observed command is released."""

    @abstractmethod
    def close_and_fetch(self, scope_id: str) -> VerifiedScopeEvidence:
        """Close the scope, verify its receipt, and return evidence."""

    def ingest_strace_path(self, scope_id: str, path: str) -> Any:
        raise NotImplementedError

    def ingest_events(
        self,
        scope_id: str,
        *,
        observed_files: Iterable[str] = (),
        observed_dirs: Iterable[str] = (),
        opened_only: Iterable[str] = (),
        payload_digests: Iterable[str] = (),
        opaque_reasons: Iterable[str] = (),
    ) -> None:
        raise NotImplementedError


class InProcessBackend(EvidenceBackend):
    """Marker backend that preserves the original process-local observer."""

    def open_scope(self, registration: ScopeRegistration) -> None:
        raise RuntimeError("InProcessBackend is handled by mareforma_pro.observe")

    def close_and_fetch(self, scope_id: str) -> VerifiedScopeEvidence:
        raise RuntimeError("InProcessBackend is handled by mareforma_pro.observe")


class CollectorBackend(EvidenceBackend):
    """Wrap a :class:`RootlessCollector` as an external evidence backend."""

    def __init__(self, collector: RootlessCollector) -> None:
        self.collector = collector

    def open_scope(self, registration: ScopeRegistration) -> None:
        self.collector.open_scope(
            registration.scope_id,
            mount_map=registration.mount_map,
            tmpfs_mounts=registration.tmpfs_mounts,
            root_passthrough=registration.root_passthrough,
            traceparent=registration.traceparent,
            parent_scope_id=registration.parent_scope_id,
            evidence_level=registration.evidence_level,
            read_semantics=registration.read_semantics,
            collector_mode=registration.collector_mode,
            coverage_roots=registration.coverage_roots,
        )

    def close_and_fetch(self, scope_id: str) -> VerifiedScopeEvidence:
        evidence = self.collector.close_scope(scope_id)
        return self.collector.verify(evidence)

    def ingest_strace_path(self, scope_id: str, path: str) -> Any:
        return self.collector.ingest_strace_path(scope_id, path)

    def ingest_events(
        self,
        scope_id: str,
        *,
        observed_files: Iterable[str] = (),
        observed_dirs: Iterable[str] = (),
        opened_only: Iterable[str] = (),
        payload_digests: Iterable[str] = (),
        opaque_reasons: Iterable[str] = (),
    ) -> None:
        self.collector.ingest_events(
            scope_id,
            observed_files=observed_files,
            observed_dirs=observed_dirs,
            opened_only=opened_only,
            payload_digests=payload_digests,
            opaque_reasons=opaque_reasons,
        )

    def verify(self, receipt: Mapping[str, Any] | object) -> VerifiedScopeEvidence:
        return self.collector.verify(receipt)  # type: ignore[arg-type]
