"""Turn verified rootless evidence into a signed Mareforma grounding record."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import os
from typing import Any, Iterable, Iterator

from mareforma.observe import ScopeNotClosedError
from mareforma.observe import observe as _core_observe
from mareforma.observe._citation import citation_kind, cited_set, normalize_identifier
from mareforma.observe._verdict import (
    GroundingVerdict,
    ObservedGrounding,
    ReadRecord,
    SeamEvent,
    _mint,
)

from .backend import CollectorBackend, EvidenceBackend, InProcessBackend
from .collector import RootlessCollector
from .evidence import (
    OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE,
    OPAQUE_EXTERNAL_MCP,
    OPAQUE_NO_CITED_SOURCE,
    OPAQUE_OPEN_ONLY,
    OPAQUE_SOCKET_UNBOUND,
    OPAQUE_TRACE_INCOMPLETE,
    OPAQUE_UNMAPPED_SANDBOX,
    OPAQUE_UNSIGNED_DECLARED,
    SOURCE_NOT_APPLICABLE,
    ScopeEvidence,
    ScopeRegistration,
    VerifiedScopeEvidence,
)


@dataclass
class RootlessObservation:
    """Observation handle returned by :func:`observe`."""

    _core_handle: Any = None
    _verified: VerifiedScopeEvidence | None = None
    _verdict: GroundingVerdict | None = None
    _close_error: BaseException | None = None

    @property
    def verdict(self) -> GroundingVerdict:
        if self._verdict is None:
            raise ScopeNotClosedError(
                "the grounding verdict is available only after the observe scope closes"
            )
        return self._verdict

    @property
    def evidence(self) -> VerifiedScopeEvidence | None:
        return self._verified

    @property
    def receipt(self) -> dict[str, Any] | None:
        return None if self._verified is None else self._verified.receipt

    @property
    def opaque_reasons(self) -> tuple[str, ...]:
        if self._verdict is None:
            return ()
        reasons = getattr(self._verdict, "opaque_reasons", None)
        if reasons is not None:
            return tuple(reasons)
        # The published core 0.4.0 wheel predates the diagnostic fields. Its
        # seams still carry the same names, so an older install can expose the
        # fail-closed reasons without pretending they are a new field.
        return tuple(
            dict.fromkeys(
                seam.kind for seam in getattr(self._verdict, "seams", ()) if seam.kind
            )
        )

    @property
    def close_error(self) -> BaseException | None:
        return self._close_error

    def assert_claim(self, graph: Any, text: str, **kwargs: Any) -> str:
        """Assert a claim with the minted external verdict."""
        return graph.assert_claim(
            text,
            observed_grounding=self.verdict.to_signed_dict(),
            **kwargs,
        )


def _is_open_only_relevant(paths: Iterable[str], cited: tuple[str, ...]) -> bool:
    cited_set_ = set(cited)
    for path in paths:
        norm = normalize_identifier(path)
        if norm in cited_set_:
            return True
    return False


def _seams(reasons: Iterable[str], *, opened_only: Iterable[str] = ()) -> tuple[SeamEvent, ...]:
    reasons = tuple(dict.fromkeys(reasons))
    opened = tuple(dict.fromkeys(opened_only))
    seams: list[SeamEvent] = []
    for reason in reasons:
        detail = ", ".join(opened) if reason == OPAQUE_OPEN_ONLY and opened else reason
        seams.append(SeamEvent(kind=reason, detail=detail))
    return tuple(seams)


_CORE_VERDICT_FIELDS = frozenset(field.name for field in fields(GroundingVerdict))
_DIAGNOSTIC_FIELDS = ("opaque_reasons", "read_semantics", "evidence_level")


def _make_verdict(**kwargs: Any) -> GroundingVerdict:
    """Build a core verdict, tolerating the released 0.4.0 wheel.

    The diagnostics were added to the core checkout after the published
    0.4.0 wheel. A standalone ``mareforma-pro`` install may therefore receive
    the older dataclass even though the source tree here has the fields. Keep
    the same fail-closed decision and preserve the diagnostics in the human
    reason; never drop a blind spot just because the installed core cannot
    carry it as a separate field.
    """
    folded: list[str] = []
    for name in _DIAGNOSTIC_FIELDS:
        if name in _CORE_VERDICT_FIELDS:
            continue
        value = kwargs.pop(name, None)
        if not value:
            continue
        text = ",".join(map(str, value)) if name == "opaque_reasons" else str(value)
        folded.append(f"{name}={text}")
    if folded:
        reason = str(kwargs.get("reason") or "").rstrip()
        kwargs["reason"] = (reason + " " if reason else "") + "[" + "; ".join(folded) + "]"
    return GroundingVerdict(**kwargs)


def verdict_from_evidence(
    verified: VerifiedScopeEvidence,
    *,
    cites: str | Iterable[str] | None,
) -> GroundingVerdict:
    """Convert a verified rootless receipt into a minted core verdict.

    The receipt must already have passed HMAC verification. A raw receipt is
    never accepted here: callers use :func:`verify_receipt`/``collector.verify``
    first, so an unsigned or tampered record falls into the core's DECLARED
    path instead of becoming GROUNDED.
    """
    if not isinstance(verified, VerifiedScopeEvidence):
        raise TypeError("verdict_from_evidence requires VerifiedScopeEvidence")
    evidence = verified.evidence
    cited = cited_set(cites)
    observed_files = tuple(
        dict.fromkeys(
            normalize_identifier(path)
            for path in evidence.observed_files
            if normalize_identifier(path)
        )
    )
    observed_urls = tuple(
        dict.fromkeys(
            normalize_identifier(url)
            for url in evidence.observed_urls
            if normalize_identifier(url)
        )
    )
    observed = tuple(dict.fromkeys((*observed_files, *observed_urls)))
    opened_only = tuple(
        dict.fromkeys(
            normalize_identifier(path)
            for path in evidence.opened_only
            if normalize_identifier(path)
        )
    )
    reasons = set(evidence.opaque_reasons)
    # ``opened_only`` is emitted for every read-open path, including system
    # libraries. It is only a blind spot for a cited source; keep unrelated
    # opens from turning every scope into OPAQUE.
    reasons.discard(OPAQUE_OPEN_ONLY)

    if not cited:
        computation_only = (
            evidence.source_requirement == SOURCE_NOT_APPLICABLE
            or evidence.read_semantics == "COMPUTED_ONLY"
        )
        reasons.add(
            OPAQUE_COMPUTED_NO_EXTERNAL_SOURCE
            if computation_only
            else OPAQUE_NO_CITED_SOURCE
        )
        return _mint(
            _make_verdict(
                grounding=ObservedGrounding.OPAQUE,
                reason=(
                    "the rootless scope was declared computation-only; "
                    "no external source was expected"
                    if computation_only
                    else "the rootless scope was observed but names no cited source"
                ),
                opaque_reasons=tuple(sorted(reasons)),
                seams=_seams(reasons),
                read_semantics=evidence.read_semantics,
                evidence_level=evidence.evidence_level,
            )
        )

    # FUSE sees one explicitly bounded view, not the whole host. A citation
    # outside every recorded coverage root was never observable by this
    # backend, so absence cannot become a confident UNGROUNDED. Older
    # receipts carry no roots and keep the legacy scope-wide behavior.
    coverage_roots = tuple(
        dict.fromkeys(
            normalize_identifier(root)
            for root in evidence.coverage_roots
            if normalize_identifier(root)
        )
    )
    if coverage_roots:
        uncovered = tuple(
            source
            for source in cited
            if source.startswith("/")
            and not any(_within_coverage(source, root) for root in coverage_roots)
        )
        if uncovered:
            reasons.add(OPAQUE_UNMAPPED_SANDBOX)

    # A local application audit hook cannot see HTTP response bytes. If a URL is
    # cited in such a scope and the adapter did not supply an explicit
    # ``observed_urls`` manifest, absence is not evidence: it is an unobserved
    # network boundary. A dedicated application-http scope that did report no
    # URL is different: its adapter owns the read manifest, so a non-match can
    # stay UNGROUNDED. FUSE and bounded views are also OPAQUE for URLs because
    # their coverage roots describe files, not network delivery.
    url_citations = tuple(c for c in cited if citation_kind(c) == "url")
    manifest_scope = (
        bool(observed_urls)
        or evidence.collector_mode == "application_http"
        or evidence.read_semantics == "URL_READ"
    )
    network_unobservable = (
        evidence.collector_mode
        in {"application_python_audit", "application_mcp", "fuse_read_proxy"}
        or evidence.read_semantics == "OPEN_INTENT"
        or bool(coverage_roots)
    )
    if url_citations and not manifest_scope and network_unobservable:
        reasons.add(OPAQUE_TRACE_INCOMPLETE)

    grounded_sources = tuple(c for c in cited if c in observed)
    relevant_open_only = _is_open_only_relevant(opened_only, cited)
    if relevant_open_only:
        reasons.add(OPAQUE_OPEN_ONLY)
    if evidence.socket_events and not grounded_sources:
        # A socket can carry bytes that become a cited file. If a cited file
        # read was observed directly, that positive evidence stands on its own;
        # if not, the socket seam makes the absence fail closed.
        reasons.add(OPAQUE_SOCKET_UNBOUND)

    application_open = evidence.read_semantics == "OPEN_INTENT"
    fuse_read = evidence.collector_mode == "fuse_read_proxy"
    read_kind = (
        "application-open"
        if application_open
        else "fuse-read"
        if fuse_read
        else "rootless-read"
    )
    base = dict(
        cited_sources=cited,
        reads=tuple(
            ReadRecord(
                kind=read_kind,
                identifier=path,
                nonempty=True,
                content_address=None,
            )
            for path in observed_files
        )
        + tuple(
            ReadRecord(
                kind="application-url",
                identifier=url,
                nonempty=True,
                content_address=None,
            )
            for url in observed_urls
        ),
        reads_seen=len(observed_files) + len(observed_urls),
        opens_detected=len(opened_only) + len(observed),
        opaque_reasons=tuple(sorted(reasons)),
        read_semantics=evidence.read_semantics,
        evidence_level=evidence.evidence_level,
    )
    seams = _seams(reasons, opened_only=opened_only)

    if OPAQUE_EXTERNAL_MCP in reasons and grounded_sources:
        # An external MCP server performs its reads outside this process. A
        # locally supplied URL manifest, or a local read in the wrapper, cannot
        # turn that remote execution into local grounding evidence. Keep the
        # positive read records for audit, but do not claim the cited source is
        # grounded by the remote call.
        grounded_sources = ()

    if grounded_sources:
        url_grounded = any(source in observed_urls for source in grounded_sources)
        return _mint(
            _make_verdict(
                grounding=ObservedGrounding.GROUNDED,
                reason=(
                    "an application-level URL read manifest matched the cited URL; "
                    "this is application evidence, not kernel network proof"
                    if url_grounded
                    else "an application-level read-open matched the cited source; "
                    "this is open intent, not proof that bytes were consumed"
                    if application_open
                    else "a rootless FUSE read matched the cited source; "
                    "the bytes crossed the read-only view"
                    if fuse_read
                    else "a rootless strace read matched the cited source; "
                    "this is read evidence, not a proof that the consumer used the result"
                ),
                grounded_sources=grounded_sources,
                seams=seams,
                **base,
            )
        )

    if reasons:
        return _mint(
            _make_verdict(
                grounding=ObservedGrounding.OPAQUE,
                reason=(
                    "the observation did not establish a cited read and discloses "
                    "a blind spot: " + ", ".join(sorted(reasons))
                ),
                seams=seams,
                **base,
            )
        )

    return _mint(
        _make_verdict(
            grounding=ObservedGrounding.UNGROUNDED,
            reason=(
                "the cited source was not opened by the application hook; "
                "no blind spot was recorded"
                if application_open
                else "the cited source was not read through the rootless FUSE view; "
                "no blind spot was recorded"
                if fuse_read
                else "the cited source was not read in a complete rootless trace; "
                "no blind spot was recorded"
            ),
            seams=seams,
            **base,
        )
    )


def _within_coverage(identifier: str, root: str) -> bool:
    """Whether a normalized citation lies under a normalized coverage root."""
    if not identifier.startswith("/") or not root.startswith("/"):
        return False
    try:
        return os.path.commonpath((identifier, root)) == root
    except ValueError:
        return False


@contextmanager
def observe(
    cites: str | Iterable[str] | None = None,
    *,
    backend: EvidenceBackend | RootlessCollector | None = None,
    registration: ScopeRegistration | None = None,
) -> Iterator[RootlessObservation]:
    """Observe a span backed by the core observer or a rootless collector.

    With ``backend=None`` or an ``InProcessBackend``, this is the original
    process-local ``mareforma.observe`` API. With ``CollectorBackend``, the
    caller supplies a registration and the collector signs the scope at exit.
    """
    if backend is None or isinstance(backend, InProcessBackend):
        handle = RootlessObservation()
        core_handle = None
        try:
            with _core_observe(cites=cites) as core_handle:
                handle._core_handle = core_handle
                yield handle
        finally:
            if core_handle is not None:
                handle._verdict = core_handle.verdict
        return

    if registration is None:
        raise ValueError("registration is required with a collector backend")
    if isinstance(backend, RootlessCollector):
        backend = CollectorBackend(backend)
    handle = RootlessObservation()
    backend.open_scope(registration)
    try:
        yield handle
    finally:
        try:
            verified = backend.close_and_fetch(registration.scope_id)
        except BaseException as exc:  # noqa: BLE001 - never mask the body error
            handle._close_error = exc
            handle._verdict = _mint(
                _make_verdict(
                    grounding=ObservedGrounding.OPAQUE,
                    reason=f"rootless collector close failed: {type(exc).__name__}: {exc}",
                    opaque_reasons=(OPAQUE_TRACE_INCOMPLETE,),
                    read_semantics="READ_INTENT",
                    evidence_level="USER_TRACE",
                    seams=(SeamEvent(kind=OPAQUE_TRACE_INCOMPLETE, detail=str(exc)),),
                )
            )
        else:
            handle._verified = verified
            handle._verdict = verdict_from_evidence(verified, cites=cites)




class ReceiptVerifier:
    """Trusted verifier object for ``mareforma.open(..., verifier)``.

    It owns the collector secret and citation set; the target process never gets
    the secret. Core calls it only when it has no locally minted verdict for the
    record, so the normal in-process observer path remains unchanged.
    """

    def __init__(self, collector: RootlessCollector, cites: str | Iterable[str] | None = None) -> None:
        self.collector = collector
        self.cites = cites

    def __call__(self, receipt: Any) -> GroundingVerdict | None:
        try:
            if isinstance(receipt, ScopeEvidence):
                payload = receipt.to_receipt_dict()
            else:
                payload = receipt
            return verdict_from_evidence(self.collector.verify(payload), cites=self.cites)
        except Exception:
            return None


def verify_and_verdict(
    receipt: Any,
    *,
    secret: str | bytes,
    cites: str | Iterable[str] | None,
    now: float | None = None,
) -> GroundingVerdict:
    """Verify a receipt in the SDK parent and mint a locally accepted verdict.

    This is the cross-process bridge. Unsigned or tampered receipts raise
    :class:`mareforma_pro.errors.ReceiptError`; callers that intentionally want
    the core DECLARED downgrade should pass the raw record to the graph without
    this function.
    """
    from .receipt import verify_scope_receipt

    if isinstance(receipt, ScopeEvidence):
        receipt = receipt.to_receipt_dict()
    elif isinstance(receipt, VerifiedScopeEvidence):
        receipt = receipt.receipt
    return verdict_from_evidence(
        verify_scope_receipt(receipt, secret, now=now),
        cites=cites,
    )


def verdict_or_opaque(receipt: Any, *, secret: str | bytes, cites: Any) -> GroundingVerdict:
    """Best-effort variant used by application boundaries."""
    try:
        return verify_and_verdict(receipt, secret=secret, cites=cites)
    except Exception as exc:  # noqa: BLE001 - fail closed at the boundary
        return _mint(
            _make_verdict(
                grounding=ObservedGrounding.OPAQUE,
                reason=f"external receipt unavailable: {type(exc).__name__}: {exc}",
                opaque_reasons=(OPAQUE_TRACE_INCOMPLETE,),
                read_semantics="READ_INTENT",
                evidence_level="USER_TRACE",
            )
        )


def assert_claim_from_receipt(
    graph: Any,
    text: str,
    *,
    receipt: Any,
    secret: str | bytes,
    cites: str | Iterable[str] | None,
    **claim_kwargs: Any,
) -> str:
    """Verify a rootless receipt and assert a claim with its minted verdict.

    This is the explicit bridge for the plan's ``assert_claim(valid HMAC)``
    rule. A bad, expired, or tampered receipt does not reach the graph as
    GROUNDED: it becomes a signed OPAQUE(``unsigned_declared``) record. Core
    Mareforma still refuses a raw external dict on its own, which is the right
    default when no verifier was supplied.
    """
    try:
        verdict = verify_and_verdict(receipt, secret=secret, cites=cites)
    except Exception as exc:
        from mareforma.observe._verdict import declared_external_record

        to_receipt = getattr(receipt, "to_receipt_dict", None)
        if callable(to_receipt):
            payload = to_receipt()
        elif isinstance(receipt, VerifiedScopeEvidence):
            payload = receipt.receipt
        elif isinstance(receipt, dict):
            payload = receipt
        else:
            payload = None
        if isinstance(payload, dict):
            # Keep the plan's provenance rule: a rejected external record is
            # DECLARED, not a computed verdict the SDK minted for it.
            payload = declared_external_record(
                payload,
                reason=f"external rootless receipt rejected: {exc}",
            )
            return graph.assert_claim(
                text,
                observed_grounding=payload,
                **claim_kwargs,
            )
        verdict = _mint(
            _make_verdict(
                grounding=ObservedGrounding.OPAQUE,
                reason=f"external rootless receipt rejected: {exc}",
                opaque_reasons=(OPAQUE_UNSIGNED_DECLARED,),
                read_semantics="READ_INTENT",
                evidence_level="USER_TRACE",
            )
        )
    return graph.assert_claim(
        text,
        observed_grounding=verdict.to_signed_dict(),
        **claim_kwargs,
    )
