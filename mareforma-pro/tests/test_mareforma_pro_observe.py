"""External receipt -> core grounding bridge."""

from __future__ import annotations

import json
from pathlib import Path

import mareforma
from mareforma.observe import GroundingVerdict, ObservedGrounding
from mareforma_pro.collector import RootlessCollector
from mareforma_pro.observe import (
    CollectorBackend,
    ReceiptVerifier,
    RootlessObservation,
    assert_claim_from_receipt,
    observe,
    verdict_from_evidence,
    verify_and_verdict,
)
from mareforma_pro.evidence import ScopeRegistration


def _receipt(tmp_path: Path, *, read: bool = True):
    data = tmp_path / "data.csv"
    data.write_text("metric,value\naccuracy,0.9\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    collector.open_scope("scp_observe", root_passthrough=True)
    if read:
        collector.ingest_events("scp_observe", observed_files=[str(data)])
    evidence = collector.close_scope("scp_observe")
    return data, evidence, collector


def test_verified_receipt_mints_a_core_grounded_verdict(tmp_path):
    data, evidence, _ = _receipt(tmp_path)
    verdict = verify_and_verdict(evidence.to_receipt_dict(), secret="secret", cites=[str(data)])
    assert verdict.grounding is ObservedGrounding.GROUNDED
    assert verdict.read_semantics == "READ_INTENT"
    assert verdict.evidence_level == "USER_TRACE"
    assert "opaque_reasons" not in verdict.to_signed_dict()

    root = tmp_path / "graph"
    with mareforma.open(root) as graph:
        cid = graph.assert_claim(
            "the measured value was read from the dataset",
            observed_grounding=verdict.to_signed_dict(),
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "GROUNDED"
    assert "provenance" not in stored


def test_unsigned_external_dict_is_still_declared(tmp_path):
    data, evidence, _ = _receipt(tmp_path)
    record = evidence.to_receipt_dict()
    record["hmac_signature"] = "hmac-sha256:" + "0" * 64
    root = tmp_path / "graph"
    with mareforma.open(root) as graph:
        cid = assert_claim_from_receipt(
            graph,
            "a rejected receipt",
            receipt=record,
            secret="secret",
            cites=[str(data)],
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "OPAQUE"
    assert stored["provenance"] == "DECLARED"
    assert "unsigned_declared" in stored.get("opaque_reasons", [])


def test_collector_backend_observe_context(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    backend = CollectorBackend(collector)
    registration = ScopeRegistration(scope_id="scp_ctx", root_passthrough=True)
    with observe(cites=str(data), backend=backend, registration=registration) as obs:
        assert isinstance(obs, RootlessObservation)
        collector.ingest_events("scp_ctx", observed_files=[str(data)])
    assert obs.verdict.grounding is ObservedGrounding.GROUNDED
    assert obs.receipt is not None


def test_missing_read_without_blind_spot_is_ungrounded(tmp_path):
    data, evidence, _ = _receipt(tmp_path, read=False)
    verdict = verify_and_verdict(evidence.to_receipt_dict(), secret="secret", cites=[str(data)])
    assert verdict.grounding is ObservedGrounding.UNGROUNDED


def test_open_only_cited_file_is_opaque(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    collector.open_scope("scp_open", root_passthrough=True)
    collector.ingest_events("scp_open", opened_only=[str(data)])
    evidence = collector.close_scope("scp_open")
    verdict = verify_and_verdict(evidence.to_receipt_dict(), secret="secret", cites=[str(data)])
    assert verdict.grounding is ObservedGrounding.OPAQUE
    assert "open_only" in verdict.opaque_reasons


def test_in_process_backend_still_preserves_core_behavior(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    with observe(cites=str(data)) as obs:
        data.read_text()
    assert obs.verdict.grounding is ObservedGrounding.GROUNDED


def test_core_accepts_a_verified_external_receipt_when_given_a_verifier(tmp_path):
    data, evidence, collector = _receipt(tmp_path)
    verifier = ReceiptVerifier(collector, cites=str(data))
    root = tmp_path / "graph_verifier"
    with mareforma.open(root, external_grounding_verifier=verifier) as graph:
        cid = graph.assert_claim(
            "the external receipt names a read",
            observed_grounding=evidence.to_receipt_dict(),
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "GROUNDED"
    assert "provenance" not in stored


def test_assert_claim_from_receipt_accepts_a_valid_receipt(tmp_path):
    data, evidence, _ = _receipt(tmp_path)
    root = tmp_path / "graph_wrapper"
    with mareforma.open(root) as graph:
        cid = assert_claim_from_receipt(
            graph,
            "the verified receipt grounds the claim",
            receipt=evidence.to_receipt_dict(),
            secret="secret",
            cites=[str(data)],
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "GROUNDED"


def test_core_without_a_verifier_declares_a_raw_external_receipt(tmp_path):
    data, evidence, _ = _receipt(tmp_path)
    root = tmp_path / "graph_raw_external"
    with mareforma.open(root) as graph:
        cid = graph.assert_claim(
            "a raw external receipt cannot speak for itself",
            observed_grounding=evidence.to_receipt_dict(),
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "OPAQUE"
    assert stored["provenance"] == "DECLARED"
    assert "unsigned_declared" in stored["opaque_reasons"]


def test_receipt_verifier_rejects_a_tampered_receipt(tmp_path):
    data, evidence, collector = _receipt(tmp_path)
    record = evidence.to_receipt_dict()
    record["observed_files"].append(str(tmp_path / "fabricated.csv"))
    verifier = ReceiptVerifier(collector, cites=str(data))
    root = tmp_path / "graph_tampered"
    with mareforma.open(root, external_grounding_verifier=verifier) as graph:
        cid = graph.assert_claim(
            "a tampered external receipt is not grounding",
            observed_grounding=record,
        )
        stored = json.loads(graph.get_claim(cid)["observed_grounding"])
    assert stored["grounding"] == "OPAQUE"
    assert stored["provenance"] == "DECLARED"
    assert "unsigned_declared" in stored["opaque_reasons"]


def test_no_cited_source_is_opaque_even_when_a_read_was_observed(tmp_path):
    data, evidence, _ = _receipt(tmp_path)
    verdict = verify_and_verdict(evidence.to_receipt_dict(), secret="secret", cites=None)
    assert verdict.grounding is ObservedGrounding.OPAQUE
    assert "no_cited_source" in verdict.opaque_reasons
    assert verdict.evidence_level == "USER_TRACE"

def test_verified_scope_evidence_can_be_reverified_without_unwrapping(tmp_path):
    data, evidence, collector = _receipt(tmp_path)
    verified = collector.verify(evidence)
    verdict = verify_and_verdict(verified, secret="secret", cites=str(data))
    assert verdict.grounding is ObservedGrounding.GROUNDED


def test_citation_outside_recorded_coverage_is_opaque_not_ungrounded(tmp_path):
    inside = tmp_path / "inside.csv"
    outside = tmp_path.parent / f"{tmp_path.name}-outside.csv"
    inside.write_text("x\n", encoding="utf-8")
    outside.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    collector.open_scope(
        "scp_bounded",
        coverage_roots=[str(tmp_path)],
        collector_mode="fuse_read_proxy",
        evidence_level="USER_FUSE",
        read_semantics="READ_BYTES",
    )
    evidence = collector.close_scope("scp_bounded")
    verdict = verify_and_verdict(
        evidence.to_receipt_dict(), secret="secret", cites=[str(outside)]
    )
    assert verdict.grounding is ObservedGrounding.OPAQUE
    assert "unmapped_sandbox_path" in verdict.opaque_reasons
    assert evidence.coverage_roots == (str(tmp_path),)


def test_citation_inside_coverage_without_read_stays_ungrounded(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    collector = RootlessCollector("secret")
    collector.open_scope(
        "scp_bounded_negative",
        coverage_roots=[str(tmp_path)],
        collector_mode="fuse_read_proxy",
        evidence_level="USER_FUSE",
        read_semantics="READ_BYTES",
    )
    evidence = collector.close_scope("scp_bounded_negative")
    verdict = verify_and_verdict(
        evidence.to_receipt_dict(), secret="secret", cites=[str(data)]
    )
    assert verdict.grounding is ObservedGrounding.UNGROUNDED
