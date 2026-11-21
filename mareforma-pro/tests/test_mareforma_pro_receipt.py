"""Receipt signing, expiry, tamper, and collector finalization."""

from __future__ import annotations

import time

import pytest

from mareforma_pro.collector import RootlessCollector
from mareforma_pro.errors import ReceiptError
from mareforma_pro.paths import MountResolver
from mareforma_pro.receipt import sign_receipt, verify_scope_receipt


@pytest.fixture
def evidence():
    collector = RootlessCollector("secret", receipt_ttl=30, clock=lambda: 100.0)
    collector.open_scope("scp_1", MountResolver.from_mounts({}, root_passthrough=True))
    collector.ingest_events("scp_1", observed_files=["/data/a.csv"])
    return collector.close_scope("scp_1")


def test_receipt_round_trip(evidence):
    receipt = evidence.to_receipt_dict()
    verified = verify_scope_receipt(receipt, "secret", now=101.0)
    assert verified.evidence.scope_id == "scp_1"
    assert verified.evidence.observed_files == ("/data/a.csv",)


def test_receipt_tamper_is_rejected(evidence):
    receipt = evidence.to_receipt_dict()
    receipt["observed_files"].append("/data/fake.csv")
    with pytest.raises(ReceiptError):
        verify_scope_receipt(receipt, "secret", now=101.0)


def test_receipt_expiry_is_rejected(evidence):
    receipt = evidence.to_receipt_dict()
    with pytest.raises(ReceiptError):
        verify_scope_receipt(receipt, "secret", now=10_000.0)


def test_signature_is_canonical(evidence):
    receipt = evidence.to_receipt_dict()
    assert receipt["hmac_signature"] == sign_receipt(receipt, "secret")
    assert verify_scope_receipt(receipt, "secret", now=101.0).evidence.scope_id == "scp_1"

def test_normalize_path_decodes_bytes():
    from mareforma_pro.evidence import normalize_path

    assert normalize_path(b"/tmp/data.csv") == "/tmp/data.csv"

def test_scope_id_cannot_escape_the_trace_directory(tmp_path):
    from mareforma_pro.runner import RootlessBwrapRunner

    runner = RootlessBwrapRunner(
        RootlessCollector("secret"),
        log_dir=tmp_path / "logs",
        strace_binary="/usr/bin/strace",
        bwrap_binary="/usr/bin/bwrap",
    )
    path, _created = runner._private_log("../../escape")
    assert path.parent == tmp_path / "logs"
    assert ".." not in path.name

