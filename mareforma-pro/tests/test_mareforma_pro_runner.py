"""Real-ish rootless bwrap/strace regression cases, skipped on hostile hosts."""

from __future__ import annotations

import shutil

import pytest

from mareforma_pro.collector import RootlessCollector
from mareforma_pro.errors import ReceiptError
from mareforma_pro.receipt import verify_scope_receipt
from mareforma_pro.runner import RootlessBwrapRunner

pytestmark = pytest.mark.rootless


def _available() -> bool:
    return bool(shutil.which("strace") and shutil.which("bwrap"))


@pytest.fixture
def runner(tmp_path):
    if not _available():
        pytest.skip("strace and bwrap are required")
    collector = RootlessCollector("runner-secret")
    return RootlessBwrapRunner(collector, log_dir=tmp_path / "logs")


def test_read_is_grounded(runner, tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("a,b\n1,2\n", encoding="utf-8")
    result = runner.run_in_bwrap(
        ["/bin/cat", "/tmp/work/data.csv"],
        ro_binds={str(tmp_path): "/tmp/work"},
    )
    assert result.process.returncode == 0
    assert str(data) in result.evidence.observed_files
    assert str(data) not in result.evidence.opened_only


def test_write_only_is_not_a_read(runner, tmp_path):
    result = runner.run_in_bwrap(
        ["/bin/sh", "-c", "echo x > /tmp/work/out.csv"],
        rw_binds={str(tmp_path): "/tmp/work"},
    )
    assert result.process.returncode == 0
    assert result.evidence.observed_files == ()


def test_unmapped_tmpfs_is_opaque(runner, tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    result = runner.run_in_bwrap(
        ["/bin/sh", "-c", "echo temp >/tmp/scratch && /bin/cat /tmp/scratch >/dev/null"],
        ro_binds={str(tmp_path): "/tmp/work"},
    )
    assert "unmapped_tmpfs" in result.evidence.opaque_reasons
    assert "/tmp/scratch" in result.evidence.unmapped_paths
    assert str(data) not in result.evidence.observed_files


def test_tampered_receipt_is_rejected(runner, tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    result = runner.run_in_bwrap(
        ["/bin/cat", "/tmp/work/data.csv"],
        ro_binds={str(tmp_path): "/tmp/work"},
    )
    receipt = result.evidence.to_receipt_dict()
    receipt["observed_files"] = []
    with pytest.raises(ReceiptError):
        verify_scope_receipt(receipt, "runner-secret")
