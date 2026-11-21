"""Optional P2: rootless FUSE read-only proxy (no ptrace)."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from mareforma.observe import ObservedGrounding
from mareforma_pro.collector import RootlessCollector
from mareforma_pro.errors import FuseMountError, RootlessUnavailableError
from mareforma_pro.fuse import FuseReadOnlyProxy
from mareforma_pro.observe import verify_and_verdict
from mareforma_pro.runner import RootlessFuseRunner

pytestmark = pytest.mark.rootless


def _has_fuse_primitives() -> bool:
    return (
        Path("/dev/fuse").exists()
        and bool(shutil.which("fusermount3") or shutil.which("fusermount"))
    )


def _open_scope(collector: RootlessCollector, scope_id: str) -> None:
    collector.open_scope(
        scope_id,
        evidence_level="USER_FUSE",
        read_semantics="READ_BYTES",
        collector_mode="fuse_read_proxy",
    )


def test_fuse_read_proxy_records_a_nonempty_read(tmp_path: Path):
    if not _has_fuse_primitives():
        pytest.skip("rootless FUSE primitives are unavailable")
    data = tmp_path / "data.csv"
    data.write_text("a,b\n1,2\n", encoding="utf-8")
    collector = RootlessCollector("fuse-secret")
    _open_scope(collector, "scp_fuse_read")
    proxy = FuseReadOnlyProxy(collector, "scp_fuse_read", tmp_path)
    mountpoint = None
    try:
        try:
            proxy.start()
        except (RootlessUnavailableError, FuseMountError) as exc:
            pytest.skip(f"FUSE mount is unavailable on this host: {exc}")
        mountpoint = proxy.mountpoint
        proc = subprocess.run(
            ["/bin/cat", str(mountpoint / "data.csv")],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
    finally:
        proxy.stop()
        evidence = collector.close_scope("scp_fuse_read")
    assert evidence.collector_mode == "fuse_read_proxy"
    assert evidence.evidence_level == "USER_FUSE"
    assert evidence.read_semantics == "READ_BYTES"
    assert str(data) in evidence.observed_files
    assert str(data) not in evidence.opened_only
    verdict = verify_and_verdict(
        evidence.to_receipt_dict(), secret="fuse-secret", cites=[str(data)]
    )
    assert verdict.grounding is ObservedGrounding.GROUNDED
    assert verdict.reason.startswith("a rootless FUSE read matched")
    if mountpoint is not None:
        assert not os.path.exists(mountpoint)


def test_fuse_open_without_read_stays_opened_only(tmp_path: Path):
    if not _has_fuse_primitives():
        pytest.skip("rootless FUSE primitives are unavailable")
    data = tmp_path / "data.csv"
    data.write_text("a,b\n1,2\n", encoding="utf-8")
    collector = RootlessCollector("fuse-secret")
    _open_scope(collector, "scp_fuse_open")
    proxy = FuseReadOnlyProxy(collector, "scp_fuse_open", tmp_path)
    try:
        try:
            proxy.start()
        except (RootlessUnavailableError, FuseMountError) as exc:
            pytest.skip(f"FUSE mount is unavailable on this host: {exc}")
        path = proxy.mountpoint / "data.csv"
        proc = subprocess.run(
            [sys.executable, "-c", f"open({str(path)!r}, 'rb').close()"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
    finally:
        proxy.stop()
        evidence = collector.close_scope("scp_fuse_open")
    assert str(data) in evidence.opened_only
    assert str(data) not in evidence.observed_files
    verdict = verify_and_verdict(
        evidence.to_receipt_dict(), secret="fuse-secret", cites=[str(data)]
    )
    assert verdict.grounding is ObservedGrounding.OPAQUE
    assert "open_only" in verdict.opaque_reasons


def test_fuse_view_rejects_writes(tmp_path: Path):
    if not _has_fuse_primitives():
        pytest.skip("rootless FUSE primitives are unavailable")
    data = tmp_path / "data.csv"
    data.write_text("a,b\n1,2\n", encoding="utf-8")
    collector = RootlessCollector("fuse-secret")
    _open_scope(collector, "scp_fuse_write")
    proxy = FuseReadOnlyProxy(collector, "scp_fuse_write", tmp_path)
    try:
        try:
            proxy.start()
        except (RootlessUnavailableError, FuseMountError) as exc:
            pytest.skip(f"FUSE mount is unavailable on this host: {exc}")
        target = proxy.mountpoint / "out.csv"
        proc = subprocess.run(
            ["/bin/sh", "-c", f"printf x > {target}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode != 0
        assert "Read-only file system" in proc.stderr
        assert not (tmp_path / "out.csv").exists()
    finally:
        proxy.stop()
        evidence = collector.close_scope("scp_fuse_write")
    assert str(data) not in evidence.observed_files
    assert evidence.opened_only == ()


def test_rootless_fuse_runner_uses_bwrap_and_no_strace(tmp_path: Path):
    if not _has_fuse_primitives() or not shutil.which("bwrap"):
        pytest.skip("bwrap and rootless FUSE primitives are unavailable")
    data = tmp_path / "data.csv"
    data.write_text("hello fuse\n", encoding="utf-8")
    collector = RootlessCollector("fuse-secret")
    runner = RootlessFuseRunner(collector)
    try:
        result = runner.run_in_bwrap(
            ["/bin/cat", "/tmp/mareforma-data/data.csv"],
            source_root=tmp_path,
        )
    except (RootlessUnavailableError, FuseMountError) as exc:
        pytest.skip(f"rootless FUSE runner is unavailable on this host: {exc}")
    assert result.process.returncode == 0, result.process.stderr
    assert result.process.stdout == "hello fuse\n"
    assert result.evidence.collector_mode == "fuse_read_proxy"
    assert str(data) in result.evidence.observed_files
    verdict = verify_and_verdict(
        result.evidence.to_receipt_dict(), secret="fuse-secret", cites=[str(data)]
    )
    assert verdict.grounding is ObservedGrounding.GROUNDED
    assert verdict.read_semantics == "READ_BYTES"
    assert verdict.evidence_level == "USER_FUSE"


def test_rootless_fuse_runner_hides_the_original_host_path(tmp_path: Path):
    if not _has_fuse_primitives() or not shutil.which("bwrap"):
        pytest.skip("bwrap and rootless FUSE primitives are unavailable")
    data = tmp_path / "data.csv"
    data.write_text("hello fuse\n", encoding="utf-8")
    collector = RootlessCollector("fuse-secret")
    runner = RootlessFuseRunner(collector)
    try:
        result = runner.run_in_bwrap(
            [
                "/bin/sh",
                "-c",
                f"/bin/cat /tmp/mareforma-data/data.csv; /bin/cat {data} 2>/dev/null || true",
            ],
            source_root=tmp_path,
        )
    except (RootlessUnavailableError, FuseMountError) as exc:
        pytest.skip(f"rootless FUSE runner is unavailable on this host: {exc}")
    assert result.process.returncode == 0, result.process.stderr
    assert result.process.stdout == "hello fuse\n"
    assert str(data) in result.evidence.observed_files
