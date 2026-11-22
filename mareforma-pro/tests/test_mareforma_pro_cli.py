"""CLI smoke tests that do not require a writable cgroup."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from mareforma_pro.cli import cli


def test_doctor_json_reports_rootless_tools():
    result = CliRunner().invoke(cli, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    names = {item["name"] for item in payload["checks"]}
    assert {"strace", "bwrap", "ptrace_scope"}.issubset(names)
    assert all("required" in item for item in payload["checks"])


@pytest.mark.skipif(
    not (shutil.which("strace") and shutil.which("bwrap")),
    reason="strace and bwrap are required",
)
def test_demo_runs_grounded_and_ungrounded_cases(tmp_path):
    result = CliRunner().invoke(cli, ["demo", "--secret", "demo-secret"])
    assert result.exit_code == 0, result.output
    assert "read verdict: GROUNDED" in result.output
    assert "write-only verdict: UNGROUNDED" in result.output


def test_run_requires_a_command():
    result = CliRunner().invoke(cli, ["run", "--secret", "x"])
    assert result.exit_code != 0


def test_supervise_help_shows_split_public_and_internal_ports():
    result = CliRunner().invoke(cli, ["supervise", "--help"])
    assert result.exit_code == 0, result.output
    assert "Public Supervisor port" in result.output
    assert "default: 18100" in result.output
    assert "default: 18000" in result.output


@pytest.mark.skipif(
    not (
        shutil.which("bwrap")
        and (shutil.which("fusermount3") or shutil.which("fusermount"))
        and Path("/dev/fuse").exists()
    ),
    reason="bwrap and rootless FUSE primitives are required",
)
def test_run_fuse_cli_emits_a_read_bytes_receipt(tmp_path):
    data = tmp_path / "data.csv"
    data.write_text("x\n", encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        [
            "run-fuse",
            "--secret",
            "fuse-secret",
            "--source",
            str(tmp_path),
            "--cite",
            str(data),
            "--",
            "/bin/cat",
            "/tmp/mareforma-data/data.csv",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "collector_mode: fuse_read_proxy" in result.output
    assert "grounding: GROUNDED" in result.output
