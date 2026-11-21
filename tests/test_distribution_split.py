"""The rootless extension is a separate distribution, not a core extra."""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
CORE = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PRO_PROJECT = ROOT / "mareforma-pro" / "pyproject.toml"


def test_core_distribution_does_not_claim_the_pro_package():
    assert CORE["project"]["name"] == "mareforma"
    assert "mareforma-pro" not in CORE["project"].get("scripts", {})
    include = CORE["tool"]["setuptools"]["packages"]["find"]["include"]
    assert not any(pattern.startswith("mareforma_pro") for pattern in include)
    assert "otel" not in CORE["project"].get("optional-dependencies", {})


def test_pro_distribution_name_and_import_package_are_distinct():
    if not PRO_PROJECT.exists():
        pytest.skip("the independent mareforma-pro project is not in this sdist")
    pro = tomllib.loads(PRO_PROJECT.read_text(encoding="utf-8"))
    assert pro["project"]["name"] == "mareforma-pro"
    assert pro["project"]["scripts"]["mareforma-pro"] == "mareforma_pro.cli:cli"
    assert pro["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]
    assert pro["project"]["dependencies"][0].startswith("mareforma>=")
    assert "otel" in pro["project"]["optional-dependencies"]


def test_pro_release_is_independent_and_gated_on_tests():
    workflow = ROOT / ".github" / "workflows" / "publish-pro.yml"
    if not workflow.exists():
        pytest.skip("the .github tree is not shipped in the core sdist")
    text = workflow.read_text(encoding="utf-8")
    assert "mareforma-pro-v" in text
    assert "uses: ./.github/workflows/tests.yml" in text
    assert "needs: test" in text
    assert "working-directory: mareforma-pro" in text
    assert "packages-dir: mareforma-pro/dist/" in text
