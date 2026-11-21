"""The distribution name and import namespace are intentionally different."""

from __future__ import annotations

from pathlib import Path
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import mareforma_pro


def test_distribution_is_mareforma_pro_with_an_underscore_import():
    project = tomllib.loads(Path(__file__).parents[1].joinpath("pyproject.toml").read_text())
    assert project["project"]["name"] == "mareforma-pro"
    assert project["project"]["scripts"]["mareforma-pro"] == "mareforma_pro.cli:cli"
    assert project["project"]["version"] == mareforma_pro.__version__
    assert mareforma_pro.__name__ == "mareforma_pro"


def test_package_is_installed_from_the_pro_project_when_built():
    # In a source checkout the editable install points into mareforma-pro/src;
    # a wheel install points into site-packages. Either way the import name is
    # the underscore package and never a hyphenated module.
    path = Path(mareforma_pro.__file__).resolve()
    assert path.name == "__init__.py"
    assert "mareforma_pro" in path.parts
    assert sys.version_info >= (3, 10)
