from __future__ import annotations

import json
import shutil
import sys
from copy import deepcopy
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve(strict=True).parents[1]
SRC = PROJECT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def project_root() -> Path:
    return PROJECT


@pytest.fixture
def case_root(project_root: Path) -> Path:
    return project_root / "examples" / "synthetic-aggregate"


@pytest.fixture
def raw_case(case_root: Path):
    return json.loads((case_root / "case.json").read_text(encoding="utf-8"))


@pytest.fixture
def mutable_case(raw_case):
    return deepcopy(raw_case)


@pytest.fixture
def copied_case(tmp_path: Path, case_root: Path) -> Path:
    target = tmp_path / "case"
    shutil.copytree(case_root, target)
    return target
