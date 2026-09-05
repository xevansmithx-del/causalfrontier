"""The reproduction guide accepts an exact commit, never a movable ref."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="guide requires Git")


@pytest.mark.parametrize(
    "candidate", ["HEAD", "main", "--help", "1234abcd", "a" * 39, "a" * 41, "A" * 40, "a" * 40 + "^{commit}"]
)
def test_guide_ref_rejects_non_exact_commit_before_git(tmp_path: Path, candidate: str) -> None:
    guide = (Path(__file__).resolve().parents[1] / "docs" / "independent-reproduction.md").read_text()
    function = guide.split("cf_select_guide_ref() {", 1)[1].split("\n}\n", 1)[0]
    result = subprocess.run(
        ["sh", "-c", "cf_select_guide_ref() {" + function + "\n}\ncf_select_guide_ref"],
        cwd=tmp_path,
        # macOS collation can include uppercase letters inside an a-f range.
        # The guide must use literal lowercase membership, not locale ranges.
        env={
            **os.environ,
            "CAUSALFRONTIER_GUIDE_REF": candidate,
            "LC_ALL": "en_US.UTF-8" if sys.platform == "darwin" else "C",
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == result.stderr == ""


def test_guide_ref_checks_out_only_resolved_commit(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=tmp_path, stderr=subprocess.PIPE, text=True).strip()

    git("init")
    git(
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=synthetic@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "synthetic fixture",
    )
    commit = git("rev-parse", "HEAD")
    guide = (Path(__file__).resolve().parents[1] / "docs" / "independent-reproduction.md").read_text()
    function = guide.split("cf_select_guide_ref() {", 1)[1].split("\n}\n", 1)[0]
    result = subprocess.run(
        ["sh", "-c", "cf_select_guide_ref() {" + function + "\n}\ncf_select_guide_ref"],
        cwd=tmp_path,
        env={**os.environ, "CAUSALFRONTIER_GUIDE_REF": commit},
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert git("rev-parse", "HEAD") == commit
    assert git("rev-parse", "--abbrev-ref", "HEAD") == "HEAD"
