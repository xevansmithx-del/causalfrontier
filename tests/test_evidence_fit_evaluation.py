"""Evaluation-harness integrity checks; these do not execute the full evaluation."""

from __future__ import annotations

import itertools
import json
import runpy
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / "evaluation/evidence-fit-v1"


def invoke(*arguments: str, optimized: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *(["-O"] if optimized else []), str(EVALUATION / "run.py"), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def test_authored_design_is_complete_and_preserves_missingness_sides():
    generator = runpy.run_path(str(EVALUATION / "generator.py"))
    cases = generator["generate_cases"]()  # Input generation only; neither program is evaluated.
    assert Counter(case["stratum"] for case in cases) == {
        "factorial": 81,
        "temporal": 33,
        "missingness": 3,
        "source_conditions": 6,
        "semantic_counterexamples": 6,
        "quantity_preservation": 3,
    }
    factors = generator["FACTORS"]
    observed = {tuple(case["design"][factor] for factor in factors) for case in cases if case["stratum"] == "factorial"}
    assert observed == set(itertools.product(("match", "mismatch", "missing"), repeat=4))
    missingness = [case for case in cases if case["stratum"] == "missingness"]
    assert {
        (
            case["extraction"]["target"]["dimensions"]["endpoint"] is None,
            case["extraction"]["records"][0]["dimensions"]["endpoint"] is None,
        )
        for case in missingness
    } == {(True, False), (False, True), (True, True)}


def test_full_run_requires_prerequisite_and_does_not_create_output(tmp_path):
    output = tmp_path / "not-created"
    result = invoke("--output", str(output))
    assert result.returncode == 2
    assert "Full run requires --freeze-commit" in result.stderr
    assert not output.exists()


def test_smoke_replays_under_optimization_and_detects_coherent_result_edit(tmp_path):
    output = tmp_path / "smoke"
    result = invoke("--output", str(output), "--smoke-case", "factorial-match-mismatch-missing-missing")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["run_mode"] == "SMOKE_ONLY"
    replay = invoke("--verify-existing", str(output), optimized=True)
    assert replay.returncode == 0, replay.stderr
    assert replay.stdout == result.stdout
    # Recompute the inventory digest after corrupting an outcome: replay must
    # reject a coherent local digest edit rather than trust its own stored claims.
    summary_path = output / "summary.json"
    summary = json.loads(summary_path.read_bytes())
    summary["human_performance_measured"] = True
    generator = runpy.run_path(str(EVALUATION / "generator.py"))
    summary_path.write_bytes(generator["encoded"](summary))
    inventory_path = output / "artifact_hashes.json"
    inventory = json.loads(inventory_path.read_bytes())
    inventory["summary.json"] = generator["digest"](summary_path.read_bytes())
    inventory_path.write_bytes(generator["encoded"](inventory))
    rejected = invoke("--verify-existing", str(output), optimized=True)
    assert rejected.returncode != 0
    assert "Replay differs from retained artifact bytes or exact inventory" in rejected.stderr
