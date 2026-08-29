from __future__ import annotations

import json
from pathlib import Path

from causalfrontier.cli import main, parser
from causalfrontier.model import load_case


def _output(capsys):
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.err


def test_cli_full_read_only_and_memory_workflow(case_root: Path, tmp_path: Path, capsys):
    assert main(["analyze", str(case_root)]) == 0
    analysis, error = _output(capsys)
    assert error == ""
    assert analysis["scientific_status"] == "PROTOTYPE_COUNTERFACTUAL_PLAN_ONLY"

    assert main(["classify", str(case_root)]) == 0
    classified, error = _output(capsys)
    assert error == ""
    assert len(classified["results"]) == 3

    destination = tmp_path / "capsule"
    assert main(["compile", str(case_root), str(destination)]) == 0
    compiled, error = _output(capsys)
    assert error == ""
    genesis_head = compiled["ledger"]["head_digest"]

    assert main(["verify", str(destination), "--expected-ledger-head", genesis_head]) == 0
    verified, error = _output(capsys)
    assert error == ""
    assert verified["status"] == "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE"

    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    branch_args = [
        experiment["id"],
        "outcome:held-invariant",
        experiment["branch_plan_sha256"],
    ]
    assert main(["simulate", str(case_root), *branch_args]) == 0
    rehearsal, error = _output(capsys)
    assert error == ""
    assert rehearsal["status"] == "COUNTERFACTUAL_REHEARSAL_NOT_AN_OBSERVATION"

    assert (
        main(
            [
                "remember-rehearsal",
                str(destination),
                "--expected-ledger-head",
                genesis_head,
                "2026-08-28T21:01:00Z",
                *branch_args,
            ]
        )
        == 0
    )
    remembered, error = _output(capsys)
    assert error == ""
    assert remembered["ledger"]["events"] == 2


def test_cli_invalid_branch_fails_closed(case_root: Path, capsys):
    result = main(["simulate", str(case_root), "experiment:held-out-invariance", "outcome:invented", "0" * 64])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "branch plan digest" in captured.err


def test_cli_version_is_registered():
    try:
        parser().parse_args(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--version did not exit")
