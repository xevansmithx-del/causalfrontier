from __future__ import annotations

import json
from pathlib import Path

import causalfrontier.cli as cli
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


def test_build_sanitized_view_cli_forwards_exact_api_contract(monkeypatch, tmp_path: Path, capsys):
    calls = []
    nonce = b"n" * 32

    def read_nonce(path, expected_sha256):
        calls.append(("nonce", path, expected_sha256))
        return nonce

    def build_view(root, manifest_sha256, sequence, race_path, race_sha256, supplied_nonce):
        calls.append(
            (
                "view",
                root,
                manifest_sha256,
                sequence,
                race_path,
                race_sha256,
                supplied_nonce,
            )
        )
        return {"status": "SYNTHETIC_VIEW_TEST_ONLY"}

    monkeypatch.setattr(cli, "read_checkpointed_blinding_nonce", read_nonce)
    monkeypatch.setattr(cli, "build_sanitized_entrant_view", build_view)
    nonce_path = tmp_path / "nonce.secret"
    race_path = tmp_path / "race.json"
    digest = "1" * 64
    race_digest = "2" * 64
    nonce_digest = "3" * 64

    result = main(
        [
            "build-sanitized-view",
            str(tmp_path / "challenge"),
            str(race_path),
            str(nonce_path),
            "--expected-manifest-sha256",
            digest,
            "--expected-sequence",
            "7",
            "--expected-race-spec-sha256",
            race_digest,
            "--expected-nonce-sha256",
            nonce_digest,
        ]
    )

    output, error = _output(capsys)
    assert result == 3
    assert error == ""
    assert output == {"status": "SYNTHETIC_VIEW_TEST_ONLY"}
    assert calls == [
        ("nonce", nonce_path, nonce_digest),
        ("view", tmp_path / "challenge", digest, 7, race_path, race_digest, nonce),
    ]


def test_cli_version_is_registered(capsys):
    try:
        parser().parse_args(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--version did not exit")
    assert capsys.readouterr().out == "causalfrontier 0.1.0a5\n"
