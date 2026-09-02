"""Public API and CLI coverage for the V2 calibration workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import causalfrontier
from causalfrontier import calibration_v2
from causalfrontier import cli as cli_module

PUBLIC_V2_FUNCTIONS = (
    "canonical_branch_rows",
    "finalize_calibration_v2",
    "observation_axes_v2",
    "preflight_calibration_v2_view",
    "reveal_commitment_v2",
    "rubric_commitment_v2",
    "seal_calibration_v2_submission",
    "verify_calibration_v2_report",
    "view_content_binding_v2",
)


def _output(capsys: pytest.CaptureFixture[str]) -> tuple[dict, str]:
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.err


def test_calibration_v2_workflow_is_exported_from_the_package_root():
    for name in PUBLIC_V2_FUNCTIONS:
        assert name in causalfrontier.__all__
        assert getattr(causalfrontier, name) is getattr(calibration_v2, name)


def test_calibration_v2_cli_dispatches_every_explicit_checkpoint(monkeypatch, capsys):
    digests = {
        "manifest": "1" * 64,
        "view_lock": "2" * 64,
        "submission": "3" * 64,
        "submission_seal": "4" * 64,
        "opening": "5" * 64,
        "rubric": "6" * 64,
        "adjudication": "7" * 64,
        "report": "8" * 64,
    }
    paths = {
        "root": Path("entrant-root"),
        "view_lock": Path("view-lock.json"),
        "submission": Path("submission.json"),
        "submission_seal": Path("submission-seal.json"),
        "opening": Path("opening.json"),
        "rubric": Path("rubric.json"),
        "adjudication": Path("adjudication.json"),
        "report": Path("report.json"),
    }
    calls = []

    def fake(command):
        def invoke(*args):
            calls.append((command, args))
            return {"command": command, "scientific_scoring_ready": False}

        return invoke

    monkeypatch.setattr(cli_module, "preflight_calibration_v2_view", fake("preflight"))
    monkeypatch.setattr(cli_module, "seal_calibration_v2_submission", fake("seal"))
    monkeypatch.setattr(cli_module, "finalize_calibration_v2", fake("finalize"))
    monkeypatch.setattr(cli_module, "verify_calibration_v2_report", fake("verify"))

    assert (
        cli_module.main(
            [
                "preflight-calibration-v2-view",
                str(paths["root"]),
                "--expected-manifest-sha256",
                digests["manifest"],
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "preflight", "scientific_scoring_ready": False}, "")
    assert calls.pop(0) == ("preflight", (paths["root"], digests["manifest"]))

    assert (
        cli_module.main(
            [
                "seal-calibration-v2-submission",
                str(paths["root"]),
                str(paths["view_lock"]),
                str(paths["submission"]),
                "--expected-manifest-sha256",
                digests["manifest"],
                "--expected-view-lock-sha256",
                digests["view_lock"],
                "--expected-submission-sha256",
                digests["submission"],
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "seal", "scientific_scoring_ready": False}, "")
    assert calls.pop(0) == (
        "seal",
        (
            paths["root"],
            digests["manifest"],
            paths["view_lock"],
            digests["view_lock"],
            paths["submission"],
            digests["submission"],
        ),
    )

    finalize_argv = [
        "finalize-calibration-v2",
        str(paths["root"]),
        str(paths["view_lock"]),
        str(paths["submission"]),
        str(paths["submission_seal"]),
        str(paths["opening"]),
        str(paths["rubric"]),
        str(paths["adjudication"]),
        "--expected-manifest-sha256",
        digests["manifest"],
        "--expected-view-lock-sha256",
        digests["view_lock"],
        "--expected-submission-sha256",
        digests["submission"],
        "--expected-submission-seal-sha256",
        digests["submission_seal"],
        "--expected-opening-sha256",
        digests["opening"],
        "--expected-rubric-sha256",
        digests["rubric"],
        "--expected-adjudication-sha256",
        digests["adjudication"],
    ]
    assert cli_module.main(finalize_argv) == 3
    assert _output(capsys) == ({"command": "finalize", "scientific_scoring_ready": False}, "")
    upstream_args = (
        paths["root"],
        digests["manifest"],
        paths["view_lock"],
        digests["view_lock"],
        paths["submission"],
        digests["submission"],
        paths["submission_seal"],
        digests["submission_seal"],
        paths["opening"],
        digests["opening"],
        paths["rubric"],
        digests["rubric"],
        paths["adjudication"],
        digests["adjudication"],
    )
    assert calls.pop(0) == ("finalize", upstream_args)

    verify_argv = [
        "verify-calibration-v2-report",
        *finalize_argv[1:8],
        str(paths["report"]),
        *finalize_argv[8:],
        "--expected-report-sha256",
        digests["report"],
    ]
    assert cli_module.main(verify_argv) == 3
    assert _output(capsys) == ({"command": "verify", "scientific_scoring_ready": False}, "")
    assert calls.pop(0) == (
        "verify",
        (*upstream_args, paths["report"], digests["report"]),
    )
    assert calls == []


@pytest.mark.parametrize(
    "argv",
    [
        ["preflight-calibration-v2-view", "entrant-root"],
        [
            "seal-calibration-v2-submission",
            "entrant-root",
            "view-lock.json",
            "submission.json",
            "--expected-manifest-sha256",
            "1" * 64,
            "--expected-view-lock-sha256",
            "2" * 64,
        ],
        [
            "finalize-calibration-v2",
            "entrant-root",
            "view-lock.json",
            "submission.json",
            "submission-seal.json",
            "opening.json",
            "rubric.json",
            "adjudication.json",
            "--expected-manifest-sha256",
            "1" * 64,
            "--expected-view-lock-sha256",
            "2" * 64,
            "--expected-submission-sha256",
            "3" * 64,
            "--expected-submission-seal-sha256",
            "4" * 64,
            "--expected-opening-sha256",
            "5" * 64,
            "--expected-rubric-sha256",
            "6" * 64,
        ],
        [
            "verify-calibration-v2-report",
            "entrant-root",
            "view-lock.json",
            "submission.json",
            "submission-seal.json",
            "opening.json",
            "rubric.json",
            "adjudication.json",
            "report.json",
            "--expected-manifest-sha256",
            "1" * 64,
            "--expected-view-lock-sha256",
            "2" * 64,
            "--expected-submission-sha256",
            "3" * 64,
            "--expected-submission-seal-sha256",
            "4" * 64,
            "--expected-opening-sha256",
            "5" * 64,
            "--expected-rubric-sha256",
            "6" * 64,
            "--expected-adjudication-sha256",
            "7" * 64,
        ],
    ],
)
def test_calibration_v2_cli_requires_every_checkpoint(argv):
    with pytest.raises(SystemExit, match="2"):
        cli_module.parser().parse_args(argv)
