"""CLI transport and source-tree example checks; all source data are synthetic."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_evidence_fit import _run
from test_evidence_fit import bundle as bundle

from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.cli import main


def _files(bundle):
    _run(bundle)
    root, _, extraction = bundle
    path = root.parent / "extraction.json"
    raw = canonical_bytes(extraction) + b"\n"
    path.write_bytes(raw)
    arguments = [
        str(root),
        str(path),
        "--expected-set-sha256",
        extraction["receipt_set_sha256"],
        "--expected-extraction-sha256",
        sha256_bytes(raw),
    ]
    return path, arguments


def test_cli_audit_and_exact_replay_return_structural_three(bundle, capsys):
    path, arguments = _files(bundle)
    before = {p: p.read_bytes() for p in path.parent.rglob("*") if p.is_file()}
    assert main(["audit-evidence-fit", *arguments]) == 3
    captured = capsys.readouterr()
    assert captured.err == ""
    raw = captured.out.encode()
    report = json.loads(raw)
    assert report["scientific_scoring"] == "DISABLED"
    assert report["historically_eligible_records_n"] == 0
    assert before == {p: p.read_bytes() for p in path.parent.rglob("*") if p.is_file()}
    report_path = path.parent / "report.json"
    report_path.write_bytes(raw)
    assert (
        main(["verify-evidence-fit", *arguments, str(report_path), "--expected-report-sha256", sha256_bytes(raw)]) == 3
    )
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "ancestor"])
def test_cli_rejects_unsafe_extraction_transport(bundle, capsys, unsafe):
    path, arguments = _files(bundle)
    alias = path.parent / "alias"
    if unsafe == "symlink":
        alias.symlink_to(path)
    elif unsafe == "hardlink":
        os.link(path, alias)
    else:
        alias.symlink_to(path.parent, target_is_directory=True)
        alias = alias / path.name
    arguments[1] = str(alias)
    assert main(["--error-format", "json", "audit-evidence-fit", *arguments]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(path.parent) not in captured.err
    assert json.loads(captured.err)["reason_code"] == "EVIDENCE_FIT_REJECTED"


@pytest.mark.parametrize("raw", [b'{"secret":', b"[" * 5000 + b"0" + b"]" * 5000, b'{"id":1,"id":2}'])
def test_cli_payload_free_malformed_errors(bundle, capsys, raw):
    path, arguments = _files(bundle)
    path.write_bytes(raw)
    arguments[-1] = sha256_bytes(raw)
    assert main(["audit-evidence-fit", *arguments]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert "secret" not in captured.err


def test_shipped_source_example_replays_and_does_not_admit(capsys):
    example = Path(__file__).resolve().parents[1] / "examples/synthetic-evidence-fit"
    root = example / "receipt-root"
    extraction = example / "extraction.json"
    assert (
        main(
            [
                "audit-evidence-fit",
                str(root),
                str(extraction),
                "--expected-set-sha256",
                sha256_bytes((root / "receipt-set.json").read_bytes()),
                "--expected-extraction-sha256",
                sha256_bytes(extraction.read_bytes()),
            ]
        )
        == 3
    )
    output = json.loads(capsys.readouterr().out)
    assert output["records_n"] >= 3
    assert output["historically_eligible_records_n"] == 0
    assert output["scientific_authority"] is False
