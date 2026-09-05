"""Replay the checked-in public-metadata-only V2 structural rehearsal."""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from causalfrontier import calibration_v2 as v2
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER

REPOSITORY = Path(__file__).resolve().parents[1]
EXAMPLE = REPOSITORY / "examples" / "calibration-tripwire-v2"
HISTORICAL_CHECKPOINT_SHA256 = "93e4899a853383d365ce8a0cc0770f5f53be7bcb29f5cab7cbf6c31d6708a050"
HISTORICAL_MODULE_SHA256 = "365a377f5e02e5ef66f0f7c93d11329de48aada20df982d20af93d19760b95dc"
REPORT_IDENTITY_FIELDS = {
    "adjudication_raw_sha256",
    "opening_raw_sha256",
    "report_sha256",
    "rubric_raw_sha256",
    "submission_raw_sha256",
    "submission_seal_sha256",
    "view_lock_sha256",
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _verify(example: Path) -> dict:
    checkpoints = _load(example / "checkpoints.json")
    digests = checkpoints["protocol_checkpoints"]
    return v2.verify_calibration_v2_report(
        example / "entrant-root",
        digests["manifest_raw_sha256"],
        example / "external-zones" / "view-lock.json",
        digests["view_lock_raw_sha256"],
        example / "external-zones" / "submission.json",
        digests["submission_raw_sha256"],
        example / "external-zones" / "submission-seal.json",
        digests["submission_seal_raw_sha256"],
        example / "external-zones" / "opening.json",
        digests["opening_raw_sha256"],
        example / "external-zones" / "rubric.json",
        digests["rubric_raw_sha256"],
        example / "external-zones" / "adjudication.json",
        digests["adjudication_raw_sha256"],
        example / "external-zones" / "report.json",
        digests["report_raw_sha256"],
    )


def test_checked_in_v2_public_metadata_example_replays_without_promoting_a_claim() -> None:
    assert sha256_bytes((EXAMPLE / "checkpoints.json").read_bytes()) == HISTORICAL_CHECKPOINT_SHA256
    checkpoints = _load(EXAMPLE / "checkpoints.json")
    assert checkpoints["fixed_parameter"] == FIXED_PARAMETER
    assert checkpoints["status"] == "LOCAL_EXAMPLE_CHECKPOINT_NOT_INDEPENDENT_CUSTODY"
    assert checkpoints["method_recovery_pass"] is False
    assert checkpoints["scientific_claim_ready"] is False
    assert len(checkpoints["artifacts"]) == checkpoints["artifact_files_n"]
    for artifact in checkpoints["artifacts"]:
        assert sha256_bytes((EXAMPLE / artifact["path"]).read_bytes()) == artifact["sha256"]

    report = _verify(EXAMPLE)
    assert canonical_bytes(report) + b"\n" == (EXAMPLE / "external-zones" / "report.json").read_bytes()
    assert report["status"] == v2.REPORT_STRUCTURAL_STATUS
    assert report["local_protocol_conformance_pass"] is True
    assert report["controls_structurally_complete_n"] == 3
    assert report["controls_declared_review_candidate_n"] == 3
    assert report["controls_semantically_verified_n"] == 0
    assert report["action_pattern"] == [
        "REQUEST_INFORMATION",
        "PROPOSE_FALSIFICATION",
        "REQUEST_INFORMATION",
    ]
    assert [row["control_role"] for row in report["case_results"]] == [
        "AMBIGUOUS",
        "POSITIVE",
        "FAILED_TRANSLATION",
    ]
    by_role = {row["control_role"]: row for row in report["case_results"]}
    assert by_role["POSITIVE"]["derived_observed_successor"] == "ADVANCE_FALSIFICATION"
    assert by_role["FAILED_TRANSLATION"]["derived_observed_successor"] == "STOP_FOR_SAFETY"
    assert by_role["AMBIGUOUS"]["derived_observed_successor"] == "NO_CALL"
    assert report["method_recovery_pass"] is False
    assert report["independent_semantic_adjudication_verified"] is False
    assert report["primary_scoring_ready"] is False
    assert report["scientific_scoring_ready"] is False
    assert report["scientific_claim_ready"] is False
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None

    manifest = _load(EXAMPLE / "entrant-root" / v2.VIEW_MANIFEST)
    historical_stage = next(
        stage for stage in manifest["toolbox_contract"] if stage["stage_id"] == "CAUSALFRONTIER_STRUCTURED_ACTION"
    )
    assert historical_stage["source_tree_sha256"] == HISTORICAL_MODULE_SHA256
    rendered_manifest = canonical_bytes(manifest)
    assert b"POSITIVE" not in rendered_manifest
    assert b"FAILED_TRANSLATION" not in rendered_manifest
    assert b"AMBIGUOUS" not in rendered_manifest
    entrant_bytes = b""
    for control in manifest["controls"]:
        for source_reference in control["sources"]:
            source = EXAMPLE / "entrant-root" / source_reference["path"]
            card = _load(source)
            entrant_bytes += source.read_bytes()
            assert card["declared_available_at"] == source_reference["available_at"]
            assert source_reference["available_at"] <= control["knowledge_cutoff"]
            assert card["status"] == "CURRENT_METADATA_RECONSTRUCTION_NOT_HISTORICAL_BYTES"
            assert card["metadata_only"] is True
            assert card["full_text_included"] is False
            assert card["historical_byte_custody_verified"] is False
            assert card["original_representation_verified"] is False
            assert card["independent_temporal_attestation_verified"] is False
            assert card["clinical_or_patient_decision_authority"] is False
            assert card["wet_lab_or_material_authority"] is False
    assert b"PMID:28304224" not in entrant_bytes
    assert b"PMID:29719179" not in entrant_bytes
    assert b"PMID:32445440" not in entrant_bytes

    opening = _load(EXAMPLE / "external-zones" / "opening.json")
    for entry in opening["payload"]["entries"]:
        suffix = entry["opaque_case_id"].rsplit(":", 1)[1][:24]
        source = EXAMPLE / "opening-sources" / f"{suffix}.json"
        assert sha256_bytes(source.read_bytes()) == entry["reveal_source_sha256"]
        card = _load(source)
        assert card["opaque_case_id"] == entry["opaque_case_id"]
        assert card["committed_coordinate"] == entry["observed_coordinate"]
        assert card["historical_byte_custody_verified"] is False
        assert card["clinical_or_patient_decision_authority"] is False
        assert card["wet_lab_or_material_authority"] is False


def _run_generator(output: Path | None, seed: str = "77") -> subprocess.CompletedProcess[bytes]:
    # The child does not inherit pytest-socket's monkeypatch. Disable Python
    # socket entry points explicitly; this is not an OS network sandbox.
    script = """
import runpy
import socket
import sys

def denied(*args, **kwargs):
    raise RuntimeError("Python network access is disabled in the example test")

socket.socket = denied
socket.create_connection = denied
socket.getaddrinfo = denied
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    command = [sys.executable, "-c", script, str(EXAMPLE / "generate_example.py")]
    if output is not None:
        command.extend(["--output", str(output)])
    source_path = os.pathsep.join(
        filter(None, (str(Path(v2.__file__).resolve().parents[1]), os.environ.get("PYTHONPATH")))
    )
    return subprocess.run(
        command,
        cwd=REPOSITORY,
        env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": source_path, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )


def test_v2_example_generator_is_offline_and_byte_deterministic(tmp_path: Path) -> None:
    roots = [tmp_path / "generated-seed-1", tmp_path / "generated-seed-77"]
    checkpoints = []
    for output, seed in zip(roots, ("1", "77"), strict=True):
        completed = _run_generator(output, seed)
        assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
        generated_checkpoints = json.loads(completed.stdout)
        assert canonical_bytes(generated_checkpoints) + b"\n" == (output / "checkpoints.json").read_bytes()
        checkpoints.append(generated_checkpoints)
    assert checkpoints[0] == checkpoints[1]
    for artifact in checkpoints[0]["artifacts"]:
        raw = (roots[0] / artifact["path"]).read_bytes()
        assert sha256_bytes(raw) == artifact["sha256"]
        assert raw == (roots[1] / artifact["path"]).read_bytes()

    generated = roots[0]
    current_module_sha256 = sha256_bytes(Path(v2.__file__).read_bytes())
    manifest = _load(generated / "entrant-root" / v2.VIEW_MANIFEST)
    generated_stage = next(
        stage for stage in manifest["toolbox_contract"] if stage["stage_id"] == "CAUSALFRONTIER_STRUCTURED_ACTION"
    )
    assert generated_stage["source_tree_sha256"] == current_module_sha256
    report = _verify(generated)
    historical_report = _verify(EXAMPLE)
    # Check every report field except the seven explicitly identity-bearing
    # commitments. Decisions, gates, claim flags, rows, and schema stay exact.
    assert {key: value for key, value in report.items() if key not in REPORT_IDENTITY_FIELDS} == {
        key: value for key, value in historical_report.items() if key not in REPORT_IDENTITY_FIELDS
    }
    checked_in = _load(EXAMPLE / "checkpoints.json")
    historical_artifacts = {row["path"]: row["sha256"] for row in checked_in["artifacts"]}
    generated_artifacts = {row["path"]: row["sha256"] for row in checkpoints[0]["artifacts"]}
    assert generated_artifacts.keys() == historical_artifacts.keys()
    if current_module_sha256 == HISTORICAL_MODULE_SHA256:
        assert checkpoints[0] == checked_in
    else:
        assert checkpoints[0] != checked_in
        assert report["report_sha256"] != historical_report["report_sha256"]
        source_bound_paths = (
            {"entrant-root/" + v2.VIEW_MANIFEST}
            | {
                "external-zones/" + name + ".json"
                for name in (
                    "adjudication",
                    "opening",
                    "report",
                    "rubric",
                    "submission-seal",
                    "submission",
                    "view-lock",
                )
            }
            | {
                path
                for path in historical_artifacts
                if path.startswith("toolbox/") and path.endswith("/04-causalfrontier-structured-action.artifact.json")
            }
        )
        assert len(source_bound_paths) == 11
        assert {
            path for path, digest in generated_artifacts.items() if digest != historical_artifacts[path]
        } == source_bound_paths
    assert sha256_bytes((EXAMPLE / "checkpoints.json").read_bytes()) == HISTORICAL_CHECKPOINT_SHA256


def test_v2_example_generator_refuses_existing_output_without_rewriting(tmp_path: Path) -> None:
    destination = tmp_path / "preserved"
    destination.mkdir()
    marker = destination / "checkpoint.txt"
    marker.write_bytes(b"historical bytes must stay intact\n")
    completed = _run_generator(destination)
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr) == {
        "schema_version": "causalfrontier.error.v1",
        "reason_code": "OUTPUT_EXISTS",
        "operation": "example_generate",
        "errno": errno.EEXIST,
    }
    assert str(destination).encode() not in completed.stderr
    assert b"Traceback" not in completed.stderr
    assert list(destination.iterdir()) == [marker]
    assert marker.read_bytes() == b"historical bytes must stay intact\n"


@pytest.mark.parametrize("target_exists", [True, False])
def test_v2_example_generator_refuses_symlink_output_with_path_free_diagnostic(
    tmp_path: Path, target_exists: bool
) -> None:
    target = tmp_path / "target"
    if target_exists:
        target.mkdir()
    destination = tmp_path / "symlink"
    destination.symlink_to(target, target_is_directory=True)
    completed = _run_generator(destination)
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert json.loads(completed.stderr) == {
        "schema_version": "causalfrontier.error.v1",
        "reason_code": "SAFE_PATH_REJECTED",
        "operation": "example_generate",
        "errno": None,
    }
    assert destination.is_symlink()
    assert target.exists() is target_exists
    if target_exists:
        assert list(target.iterdir()) == []


@pytest.mark.parametrize(
    ("number", "reason"),
    [(errno.EACCES, "ENVIRONMENT_DENIED"), (errno.ENOENT, "INPUT_MISSING"), (errno.EEXIST, "OUTPUT_EXISTS")],
)
def test_v2_generator_io_failures_have_numeric_diagnostics_without_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, number: int, reason: str
) -> None:
    path = EXAMPLE / "generate_example.py"
    spec = importlib.util.spec_from_file_location("v2_example_generator", path)
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)

    def failed(_output: Path) -> dict:
        raise OSError(number, "synthetic private operating-system detail", "/private/synthetic/output")

    monkeypatch.setattr(generator, "generate", failed)
    monkeypatch.setattr(sys, "argv", [str(path), "--output", str(tmp_path / "output")])
    assert generator.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "causalfrontier.error.v1",
        "reason_code": reason,
        "operation": "example_generate",
        "errno": number,
    }
    assert "/private/synthetic" not in captured.err
    assert "Traceback" not in captured.err
    assert not (tmp_path / "output").exists()


def test_v2_example_generator_requires_an_explicit_output() -> None:
    completed = _run_generator(None)
    assert completed.returncode == 2
    assert b"--output" in completed.stderr
    assert sha256_bytes((EXAMPLE / "checkpoints.json").read_bytes()) == HISTORICAL_CHECKPOINT_SHA256
