"""Replay the checked-in public-metadata-only V2 structural rehearsal."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from causalfrontier import calibration_v2 as v2
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER

REPOSITORY = Path(__file__).resolve().parents[1]
EXAMPLE = REPOSITORY / "examples" / "calibration-tripwire-v2"


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


def test_v2_example_generator_is_offline_and_byte_deterministic(tmp_path: Path) -> None:
    generated = tmp_path / "generated-example"
    completed = subprocess.run(
        [sys.executable, str(EXAMPLE / "generate_example.py"), "--output", str(generated)],
        cwd=REPOSITORY,
        env={**os.environ, "PYTHONHASHSEED": "77", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    generated_checkpoints = json.loads(completed.stdout)
    assert canonical_bytes(generated_checkpoints) + b"\n" == (generated / "checkpoints.json").read_bytes()
    checked_in = _load(EXAMPLE / "checkpoints.json")
    assert generated_checkpoints == checked_in
    for artifact in checked_in["artifacts"]:
        assert (generated / artifact["path"]).read_bytes() == (EXAMPLE / artifact["path"]).read_bytes()
    assert _verify(generated)["method_recovery_pass"] is False
