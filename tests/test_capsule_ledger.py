from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes, sha256_file
from causalfrontier.capsule import build_capsule, record_rehearsal, verify_capsule
from causalfrontier.ledger import append_event
from causalfrontier.model import load_case


def test_capsule_build_and_exact_replay(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    replayed = verify_capsule(destination)
    assert built["status"] == "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE"
    assert replayed["status"] == built["status"]
    assert replayed["run_id"] == built["run_id"]
    assert replayed["ledger"]["state"] == "VERIFIED"


@pytest.mark.parametrize("nested_basename", ["manifest.json", "ledger.sqlite"])
def test_nested_capsule_control_basename_remains_immutable_source(
    copied_case: Path,
    tmp_path: Path,
    nested_basename: str,
):
    case_path = copied_case / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    original = copied_case / case["provenance"][0]["path"]
    renamed = original.with_name(nested_basename)
    original.rename(renamed)
    case["provenance"][0]["path"] = renamed.relative_to(copied_case).as_posix()
    case_path.write_bytes(canonical_bytes(case) + b"\n")

    destination = tmp_path / "capsule"
    built = build_capsule(copied_case, destination)
    relative = "case/" + renamed.relative_to(copied_case).as_posix()
    assert relative in json.loads((destination / "manifest.json").read_text())["immutable_files"]
    assert built["status"] == "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE"


def test_two_capsules_have_identical_immutable_outputs(case_root: Path, tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    build_capsule(case_root, first)
    build_capsule(case_root, second)
    for relative in ("analysis.json", "case/case.json", "manifest.json"):
        assert (first / relative).read_bytes() == (second / relative).read_bytes()
    assert verify_capsule(first)["ledger"]["head_digest"] == verify_capsule(second)["ledger"]["head_digest"]


def test_capsule_build_refuses_overwrite(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    with pytest.raises(CausalFrontierError, match="refusing to overwrite"):
        build_capsule(case_root, destination)


def test_capsule_build_refuses_destination_inside_frozen_case(copied_case: Path):
    destination = copied_case / "capsule"
    with pytest.raises(CausalFrontierError, match="must not be inside the frozen case root"):
        build_capsule(copied_case, destination)
    assert not destination.exists()
    assert load_case(copied_case)["case_id"] == "synthetic-aggregate-response"


def test_analysis_tamper_is_detected(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    analysis_path = destination / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["scientific_status"] = "PROVEN"
    analysis_path.write_bytes(canonical_bytes(analysis) + b"\n")
    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "digest mismatch" in verification["error"]


def test_coherently_rehashed_classifier_result_forgery_fails_semantic_replay(
    case_root: Path,
    tmp_path: Path,
):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    results_path = destination / "classifier-results.json"
    results = json.loads(results_path.read_text(encoding="utf-8"))
    results["results"][0]["outcome_id"] = "outcome:global-context"
    results_path.write_bytes(canonical_bytes(results) + b"\n")

    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["immutable_files"]["classifier-results.json"] = sha256_file(results_path)
    core = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = sha256_bytes(canonical_bytes(core))
    manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")

    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "classifier results do not exactly replay" in verification["error"]


def test_append_only_trigger_rejects_event_update(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    connection = sqlite3.connect(destination / "ledger.sqlite")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE events SET subject='tamper' WHERE seq=1")
    finally:
        connection.close()


def test_missing_append_only_trigger_invalidates_capsule(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    connection = sqlite3.connect(destination / "ledger.sqlite")
    try:
        connection.execute("DROP TRIGGER events_no_update")
        connection.commit()
    finally:
        connection.close()
    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "trigger inventory differs" in verification["error"]


def test_rehearsal_appends_and_capsule_still_replays(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    recorded = record_rehearsal(
        destination,
        built["ledger"]["head_digest"],
        "2026-08-28T21:01:00Z",
        experiment["id"],
        "outcome:held-invariant",
        experiment["branch_plan_sha256"],
    )
    assert recorded["ledger"]["events"] == 2
    assert recorded["ledger"]["replay"]["event_counts"] == {
        "CAPSULE_COMPILED": 1,
        "COUNTERFACTUAL_REHEARSAL": 1,
    }
    assert verify_capsule(destination)["status"] == ("SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE")


def test_posthoc_rehearsal_is_not_appended(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    with pytest.raises(CausalFrontierError, match="post-hoc outcome"):
        record_rehearsal(
            destination,
            built["ledger"]["head_digest"],
            "2026-08-28T21:01:00Z",
            "experiment:held-out-invariance",
            "outcome:posthoc",
            "4fca74e460ea51cd257ab80060da8e594448e9324b2f805ad0f992bcc3e6c0b6",
        )
    assert verify_capsule(destination)["ledger"]["head_digest"] == built["ledger"]["head_digest"]


def test_rehashed_but_false_rehearsal_is_rejected_semantically(
    case_root: Path,
    tmp_path: Path,
):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    append_event(
        destination / "ledger.sqlite",
        "2026-08-28T21:01:00Z",
        "COUNTERFACTUAL_REHEARSAL",
        case["case_id"],
        {
            "predecessor_run_id": built["run_id"],
            "predecessor_active_world_ids": sorted(item["id"] for item in case["worlds"]),
            "predecessor_case_state": "DECLARED_PARTITION_ACTIVE",
            "experiment_id": experiment["id"],
            "outcome_id": "outcome:held-invariant",
            "branch_plan_sha256": experiment["branch_plan_sha256"],
            "successor_run_id": "0" * 64,
            "successor_active_world_ids": ["world:invariant-mechanism", "world:residual"],
            "successor_case_state": "DECLARED_PARTITION_ACTIVE",
            "status": "COUNTERFACTUAL_REHEARSAL_NOT_AN_OBSERVATION",
        },
        expected_head=built["ledger"]["head_digest"],
    )

    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "does not semantically replay" in verification["error"]


def test_manifest_binds_ledger_genesis(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["ledger_genesis_head"] = "0" * 64
    core = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = sha256_bytes(canonical_bytes(core))
    manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")

    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "genesis head differs" in verification["error"]


def test_manifest_case_id_must_match_replayed_case(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    build_capsule(case_root, destination)
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["case_id"] = "different-case"
    core = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = sha256_bytes(canonical_bytes(core))
    manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")

    verification = verify_capsule(destination)
    assert verification["status"] == "INVALID"
    assert "case_id differs" in verification["error"]


def test_rehearsal_chain_uses_previous_successor_as_parent(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    case = load_case(case_root)
    held = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    first = record_rehearsal(
        destination,
        built["ledger"]["head_digest"],
        "2026-08-28T21:01:00Z",
        held["id"],
        "outcome:held-invariant",
        held["branch_plan_sha256"],
    )
    control = next(item for item in case["experiments"] if item["id"] == "experiment:negative-control")
    second = record_rehearsal(
        destination,
        first["ledger"]["head_digest"],
        "2026-08-28T21:02:00Z",
        control["id"],
        "outcome:control-null",
        control["branch_plan_sha256"],
    )
    rehearsals = second["ledger"]["replay"]["rehearsals"]
    assert rehearsals[1]["predecessor_run_id"] == rehearsals[0]["successor_run_id"]
    assert rehearsals[1]["predecessor_active_world_ids"] == rehearsals[0]["successor_active_world_ids"]


def test_contradiction_blocks_further_rehearsal_until_new_case(case_root: Path, tmp_path: Path):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    case = load_case(case_root)
    held = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    contradicted = record_rehearsal(
        destination,
        built["ledger"]["head_digest"],
        "2026-08-28T21:01:00Z",
        held["id"],
        "outcome:held-contradiction",
        held["branch_plan_sha256"],
    )
    with pytest.raises(CausalFrontierError, match="partition is invalidated"):
        record_rehearsal(
            destination,
            contradicted["ledger"]["head_digest"],
            "2026-08-28T21:02:00Z",
            held["id"],
            "outcome:held-invariant",
            held["branch_plan_sha256"],
        )


def test_external_head_checkpoint_detects_local_ledger_rollback(
    case_root: Path,
    tmp_path: Path,
):
    destination = tmp_path / "capsule"
    built = build_capsule(case_root, destination)
    genesis_copy = tmp_path / "ledger-genesis.sqlite"
    shutil.copyfile(destination / "ledger.sqlite", genesis_copy)
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    recorded = record_rehearsal(
        destination,
        built["ledger"]["head_digest"],
        "2026-08-28T21:01:00Z",
        experiment["id"],
        "outcome:held-invariant",
        experiment["branch_plan_sha256"],
    )
    latest_head = recorded["ledger"]["head_digest"]
    assert latest_head != built["ledger"]["head_digest"]

    shutil.copyfile(genesis_copy, destination / "ledger.sqlite")
    assert verify_capsule(destination)["status"] == ("SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE")
    checkpointed = verify_capsule(destination, expected_ledger_head=latest_head)
    assert checkpointed["status"] == "INVALID"
    assert "external checkpoint" in checkpointed["error"]
    with pytest.raises(CausalFrontierError, match="cannot rehearse against an invalid capsule"):
        record_rehearsal(
            destination,
            latest_head,
            "2026-08-28T21:02:00Z",
            experiment["id"],
            "outcome:held-invariant",
            experiment["branch_plan_sha256"],
        )
