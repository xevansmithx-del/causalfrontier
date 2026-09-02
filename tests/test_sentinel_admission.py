"""Hostile tests for the artifact-closed sentinel admission boundary."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from sentinel_fixture import (
    build_sentinel_fixture,
    reseal_generation_plan,
    reseal_manifest_and_goal,
)

import causalfrontier
import causalfrontier.cli as cli
import causalfrontier.sentinel as sentinel
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes


@pytest.fixture
def closed_fixture(tmp_path: Path) -> dict:
    return build_sentinel_fixture(tmp_path)


def _preflight(fixture: dict) -> dict:
    return sentinel.preflight_sentinel_admission(
        fixture["root"],
        fixture["manifest_sha256"],
        1,
        fixture["generation_plan_path"],
        fixture["generation_plan_sha256"],
        fixture["goal_plan_path"],
        fixture["goal_plan_sha256"],
    )


def _verify_report(fixture: dict, report: dict) -> dict:
    return sentinel.verify_sentinel_admission_preflight(
        report,
        fixture["root"],
        fixture["manifest_sha256"],
        1,
        fixture["generation_plan_path"],
        fixture["generation_plan_sha256"],
        fixture["goal_plan_path"],
        fixture["goal_plan_sha256"],
    )


def _replace_artifact_json(fixture: dict, artifact_id: str, value: dict) -> None:
    descriptor = fixture["artifact_descriptors"][artifact_id]
    raw = canonical_bytes(value) + b"\n"
    (fixture["root"] / descriptor["path"]).write_bytes(raw)
    descriptor["sha256"] = sha256_bytes(raw)
    reseal_manifest_and_goal(fixture)


def _artifact_json(fixture: dict, artifact_id: str) -> dict:
    descriptor = fixture["artifact_descriptors"][artifact_id]
    return json.loads((fixture["root"] / descriptor["path"]).read_text(encoding="utf-8"))


def _reseal_report(report: dict) -> dict:
    core = {key: value for key, value in report.items() if key != "preflight_sha256"}
    report["preflight_sha256"] = sha256_bytes(sentinel.PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    return report


def test_complete_packet_is_still_not_admitted_or_scored(closed_fixture: dict) -> None:
    report = _preflight(closed_fixture)
    assert report["admission_state"] == "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"
    assert report["rejection_reasons"] == []
    assert report["declared_domains_n"] == 3
    assert report["declared_generator_families_n"] == 3
    assert report["primary_cases_n"] == 30
    assert report["calibration_cases_n"] == 9
    assert report["declared_laboratories_n"] == 6
    assert report["artifact_files_n"] == 326
    assert report["generator_pair_audits_n"] == 3
    assert report["domain_pair_reviews_n"] == 3
    assert report["artifact_closure_verified"] is True
    assert report["goal_plan_cohort_preimage_verified"] is True
    assert report["generation_plan_replayed"] is True
    assert report["case_geometry_replayed"] is True
    assert report["latin_square_verified"] is True
    assert report["primary_generator_laboratory_assignment_balance_verified"] is True
    assert report["declared_case_provenance_graph_structure_verified"] is True
    assert report["declared_branch_totality_verified"] is True
    assert report["oracle_commitments_unique_verified"] is True
    assert report["generator_seed_and_case_oracle_commitments_disjoint_verified"] is True
    assert report["generator_seed_or_case_oracle_enumerated_bundle_digest_alias_absent_verified"] is True
    assert report["declared_cutoff_consistency_verified"] is True
    assert all(report[field] is False for field in sentinel.FIXED_FALSE_FIELDS)


def test_generation_plan_replays_but_does_not_claim_timely_custody(closed_fixture: dict) -> None:
    plan = sentinel.preflight_sentinel_generation_plan(
        closed_fixture["generation_plan_path"], closed_fixture["generation_plan_sha256"]
    )
    assert plan["status"] == sentinel.GENERATION_PLAN_STATUS
    assert plan["case_selection_after_generation_allowed"] is False
    assert plan["oracle_opening_input_allowed"] is False
    assert plan["scoring_disabled"] is True


def test_public_verifier_rebuilds_exact_report(closed_fixture: dict) -> None:
    report = _preflight(closed_fixture)
    verified = sentinel.verify_sentinel_admission_preflight(
        report,
        closed_fixture["root"],
        closed_fixture["manifest_sha256"],
        1,
        closed_fixture["generation_plan_path"],
        closed_fixture["generation_plan_sha256"],
        closed_fixture["goal_plan_path"],
        closed_fixture["goal_plan_sha256"],
    )
    assert verified == report


@pytest.mark.parametrize("field", sorted(sentinel.FIXED_FALSE_FIELDS))
def test_coherently_rehashed_authority_escalation_is_rejected(closed_fixture: dict, field: str) -> None:
    report = _preflight(closed_fixture)
    report[field] = True
    with pytest.raises(CausalFrontierError, match="no-authority boundary"):
        _verify_report(closed_fixture, _reseal_report(report))


def test_coherently_rehashed_counts_are_rejected_by_replay(closed_fixture: dict) -> None:
    report = _preflight(closed_fixture)
    report["primary_cases_n"] = 31
    forged = _reseal_report(report)
    with pytest.raises(CausalFrontierError, match=r"fixed geometry|exact deterministic replay"):
        _verify_report(closed_fixture, forged)


def test_missing_or_unknown_report_field_fails(closed_fixture: dict) -> None:
    report = _preflight(closed_fixture)
    missing = deepcopy(report)
    missing.pop("gates")
    with pytest.raises(CausalFrontierError, match="schema mismatch"):
        _verify_report(closed_fixture, missing)
    unknown = deepcopy(report)
    unknown["winner"] = "candidate"
    with pytest.raises(CausalFrontierError, match="schema mismatch"):
        _verify_report(closed_fixture, unknown)


def test_wrong_manifest_checkpoint_fails(closed_fixture: dict) -> None:
    with pytest.raises(CausalFrontierError, match="manifest checkpoint mismatch"):
        sentinel.preflight_sentinel_admission(
            closed_fixture["root"],
            "f" * 64,
            1,
            closed_fixture["generation_plan_path"],
            closed_fixture["generation_plan_sha256"],
            closed_fixture["goal_plan_path"],
            closed_fixture["goal_plan_sha256"],
        )


def test_wrong_plan_checkpoints_fail(closed_fixture: dict) -> None:
    with pytest.raises(CausalFrontierError, match="external checkpoint mismatch"):
        sentinel.preflight_sentinel_admission(
            closed_fixture["root"],
            closed_fixture["manifest_sha256"],
            1,
            closed_fixture["generation_plan_path"],
            "e" * 64,
            closed_fixture["goal_plan_path"],
            closed_fixture["goal_plan_sha256"],
        )
    with pytest.raises(CausalFrontierError, match="claim-plan external checkpoint mismatch"):
        sentinel.preflight_sentinel_admission(
            closed_fixture["root"],
            closed_fixture["manifest_sha256"],
            1,
            closed_fixture["generation_plan_path"],
            closed_fixture["generation_plan_sha256"],
            closed_fixture["goal_plan_path"],
            "d" * 64,
        )


@pytest.mark.parametrize("sequence", [True, 0, -1, 1.0])
def test_external_sequence_is_strict_positive_integer(closed_fixture: dict, sequence: object) -> None:
    with pytest.raises(CausalFrontierError, match="positive integer"):
        sentinel.preflight_sentinel_admission(
            closed_fixture["root"],
            closed_fixture["manifest_sha256"],
            sequence,  # type: ignore[arg-type]
            closed_fixture["generation_plan_path"],
            closed_fixture["generation_plan_sha256"],
            closed_fixture["goal_plan_path"],
            closed_fixture["goal_plan_sha256"],
        )


def test_goal_plan_must_bind_raw_manifest_preimage(closed_fixture: dict) -> None:
    closed_fixture["goal_plan"]["cohort_checkpoint_sha256"] = "c" * 64
    from test_claim import _reseal

    _reseal(closed_fixture["goal_plan"])
    raw = canonical_bytes(closed_fixture["goal_plan"]) + b"\n"
    closed_fixture["goal_plan_path"].write_bytes(raw)
    closed_fixture["goal_plan_sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="not the preimage"):
        _preflight(closed_fixture)


def test_manifest_must_bind_exact_generation_predecessor(closed_fixture: dict) -> None:
    closed_fixture["manifest"]["generation_plan_checkpoint_sha256"] = "b" * 64
    reseal_manifest_and_goal(closed_fixture)
    with pytest.raises(CausalFrontierError, match="predecessor"):
        _preflight(closed_fixture)


def test_extra_file_fails_closed_inventory(closed_fixture: dict) -> None:
    (closed_fixture["root"] / "surplus.txt").write_text("surplus\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="inventory differs"):
        _preflight(closed_fixture)


def test_orphan_declared_artifact_fails_usage_closure(closed_fixture: dict) -> None:
    raw = b"declared but unreferenced\n"
    path = "artifacts/artifact_orphan.txt"
    (closed_fixture["root"] / path).write_bytes(raw)
    descriptor = {
        "artifact_id": "artifact:orphan",
        "path": path,
        "sha256": sha256_bytes(raw),
        "role": "TRANSFORM_INTERMEDIATE",
        "media_type": "text/plain",
        "data_class": "SYNTHETIC",
    }
    closed_fixture["manifest"]["artifacts"].append(descriptor)
    closed_fixture["manifest"]["artifacts"].sort(key=lambda item: item["artifact_id"])
    closed_fixture["artifact_descriptors"][descriptor["artifact_id"]] = descriptor
    reseal_manifest_and_goal(closed_fixture)
    with pytest.raises(CausalFrontierError, match="orphan or unreferenced"):
        _preflight(closed_fixture)


def test_symlink_root_and_leaf_fail(tmp_path: Path, closed_fixture: dict) -> None:
    root_link = tmp_path / "root-link"
    root_link.symlink_to(closed_fixture["root"], target_is_directory=True)
    with pytest.raises(CausalFrontierError, match="cannot be read safely"):
        sentinel.preflight_sentinel_admission(
            root_link,
            closed_fixture["manifest_sha256"],
            1,
            closed_fixture["generation_plan_path"],
            closed_fixture["generation_plan_sha256"],
            closed_fixture["goal_plan_path"],
            closed_fixture["goal_plan_sha256"],
        )
    descriptor = next(iter(closed_fixture["artifact_descriptors"].values()))
    target = closed_fixture["root"] / descriptor["path"]
    saved = target.read_bytes()
    target.unlink()
    external = tmp_path / "external.txt"
    external.write_bytes(saved)
    target.symlink_to(external)
    with pytest.raises(CausalFrontierError, match="unsafe filesystem object"):
        _preflight(closed_fixture)


def test_hard_link_artifact_fails(closed_fixture: dict, tmp_path: Path) -> None:
    descriptor = next(iter(closed_fixture["artifact_descriptors"].values()))
    target = closed_fixture["root"] / descriptor["path"]
    os.link(target, tmp_path / "second-link")
    with pytest.raises(CausalFrontierError, match=r"unsafe filesystem object|single-link"):
        _preflight(closed_fixture)


def test_artifact_digest_and_private_material_fail(closed_fixture: dict) -> None:
    descriptor = closed_fixture["artifact_descriptors"]["artifact:case:case-1-01:source"]
    path = closed_fixture["root"] / descriptor["path"]
    path.write_text("changed bytes\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="artifact digest mismatch"):
        _preflight(closed_fixture)

    fixture = build_sentinel_fixture(path.parent.parent.parent / "private-material")
    private_descriptor = fixture["artifact_descriptors"]["artifact:case:case-1-01:source"]
    private_path = fixture["root"] / private_descriptor["path"]
    raw = b'{"patient_id":"synthetic-looking-identifier"}\n'
    private_path.write_bytes(raw)
    private_descriptor["sha256"] = sha256_bytes(raw)
    reseal_manifest_and_goal(fixture)
    with pytest.raises(CausalFrontierError, match="prohibited material"):
        _preflight(fixture)


def test_duplicate_json_key_in_manifest_is_rejected(closed_fixture: dict) -> None:
    raw = (closed_fixture["manifest_path"]).read_bytes()
    tampered = raw.replace(b'{"artifacts":', b'{"artifacts":[],"artifacts":', 1)
    closed_fixture["manifest_path"].write_bytes(tampered)
    closed_fixture["manifest_sha256"] = sha256_bytes(tampered)
    with pytest.raises(CausalFrontierError, match="duplicate JSON key"):
        _preflight(closed_fixture)


@pytest.mark.parametrize(
    ("option", "reason", "count_field"),
    [
        (
            {"generator_source_collision": True},
            "EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION",
            "generator_component_identity_or_content_collision_pairs_n",
        ),
        (
            {"shared_generator_source_identity": True},
            "EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION",
            "generator_component_identity_or_content_collision_pairs_n",
        ),
        (
            {"shared_generator_source_content_with_distinct_identity": True},
            "EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION",
            "generator_component_identity_or_content_collision_pairs_n",
        ),
        (
            {"shared_generator_component_content_with_distinct_identity": True},
            "EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION",
            "generator_component_identity_or_content_collision_pairs_n",
        ),
        (
            {"generator_role_collision": True},
            "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
            "declared_generator_role_collision_pairs_n",
        ),
        (
            {"generator_ancestry_collision": True},
            "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
            "declared_generator_role_collision_pairs_n",
        ),
        (
            {"generator_group_casefold_collision": True},
            "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
            "declared_generator_role_collision_pairs_n",
        ),
        (
            {"generator_cross_dimension_group_collision": True},
            "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
            "declared_generator_role_collision_pairs_n",
        ),
        (
            {"generator_mechanism_casefold_collision": True},
            "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
            "declared_generator_role_collision_pairs_n",
        ),
        (
            {"cross_role_group_collision": True},
            "DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION",
            "declared_cross_role_group_collision_pairs_n",
        ),
        (
            {"outcome_role_collision": True},
            "DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION",
            "declared_cross_role_group_collision_pairs_n",
        ),
        (
            {"cross_role_group_casefold_collision": True},
            "DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION",
            "declared_cross_role_group_collision_pairs_n",
        ),
        (
            {"cross_role_cross_dimension_group_collision": True},
            "DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION",
            "declared_cross_role_group_collision_pairs_n",
        ),
        (
            {"domain_semantics_collision": True},
            "NORMALIZED_DOMAIN_SEMANTICS_COLLISION",
            "normalized_domain_semantics_collision_pairs_n",
        ),
        (
            {"case_core_collision": True},
            "NORMALIZED_CASE_DECISION_CORE_COLLISION",
            "normalized_case_decision_core_collision_pairs_n",
        ),
        ({"late_source": True}, "DECLARED_SOURCE_AFTER_CASE_CUTOFF", "declared_post_cutoff_cases_n"),
        (
            {"late_generator_inventory": True},
            "DECLARED_GENERATOR_KNOWLEDGE_AFTER_CASE_CUTOFF",
            "declared_post_cutoff_generator_inventories_n",
        ),
    ],
)
def test_computable_kill_gates_return_structured_rejection(
    tmp_path: Path,
    option: dict,
    reason: str,
    count_field: str,
) -> None:
    fixture = build_sentinel_fixture(tmp_path, **option)
    report = _preflight(fixture)
    assert report["admission_state"] == "REJECTED_STRUCTURAL_ADMISSION_GATES_NOT_ADMITTED"
    assert reason in report["rejection_reasons"]
    assert report[count_field] > 0
    assert report["cohort_admitted"] is False
    assert report["scientific_scoring_ready"] is False


def test_latin_square_and_primary_balance_are_generation_time_invariants(closed_fixture: dict) -> None:
    plan = closed_fixture["generation_plan"]
    control = next(item for item in plan["case_assignments"] if item["case_role"] == "POSITIVE")
    control["generator_family_id"] = "generator:2"
    reseal_generation_plan(closed_fixture)
    with pytest.raises(CausalFrontierError, match=r"control trio|Latin square"):
        _preflight(closed_fixture)

    fixture = build_sentinel_fixture(closed_fixture["root"].parent / "primary-balance")
    for item in fixture["generation_plan"]["case_assignments"]:
        if item["domain_id"] == "domain:1" and item["case_role"] == "PRIMARY":
            item["generator_family_id"] = "generator:1"
    reseal_generation_plan(fixture)
    with pytest.raises(CausalFrontierError, match="no-majority"):
        _preflight(fixture)


def test_primary_generator_cannot_be_confounded_with_laboratory(closed_fixture: dict) -> None:
    plan = closed_fixture["generation_plan"]
    primary = [
        item for item in plan["case_assignments"] if item["domain_id"] == "domain:1" and item["case_role"] == "PRIMARY"
    ]
    family_three_seen = 0
    for item in primary:
        if item["generator_family_id"] == "generator:1":
            item["laboratory_id"] = "laboratory:1:1"
        elif item["generator_family_id"] == "generator:2":
            item["laboratory_id"] = "laboratory:1:2"
        else:
            family_three_seen += 1
            item["laboratory_id"] = "laboratory:1:1" if family_three_seen == 1 else "laboratory:1:2"
    reseal_generation_plan(closed_fixture)
    with pytest.raises(CausalFrontierError, match="must occur in both domain laboratories"):
        _preflight(closed_fixture)


def test_declared_branch_behavior_must_implement_the_case_role(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, branch_role_mismatch=True)
    with pytest.raises(CausalFrontierError, match="behavior observation states do not map"):
        _preflight(fixture)

    fixture = build_sentinel_fixture(tmp_path / "observation-link", branch_role_observation_mismatch=True)
    with pytest.raises(CausalFrontierError, match="behavior observation states do not map"):
        _preflight(fixture)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_selection_after_generation_allowed", True, "post-outcome or scoring"),
        ("oracle_opening_input_allowed", True, "post-outcome or scoring"),
        ("scoring_disabled", False, "post-outcome or scoring"),
        ("designated_outcome_input_absent", False, "post-outcome or scoring"),
    ],
)
def test_generation_plan_cannot_open_outcome_or_selection_path(
    closed_fixture: dict,
    field: str,
    value: bool,
    message: str,
) -> None:
    closed_fixture["generation_plan"][field] = value
    reseal_generation_plan(closed_fixture)
    with pytest.raises(CausalFrontierError, match=message):
        _preflight(closed_fixture)


def test_consistent_projection_forgery_requires_full_replay(closed_fixture: dict) -> None:
    report = _preflight(closed_fixture)
    report["artifact_files_n"] = 1
    forged = _reseal_report(report)
    with pytest.raises(CausalFrontierError, match="exact deterministic replay"):
        _verify_report(closed_fixture, forged)


def test_role_and_source_packets_cannot_change_after_generation_lock(closed_fixture: dict) -> None:
    role_id = "artifact:case:case-1-01:role-packet"
    role_packet = _artifact_json(closed_fixture, role_id)
    role_packet["observation_protocol"] = "Post-lock replacement protocol."
    _replace_artifact_json(closed_fixture, role_id, role_packet)
    with pytest.raises(CausalFrontierError, match="pre-generation lock"):
        _preflight(closed_fixture)

    fixture = build_sentinel_fixture(closed_fixture["root"].parent / "source-packet-lock")
    source_id = "artifact:case:case-1-01:source"
    descriptor = fixture["artifact_descriptors"][source_id]
    replacement = b"post-lock replacement synthetic source bytes\n"
    (fixture["root"] / descriptor["path"]).write_bytes(replacement)
    descriptor["sha256"] = sha256_bytes(replacement)
    reseal_manifest_and_goal(fixture)
    with pytest.raises(CausalFrontierError, match="source inventory bytes"):
        _preflight(fixture)


def test_precommitted_identity_semantics_and_organization_registry_cannot_drift(closed_fixture: dict) -> None:
    closed_fixture["manifest"]["generators"][0]["mechanism_family_id"] = "mechanism:replacement"
    reseal_manifest_and_goal(closed_fixture)
    with pytest.raises(CausalFrontierError, match="identity or source tree"):
        _preflight(closed_fixture)

    fixture = build_sentinel_fixture(closed_fixture["root"].parent / "semantic-lock")
    semantics_id = "artifact:domain:1:semantics"
    semantics = _artifact_json(fixture, semantics_id)
    semantics["decision_unit"] = "post-lock replacement unit"
    _replace_artifact_json(fixture, semantics_id, semantics)
    with pytest.raises(CausalFrontierError, match="pre-generation commitment"):
        _preflight(fixture)

    fixture = build_sentinel_fixture(closed_fixture["root"].parent / "organization-lock")
    fixture["manifest"]["organizations"][0]["controller_group_id"] = "controller:post-lock-replacement"
    reseal_manifest_and_goal(fixture)
    with pytest.raises(CausalFrontierError, match="organization registry"):
        _preflight(fixture)


def test_case_outcome_provider_cannot_change_after_generation_lock(closed_fixture: dict) -> None:
    closed_fixture["manifest"]["domains"][0]["cases"][0]["outcome_provider_organization_id"] = (
        "organization:adjudicator:2"
    )
    reseal_manifest_and_goal(closed_fixture)
    with pytest.raises(CausalFrontierError, match="assignment differs"):
        _preflight(closed_fixture)


def test_generator_seed_commitments_must_be_unique(closed_fixture: dict) -> None:
    plan = closed_fixture["generation_plan"]
    plan["generator_precommitments"][1]["seed_external_commitment_sha256"] = plan["generator_precommitments"][0][
        "seed_external_commitment_sha256"
    ]
    reseal_generation_plan(closed_fixture)
    with pytest.raises(CausalFrontierError, match="seed commitments must be unique"):
        _preflight(closed_fixture)


def test_case_identifiers_are_case_insensitively_unique(closed_fixture: dict) -> None:
    plan = closed_fixture["generation_plan"]
    first = plan["domain_contracts"][0]["calibration_cases"][0]["case_id"]
    plan["domain_contracts"][0]["calibration_cases"][1]["case_id"] = first.upper()
    reseal_generation_plan(closed_fixture)
    with pytest.raises(CausalFrontierError, match="case-insensitively unique"):
        _preflight(closed_fixture)


def test_declared_branch_contract_must_be_total(closed_fixture: dict) -> None:
    payload_id = "artifact:case:case-1-01:payload"
    payload = _artifact_json(closed_fixture, payload_id)
    payload["decision_core"]["branch_contract"]["mappings"].pop()
    _replace_artifact_json(closed_fixture, payload_id, payload)
    with pytest.raises(CausalFrontierError, match="map every declared observation state"):
        _preflight(closed_fixture)


def test_provenance_rejects_disconnected_branch(closed_fixture: dict) -> None:
    intermediate_id = "artifact:case:case-1-01:orphan-intermediate"
    path = "artifacts/artifact_case_case-1-01_orphan-intermediate.txt"
    raw = b"synthetic disconnected intermediate\n"
    (closed_fixture["root"] / path).write_bytes(raw)
    descriptor = {
        "artifact_id": intermediate_id,
        "path": path,
        "sha256": sha256_bytes(raw),
        "role": "TRANSFORM_INTERMEDIATE",
        "media_type": "text/plain",
        "data_class": "SYNTHETIC",
    }
    closed_fixture["manifest"]["artifacts"].append(descriptor)
    closed_fixture["manifest"]["artifacts"].sort(key=lambda item: item["artifact_id"])
    closed_fixture["artifact_descriptors"][intermediate_id] = descriptor
    provenance_id = "artifact:case:case-1-01:provenance"
    provenance = _artifact_json(closed_fixture, provenance_id)
    provenance["transformations"].append(
        {
            "step_id": "step:case-1-01:orphan",
            "implementation_artifact_id": "artifact:generator:1:source:main",
            "input_artifact_ids": ["artifact:case:case-1-01:source"],
            "output_artifact_id": intermediate_id,
        }
    )
    provenance["transformations"].sort(key=lambda item: item["step_id"])
    _replace_artifact_json(closed_fixture, provenance_id, provenance)
    with pytest.raises(CausalFrontierError, match="disconnected from every final"):
        _preflight(closed_fixture)


def test_oracle_commitments_are_case_linked_and_unique(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, oracle_commitment_collision=True)
    with pytest.raises(CausalFrontierError, match="oracle commitments must be globally unique"):
        _preflight(fixture)


def test_generator_seed_and_oracle_commitment_classes_are_disjoint(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, seed_oracle_commitment_collision=True)
    with pytest.raises(CausalFrontierError, match="commitment classes must be disjoint"):
        _preflight(fixture)


@pytest.mark.parametrize(
    "option",
    [
        "oracle_artifact_digest_collision",
        "seed_artifact_digest_collision",
        "seed_bundle_inventory_digest_collision",
    ],
)
def test_commitment_preimages_must_remain_outside_supplied_inputs(tmp_path: Path, option: str) -> None:
    fixture = build_sentinel_fixture(tmp_path, **{option: True})
    with pytest.raises(CausalFrontierError, match="supplied input preimage"):
        _preflight(fixture)


def test_primary_branch_contract_requires_falsification_and_abstention_paths(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, primary_branch_all_no_call=True)
    with pytest.raises(CausalFrontierError, match="behavior observation states do not map"):
        _preflight(fixture)


def test_availability_evidence_must_link_its_source_and_declared_date(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, availability_evidence_mismatch=True)
    with pytest.raises(CausalFrontierError, match="availability evidence identity or declared date differs"):
        _preflight(fixture)


def test_protocol_artifacts_must_contain_committed_bytes(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, empty_protocol_artifact=True)
    with pytest.raises(CausalFrontierError, match="protocol artifacts must be nonempty"):
        _preflight(fixture)


def test_case_structured_artifacts_require_json_media_type(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, wrong_case_artifact_media_type=True)
    with pytest.raises(CausalFrontierError, match="structured artifacts must use application/json"):
        _preflight(fixture)


def test_goal_calibration_must_bind_control_artifact_preimages(closed_fixture: dict) -> None:
    closed_fixture["goal_plan"]["calibration"]["control_oracle_commitment_sha256"] = "a" * 64
    reseal_manifest_and_goal(closed_fixture)
    with pytest.raises(CausalFrontierError, match="calibration commitments are not preimages"):
        _preflight(closed_fixture)


def test_false_domain_difference_declaration_is_rejected(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path, false_domain_axis_declaration=True)
    with pytest.raises(CausalFrontierError, match="declares a difference absent"):
        _preflight(fixture)


def test_unused_organization_and_metadata_decision_source_fail(tmp_path: Path) -> None:
    fixture = build_sentinel_fixture(tmp_path / "unused", unused_organization=True)
    with pytest.raises(CausalFrontierError, match="unused organization"):
        _preflight(fixture)
    fixture = build_sentinel_fixture(tmp_path / "metadata", public_metadata_source=True)
    with pytest.raises(CausalFrontierError, match="ineligible data class"):
        _preflight(fixture)


def test_generator_audit_cannot_self_certify_independence(closed_fixture: dict) -> None:
    artifact_id = "artifact:generator-audit:1:2"
    audit = _artifact_json(closed_fixture, artifact_id)
    audit["semantic_independence_verified"] = True
    _replace_artifact_json(closed_fixture, artifact_id, audit)
    with pytest.raises(CausalFrontierError, match="overclaims independence"):
        _preflight(closed_fixture)


def test_domain_review_cannot_self_certify_semantics(closed_fixture: dict) -> None:
    artifact_id = "artifact:domain:1:review"
    review = _artifact_json(closed_fixture, artifact_id)
    review["domain_semantic_validity_verified"] = True
    _replace_artifact_json(closed_fixture, artifact_id, review)
    with pytest.raises(CausalFrontierError, match="domain review packet overclaims"):
        _preflight(closed_fixture)


def test_cutoff_packet_cannot_self_certify_time(closed_fixture: dict) -> None:
    artifact_id = "artifact:case:case-1-01:cutoff-audit"
    audit = _artifact_json(closed_fixture, artifact_id)
    audit["public_availability_verified"] = True
    _replace_artifact_json(closed_fixture, artifact_id, audit)
    with pytest.raises(CausalFrontierError, match="overclaims independent time"):
        _preflight(closed_fixture)


def test_provenance_unknown_input_and_case_artifact_reuse_fail(closed_fixture: dict) -> None:
    artifact_id = "artifact:case:case-1-01:provenance"
    provenance = _artifact_json(closed_fixture, artifact_id)
    provenance["transformations"][0]["input_artifact_ids"] = ["artifact:unknown"]
    _replace_artifact_json(closed_fixture, artifact_id, provenance)
    with pytest.raises(CausalFrontierError, match="unknown input"):
        _preflight(closed_fixture)

    fixture = build_sentinel_fixture(closed_fixture["root"].parent / "reuse")
    first_domain = fixture["manifest"]["domains"][0]
    first_domain["cases"][1]["case_payload_artifact_id"] = first_domain["cases"][0]["case_payload_artifact_id"]
    reseal_manifest_and_goal(fixture)
    with pytest.raises(CausalFrontierError, match="case-specific artifact is reused"):
        _preflight(fixture)


def test_second_snapshot_detects_drift(closed_fixture: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    original = sentinel._snapshot_bundle
    calls = 0

    def drifting_snapshot(root: Path, expected_sha256: str):
        nonlocal calls
        result = original(root, expected_sha256)
        calls += 1
        if calls == 1:
            descriptor = closed_fixture["artifact_descriptors"]["artifact:case:case-1-01:source"]
            (closed_fixture["root"] / descriptor["path"]).write_text("drift\n", encoding="utf-8")
        return result

    monkeypatch.setattr(sentinel, "_snapshot_bundle", drifting_snapshot)
    with pytest.raises(CausalFrontierError, match="artifact digest mismatch"):
        _preflight(closed_fixture)


def test_preflight_uses_no_network_or_subprocess(closed_fixture: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("external execution is forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert _preflight(closed_fixture)["admission_state"] == "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"


def test_preflight_is_read_only(closed_fixture: dict) -> None:
    before = {
        path.relative_to(closed_fixture["root"]).as_posix(): sha256_bytes(path.read_bytes())
        for path in closed_fixture["root"].rglob("*")
        if path.is_file()
    }
    _preflight(closed_fixture)
    after = {
        path.relative_to(closed_fixture["root"]).as_posix(): sha256_bytes(path.read_bytes())
        for path in closed_fixture["root"].rglob("*")
        if path.is_file()
    }
    assert after == before


def test_public_api_exports_sentinel_boundary() -> None:
    assert causalfrontier.preflight_sentinel_admission is sentinel.preflight_sentinel_admission
    assert causalfrontier.preflight_sentinel_generation_plan is sentinel.preflight_sentinel_generation_plan
    assert causalfrontier.verify_sentinel_admission_preflight is sentinel.verify_sentinel_admission_preflight
    assert not hasattr(causalfrontier, "validate_sentinel_admission_report")


def test_cli_preflights_generation_and_admission(closed_fixture: dict, capsys: pytest.CaptureFixture) -> None:
    generation_exit = cli.main(
        [
            "preflight-sentinel-generation-plan",
            str(closed_fixture["generation_plan_path"]),
            "--expected-generation-plan-sha256",
            closed_fixture["generation_plan_sha256"],
        ]
    )
    generation_output = json.loads(capsys.readouterr().out)
    assert generation_exit == 3
    assert generation_output["status"] == sentinel.GENERATION_PLAN_STATUS

    admission_exit = cli.main(
        [
            "preflight-sentinel-admission",
            str(closed_fixture["root"]),
            str(closed_fixture["generation_plan_path"]),
            str(closed_fixture["goal_plan_path"]),
            "--expected-manifest-sha256",
            closed_fixture["manifest_sha256"],
            "--expected-sequence",
            "1",
            "--expected-generation-plan-sha256",
            closed_fixture["generation_plan_sha256"],
            "--expected-goal-claim-plan-sha256",
            closed_fixture["goal_plan_sha256"],
        ]
    )
    admission_output = json.loads(capsys.readouterr().out)
    assert admission_exit == 3
    assert admission_output["admission_state"] == "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"
    assert admission_output["scientific_scoring_ready"] is False


def test_cli_malformed_sentinel_exits_two_without_json(closed_fixture: dict, capsys: pytest.CaptureFixture) -> None:
    exit_code = cli.main(
        [
            "preflight-sentinel-admission",
            str(closed_fixture["root"]),
            str(closed_fixture["generation_plan_path"]),
            str(closed_fixture["goal_plan_path"]),
            "--expected-manifest-sha256",
            "a" * 64,
            "--expected-sequence",
            "1",
            "--expected-generation-plan-sha256",
            closed_fixture["generation_plan_sha256"],
            "--expected-goal-claim-plan-sha256",
            closed_fixture["goal_plan_sha256"],
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "manifest checkpoint mismatch" in captured.err
