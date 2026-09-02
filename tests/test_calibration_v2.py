"""Hostile tests for the role-hidden structured-action calibration protocol."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from itertools import permutations
from pathlib import Path
from typing import Any

import pytest

from causalfrontier import calibration_v2 as v2
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


def _opaque(kind: str, label: str) -> str:
    return f"entrant:{kind}:" + _digest(f"{kind}:{label}")


def _coordinate(
    execution: str,
    target: str,
    translation: str,
    consistency: str,
) -> list[dict[str, str]]:
    states = (execution, target, translation, consistency)
    return [{"axis_id": axis_id, "state_id": state_id} for axis_id, state_id in zip(v2.AXIS_ORDER, states, strict=True)]


def _inactive_proposed() -> dict[str, Any]:
    return {
        "status": "NOT_APPLICABLE",
        "question": None,
        "design_class": None,
        "population_or_system": None,
        "intervention_or_exposure": None,
        "comparator": None,
        "primary_endpoint": None,
        "time_horizon": None,
        "falsification_threshold": None,
        "replication_requirement": None,
        "stopping_boundary": None,
        "required_authorities_if_executed": [],
        "execution_authorized": False,
    }


def _inactive_rejection() -> dict[str, Any]:
    return {
        "status": "NOT_APPLICABLE",
        "rejected_claim_ids": [],
        "retained_claim_ids": [],
        "scope_limit": None,
        "reversal_information_ids": [],
    }


def _inactive_information() -> dict[str, Any]:
    return {
        "status": "NOT_APPLICABLE",
        "unresolved_claim_ids": [],
        "competing_claim_sets": [],
        "requested_information_ids": [],
        "resolution_rule": None,
    }


def _decision(mode: str, claims: list[str]) -> dict[str, Any]:
    proposed = _inactive_proposed()
    rejection = _inactive_rejection()
    information = _inactive_information()
    if mode == "PROPOSE_FALSIFICATION":
        proposed = {
            "status": "DESCRIPTION_ONLY_NOT_AUTHORIZED",
            "question": "Does a bounded intervention change the prespecified hard endpoint?",
            "design_class": "RANDOMIZED_CONTROLLED_COMPUTATIONAL_DESCRIPTION",
            "population_or_system": "The explicitly bounded aggregate study population",
            "intervention_or_exposure": "The named intervention at a frozen dose and schedule",
            "comparator": "A concurrently randomized control under the same measurement protocol",
            "primary_endpoint": "The frozen aggregate primary endpoint, without surrogate substitution",
            "time_horizon": "The predeclared follow-up interval",
            "falsification_threshold": "The frozen interval must exclude the null in the beneficial direction",
            "replication_requirement": "One prespecified independent replication or coherent held-out cohort",
            "stopping_boundary": "Stop for harm, integrity failure, or the frozen futility boundary",
            "required_authorities_if_executed": [
                "DOMAIN_AUTHORITY",
                "ETHICS_IF_APPLICABLE",
                "EXTERNAL_REVIEW",
                "RESOURCE_AUTHORITY",
            ],
            "execution_authorized": False,
        }
    elif mode == "BOUNDED_REJECTION":
        rejection = {
            "status": "BOUNDED_REVERSIBLE_REJECTION",
            "rejected_claim_ids": [claims[0]],
            "retained_claim_ids": claims[1:],
            "scope_limit": "Reject only this translation claim, population, endpoint, and intervention version",
            "reversal_information_ids": ["information.clinical-outcome"],
        }
    else:
        information = {
            "status": "ACTIONABLE_MINIMUM_INFORMATION_BOUNDARY",
            "unresolved_claim_ids": claims,
            "competing_claim_sets": [[claims[0]], [claims[1]]],
            "requested_information_ids": ["information.clinical-outcome"],
            "resolution_rule": "Resolve only after the prespecified endpoint and safety branches are jointly observed",
        }
    return {
        "mode": mode,
        "target_claim_ids": claims,
        "selected_feature_ids": ["feature.endpoint-specificity", "feature.required"],
        "proposed_falsification": proposed,
        "bounded_rejection": rejection,
        "minimum_information_boundary": information,
    }


def _evidence_assessments(source_ids: list[str], claim_ids: list[str], relations: list[str]) -> list[dict[str, str]]:
    coordinates = [(source_id, claim_id) for source_id in source_ids for claim_id in claim_ids]
    return [
        {
            "opaque_source_id": source_id,
            "claim_id": claim_id,
            "relation": relations[index % len(relations)],
            "reason": f"Frozen pre-cutoff relation {index + 1} is assessed without opening access.",
        }
        for index, (source_id, claim_id) in enumerate(coordinates)
    ]


def _branch_contract(claim_ids: list[str], decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": v2.BRANCH_SCHEMA_VERSION,
        "partition": "CARTESIAN_TOTAL_ENUMERATION_WITH_FAILURE_HARM_CONTRADICTION_AND_RESIDUAL",
        "axis_order": list(v2.AXIS_ORDER),
        "coordinate_count": v2.COORDINATE_COUNT,
        "target_claim_ids": claim_ids,
        "decision_sha256": sha256_bytes(canonical_bytes(decision)),
        "rows": v2.canonical_branch_rows(claim_ids),
    }


def _trace(toolbox_contract: list[dict[str, str]], case_id: str) -> list[dict[str, str]]:
    return [
        {
            **stage,
            "status": "DECLARED_ARTIFACT_BOUND_NOT_REPLAYED",
            "artifact_sha256": _digest(f"artifact:{case_id}:{stage['stage_id']}"),
            "resource_receipt_sha256": _digest(f"resource:{case_id}:{stage['stage_id']}"),
        }
        for stage in toolbox_contract
    ]


def _ledger(case_id: str) -> dict[str, Any]:
    stages = dict.fromkeys(v2.LEDGER_STAGES, 0)
    stages["preprocessing"] = 1
    stages["compute"] = 2
    return {
        "opaque_case_id": case_id,
        "stages": stages,
        "model_input_tokens": 100,
        "model_output_tokens": 50,
        "tool_calls": 0,
        "network_requests": 0,
        "input_bytes": 1000,
        "output_bytes": 2000,
        "calendar_elapsed_ns": 100,
        "measurement_origin": "DECLARED_ONLY",
        "complete": True,
        "reveal_accessed": False,
    }


PANEL = (
    ("reviewer.a", "organization.a"),
    ("reviewer.b", "organization.b"),
    ("reviewer.c", "organization.b"),
)


def _rubric(protocol_id: str, case_ids: list[str], view_content_binding_sha256: str) -> dict[str, Any]:
    sentinel_coordinates = [
        _coordinate("FAILED", "CONFIRMED", "BENEFIT", "CONSISTENT"),
        _coordinate("COMPLETE", "CONFIRMED", "HARM", "CONSISTENT"),
        _coordinate("COMPLETE", "CONFIRMED", "BENEFIT", "DISCORDANT"),
    ]
    entries = []
    for case_id, coordinate in zip(case_ids, sentinel_coordinates, strict=True):
        branch = v2._expected_branch(coordinate)
        entries.append(
            {
                "opaque_case_id": case_id,
                "required_feature_ids": ["feature.required"],
                "forbidden_feature_ids": ["feature.surrogate-substitution"],
                "sentinel_rows": [
                    {
                        "coordinate": coordinate,
                        "required_branch_class": branch,
                        "required_successor": v2.SUCCESSOR_BY_BRANCH[branch],
                    }
                ],
                "semantic_criteria": [
                    {
                        "criterion_id": criterion_id,
                        "question": f"Does the anonymous output satisfy {criterion_id.lower()}?",
                    }
                    for criterion_id in v2.ADJUDICATION_CRITERIA
                ],
            }
        )
    return {
        "schema_version": v2.RUBRIC_SCHEMA_VERSION,
        "protocol_id": protocol_id,
        "view_content_binding_sha256": view_content_binding_sha256,
        "nonce_hex": "cd" * 32,
        "criteria_order": list(v2.ADJUDICATION_CRITERIA),
        "entries": entries,
        "review_plan": {
            "plan_id": "review.plan.v2.test",
            "minimum_reviewers": 3,
            "minimum_organizations": 2,
            "reviewer_assignments": [
                {
                    "reviewer_id": reviewer_id,
                    "organization_id": organization_id,
                    "assignment_checkpoint_sha256": _digest(f"review:{reviewer_id}"),
                }
                for reviewer_id, organization_id in PANEL
            ],
            "policy_identity_blinded_required": True,
            "ex_ante_outcome_hidden_required": True,
            "phase_separation_required": True,
            "aggregation_rule": "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL",
        },
        "aggregation_rule": "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL",
    }


def _votes(verdict: str = "PASS") -> list[dict[str, Any]]:
    return [
        {
            "reviewer_id": reviewer_id,
            "organization_id": organization_id,
            "policy_identity_blinded_declared": True,
            "outcome_hidden_during_ex_ante_review_declared": True,
            "criteria": [
                {"criterion_id": criterion_id, "verdict": verdict, "reason_code": "DECLARED_REVIEW_PASS"}
                for criterion_id in v2.ADJUDICATION_CRITERIA
            ],
            "review_checkpoint_sha256": _digest(f"review:{reviewer_id}"),
        }
        for reviewer_id, organization_id in PANEL
    ]


def _refresh_downstream(fixture: dict[str, Any]) -> None:
    fixture["submission_sha256"] = _write_json(fixture["submission_path"], fixture["submission"])
    fixture["submission_seal"] = v2.seal_calibration_v2_submission(
        fixture["root"],
        fixture["manifest_sha256"],
        fixture["view_lock_path"],
        fixture["view_lock_sha256"],
        fixture["submission_path"],
        fixture["submission_sha256"],
    )
    fixture["submission_seal_sha256"] = _write_json(fixture["submission_seal_path"], fixture["submission_seal"])
    fixture["opening"]["submission_seal_sha256"] = fixture["submission_seal"]["submission_seal_sha256"]
    fixture["opening_sha256"] = _write_json(fixture["opening_path"], fixture["opening"])
    fixture["rubric_sha256"] = _write_json(fixture["rubric_path"], fixture["rubric"])
    fixture["adjudication"].update(
        {
            "submission_raw_sha256": fixture["submission_sha256"],
            "submission_seal_sha256": fixture["submission_seal"]["submission_seal_sha256"],
            "opening_raw_sha256": fixture["opening_sha256"],
            "rubric_raw_sha256": fixture["rubric_sha256"],
        }
    )
    fixture["adjudication_sha256"] = _write_json(fixture["adjudication_path"], fixture["adjudication"])
    fixture["report"] = _finalize(fixture)
    fixture["report_sha256"] = _write_json(fixture["report_path"], fixture["report"])


def _finalize(fixture: dict[str, Any]) -> dict[str, Any]:
    return v2.finalize_calibration_v2(
        fixture["root"],
        fixture["manifest_sha256"],
        fixture["view_lock_path"],
        fixture["view_lock_sha256"],
        fixture["submission_path"],
        fixture["submission_sha256"],
        fixture["submission_seal_path"],
        fixture["submission_seal_sha256"],
        fixture["opening_path"],
        fixture["opening_sha256"],
        fixture["rubric_path"],
        fixture["rubric_sha256"],
        fixture["adjudication_path"],
        fixture["adjudication_sha256"],
    )


def build_v2_fixture(
    base: Path,
    *,
    modes: tuple[str, str, str] = (
        "PROPOSE_FALSIFICATION",
        "REQUEST_INFORMATION",
        "REQUEST_INFORMATION",
    ),
    role_order: tuple[str, str, str] = ("AMBIGUOUS", "POSITIVE", "FAILED_TRANSLATION"),
) -> dict[str, Any]:
    root = base / "entrant-root"
    external = base / "external-zones"
    root.mkdir(parents=True)
    external.mkdir(parents=True)
    protocol_id = "calibration.v2.test"
    case_ids = sorted(_opaque("case", str(index)) for index in range(3))
    source_ids = {_id: _opaque("source", _id) for _id in case_ids}
    roles = dict(zip(case_ids, role_order, strict=True))
    cutoffs = {
        case_ids[0]: "2012-12-31T23:59:59Z",
        case_ids[1]: "2016-11-03T23:59:59Z",
        case_ids[2]: "2020-02-20T23:59:59Z",
    }
    available = {
        case_ids[0]: "2012-12-08T00:00:00Z",
        case_ids[1]: "2016-11-02T00:00:00Z",
        case_ids[2]: "2020-02-13T00:00:00Z",
    }
    reveal_available = {
        case_ids[0]: "2017-03-17T00:00:00Z",
        case_ids[1]: "2018-05-03T00:00:00Z",
        case_ids[2]: "2020-05-22T00:00:00Z",
    }
    observed_by_role = {
        "POSITIVE": _coordinate("COMPLETE", "CONFIRMED", "BENEFIT", "CONSISTENT"),
        "FAILED_TRANSLATION": _coordinate("COMPLETE", "CONFIRMED", "HARM", "CONSISTENT"),
        "AMBIGUOUS": _coordinate("COMPLETE", "CONFIRMED", "UNKNOWN", "INSUFFICIENT"),
    }
    observed = {case_id: observed_by_role[roles[case_id]] for case_id in case_ids}
    toolbox_contract = [
        {
            "stage_id": stage_id,
            "implementation_version": "test-1.0",
            "source_tree_sha256": _digest(f"source-tree:{stage_id}"),
        }
        for stage_id in v2.DERIVATION_STAGES
    ]
    controls = []
    for index, case_id in enumerate(case_ids):
        source_path = f"sources/source-{index}.json"
        source_sha256 = _write_json(
            root / source_path,
            {
                "schema_version": "test.public-evidence-card.v1",
                "source_id": source_ids[case_id],
                "statement": f"Cutoff-valid aggregate evidence fragment {index + 1}",
            },
        )
        controls.append(
            {
                "opaque_case_id": case_id,
                "knowledge_cutoff": cutoffs[case_id],
                "decision_question": "What bounded next action best separates the live translation claims?",
                "sources": [
                    {
                        "opaque_source_id": source_ids[case_id],
                        "path": source_path,
                        "sha256": source_sha256,
                        "available_at": available[case_id],
                        "data_class": "PUBLIC_METADATA",
                        "authority": "PUBLIC_DATA",
                    }
                ],
                "claim_catalog": [
                    {"claim_id": "claim.a", "label": "Bounded translation claim A", "scope": "scope.a"},
                    {"claim_id": "claim.b", "label": "Bounded translation claim B", "scope": "scope.b"},
                ],
                "information_requirements": [
                    {
                        "requirement_id": "information.clinical-outcome",
                        "description": "Prespecified hard endpoint and safety readout",
                    },
                    {
                        "requirement_id": "information.target-engagement",
                        "description": "Prespecified target-engagement readout",
                    },
                ],
                "feature_catalog": [
                    {"feature_id": "feature.endpoint-specificity", "label": "Endpoint-specific interpretation"},
                    {"feature_id": "feature.required", "label": "Case-specific required feature"},
                    {
                        "feature_id": "feature.surrogate-substitution",
                        "label": "Forbidden surrogate substitution",
                    },
                ],
            }
        )
    manifest = {
        "schema_version": v2.VIEW_SCHEMA_VERSION,
        "id": protocol_id,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "scientific_scoring_ready": False,
        "role_labels_omitted": True,
        "required_behaviors_omitted": True,
        "oracle_material_omitted": True,
        "reveal_input_accepted": False,
        "reveal_commitment_scheme": v2.REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": _digest("pending-reveal-commitment"),
        "rubric_commitment_scheme": v2.RUBRIC_COMMITMENT_SCHEME,
        "rubric_commitment_sha256": _digest("pending-rubric-commitment"),
        "observation_axes": v2.observation_axes_v2(),
        "toolbox_contract": toolbox_contract,
        "controls": controls,
    }
    view_content_binding_sha256 = v2.view_content_binding_v2(manifest)
    opening_payload = {
        "schema_version": v2.OPENING_PAYLOAD_SCHEMA_VERSION,
        "protocol_id": protocol_id,
        "view_content_binding_sha256": view_content_binding_sha256,
        "entries": [
            {
                "opaque_case_id": case_id,
                "control_role": roles[case_id],
                "observed_coordinate": observed[case_id],
                "reveal_source_sha256": _digest(f"reveal:{case_id}"),
                "reveal_available_at": reveal_available[case_id],
            }
            for case_id in case_ids
        ],
    }
    nonce_hex = "ab" * 32
    rubric = _rubric(protocol_id, case_ids, view_content_binding_sha256)
    manifest["reveal_commitment_sha256"] = v2.reveal_commitment_v2(opening_payload, nonce_hex)
    manifest["rubric_commitment_sha256"] = v2.rubric_commitment_v2(rubric)
    manifest_path = root / v2.VIEW_MANIFEST
    manifest_sha256 = _write_json(manifest_path, manifest)
    view_lock = v2.preflight_calibration_v2_view(root, manifest_sha256)
    view_lock_path = external / "view-lock.json"
    view_lock_sha256 = _write_json(view_lock_path, view_lock)
    relations = (
        ["SUPPORTS", "SUPPORTS"],
        ["WEAKENS", "LIMITS_TRANSPORT"],
        ["LIMITS_TRANSPORT", "UNKNOWN"],
    )
    claim_ids = ["claim.a", "claim.b"]
    submission_cases = []
    ledgers = []
    for index, (case_id, mode) in enumerate(zip(case_ids, modes, strict=True)):
        decision = _decision(mode, claim_ids)
        submission_cases.append(
            {
                "opaque_case_id": case_id,
                "completion_state": "COMPLETE",
                "failure_code": None,
                "decision": decision,
                "evidence_assessments": _evidence_assessments([source_ids[case_id]], claim_ids, relations[index]),
                "branch_contract": _branch_contract(claim_ids, decision),
                "derivation_trace": _trace(toolbox_contract, case_id),
            }
        )
        ledgers.append(_ledger(case_id))
    submission = {
        "schema_version": v2.SUBMISSION_SCHEMA_VERSION,
        "protocol_id": protocol_id,
        "run_id": "run.v2.test",
        "policy_id": "policy.causalfrontier.v2",
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "fixed_parameter": FIXED_PARAMETER,
        "generated_from_role_hidden_view_only_declared": True,
        "cases": submission_cases,
        "resource_ledgers": ledgers,
    }
    opening = {
        "schema_version": v2.OPENING_SCHEMA_VERSION,
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_seal_sha256": GENESIS_PLACEHOLDER,
        "nonce_hex": nonce_hex,
        "payload": opening_payload,
    }
    adjudication = {
        "schema_version": v2.ADJUDICATION_SCHEMA_VERSION,
        "protocol_id": protocol_id,
        "run_id": submission["run_id"],
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_raw_sha256": GENESIS_PLACEHOLDER,
        "submission_seal_sha256": GENESIS_PLACEHOLDER,
        "opening_raw_sha256": GENESIS_PLACEHOLDER,
        "rubric_raw_sha256": GENESIS_PLACEHOLDER,
        "criteria_order": list(v2.ADJUDICATION_CRITERIA),
        "entries": [{"opaque_case_id": case_id, "votes": _votes()} for case_id in case_ids],
    }
    fixture = {
        "root": root,
        "external": external,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_sha256": manifest_sha256,
        "view_lock": view_lock,
        "view_lock_path": view_lock_path,
        "view_lock_sha256": view_lock_sha256,
        "submission": submission,
        "submission_path": external / "submission.json",
        "submission_seal_path": external / "submission-seal.json",
        "opening": opening,
        "opening_path": external / "opening.json",
        "rubric": rubric,
        "rubric_path": external / "rubric.json",
        "adjudication": adjudication,
        "adjudication_path": external / "adjudication.json",
        "report_path": external / "report.json",
        "case_ids": case_ids,
        "source_ids": source_ids,
    }
    _refresh_downstream(fixture)
    return fixture


GENESIS_PLACEHOLDER = "0" * 64


@pytest.fixture
def v2_fixture(tmp_path: Path) -> dict[str, Any]:
    return build_v2_fixture(tmp_path)


def test_v2_completes_structural_rehearsal_without_self_issuing_method_recovery(
    v2_fixture: dict[str, Any],
) -> None:
    report = _finalize(v2_fixture)
    assert report == v2_fixture["report"]
    assert report["status"] == v2.REPORT_STRUCTURAL_STATUS
    assert report["controls_structurally_complete_n"] == 3
    assert report["controls_declared_review_candidate_n"] == 3
    assert report["controls_semantically_verified_n"] == 0
    assert report["local_protocol_conformance_pass"] is True
    assert report["declared_review_candidate_pass"] is True
    assert report["fixed_protocol_safety_table_replayed"] is True
    assert report["method_recovery_status"] == "NO_CALL_EXTERNAL_REVIEW_REQUIRED"
    assert report["method_recovery_pass"] is False
    assert report["action_pattern"] == [
        "PROPOSE_FALSIFICATION",
        "REQUEST_INFORMATION",
        "REQUEST_INFORMATION",
    ]
    by_role = {item["control_role"]: item for item in report["case_results"]}
    assert by_role["POSITIVE"]["fixed_protocol_opened_outcome_class"] == "SUPPORTS_NEXT_FALSIFICATION"
    assert by_role["FAILED_TRANSLATION"]["fixed_protocol_opened_outcome_class"] == "HARM_SIGNAL"
    assert by_role["AMBIGUOUS"]["fixed_protocol_opened_outcome_class"] == "UNRESOLVED"
    assert report["precutoff_action_and_successor_outcome_orthogonalized"] is False
    assert report["candidate_branch_semantics_evaluated"] is False
    assert report["action_branch_semantics_verified"] is False
    assert report["reviewer_plan_precommitted_verified"] is True
    assert report["vote_signatures_verified"] is False
    assert report["independent_semantic_adjudication_verified"] is False
    assert report["primary_scoring_ready"] is False
    assert report["scientific_scoring_ready"] is False
    assert report["scientific_claim_ready"] is False
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None


def test_view_lock_reads_no_opening_and_exposes_no_roles(v2_fixture: dict[str, Any]) -> None:
    lock = v2.preflight_calibration_v2_view(v2_fixture["root"], v2_fixture["manifest_sha256"])
    rendered = canonical_bytes(lock)
    assert lock["status"] == v2.VIEW_LOCK_STATUS
    assert lock["opening_read"] is False
    assert b"POSITIVE" not in rendered
    assert b"FAILED_TRANSLATION" not in rendered
    assert b"AMBIGUOUS" not in rendered
    assert lock["semantic_blinding_verified"] is False
    assert lock["opaque_identifier_hmac_verified"] is False


def test_all_role_permutations_are_valid_and_sorted_position_does_not_fix_role(tmp_path: Path) -> None:
    observed_orders = []
    for index, role_order in enumerate(permutations(v2.CONTROL_ROLES)):
        fixture = build_v2_fixture(tmp_path / f"permutation-{index}", role_order=role_order)
        opened = tuple(item["control_role"] for item in fixture["report"]["case_results"])
        assert opened == role_order
        assert fixture["report"]["positional_role_mapping_absent_verified"] is True
        assert fixture["report"]["method_recovery_pass"] is False
        observed_orders.append(opened)
    assert len(set(observed_orders)) == 6


def test_submission_seal_reads_no_opening_or_rubric(v2_fixture: dict[str, Any]) -> None:
    seal = v2.seal_calibration_v2_submission(
        v2_fixture["root"],
        v2_fixture["manifest_sha256"],
        v2_fixture["view_lock_path"],
        v2_fixture["view_lock_sha256"],
        v2_fixture["submission_path"],
        v2_fixture["submission_sha256"],
    )
    assert seal == v2_fixture["submission_seal"]
    assert seal["opening_read"] is False
    assert seal["rubric_read"] is False
    assert seal["complete_intention_to_test_matrix_verified"] is True
    assert seal["branch_partition_total_and_exclusive_for_complete_cases_verified"] is True


def test_fixed_branch_contract_covers_all_72_coordinates_and_failure_classes() -> None:
    rows = v2.canonical_branch_rows(["claim.a", "claim.b"])
    assert len(rows) == 72
    assert len({canonical_bytes(row["coordinate"]) for row in rows}) == 72
    assert {row["branch_class"] for row in rows} == set(v2.BRANCH_CLASSES)
    failed = next(
        row
        for row in rows
        if {item["axis_id"]: item["state_id"] for item in row["coordinate"]}["execution_state"] == "FAILED"
    )
    assert failed["branch_class"] == "OPERATIONAL_FAILURE"
    assert failed["successor"] == "REPAIR_OR_REPEAT"
    assert all(item["state"] == "UNKNOWN" for item in failed["claim_states"])
    harm_rows = [
        row
        for row in rows
        if {item["axis_id"]: item["state_id"] for item in row["coordinate"]}["translation_outcome"] == "HARM"
    ]
    assert len(harm_rows) == 18
    assert all(item["branch_class"] == "HARM_SIGNAL" for item in harm_rows)
    assert all(item["successor"] == "STOP_FOR_SAFETY" for item in harm_rows)
    assert all(state["state"] == "UNKNOWN" for item in harm_rows for state in item["claim_states"])


def test_returned_branch_rows_and_axis_snapshots_cannot_poison_validator_policy() -> None:
    first = v2.canonical_branch_rows(["claim.a", "claim.b"])
    expected = canonical_bytes(v2.canonical_branch_rows(["claim.a", "claim.b"]))
    first[0]["coordinate"][0]["state_id"] = "FAILED"
    first[1]["claim_states"][0]["state"] = "EXCLUDED"
    assert canonical_bytes(v2.canonical_branch_rows(["claim.a", "claim.b"])) == expected

    original = v2.OBSERVATION_AXES[0]["state_ids"][0]
    try:
        v2.OBSERVATION_AXES[0]["state_ids"][0] = "POISONED"
        assert v2.observation_axes_v2()[0]["state_ids"][0] == "COMPLETE"
        assert len(v2.canonical_branch_rows(["claim.a", "claim.b"])) == 72
    finally:
        v2.OBSERVATION_AXES[0]["state_ids"][0] = original

    original_successor = v2.SUCCESSOR_BY_BRANCH["HARM_SIGNAL"]
    original_claim_state = v2.CLAIM_STATE_BY_BRANCH["HARM_SIGNAL"]
    try:
        v2.SUCCESSOR_BY_BRANCH["HARM_SIGNAL"] = "ADVANCE_FALSIFICATION"
        v2.CLAIM_STATE_BY_BRANCH["HARM_SIGNAL"] = "SURVIVES"
        harm = next(
            row
            for row in v2.canonical_branch_rows(["claim.a"])
            if {item["axis_id"]: item["state_id"] for item in row["coordinate"]}["translation_outcome"] == "HARM"
        )
        assert harm["successor"] == "STOP_FOR_SAFETY"
        assert harm["claim_states"] == [{"claim_id": "claim.a", "state": "UNKNOWN"}]
    finally:
        v2.SUCCESSOR_BY_BRANCH["HARM_SIGNAL"] = original_successor
        v2.CLAIM_STATE_BY_BRANCH["HARM_SIGNAL"] = original_claim_state


def test_branch_gap_overlap_reorder_or_semantic_rewrite_fails(v2_fixture: dict[str, Any]) -> None:
    rows = v2_fixture["submission"]["cases"][0]["branch_contract"]["rows"]
    rows.pop()
    v2_fixture["submission_sha256"] = _write_json(v2_fixture["submission_path"], v2_fixture["submission"])
    with pytest.raises(CausalFrontierError, match="complete Cartesian enumeration"):
        v2.seal_calibration_v2_submission(
            v2_fixture["root"],
            v2_fixture["manifest_sha256"],
            v2_fixture["view_lock_path"],
            v2_fixture["view_lock_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
        )

    second = build_v2_fixture(v2_fixture["external"] / "second")
    second["submission"]["cases"][0]["branch_contract"]["rows"][0]["branch_class"] = "HARM_SIGNAL"
    second["submission_sha256"] = _write_json(second["submission_path"], second["submission"])
    with pytest.raises(CausalFrontierError, match="fixed failure, harm, contradiction, or residual semantics"):
        v2.seal_calibration_v2_submission(
            second["root"],
            second["manifest_sha256"],
            second["view_lock_path"],
            second["view_lock_sha256"],
            second["submission_path"],
            second["submission_sha256"],
        )


def test_action_threshold_change_requires_a_new_branch_binding(v2_fixture: dict[str, Any]) -> None:
    decision = v2_fixture["submission"]["cases"][0]["decision"]
    decision["proposed_falsification"]["falsification_threshold"] = "A materially different frozen threshold"
    v2_fixture["submission_sha256"] = _write_json(v2_fixture["submission_path"], v2_fixture["submission"])
    with pytest.raises(CausalFrontierError, match="structured-action binding differs"):
        v2.seal_calibration_v2_submission(
            v2_fixture["root"],
            v2_fixture["manifest_sha256"],
            v2_fixture["view_lock_path"],
            v2_fixture["view_lock_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
        )


def test_constant_and_all_abstain_policies_cannot_pass(tmp_path: Path) -> None:
    constant = build_v2_fixture(
        tmp_path / "constant",
        modes=("PROPOSE_FALSIFICATION", "PROPOSE_FALSIFICATION", "PROPOSE_FALSIFICATION"),
    )
    assert constant["report"]["constant_action_pattern"] is True
    assert constant["report"]["method_recovery_pass"] is False
    assert constant["report"]["status"] == v2.REPORT_BLOCKED_STATUS

    abstain = build_v2_fixture(
        tmp_path / "abstain",
        modes=("REQUEST_INFORMATION", "REQUEST_INFORMATION", "REQUEST_INFORMATION"),
    )
    assert abstain["report"]["always_abstain_equivalent"] is True
    assert abstain["report"]["method_recovery_pass"] is False


def test_all_unknown_evidence_relations_never_establish_local_conformance(tmp_path: Path) -> None:
    fixture = build_v2_fixture(tmp_path)
    for case in fixture["submission"]["cases"]:
        for assessment in case["evidence_assessments"]:
            assessment["relation"] = "UNKNOWN"
    _refresh_downstream(fixture)
    assert fixture["submission_seal"]["all_complete_cases_decision_relevant_evidence_declared"] is False
    assert fixture["report"]["local_protocol_conformance_pass"] is False
    assert fixture["report"]["method_recovery_pass"] is False


def test_entrant_failure_is_retained_intention_to_test_and_counts_as_failure(tmp_path: Path) -> None:
    fixture = build_v2_fixture(tmp_path)
    case = fixture["submission"]["cases"][1]
    case.update(
        {
            "completion_state": "ENTRANT_FAILURE",
            "failure_code": "TIMEOUT",
            "decision": None,
            "evidence_assessments": [],
            "branch_contract": None,
            "derivation_trace": [],
        }
    )
    _refresh_downstream(fixture)
    assert fixture["submission_seal"]["intention_to_test_cases_n"] == 3
    assert fixture["submission_seal"]["entrant_failure_cases_n"] == 1
    assert fixture["report"]["controls_failed_n"] >= 1
    assert fixture["report"]["fixed_protocol_safety_table_replayed"] is False
    assert fixture["report"]["method_recovery_pass"] is False


def test_opening_accepts_only_exact_coordinate_language(v2_fixture: dict[str, Any]) -> None:
    v2_fixture["opening"]["payload"]["entries"][0]["observed_coordinate"][0]["state_id"] = "UNKNOWN"
    v2_fixture["opening_sha256"] = _write_json(v2_fixture["opening_path"], v2_fixture["opening"])
    v2_fixture["adjudication"]["opening_raw_sha256"] = v2_fixture["opening_sha256"]
    v2_fixture["adjudication_sha256"] = _write_json(v2_fixture["adjudication_path"], v2_fixture["adjudication"])
    with pytest.raises(CausalFrontierError, match="outside the fixed coordinate language"):
        _finalize(v2_fixture)


def test_failed_translation_role_does_not_force_ex_ante_rejection(v2_fixture: dict[str, Any]) -> None:
    result = next(item for item in v2_fixture["report"]["case_results"] if item["control_role"] == "FAILED_TRANSLATION")
    assert result["decision_mode"] == "REQUEST_INFORMATION"
    assert result["fixed_protocol_opened_outcome_class"] == "HARM_SIGNAL"
    assert result["derived_observed_successor"] == "STOP_FOR_SAFETY"
    assert result["case_status"] == "DECLARED_REVIEW_CANDIDATE_INDEPENDENCE_UNVERIFIED"


def test_rubric_required_or_forbidden_feature_failure_blocks_method_recovery(v2_fixture: dict[str, Any]) -> None:
    decision = v2_fixture["submission"]["cases"][0]["decision"]
    decision["selected_feature_ids"] = ["feature.endpoint-specificity", "feature.surrogate-substitution"]
    v2_fixture["submission"]["cases"][0]["branch_contract"]["decision_sha256"] = sha256_bytes(canonical_bytes(decision))
    _refresh_downstream(v2_fixture)
    result = v2_fixture["report"]["case_results"][0]
    assert result["rubric_feature_check"] is False
    assert result["case_status"] == "STRUCTURAL_FAIL"
    assert v2_fixture["report"]["method_recovery_pass"] is False


@pytest.mark.parametrize(("verdict", "expected"), [("NO_CALL", "NO_CALL"), ("FAIL", "FAIL")])
def test_panel_aggregation_is_conservative(tmp_path: Path, verdict: str, expected: str) -> None:
    fixture = build_v2_fixture(tmp_path)
    fixture["adjudication"]["entries"][0]["votes"][0]["criteria"][0]["verdict"] = verdict
    fixture["adjudication_sha256"] = _write_json(fixture["adjudication_path"], fixture["adjudication"])
    fixture["report"] = _finalize(fixture)
    aggregate = fixture["report"]["case_results"][0]["adjudication_aggregates"][0]
    assert aggregate["verdict"] == expected
    assert fixture["report"]["method_recovery_pass"] is False


def test_declared_reviewer_diversity_never_becomes_verified_independence(v2_fixture: dict[str, Any]) -> None:
    assert all(item["declared_panel_unanimous_pass"] for item in v2_fixture["report"]["case_results"])
    assert v2_fixture["report"]["independent_semantic_adjudication_verified"] is False
    gate = next(item for item in v2_fixture["report"]["gates"] if item["id"] == "INDEPENDENT_ADJUDICATION")
    assert gate["status"] == "NO_CALL"
    method_gate = next(item for item in v2_fixture["report"]["gates"] if item["id"] == "METHOD_RECOVERY")
    assert method_gate["status"] == "NO_CALL"


def test_reviewer_assignment_must_match_nonce_committed_plan(v2_fixture: dict[str, Any]) -> None:
    v2_fixture["adjudication"]["entries"][0]["votes"][0]["reviewer_id"] = "reviewer.unplanned"
    v2_fixture["adjudication_sha256"] = _write_json(v2_fixture["adjudication_path"], v2_fixture["adjudication"])
    with pytest.raises(CausalFrontierError, match="precommitted reviewer assignment"):
        _finalize(v2_fixture)

    assert v2_fixture["report"]["method_recovery_pass"] is False
    assert "VOTE_SIGNATURES_UNVERIFIED" in v2_fixture["report"]["promotion_block_reasons"]


def test_report_verifier_replays_upstream_and_rejects_coherently_rehashed_forgery(
    v2_fixture: dict[str, Any],
) -> None:
    verified = v2.verify_calibration_v2_report(
        v2_fixture["root"],
        v2_fixture["manifest_sha256"],
        v2_fixture["view_lock_path"],
        v2_fixture["view_lock_sha256"],
        v2_fixture["submission_path"],
        v2_fixture["submission_sha256"],
        v2_fixture["submission_seal_path"],
        v2_fixture["submission_seal_sha256"],
        v2_fixture["opening_path"],
        v2_fixture["opening_sha256"],
        v2_fixture["rubric_path"],
        v2_fixture["rubric_sha256"],
        v2_fixture["adjudication_path"],
        v2_fixture["adjudication_sha256"],
        v2_fixture["report_path"],
        v2_fixture["report_sha256"],
    )
    assert verified == v2_fixture["report"]

    forged = deepcopy(v2_fixture["report"])
    forged["scientific_scoring_ready"] = True
    core = {key: value for key, value in forged.items() if key != "report_sha256"}
    forged["report_sha256"] = sha256_bytes(v2.REPORT_DOMAIN_TAG + canonical_bytes(core))
    v2_fixture["report_sha256"] = _write_json(v2_fixture["report_path"], forged)
    with pytest.raises(CausalFrontierError, match="does not replay from every upstream checkpoint"):
        v2.verify_calibration_v2_report(
            v2_fixture["root"],
            v2_fixture["manifest_sha256"],
            v2_fixture["view_lock_path"],
            v2_fixture["view_lock_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
            v2_fixture["submission_seal_path"],
            v2_fixture["submission_seal_sha256"],
            v2_fixture["opening_path"],
            v2_fixture["opening_sha256"],
            v2_fixture["rubric_path"],
            v2_fixture["rubric_sha256"],
            v2_fixture["adjudication_path"],
            v2_fixture["adjudication_sha256"],
            v2_fixture["report_path"],
            v2_fixture["report_sha256"],
        )


def test_external_artifact_path_or_inode_alias_fails(v2_fixture: dict[str, Any]) -> None:
    with pytest.raises(CausalFrontierError, match="disjoint paths and file identities"):
        v2.finalize_calibration_v2(
            v2_fixture["root"],
            v2_fixture["manifest_sha256"],
            v2_fixture["view_lock_path"],
            v2_fixture["view_lock_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
            v2_fixture["opening_path"],
            v2_fixture["opening_sha256"],
            v2_fixture["rubric_path"],
            v2_fixture["rubric_sha256"],
            v2_fixture["adjudication_path"],
            v2_fixture["adjudication_sha256"],
        )

    alias = v2_fixture["external"] / "hardlink.json"
    os.link(v2_fixture["opening_path"], alias)
    with pytest.raises(CausalFrontierError, match="disjoint paths and file identities"):
        v2._require_disjoint_external_zones(v2_fixture["root"], [v2_fixture["opening_path"], alias])


def test_surplus_empty_directory_and_hidden_source_key_fail(v2_fixture: dict[str, Any], tmp_path: Path) -> None:
    (v2_fixture["root"] / "surplus-empty").mkdir()
    with pytest.raises(CausalFrontierError, match="empty directory"):
        v2.preflight_calibration_v2_view(v2_fixture["root"], v2_fixture["manifest_sha256"])

    second = build_v2_fixture(tmp_path / "hidden")
    source_path = second["root"] / second["manifest"]["controls"][0]["sources"][0]["path"]
    source_sha256 = _write_json(source_path, {"control_role": "POSITIVE"})
    second["manifest"]["controls"][0]["sources"][0]["sha256"] = source_sha256
    second["manifest_sha256"] = _write_json(second["manifest_path"], second["manifest"])
    with pytest.raises(CausalFrontierError, match="exposes hidden oracle keys"):
        v2.preflight_calibration_v2_view(second["root"], second["manifest_sha256"])


def test_deeply_nested_source_fails_closed_without_recursion_error(tmp_path: Path) -> None:
    fixture = build_v2_fixture(tmp_path / "deep-source")
    source_path = fixture["root"] / fixture["manifest"]["controls"][0]["sources"][0]["path"]
    raw = b'{"payload":' + (b"[" * 998) + b"null" + (b"]" * 998) + b"}\n"
    source_path.write_bytes(raw)
    fixture["manifest"]["controls"][0]["sources"][0]["sha256"] = sha256_bytes(raw)
    fixture["manifest_sha256"] = _write_json(fixture["manifest_path"], fixture["manifest"])

    with pytest.raises(CausalFrontierError):
        v2.preflight_calibration_v2_view(fixture["root"], fixture["manifest_sha256"])


@pytest.mark.parametrize(
    "hidden_statement",
    (
        "This is the POSITIVE control.",
        "The role is POSITIVE.",
        "This case is AMBIGUOUS.",
        "Assigned label: POSITIVE",
    ),
)
def test_hidden_key_variants_role_paths_and_duplicate_source_ids_fail(
    tmp_path: Path,
    hidden_statement: str,
) -> None:
    hidden = build_v2_fixture(tmp_path / "hidden-variant")
    source_path = hidden["root"] / hidden["manifest"]["controls"][0]["sources"][0]["path"]
    source_sha256 = _write_json(source_path, {"RequiredActionKind": "advance"})
    hidden["manifest"]["controls"][0]["sources"][0]["sha256"] = source_sha256
    hidden["manifest_sha256"] = _write_json(hidden["manifest_path"], hidden["manifest"])
    with pytest.raises(CausalFrontierError, match="normalized hidden oracle key"):
        v2.preflight_calibration_v2_view(hidden["root"], hidden["manifest_sha256"])

    hidden_prose = build_v2_fixture(tmp_path / "hidden-prose")
    prose_path = hidden_prose["root"] / hidden_prose["manifest"]["controls"][0]["sources"][0]["path"]
    prose_sha256 = _write_json(prose_path, {"statement": hidden_statement})
    hidden_prose["manifest"]["controls"][0]["sources"][0]["sha256"] = prose_sha256
    hidden_prose["manifest_sha256"] = _write_json(hidden_prose["manifest_path"], hidden_prose["manifest"])
    with pytest.raises(CausalFrontierError, match="explicit hidden control-role value"):
        v2.preflight_calibration_v2_view(hidden_prose["root"], hidden_prose["manifest_sha256"])

    role_path = build_v2_fixture(tmp_path / "role-path")
    source = role_path["manifest"]["controls"][0]["sources"][0]
    old_path = role_path["root"] / source["path"]
    new_relative = "sources/POSITIVE.json"
    old_path.rename(role_path["root"] / new_relative)
    source["path"] = new_relative
    role_path["manifest_sha256"] = _write_json(role_path["manifest_path"], role_path["manifest"])
    with pytest.raises(CausalFrontierError, match="explicit hidden control role"):
        v2.preflight_calibration_v2_view(role_path["root"], role_path["manifest_sha256"])

    duplicate = build_v2_fixture(tmp_path / "duplicate-source")
    first_id = duplicate["manifest"]["controls"][0]["sources"][0]["opaque_source_id"]
    duplicate["manifest"]["controls"][1]["sources"][0]["opaque_source_id"] = first_id
    duplicate["manifest_sha256"] = _write_json(duplicate["manifest_path"], duplicate["manifest"])
    with pytest.raises(CausalFrontierError, match="globally one-to-one"):
        v2.preflight_calibration_v2_view(duplicate["root"], duplicate["manifest_sha256"])

    duplicate_within = build_v2_fixture(tmp_path / "duplicate-source-within")
    original_source = duplicate_within["manifest"]["controls"][0]["sources"][0]
    extra_path = "sources/source-extra.json"
    extra_sha256 = _write_json(
        duplicate_within["root"] / extra_path,
        {
            "schema_version": "test.public-evidence-card.v1",
            "source_id": original_source["opaque_source_id"],
            "statement": "Another aggregate fragment with a reused identifier",
        },
    )
    duplicate_within["manifest"]["controls"][0]["sources"].append(
        {**original_source, "path": extra_path, "sha256": extra_sha256}
    )
    duplicate_within["manifest_sha256"] = _write_json(duplicate_within["manifest_path"], duplicate_within["manifest"])
    with pytest.raises(CausalFrontierError, match="globally one-to-one"):
        v2.preflight_calibration_v2_view(duplicate_within["root"], duplicate_within["manifest_sha256"])


def test_zero_nonces_and_overlapping_competing_claim_sets_fail(tmp_path: Path) -> None:
    with pytest.raises(CausalFrontierError, match="must not be all zero"):
        v2.reveal_commitment_v2({"test": "value"}, "00" * 32)
    fixture = build_v2_fixture(tmp_path / "rubric-nonce")
    zero_rubric = deepcopy(fixture["rubric"])
    zero_rubric["nonce_hex"] = "00" * 32
    with pytest.raises(CausalFrontierError, match="must not be all zero"):
        v2.rubric_commitment_v2(zero_rubric)

    changed_lock = deepcopy(fixture["view_lock"])
    changed_lock["view_content_binding_sha256"] = _digest("another-view")
    with pytest.raises(CausalFrontierError, match="targets another protocol"):
        v2._validate_opening(fixture["opening"], changed_lock, fixture["submission_seal"])
    with pytest.raises(CausalFrontierError, match="differs from the fixed protocol"):
        v2._validate_rubric(fixture["rubric"], changed_lock)

    overlapping = build_v2_fixture(tmp_path / "overlapping-claims")
    decision = overlapping["submission"]["cases"][1]["decision"]
    decision["minimum_information_boundary"]["competing_claim_sets"] = [
        ["claim.a"],
        ["claim.a", "claim.b"],
    ]
    overlapping["submission_sha256"] = _write_json(overlapping["submission_path"], overlapping["submission"])
    with pytest.raises(CausalFrontierError, match="mutually exclusive and collectively complete"):
        v2.seal_calibration_v2_submission(
            overlapping["root"],
            overlapping["manifest_sha256"],
            overlapping["view_lock_path"],
            overlapping["view_lock_sha256"],
            overlapping["submission_path"],
            overlapping["submission_sha256"],
        )


def test_late_source_and_late_or_pre_cutoff_reveal_fail(v2_fixture: dict[str, Any]) -> None:
    v2_fixture["manifest"]["controls"][0]["sources"][0]["available_at"] = "2013-01-01T00:00:00Z"
    v2_fixture["manifest_sha256"] = _write_json(v2_fixture["manifest_path"], v2_fixture["manifest"])
    with pytest.raises(CausalFrontierError, match="available after its knowledge cutoff"):
        v2.preflight_calibration_v2_view(v2_fixture["root"], v2_fixture["manifest_sha256"])


def test_duplicate_json_keys_bool_counters_and_network_use_fail(v2_fixture: dict[str, Any], tmp_path: Path) -> None:
    raw = v2_fixture["submission_path"].read_bytes()
    duplicated = raw.replace(b'{"cases":', b'{"cases":[],"cases":', 1)
    v2_fixture["submission_path"].write_bytes(duplicated)
    v2_fixture["submission_sha256"] = sha256_bytes(duplicated)
    with pytest.raises(CausalFrontierError, match="duplicate JSON key"):
        v2.seal_calibration_v2_submission(
            v2_fixture["root"],
            v2_fixture["manifest_sha256"],
            v2_fixture["view_lock_path"],
            v2_fixture["view_lock_sha256"],
            v2_fixture["submission_path"],
            v2_fixture["submission_sha256"],
        )

    second = build_v2_fixture(tmp_path / "counter")
    second["submission"]["resource_ledgers"][0]["calendar_elapsed_ns"] = True
    second["submission_sha256"] = _write_json(second["submission_path"], second["submission"])
    with pytest.raises(CausalFrontierError, match="bounded nonnegative integer"):
        v2.seal_calibration_v2_submission(
            second["root"],
            second["manifest_sha256"],
            second["view_lock_path"],
            second["view_lock_sha256"],
            second["submission_path"],
            second["submission_sha256"],
        )

    third = build_v2_fixture(tmp_path / "network")
    third["submission"]["resource_ledgers"][0]["network_requests"] = 1
    third["submission_sha256"] = _write_json(third["submission_path"], third["submission"])
    with pytest.raises(CausalFrontierError, match="zero network requests"):
        v2.seal_calibration_v2_submission(
            third["root"],
            third["manifest_sha256"],
            third["view_lock_path"],
            third["view_lock_sha256"],
            third["submission_path"],
            third["submission_sha256"],
        )


def test_v2_probe_is_assertion_independent_and_hash_seed_stable() -> None:
    repository = Path(__file__).resolve().parents[1]
    probe = repository / "tests" / "calibration_v2_optimized_probe.py"
    source = probe.read_text(encoding="utf-8")
    assert "assert " not in source
    outputs = []
    for optimized in (False, True):
        for seed in ("1", "77"):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(probe))
            completed = subprocess.run(
                command,
                cwd=repository,
                env={**os.environ, "PYTHONHASHSEED": seed, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
            assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
            outputs.append(completed.stdout)
    assert len(set(outputs)) == 1
    payload = json.loads(outputs[0])
    assert payload["status"] == v2.REPORT_STRUCTURAL_STATUS
    assert payload["local_protocol_conformance_pass"] is True
    assert payload["method_recovery_pass"] is False
    assert payload["scientific_scoring_ready"] is False
