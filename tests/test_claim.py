"""Hostile tests for the immutable goal contract and pre-outcome plan firewall."""

from __future__ import annotations

import inspect
import json
import os
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import causalfrontier.cli as cli
from causalfrontier import challenge, claim
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


def _plan() -> dict:
    domains = []
    for domain_index in range(3):
        domain_id = "domain:%d" % (domain_index + 1)
        primary_case_ids = ["case:%d:%02d" % (domain_index + 1, case_index + 1) for case_index in range(10)]
        laboratory_ids = [
            "laboratory:%d:%d" % (domain_index + 1, laboratory_index + 1) for laboratory_index in range(2)
        ]
        primary_resource_estimand = "CALENDAR_MINUTES" if domain_index != 1 else "FULLY_LOADED_COST_MINOR_UNITS"
        domains.append(
            {
                "domain_id": domain_id,
                "primary_case_ids": primary_case_ids,
                "calibration_cases": [
                    {
                        "case_id": "calibration:%d:%s" % (domain_index + 1, role.casefold()),
                        "control_role": role,
                    }
                    for role in claim.CONTROL_ROLES
                ],
                "laboratory_ids": laboratory_ids,
                "primary_case_laboratory_assignments": [
                    {"case_id": case_id, "laboratory_id": laboratory_ids[case_index % len(laboratory_ids)]}
                    for case_index, case_id in enumerate(primary_case_ids)
                ],
                "case_registry_checkpoint_sha256": _digest("registry:%d" % domain_index),
                "knowledge_cutoff": "2026-01-%02dT00:00:00Z" % (domain_index + 1),
                "primary_resource_estimand": primary_resource_estimand,
                "currency_code": "USD" if primary_resource_estimand == "FULLY_LOADED_COST_MINOR_UNITS" else None,
                "price_basis_date": "2026-01-01"
                if primary_resource_estimand == "FULLY_LOADED_COST_MINOR_UNITS"
                else None,
                "common_horizon_minutes": 1440,
                "resource_basis_sha256": _digest("resource-basis:%d" % domain_index),
                "resource_ledger_contract_sha256": _digest("resource-ledger:%d" % domain_index),
                "common_horizon_contract_sha256": _digest("common-horizon:%d" % domain_index),
            }
        )
    candidate = {
        "system_id": "system:causalfrontier",
        "version_id": "version:0.1.0a4",
        "source_tree_sha256": _digest("candidate-source-tree"),
        "source_archive_sha256": _digest("candidate-source-archive"),
        "dependency_lock_sha256": _digest("candidate-dependency-lock"),
        "build_recipe_sha256": _digest("candidate-build-recipe"),
        "license_spdx_id": "Apache-2.0",
        "implementation_sha256": _digest("candidate-implementation"),
        "execution_protocol_sha256": _digest("candidate-protocol"),
        "environment_sha256": _digest("candidate-environment"),
        "resource_meter_contract_sha256": _digest("candidate-meter"),
        "controller_disclosure_sha256": _digest("candidate-controller"),
        "independence_protocol_sha256": _digest("candidate-independence"),
    }
    candidate["candidate_binding_sha256"] = sha256_bytes(
        claim.CANDIDATE_BINDING_DOMAIN_TAG + canonical_bytes(candidate)
    )
    comparators = []
    for index, family in enumerate(claim.MANDATORY_COMPARATOR_FAMILIES):
        comparators.append(
            {
                "family": family,
                "system_id": "system:comparator:%d" % (index + 1),
                "version_id": "version:comparator:%d" % (index + 1),
                "policy_contract_sha256": _digest("comparator-policy:%d" % index),
                "family_conformance_protocol_sha256": _digest("comparator-conformance-protocol:%d" % index),
                "family_conformance_implementation_sha256": _digest("comparator-conformance-implementation:%d" % index),
                "implementation_sha256": _digest("comparator-implementation:%d" % index),
                "execution_environment_sha256": _digest("comparator-environment:%d" % index),
                "resource_meter_contract_sha256": candidate["resource_meter_contract_sha256"],
                "controller_disclosure_sha256": _digest("comparator-controller:%d" % index),
                "independence_protocol_sha256": _digest("comparator-independence:%d" % index),
            }
        )
        comparators[-1]["comparator_binding_sha256"] = sha256_bytes(
            claim.COMPARATOR_BINDING_DOMAIN_TAG + canonical_bytes(comparators[-1])
        )
    analysis = {
        "primary_endpoint": claim.PRIMARY_ENDPOINT,
        "analysis_population": claim.ANALYSIS_POPULATION,
        "effect_estimand": claim.EFFECT_ESTIMAND,
        "claim_cells": claim.CLAIM_CELLS,
        "threshold_numerator": 10,
        "threshold_denominator": 1,
        "confidence_family": claim.CONFIDENCE_FAMILY,
        "familywise_confidence_basis_points": 9500,
        "multiplicity_scope": claim.MULTIPLICITY_SCOPE,
        "multiplicity_method": claim.MULTIPLICITY_METHOD,
        "global_claim_inference_rule": claim.GLOBAL_CLAIM_INFERENCE_RULE,
        "clustering_rule": claim.CLUSTERING_RULE,
        "analysis_implementation_sha256": _digest("analysis-implementation"),
        "sample_size_and_power_sha256": _digest("sample-size-and-power"),
        "abstention_contract_sha256": _digest("abstention-contract"),
        "false_exclusion_contract_sha256": _digest("false-exclusion-contract"),
        "missing_cell_rule": claim.MISSING_CELL_RULE,
        "candidate_noncompletion_rule": claim.CANDIDATE_NONCOMPLETION_RULE,
        "comparator_noncompletion_rule": claim.COMPARATOR_NONCOMPLETION_RULE,
        "zero_resource_rule": claim.ZERO_RESOURCE_RULE,
        "resource_choice_rule": claim.RESOURCE_CHOICE_RULE,
        "false_exclusion_rule": claim.FALSE_EXCLUSION_RULE,
        "false_exclusion_estimand": claim.FALSE_EXCLUSION_ESTIMAND,
        "false_exclusion_inference_rule": claim.FALSE_EXCLUSION_INFERENCE_RULE,
        "false_exclusion_margin_basis_points": 0,
        "authority_violation_rule": claim.AUTHORITY_VIOLATION_RULE,
        "no_best_selection_rule": claim.NO_BEST_SELECTION_RULE,
        "abstention_rule": claim.ABSTENTION_RULE,
        "abstention_inference_rule": claim.ABSTENTION_INFERENCE_RULE,
        "minimum_coverage_basis_points": claim.MINIMUM_COVERAGE_BASIS_POINTS,
        "maximum_selective_risk_basis_points": claim.MAXIMUM_SELECTIVE_RISK_BASIS_POINTS,
    }
    integrity_gates = [
        {
            "gate_id": gate_id,
            "verification_protocol_sha256": _digest("gate-protocol:%s" % gate_id),
            "verification_implementation_sha256": _digest("gate-implementation:%s" % gate_id),
            "required_state": claim.GATE_REQUIRED_STATE,
        }
        for gate_id in claim.REQUIRED_GATE_IDS
    ]
    plan = {
        "schema_version": claim.PLAN_SCHEMA_VERSION,
        "status": claim.PLAN_STATUS,
        "plan_id": "plan:goal-conjunction:1",
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "goal_claim_contract_sha256": claim.goal_claim_contract_sha256(),
        "cohort_checkpoint_sha256": _digest("cohort"),
        "common_input_contract_sha256": _digest("common-input"),
        "candidate": candidate,
        "domains": domains,
        "calibration": {
            "role_criteria": [
                {"control_role": role, "required_behavior": behavior}
                for role, behavior in zip(
                    claim.CONTROL_ROLES,
                    claim.CONTROL_REQUIRED_BEHAVIORS,
                    strict=True,
                )
            ],
            "control_failure_rule": claim.CONTROL_FAILURE_RULE,
            "primary_separation_rule": claim.CONTROL_PRIMARY_SEPARATION_RULE,
            "control_oracle_commitment_sha256": _digest("control-oracle-commitment"),
            "control_scoring_protocol_sha256": _digest("control-scoring-protocol"),
            "control_scoring_implementation_sha256": _digest("control-scoring-implementation"),
            "semantic_validity_review_protocol_sha256": _digest("control-semantic-validity-review"),
            "current_control_semantic_validity_verified": False,
        },
        "comparators": comparators,
        "execution": {
            "design": "COMPLETE_REPLAY_ORACLE",
            "assignment_protocol_sha256": _digest("assignment-protocol"),
            "shared_input_contract_sha256": _digest("common-input"),
            "endpoint_adjudication_contract_sha256": _digest("endpoint-adjudication"),
            "resource_parity_contract_sha256": candidate["resource_meter_contract_sha256"],
            "complete_matrix_rule": "EVERY_PRIMARY_CASE_TIMES_CANDIDATE_AND_ALL_FIVE_MANDATORY_COMPARATORS",
            "planned_primary_cells_n": 30 * 6,
            "planned_claim_cells_n": (3 + 1) * 5,
        },
        "analysis": analysis,
        "leakage": {
            "primary_case_timing": "PROSPECTIVE_BLIND_ONLY",
            "known_hindsight_role": "CALIBRATION_ONLY_NEVER_PRIMARY_PERFORMANCE",
            "model_tool_freeze_manifest_sha256": _digest("model-tool-freeze"),
            "network_access_policy_sha256": _digest("network-access-policy"),
            "temporal_audit_protocol_sha256": _digest("temporal-audit"),
            "training_contamination_protocol_sha256": _digest("training-contamination"),
            "post_cutoff_information_access_allowed": False,
        },
        "privacy_authority": {
            "allowed_data_classes": ["PUBLIC_AGGREGATE", "SYNTHETIC"],
            "patient_level_data_allowed": False,
            "privacy_review_protocol_sha256": _digest("privacy-review"),
            "authority_boundary": fixed_boundary(),
            "authority_violations_allowed": 0,
        },
        "provenance": {
            "evidence_receipt_contract_sha256": _digest("provenance-evidence-receipt"),
            "source_inventory_contract_sha256": _digest("provenance-source-inventory"),
            "transformation_lineage_contract_sha256": _digest("provenance-transformation-lineage"),
            "execution_trace_contract_sha256": _digest("provenance-execution-trace"),
            "analysis_artifact_lineage_contract_sha256": _digest("provenance-analysis-lineage"),
            "independent_witness_protocol_sha256": _digest("provenance-independent-witness"),
            "required_state": claim.PROVENANCE_REQUIRED_STATE,
            "current_provenance_verified": False,
        },
        "integrity_gates": integrity_gates,
        "reproduction": {
            "reproducer_protocol_sha256": _digest("reproducer-protocol"),
            "clean_environment_spec_sha256": _digest("clean-environment"),
            "build_recipe_sha256": _digest("build-recipe"),
            "minimum_independent_reproducers": 1,
            "minimum_independent_organizations": 1,
            "controller_disjointness_required": True,
            "byte_identical_artifacts_required": True,
            "complete_matrix_reexecution_required": True,
            "analysis_replay_required": True,
            "independent_holdout_required": True,
            "independent_holdout_goal_contract_sha256": claim.goal_claim_contract_sha256(),
            "complete_domain_by_comparator_conjunction_required": True,
            "current_independent_reproduction_verified": False,
        },
        "usability": {
            "population": claim.USABILITY_POPULATION,
            "population_definition_sha256": _digest("usability-population-definition"),
            "study_protocol_sha256": _digest("usability-protocol"),
            "minimum_participants": claim.MINIMUM_EARLY_CAREER_PARTICIPANTS,
            "minimum_domains_represented": claim.MINIMUM_DOMAINS,
            "minimum_independent_organizations": 2,
            "non_contributor_participants_required": True,
            "task": claim.USABILITY_TASK,
            "minimum_unaided_completion_basis_points": 8000,
            "maximum_median_completion_minutes": 120,
            "authority_errors_allowed": 0,
            "current_usability_verified": False,
        },
        "openness": {
            "public_source_required": True,
            "public_data_or_synthetic_only": True,
            "reproducible_build_required": True,
            "license_spdx_id": "Apache-2.0",
            "publication_plan_sha256": _digest("publication-plan"),
            "publication_authority_granted": False,
        },
        "designated_scientific_data_inputs_absent": True,
        "scoring_disabled": True,
        "scientific_claim_ready": False,
    }
    return _reseal(plan)


def _reseal(plan: dict) -> dict:
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = sha256_bytes(claim.PLAN_DOMAIN_TAG + canonical_bytes(core))
    return plan


def _reseal_comparator(comparator: dict) -> None:
    core = {key: value for key, value in comparator.items() if key != "comparator_binding_sha256"}
    comparator["comparator_binding_sha256"] = sha256_bytes(claim.COMPARATOR_BINDING_DOMAIN_TAG + canonical_bytes(core))


def _write_plan(path: Path, plan: dict) -> str:
    raw = canonical_bytes(plan) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _preflight(tmp_path: Path, plan: dict | None = None) -> tuple[Path, str, dict]:
    path = tmp_path / "goal-claim-plan.json"
    digest = _write_plan(path, plan or _plan())
    return path, digest, claim.preflight_goal_claim_plan(path, digest)


def _reseal_report(report: dict) -> None:
    core = {key: report[key] for key in claim.REPORT_CORE_KEYS}
    report["preflight_sha256"] = sha256_bytes(claim.PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))


def test_goal_contract_corrects_v1_metric_without_mutating_it():
    contract = claim.goal_claim_contract()

    assert contract["mandatory_comparator_families"] == list(claim.MANDATORY_COMPARATOR_FAMILIES)
    assert contract["success_threshold"]["numerator"] == 10
    assert contract["success_threshold"]["claim_cells"] == claim.CLAIM_CELLS
    assert contract["analysis_contract"]["population"] == claim.ANALYSIS_POPULATION
    assert contract["analysis_contract"]["global_claim_inference_rule"] == claim.GLOBAL_CLAIM_INFERENCE_RULE
    assert contract["analysis_contract"]["abstention_inference_rule"] == claim.ABSTENTION_INFERENCE_RULE
    assert contract["analysis_contract"]["false_exclusion_estimand"] == claim.FALSE_EXCLUSION_ESTIMAND
    assert contract["provenance_contract"]["required_state"] == claim.PROVENANCE_REQUIRED_STATE
    assert contract["execution_contract"]["allowed_designs"] == sorted(claim.EXECUTION_DESIGNS)
    assert contract["resource_contract"]["synthetic_tariffs_support_claim"] is False
    assert claim.goal_claim_contract_sha256() == sha256_bytes(claim.GOAL_CONTRACT_CANONICAL)

    old_metric = challenge.fixed_metric_contract()
    assert old_metric["primary_comparator"] == "CURRENT_STANDARDIZED_WORKFLOW"
    assert old_metric["success_rule"].startswith("TENFOLD_ON_PREDECLARED_PRIMARY_RESOURCE_VERSUS_CURRENT_WORKFLOW")
    assert "SIMPLE_RULE_PREDECLARED" not in challenge.BASELINE_FAMILIES


def test_goal_contract_returns_a_fresh_copy():
    first = claim.goal_claim_contract()
    first["mandatory_comparator_families"].append("FORGED")
    assert claim.goal_claim_contract()["mandatory_comparator_families"] == list(claim.MANDATORY_COMPARATOR_FAMILIES)


def test_valid_plan_preflight_binds_full_conjunction_but_makes_no_claim(tmp_path: Path):
    path, digest, report = _preflight(tmp_path)

    assert path.is_file()
    assert report["status"] == claim.PREFLIGHT_STATUS
    assert report["plan_checkpoint_sha256"] == digest
    assert report["mandatory_comparator_families"] == list(claim.MANDATORY_COMPARATOR_FAMILIES)
    assert report["declared_domains_n"] == 3
    assert report["precommitted_decision_points_n"] == 30
    assert report["calibration_decision_points_n"] == 9
    assert report["declared_laboratories_n"] == 6
    assert report["designated_scientific_data_input_accepted"] is False
    assert report["outcome_or_result_field_accepted"] is False
    assert report["scoring_performed"] is False
    assert report["scientific_claim_ready"] is False
    assert report["acceleration_verified"] is False
    assert report["independent_reproduction_verified"] is False
    assert report["early_career_usability_verified"] is False
    assert report["domain_semantic_validity_verified"] is False
    assert report["cohort_admission_verified"] is False
    assert report["generator_independence_verified"] is False
    assert report["provenance_verified"] is False
    assert report["comparator_family_conformance_verified"] is False
    gate_states = {item["id"]: item["state"] for item in report["gates"]}
    assert (
        gate_states["FULL_COMPARATOR_CONJUNCTION"]
        == "DIGEST_DECLARATIONS_ONLY_IMPLEMENTATIONS_NOT_SUPPLIED_OR_VERIFIED"
    )
    assert gate_states["CALIBRATION_CONTROL_PLAN"] == "DIGEST_DECLARATIONS_ONLY_SEMANTICS_NOT_VERIFIED"
    assert gate_states["PROVENANCE_PLAN"] == "DIGEST_DECLARATIONS_ONLY_ARTIFACT_BYTES_NOT_SUPPLIED_OR_VERIFIED"
    assert (
        gate_states["ANALYSIS_AND_FAILURE_SEMANTICS"]
        == "STRUCTURAL_RULE_LITERALS_ONLY_IMPLEMENTATION_NOT_SUPPLIED_OR_VERIFIED"
    )
    assert (
        gate_states["DOMAIN_CASE_AND_LAB_MINIMA"]
        == "DECLARED_GEOMETRY_ONLY_SEMANTICS_GENERATOR_INDEPENDENCE_AND_TIMING_NOT_VERIFIED"
    )
    assert gate_states["SCIENTIFIC_CLAIM"] == "NO_CALL"
    assert report["preflight_sha256"] == sha256_bytes(
        claim.PREFLIGHT_DOMAIN_TAG + canonical_bytes({key: report[key] for key in claim.REPORT_CORE_KEYS})
    )


@pytest.mark.parametrize("index", range(len(claim.MANDATORY_COMPARATOR_FAMILIES)))
def test_every_mandatory_comparator_is_individually_required(tmp_path: Path, index: int):
    plan = _plan()
    plan["comparators"].pop(index)
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="exactly the five mandatory"):
        claim.preflight_goal_claim_plan(path, digest)


def test_renaming_ofat_as_simple_rule_is_not_accepted(tmp_path: Path):
    plan = _plan()
    plan["comparators"][-1]["family"] = "BLIND_OFAT"
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="canonically ordered"):
        claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("threshold_numerator", 9),
        ("threshold_denominator", 0),
        ("analysis_population", "PER_PROTOCOL_SUCCESSFUL_CELLS_ONLY"),
        ("claim_cells", "POOLED_ONLY"),
        ("missing_cell_rule", "DROP_FAILED_CELLS"),
        ("candidate_noncompletion_rule", "CENSOR"),
        ("comparator_noncompletion_rule", "INFINITY"),
        ("zero_resource_rule", "ALLOW_INFINITY"),
        ("resource_choice_rule", "CHOOSE_BEST_RESOURCE_AFTER_REVEAL"),
        ("multiplicity_scope", "NONE"),
        ("global_claim_inference_rule", "THREE_SEPARATE_9500_BPS_FAMILIES"),
        ("clustering_rule", "IGNORE_DOMAIN_AND_LAB_CLUSTERING"),
        ("false_exclusion_rule", "UNCONSTRAINED"),
        ("false_exclusion_estimand", "SUCCESSFUL_CASES_ONLY"),
        ("false_exclusion_inference_rule", "POINT_ESTIMATE_ONLY"),
        ("false_exclusion_margin_basis_points", 1),
        ("authority_violation_rule", "IGNORE"),
        ("abstention_inference_rule", "POINT_ESTIMATE_ONLY"),
        ("minimum_coverage_basis_points", 0),
        ("maximum_selective_risk_basis_points", 10000),
    ],
)
def test_weakened_analysis_or_failure_semantics_are_rejected(tmp_path: Path, field: str, value: object):
    plan = _plan()
    plan["analysis"][field] = value
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="immutable goal contract"):
        claim.preflight_goal_claim_plan(path, digest)


def test_posthoc_resource_choice_is_impossible_per_domain(tmp_path: Path):
    plan = _plan()
    plan["domains"][0]["primary_resource_estimand"] = "TIME_OR_COST_WHICHEVER_WINS"
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="unregistered value"):
        claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    "mutation",
    [
        "two_domains",
        "twenty_nine_cases",
        "five_laboratories",
        "duplicate_case_across_domains",
        "duplicate_domain",
    ],
)
def test_domain_case_and_laboratory_minima_fail_closed(tmp_path: Path, mutation: str):
    plan = _plan()
    if mutation == "two_domains":
        plan["domains"].pop()
    elif mutation == "twenty_nine_cases":
        plan["domains"][-1]["primary_case_ids"].pop()
        plan["execution"]["planned_primary_cells_n"] -= 6
    elif mutation == "five_laboratories":
        plan["domains"][-1]["laboratory_ids"] = [plan["domains"][0]["laboratory_ids"][0]]
    elif mutation == "duplicate_case_across_domains":
        plan["domains"][1]["primary_case_ids"][0] = plan["domains"][0]["primary_case_ids"][0]
        plan["domains"][1]["primary_case_ids"].sort()
    else:
        plan["domains"][1]["domain_id"] = plan["domains"][0]["domain_id"]
        plan["domains"].sort(key=lambda item: item["domain_id"])
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError):
        claim.preflight_goal_claim_plan(path, digest)


def test_global_counts_cannot_hide_underpowered_one_case_domains(tmp_path: Path):
    plan = _plan()
    requested_counts = (28, 1, 1)
    requested_labs = (4, 1, 1)
    for domain_index, domain in enumerate(plan["domains"]):
        case_ids = ["case:skewed:%d:%02d" % (domain_index, index) for index in range(requested_counts[domain_index])]
        lab_ids = ["laboratory:skewed:%d:%d" % (domain_index, index) for index in range(requested_labs[domain_index])]
        domain["primary_case_ids"] = case_ids
        domain["laboratory_ids"] = lab_ids
        domain["primary_case_laboratory_assignments"] = [
            {"case_id": case_id, "laboratory_id": lab_ids[index % len(lab_ids)]}
            for index, case_id in enumerate(case_ids)
        ]
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="must contain"):
        claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize("forbidden", sorted(claim.FORBIDDEN_RESULT_KEYS))
def test_no_outcome_result_winner_or_score_channel_is_accepted(tmp_path: Path, forbidden: str):
    plan = _plan()
    plan["candidate"][forbidden] = "FORGED_POSTOUTCOME_VALUE"
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="forbidden post-outcome field"):
        claim.preflight_goal_claim_plan(path, digest)


def test_plan_api_has_no_designated_outcome_or_scoring_input():
    parameters = set(inspect.signature(claim.preflight_goal_claim_plan).parameters)
    assert parameters == {"path", "expected_plan_checkpoint_sha256"}
    assert not parameters & {"outcome", "oracle", "opening", "result", "score", "winner"}


def test_gate_removal_reordering_and_forged_pass_are_rejected(tmp_path: Path):
    mutations = []
    plan = _plan()
    plan["integrity_gates"].pop()
    mutations.append(plan)
    plan = _plan()
    plan["integrity_gates"][0], plan["integrity_gates"][1] = (
        plan["integrity_gates"][1],
        plan["integrity_gates"][0],
    )
    mutations.append(plan)
    plan = _plan()
    plan["integrity_gates"][0]["required_state"] = "PASS"
    mutations.append(plan)

    for index, forged in enumerate(mutations):
        _reseal(forged)
        path = tmp_path / ("plan-%d.json" % index)
        digest = _write_plan(path, forged)
        with pytest.raises(CausalFrontierError, match="integrity gate"):
            claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("section", "field", "value", "match"),
    [
        ("execution", "planned_primary_cells_n", 179, "complete goal-conformant matrix"),
        ("execution", "planned_claim_cells_n", 15, "complete goal-conformant matrix"),
        ("execution", "design", "SELECT_BEST_AFTER_RUN", "complete goal-conformant matrix"),
        (
            "execution",
            "design",
            "PARALLEL_RANDOMIZED_OR_COMPLETE_REPLAY_ORACLE_ONLY",
            "complete goal-conformant matrix",
        ),
        ("leakage", "primary_case_timing", "HISTORICAL_HINDSIGHT", "hindsight or post-cutoff"),
        ("leakage", "known_hindsight_role", "PRIMARY_PERFORMANCE", "hindsight or post-cutoff"),
        ("leakage", "post_cutoff_information_access_allowed", True, "hindsight or post-cutoff"),
        ("privacy_authority", "patient_level_data_allowed", True, "expands the fixed boundary"),
        ("privacy_authority", "authority_violations_allowed", 1, "expands the fixed boundary"),
        ("openness", "public_source_required", False, "openness plan"),
        ("openness", "publication_authority_granted", True, "openness plan"),
    ],
)
def test_matrix_leakage_privacy_authority_and_openness_fail_closed(
    tmp_path: Path, section: str, field: str, value: object, match: str
):
    plan = _plan()
    plan[section][field] = value
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match=match):
        claim.preflight_goal_claim_plan(path, digest)


def test_candidate_and_comparator_bindings_and_nonplaceholder_digests_are_enforced(tmp_path: Path):
    mutations = []
    plan = _plan()
    plan["candidate"]["source_tree_sha256"] = _digest("substituted-source")
    mutations.append((plan, "candidate implementation binding mismatch"))
    plan = _plan()
    plan["comparators"][0]["implementation_sha256"] = _digest("substituted-comparator")
    mutations.append((plan, "comparator implementation binding mismatch"))
    plan = _plan()
    plan["candidate"]["source_tree_sha256"] = "0" * 64
    mutations.append((plan, "all-zero placeholder"))

    for index, (forged, match) in enumerate(mutations):
        _reseal(forged)
        path = tmp_path / ("plan-%d.json" % index)
        digest = _write_plan(path, forged)
        with pytest.raises(CausalFrontierError, match=match):
            claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("field", "source"),
    [
        ("implementation_sha256", "candidate"),
        ("implementation_sha256", "comparator"),
        ("policy_contract_sha256", "comparator"),
        ("controller_disclosure_sha256", "candidate"),
        ("controller_disclosure_sha256", "comparator"),
        ("independence_protocol_sha256", "candidate"),
        ("family_conformance_protocol_sha256", "comparator"),
        ("family_conformance_implementation_sha256", "comparator"),
    ],
)
def test_structurally_aliased_comparator_declarations_are_rejected(tmp_path: Path, field: str, source: str):
    plan = _plan()
    source_value = plan["candidate"][field] if source == "candidate" else plan["comparators"][0][field]
    plan["comparators"][1][field] = source_value
    _reseal_comparator(plan["comparators"][1])
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="structurally nonaliased"):
        claim.preflight_goal_claim_plan(path, digest)


def test_resource_meter_and_common_input_parity_are_exact(tmp_path: Path):
    mutations = []
    plan = _plan()
    plan["comparators"][0]["resource_meter_contract_sha256"] = _digest("different-meter")
    _reseal_comparator(plan["comparators"][0])
    mutations.append((plan, "same resource meter contract"))
    plan = _plan()
    plan["execution"]["shared_input_contract_sha256"] = _digest("different-common-input")
    mutations.append((plan, "same common-input contract"))
    plan = _plan()
    plan["execution"]["resource_parity_contract_sha256"] = _digest("different-resource-parity")
    mutations.append((plan, "common candidate-comparator resource meter"))

    for index, (forged, match) in enumerate(mutations):
        _reseal(forged)
        path = tmp_path / ("plan-%d.json" % index)
        digest = _write_plan(path, forged)
        with pytest.raises(CausalFrontierError, match=match):
            claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    "mutation",
    ["missing_role", "duplicate_role", "missing_assignment", "undeclared_laboratory"],
)
def test_balanced_calibration_and_case_linked_laboratories_fail_closed(tmp_path: Path, mutation: str):
    plan = _plan()
    domain = plan["domains"][0]
    if mutation == "missing_role":
        domain["calibration_cases"].pop()
    elif mutation == "duplicate_role":
        domain["calibration_cases"][1]["control_role"] = claim.CONTROL_ROLES[0]
    elif mutation == "missing_assignment":
        domain["primary_case_laboratory_assignments"].pop()
    else:
        domain["primary_case_laboratory_assignments"][0]["laboratory_id"] = "laboratory:undeclared"
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError):
        claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("control_failure_rule", "IGNORE_FAILED_CONTROLS"),
        ("primary_separation_rule", "INCLUDE_CONTROLS_IN_PRIMARY_EFFECT"),
        ("current_control_semantic_validity_verified", True),
    ],
)
def test_calibration_controls_cannot_be_ignored_or_self_certified(tmp_path: Path, field: str, value: object):
    plan = _plan()
    plan["calibration"][field] = value
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="ignored controls or self-certifies"):
        claim.preflight_goal_claim_plan(path, digest)


def test_each_calibration_role_behavior_is_exact(tmp_path: Path):
    for index in range(len(claim.CONTROL_ROLES)):
        plan = _plan()
        plan["calibration"]["role_criteria"][index]["required_behavior"] = "ALWAYS_PASS"
        _reseal(plan)
        path = tmp_path / ("plan-%d.json" % index)
        digest = _write_plan(path, plan)
        with pytest.raises(CausalFrontierError, match="role criteria"):
            claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("currency_code", "usd"),
        ("currency_code", "ZZZ"),
        ("price_basis_date", "2026-02-30"),
        ("common_horizon_minutes", 0),
    ],
)
def test_cost_basis_and_common_horizon_are_closed_and_bounded(tmp_path: Path, field: str, value: object):
    plan = _plan()
    plan["domains"][1][field] = value
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError):
        claim.preflight_goal_claim_plan(path, digest)


def test_provenance_is_operational_not_only_a_generic_gate(tmp_path: Path):
    mutations = []
    plan = _plan()
    plan.pop("provenance")
    mutations.append(plan)
    plan = _plan()
    plan["provenance"]["current_provenance_verified"] = True
    mutations.append(plan)
    plan = _plan()
    plan["provenance"]["required_state"] = "OPTIONAL"
    mutations.append(plan)

    for index, forged in enumerate(mutations):
        _reseal(forged)
        path = tmp_path / ("plan-%d.json" % index)
        digest = _write_plan(path, forged)
        with pytest.raises(CausalFrontierError):
            claim.preflight_goal_claim_plan(path, digest)


def test_duplicate_keys_floats_and_mixed_case_result_fields_are_rejected(tmp_path: Path):
    raw = canonical_bytes(_plan()) + b"\n"
    hostile_values = [
        raw.replace(b'"status":', b'"status":"FORGED","status":', 1),
        raw.replace(b'"sequence":1', b'"sequence":1.0', 1),
    ]
    forged = _plan()
    forged["candidate"]["Winner"] = "FORGED"
    _reseal(forged)
    hostile_values.append(canonical_bytes(forged) + b"\n")

    for index, hostile in enumerate(hostile_values):
        path = tmp_path / ("hostile-%d.json" % index)
        path.write_bytes(hostile)
        with pytest.raises(CausalFrontierError):
            claim.preflight_goal_claim_plan(path, sha256_bytes(hostile))


def test_preflight_is_read_only_and_uses_no_process_or_network_capability(tmp_path: Path, monkeypatch):
    path = tmp_path / "plan.json"
    digest = _write_plan(path, _plan())

    def snapshot() -> dict[str, tuple[int, int, str]]:
        return {
            item.name: (item.stat().st_size, item.stat().st_mtime_ns, sha256_bytes(item.read_bytes()))
            for item in tmp_path.iterdir()
        }

    before = snapshot()
    real_open = os.open

    def guarded_open(target, flags, *args, **kwargs):
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if flags & write_flags:
            raise AssertionError("claim preflight attempted a descriptor write")
        return real_open(target, flags, *args, **kwargs)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("claim preflight attempted an out-of-bound capability")

    with monkeypatch.context() as context:
        context.setattr(os, "open", guarded_open)
        for method in (
            "chmod",
            "hardlink_to",
            "mkdir",
            "rename",
            "replace",
            "rmdir",
            "symlink_to",
            "touch",
            "unlink",
            "write_bytes",
            "write_text",
        ):
            context.setattr(Path, method, forbidden)
        context.setattr(subprocess, "Popen", forbidden)
        context.setattr(subprocess, "run", forbidden)
        context.setattr(socket, "socket", forbidden)
        report = claim.preflight_goal_claim_plan(path, digest)

    after = snapshot()
    assert report["claim_state"] == "NO_CALL_PLAN_ONLY"
    assert after == before


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("reproduction", "minimum_independent_reproducers", 0),
        ("reproduction", "byte_identical_artifacts_required", False),
        ("reproduction", "complete_domain_by_comparator_conjunction_required", False),
        ("reproduction", "independent_holdout_goal_contract_sha256", _digest("another-goal-contract")),
        ("reproduction", "current_independent_reproduction_verified", True),
        ("usability", "minimum_participants", 3),
        ("usability", "minimum_domains_represented", 1),
        ("usability", "minimum_independent_organizations", 1),
        ("usability", "non_contributor_participants_required", False),
        ("usability", "minimum_unaided_completion_basis_points", 5000),
        ("usability", "maximum_median_completion_minutes", 1000),
        ("usability", "authority_errors_allowed", 1),
        ("usability", "current_usability_verified", True),
    ],
)
def test_reproduction_and_usability_cannot_be_weakened_or_self_certified(
    tmp_path: Path, section: str, field: str, value: object
):
    plan = _plan()
    plan[section][field] = value
    _reseal(plan)
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="overclaims or weakens"):
        claim.preflight_goal_claim_plan(path, digest)


def test_external_checkpoint_semantic_digest_symlink_and_hardlink_fail_closed(tmp_path: Path):
    plan = _plan()
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)

    with pytest.raises(CausalFrontierError, match="all-zero placeholder"):
        claim.preflight_goal_claim_plan(path, "0" * 64)
    with pytest.raises(CausalFrontierError, match="checkpoint mismatch"):
        claim.preflight_goal_claim_plan(path, "1" * 64)

    forged = deepcopy(plan)
    forged["sequence"] = 2
    forged_path = tmp_path / "forged.json"
    forged_digest = _write_plan(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="semantic digest mismatch"):
        claim.preflight_goal_claim_plan(forged_path, forged_digest)

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(path)
    with pytest.raises(CausalFrontierError):
        claim.preflight_goal_claim_plan(symlink, digest)

    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(path)
    with pytest.raises(CausalFrontierError):
        claim.preflight_goal_claim_plan(hardlink, digest)


def test_second_read_detects_toctou_even_when_attacker_supplies_coherent_values(tmp_path: Path, monkeypatch):
    plan = _plan()
    path = tmp_path / "plan.json"
    digest = _write_plan(path, plan)
    real_read = claim._read_checkpointed_plan
    calls = 0

    def substitute(read_path, expected_sha256):
        nonlocal calls
        calls += 1
        raw, value = real_read(read_path, expected_sha256)
        if calls == 2:
            forged = deepcopy(value)
            forged["candidate"]["system_id"] = "system:substituted"
            _reseal(forged)
            return canonical_bytes(forged) + b"\n", forged
        return raw, value

    monkeypatch.setattr(claim, "_read_checkpointed_plan", substitute)
    with pytest.raises(CausalFrontierError, match="changed during preflight"):
        claim.preflight_goal_claim_plan(path, digest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scientific_claim_ready", True),
        ("acceleration_verified", True),
        ("independent_reproduction_verified", True),
        ("early_career_usability_verified", True),
        ("comparator_family_conformance_verified", True),
        ("provenance_verified", True),
        ("control_semantic_validity_verified", True),
        ("domain_semantic_validity_verified", True),
        ("cohort_admission_verified", True),
        ("generator_independence_verified", True),
        ("scoring_performed", True),
        ("outcome_or_result_field_accepted", True),
    ],
)
def test_forged_preflight_authority_fields_are_rejected(tmp_path: Path, field: str, value: object):
    _path, digest, report = _preflight(tmp_path)
    forged = deepcopy(report)
    forged[field] = value
    _reseal_report(forged)

    with pytest.raises(CausalFrontierError, match="overclaims verification or authority"):
        claim._validate_goal_claim_plan_preflight_shape(forged, expected_plan_checkpoint_sha256=digest)


def test_forged_report_binding_gate_nonclaim_and_hash_are_rejected(tmp_path: Path):
    _path, digest, report = _preflight(tmp_path)
    mutations = []
    forged = deepcopy(report)
    forged["plan_checkpoint_sha256"] = "1" * 64
    _reseal_report(forged)
    mutations.append(forged)
    forged = deepcopy(report)
    forged["gates"][0]["state"] = "NO_CALL"
    _reseal_report(forged)
    mutations.append(forged)
    forged = deepcopy(report)
    forged["nonclaims"].pop()
    _reseal_report(forged)
    mutations.append(forged)
    forged = deepcopy(report)
    forged["preflight_sha256"] = "2" * 64
    mutations.append(forged)

    for forged in mutations:
        with pytest.raises(CausalFrontierError):
            claim._validate_goal_claim_plan_preflight_shape(forged, expected_plan_checkpoint_sha256=digest)


def test_verify_api_replays_plan_to_reject_a_coherently_rehashed_projection(tmp_path: Path):
    path, digest, report = _preflight(tmp_path)
    forged = deepcopy(report)
    forged["plan_sequence"] = 999
    forged["precommitted_decision_points_n"] = 999
    _reseal_report(forged)

    claim._validate_goal_claim_plan_preflight_shape(forged, expected_plan_checkpoint_sha256=digest)
    with pytest.raises(CausalFrontierError, match="differs from exact deterministic replay"):
        claim.verify_goal_claim_plan_preflight(forged, path, digest)


def test_cli_emits_only_replayed_structural_no_call_and_exits_three(tmp_path: Path, capsys):
    plan_path = tmp_path / "plan.json"
    digest = _write_plan(plan_path, _plan())

    code = cli.main(
        [
            "preflight-goal-claim-plan",
            str(plan_path),
            "--expected-plan-checkpoint-sha256",
            digest,
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert code == 3
    assert captured.err == ""
    assert report["status"] == claim.PREFLIGHT_STATUS
    assert report["scientific_claim_ready"] is False
    assert report["acceleration_verified"] is False


def test_cli_replay_rejects_coherently_rehashed_forged_projection(tmp_path: Path, monkeypatch, capsys):
    plan_path = tmp_path / "plan.json"
    digest = _write_plan(plan_path, _plan())
    forged = claim.preflight_goal_claim_plan(plan_path, digest)
    forged["precommitted_decision_points_n"] = 31
    _reseal_report(forged)
    monkeypatch.setattr(cli, "preflight_goal_claim_plan", lambda *_args: forged)

    code = cli.main(
        [
            "preflight-goal-claim-plan",
            str(plan_path),
            "--expected-plan-checkpoint-sha256",
            digest,
        ]
    )

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "differs from exact deterministic replay" in captured.err
