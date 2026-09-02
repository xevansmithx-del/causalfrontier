"""Immutable goal contract and pre-outcome claim-plan firewall.

The original challenge-lock v1 metric is a preserved historical artifact.  This
module does not mutate it.  Instead, it binds the stronger program objective to
an exact successor contract and validates a closed, outcome-free
preregistration plan against that contract.  Passing this preflight means only
that the required comparison has been specified before outcome access; it does
not make a scientific, acceleration, independence, reproducibility, usability,
or health-impact claim.
"""

from __future__ import annotations

import re
from contextlib import ExitStack
from datetime import date
from pathlib import Path
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

CONTRACT_SCHEMA_VERSION = "causalfrontier.goal-claim-contract.v1"
PLAN_SCHEMA_VERSION = "causalfrontier.goal-claim-plan.v1"
PREFLIGHT_SCHEMA_VERSION = "causalfrontier.goal-claim-plan-preflight.v1"
PLAN_STATUS = "PREOUTCOME_GOAL_CLAIM_PLAN_DRAFT"
PREFLIGHT_STATUS = "GOAL_CONFORMANT_CLAIM_PLAN_BOUND_OUTCOMES_AND_SCORING_DISABLED"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_STRUCTURAL_PREFLIGHT"
PLAN_DOMAIN_TAG = b"causalfrontier.goal-claim-plan.v1\0"
PREFLIGHT_DOMAIN_TAG = b"causalfrontier.goal-claim-plan-preflight.v1\0"
CANDIDATE_BINDING_DOMAIN_TAG = b"causalfrontier.goal-claim-candidate-binding.v1\0"
COMPARATOR_BINDING_DOMAIN_TAG = b"causalfrontier.goal-claim-comparator-binding.v1\0"

MANDATORY_COMPARATOR_FAMILIES = (
    "INDEPENDENT_EXPERT",
    "RETRIEVAL_ONLY",
    "GRAPH_ONLY",
    "RANDOM",
    "SIMPLE_RULE_PREDECLARED",
)
PRIMARY_RESOURCE_ESTIMANDS = frozenset({"CALENDAR_MINUTES", "FULLY_LOADED_COST_MINOR_UNITS"})
COST_CURRENCY = "USD"
REQUIRED_GATE_IDS = (
    "TEMPORAL_LEAKAGE",
    "PROVENANCE",
    "PRIVACY",
    "AUTHORITY",
    "BRANCH_TOTALITY",
    "ROLLBACK_AND_EQUIVOCATION",
    "HOSTILE_INPUT",
    "COMMON_INPUT_PARITY",
    "ORACLE_TOTALITY",
    "REAL_RESOURCE_ACCOUNTING",
    "ROLE_SEPARATION",
)
CONTROL_ROLES = ("POSITIVE", "FAILED_TRANSLATION", "AMBIGUOUS")
CONTROL_REQUIRED_BEHAVIORS = (
    "PREDECLARED_METHOD_RECOVERY_CRITERION_PASSES",
    "PREDECLARED_FAILED_TRANSLATION_REJECTION_CRITERION_PASSES",
    "PREDECLARED_AMBIGUITY_ABSTENTION_CRITERION_PASSES",
)
EXECUTION_DESIGNS = frozenset({"PARALLEL_RANDOMIZED", "COMPLETE_REPLAY_ORACLE"})

MINIMUM_DOMAINS = 3
MINIMUM_DECISION_POINTS = 30
MINIMUM_LABORATORIES = 6
MINIMUM_DECISION_POINTS_PER_DOMAIN = 10
MINIMUM_LABORATORIES_PER_DOMAIN = 2
MINIMUM_EARLY_CAREER_PARTICIPANTS = 12
MAXIMUM_DOMAINS = 64
MAXIMUM_DECISION_POINTS = 100_000
MAXIMUM_LABORATORIES = 10_000

PRIMARY_ENDPOINT = (
    "FIRST_CORRECT_PREDECLARED_DECISION_RELEVANT_FALSIFICATION_EXCLUDING_AT_LEAST_ONE_LIVE_"
    "DECISION_EQUIVALENCE_CLASS_SUSTAINED_ON_REQUIRED_REPLICATION"
)
ANALYSIS_POPULATION = "INTENTION_TO_TREAT_ALL_PRECOMMITTED_CELLS"
EFFECT_ESTIMAND = "COMPARATOR_PRIMARY_RESOURCE_DIVIDED_BY_CANDIDATE_PRIMARY_RESOURCE"
CLAIM_CELLS = "EACH_MANDATORY_COMPARATOR_IN_EACH_DECLARED_DOMAIN_AND_POOLED"
CONFIDENCE_FAMILY = "GLOBAL_SIMULTANEOUS_ONE_SIDED_CONFIDENCE_BOUNDS"
MULTIPLICITY_SCOPE = (
    "GLOBAL_FAMILY_OF_ALL_ACCELERATION_FALSE_EXCLUSION_COVERAGE_AND_SELECTIVE_RISK_BOUNDS_ACROSS_EVERY_"
    "REQUIRED_DOMAIN_AND_POOLED_CELL"
)
MULTIPLICITY_METHOD = "BONFERRONI_ONE_SIDED_SIMULTANEOUS_BOUNDS_OVER_THE_GLOBAL_CLAIM_FAMILY"
GLOBAL_CLAIM_INFERENCE_RULE = (
    "ONE_9500_BPS_FAMILYWISE_ERROR_BUDGET_OVER_ALL_CLAIM_BEARING_BOUNDS_AND_SUCCESS_REQUIRES_THE_COMPLETE_INTERSECTION"
)
CLUSTERING_RULE = "ACCOUNT_FOR_PREDECLARED_LABORATORY_AND_DOMAIN_CLUSTERING"
MISSING_CELL_RULE = "MISSING_OR_INCOMPLETE_RESOURCE_LEDGER_YIELDS_NO_CALL_NEVER_FAVORABLE_CENSORING"
CANDIDATE_NONCOMPLETION_RULE = "CLAIM_FAILS_FOR_EACH_AFFECTED_COMPARATOR_BY_DOMAIN_CELL"
COMPARATOR_NONCOMPLETION_RULE = (
    "RIGHT_CENSORED_LOWER_BOUND_ONLY_WITH_COMPLETE_LEDGER_THROUGH_PRECOMMITTED_COMMON_HORIZON_AND_THRESHOLD_"
    "PROOF_OTHERWISE_NO_CALL"
)
ZERO_RESOURCE_RULE = "STRICTLY_POSITIVE_MEASURED_RESOURCES_ZERO_OR_INVALID_NO_CALL_NEVER_INFINITY"
RESOURCE_CHOICE_RULE = "PREDECLARED_PER_DOMAIN_NO_POSTHOC_TIME_OR_COST_CHOICE"
FALSE_EXCLUSION_RULE = "NO_INCREASE_IN_FALSE_DECISION_EQUIVALENCE_CLASS_EXCLUSION"
AUTHORITY_VIOLATION_RULE = "ANY_AUTHORITY_VIOLATION_INVALIDATES_THE_AFFECTED_RUN_AND_BLOCKS_THE_CLAIM"
NO_BEST_SELECTION_RULE = "NO_BEST_DOMAIN_CASE_SEED_EXPERT_MODEL_OR_COMPARATOR_SELECTION"
ABSTENTION_RULE = "PREDECLARED_DOMAIN_SPECIFIC_SELECTIVE_RISK_AND_MINIMUM_COVERAGE_BOTH_MUST_PASS"
ABSTENTION_INFERENCE_RULE = (
    "GLOBAL_FAMILY_ADJUSTED_ONE_SIDED_LOWER_COVERAGE_AND_UPPER_SELECTIVE_RISK_BOUNDS_IN_EVERY_DOMAIN"
)
MINIMUM_COVERAGE_BASIS_POINTS = 5000
MAXIMUM_SELECTIVE_RISK_BASIS_POINTS = 500
FALSE_EXCLUSION_ESTIMAND = "CANDIDATE_MINUS_MATCHED_COMPARATOR_FALSE_EXCLUSION_RATE"
FALSE_EXCLUSION_INFERENCE_RULE = "GLOBAL_FAMILY_ADJUSTED_ONE_SIDED_UPPER_BOUND_AT_MOST_ZERO_IN_EVERY_DOMAIN_AND_POOLED"
PROVENANCE_REQUIRED_STATE = "EXACT_END_TO_END_PROVENANCE_PASS_BEFORE_OUTCOME_ACCESS_OR_CLAIM_NO_CALL"
CONTROL_FAILURE_RULE = "ANY_REQUIRED_CONTROL_FAILURE_IN_ANY_DOMAIN_BLOCKS_PRIMARY_SCORING_AND_YIELDS_NO_CALL"
CONTROL_PRIMARY_SEPARATION_RULE = "CALIBRATION_CONTROLS_NEVER_ENTER_PRIMARY_EFFECT_ESTIMATION"
GATE_REQUIRED_STATE = "PASS_BEFORE_OUTCOME_ACCESS_OR_CLAIM_NO_CALL"
USABILITY_POPULATION = "EARLY_CAREER_SCIENTISTS"
USABILITY_TASK = "CLEAN_INSTALL_AUTHOR_VERIFY_AND_REPLAY_ONE_SYNTHETIC_CASE"

_GOAL_CONTRACT_TEMPLATE = {
    "schema_version": CONTRACT_SCHEMA_VERSION,
    "contract_status": "IMMUTABLE_SUCCESS_CRITERIA_OUTCOMES_NOT_ACCEPTED",
    "objective": (
        "Build and validate an open, machine-verifiable scientific discovery operating system that, on "
        "preregistered leakage-resistant challenges across at least three scientific domains, reduces the time "
        "or cost to the next decision-relevant falsification by at least 10x versus expert, retrieval, graph, "
        "random, and simple-rule baselines; preserves provenance, calibrated abstention, privacy, and authority "
        "boundaries; and is independently reproducible and usable by early-career scientists."
    ),
    "fixed_parameter": FIXED_PARAMETER,
    "boundary": fixed_boundary(),
    "benchmark_minima": {
        "scientific_domains": MINIMUM_DOMAINS,
        "precommitted_decision_points": MINIMUM_DECISION_POINTS,
        "declared_laboratories": MINIMUM_LABORATORIES,
        "precommitted_decision_points_per_domain": MINIMUM_DECISION_POINTS_PER_DOMAIN,
        "declared_laboratories_per_domain": MINIMUM_LABORATORIES_PER_DOMAIN,
    },
    "primary_endpoint": PRIMARY_ENDPOINT,
    "required_calibration_control_roles_per_domain": list(CONTROL_ROLES),
    "calibration_contract": {
        "role_criteria": [
            {"control_role": role, "required_behavior": behavior}
            for role, behavior in zip(CONTROL_ROLES, CONTROL_REQUIRED_BEHAVIORS, strict=True)
        ],
        "control_failure_rule": CONTROL_FAILURE_RULE,
        "primary_separation_rule": CONTROL_PRIMARY_SEPARATION_RULE,
        "semantic_validity_must_be_externally_verified": True,
    },
    "mandatory_comparator_families": list(MANDATORY_COMPARATOR_FAMILIES),
    "success_threshold": {
        "effect_estimand": EFFECT_ESTIMAND,
        "numerator": 10,
        "denominator": 1,
        "claim_cells": CLAIM_CELLS,
        "criterion": "SIMULTANEOUS_LOWER_CONFIDENCE_BOUND_AT_LEAST_THRESHOLD_IN_EVERY_CLAIM_CELL",
    },
    "resource_contract": {
        "allowed_primary_estimands": sorted(PRIMARY_RESOURCE_ESTIMANDS),
        "choice_rule": RESOURCE_CHOICE_RULE,
        "included_costs": [
            "PREPROCESSING",
            "RETRIEVAL",
            "MODEL_AND_TOOL_INVOCATIONS",
            "RETRIES",
            "HUMAN_LABOR",
            "COMPUTE",
            "CALENDAR_TIME",
            "DIRECT_COST",
        ],
        "zero_resource_rule": ZERO_RESOURCE_RULE,
        "same_resource_meter_contract_required": True,
        "fully_loaded_cost_currency": COST_CURRENCY,
        "synthetic_tariffs_support_claim": False,
        "same_process_telemetry_supports_claim": False,
    },
    "analysis_contract": {
        "population": ANALYSIS_POPULATION,
        "confidence_family": CONFIDENCE_FAMILY,
        "familywise_confidence_basis_points": 9500,
        "multiplicity_scope": MULTIPLICITY_SCOPE,
        "multiplicity_method": MULTIPLICITY_METHOD,
        "global_claim_inference_rule": GLOBAL_CLAIM_INFERENCE_RULE,
        "clustering_rule": CLUSTERING_RULE,
        "missing_cell_rule": MISSING_CELL_RULE,
        "candidate_noncompletion_rule": CANDIDATE_NONCOMPLETION_RULE,
        "comparator_noncompletion_rule": COMPARATOR_NONCOMPLETION_RULE,
        "false_exclusion_rule": FALSE_EXCLUSION_RULE,
        "false_exclusion_estimand": FALSE_EXCLUSION_ESTIMAND,
        "false_exclusion_inference_rule": FALSE_EXCLUSION_INFERENCE_RULE,
        "false_exclusion_margin_basis_points": 0,
        "authority_violation_rule": AUTHORITY_VIOLATION_RULE,
        "no_best_selection_rule": NO_BEST_SELECTION_RULE,
        "abstention_rule": ABSTENTION_RULE,
        "abstention_inference_rule": ABSTENTION_INFERENCE_RULE,
        "minimum_coverage_basis_points": MINIMUM_COVERAGE_BASIS_POINTS,
        "maximum_selective_risk_basis_points": MAXIMUM_SELECTIVE_RISK_BASIS_POINTS,
    },
    "execution_contract": {
        "allowed_designs": sorted(EXECUTION_DESIGNS),
        "one_design_selected_before_outcome_access": True,
        "complete_matrix_rule": "EVERY_PRIMARY_CASE_TIMES_CANDIDATE_AND_ALL_FIVE_MANDATORY_COMPARATORS",
        "common_input_parity_required": True,
        "common_horizon_required_within_domain": True,
        "endpoint_adjudication_totality_required": True,
    },
    "provenance_contract": {
        "exact_source_inventory_required": True,
        "evidence_receipts_required": True,
        "transformation_lineage_required": True,
        "execution_trace_required": True,
        "analysis_artifact_lineage_required": True,
        "independent_witness_required": True,
        "required_state": PROVENANCE_REQUIRED_STATE,
    },
    "leakage_contract": {
        "primary_case_timing": "PROSPECTIVE_BLIND_ONLY",
        "known_hindsight_role": "CALIBRATION_ONLY_NEVER_PRIMARY_PERFORMANCE",
        "post_cutoff_information_access_allowed": False,
        "training_contamination_review_required": True,
    },
    "data_and_authority_contract": {
        "allowed_data_classes": ["PUBLIC_AGGREGATE", "SYNTHETIC"],
        "patient_level_data_allowed": False,
        "authority_violations_allowed": 0,
    },
    "required_integrity_gates": list(REQUIRED_GATE_IDS),
    "independent_reproduction": {
        "minimum_independent_reproducers": 1,
        "minimum_independent_organizations": 1,
        "controller_disjointness_required": True,
        "clean_environment_required": True,
        "released_artifact_recipe_required": True,
        "byte_identical_artifacts_required": True,
        "complete_matrix_and_analysis_replay_required": True,
        "independent_holdout_required": True,
        "independent_holdout_goal_contract_binding_required": True,
        "complete_domain_by_comparator_conjunction_required": True,
    },
    "early_career_usability": {
        "population": USABILITY_POPULATION,
        "task": USABILITY_TASK,
        "minimum_participants": MINIMUM_EARLY_CAREER_PARTICIPANTS,
        "minimum_independent_organizations": 2,
        "non_contributor_participants_required": True,
        "population_definition_required": True,
        "minimum_domains_represented": MINIMUM_DOMAINS,
        "minimum_unaided_completion_basis_points": 8000,
        "maximum_median_completion_minutes": 120,
        "authority_errors_allowed": 0,
    },
    "claim_boundary": {
        "structural_plan_preflight_is_scientific_validation": False,
        "structural_noncollision_is_independence": False,
        "declared_organization_is_independent_controller": False,
        "historical_hindsight_is_prospective": False,
        "publication_or_release_authority_granted": False,
        "patient_or_material_authority_granted": False,
    },
}
GOAL_CONTRACT_CANONICAL = canonical_bytes(_GOAL_CONTRACT_TEMPLATE)

PLAN_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "plan_id",
        "sequence",
        "fixed_parameter",
        "boundary",
        "goal_claim_contract_sha256",
        "cohort_checkpoint_sha256",
        "common_input_contract_sha256",
        "candidate",
        "domains",
        "calibration",
        "comparators",
        "execution",
        "analysis",
        "leakage",
        "privacy_authority",
        "provenance",
        "integrity_gates",
        "reproduction",
        "usability",
        "openness",
        "designated_scientific_data_inputs_absent",
        "scoring_disabled",
        "scientific_claim_ready",
        "plan_sha256",
    }
)
REPORT_CORE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "claim_state",
        "implementation_status",
        "base_compiler_version",
        "fixed_parameter",
        "boundary",
        "plan_id",
        "plan_sequence",
        "plan_checkpoint_sha256",
        "plan_sha256",
        "goal_claim_contract_sha256",
        "mandatory_comparator_families",
        "declared_domains_n",
        "precommitted_decision_points_n",
        "calibration_decision_points_n",
        "declared_laboratories_n",
        "primary_resource_estimands_by_domain",
        "required_gate_ids",
        "designated_scientific_data_input_accepted",
        "outcome_or_result_field_accepted",
        "scoring_performed",
        "scientific_scoring_ready",
        "scientific_claim_ready",
        "acceleration_verified",
        "independent_reproduction_verified",
        "early_career_usability_verified",
        "prospective_primary_cases_verified",
        "domain_semantic_validity_verified",
        "cohort_admission_verified",
        "generator_independence_verified",
        "control_semantic_validity_verified",
        "public_open_build_verified",
        "comparator_family_conformance_verified",
        "controller_independence_verified",
        "externally_registered",
        "comparators_executed",
        "endpoint_adjudicated",
        "privacy_certified",
        "provenance_verified",
        "real_resource_verified",
        "publication_claim_authorized",
        "temporal_leakage_gate_verified",
        "privacy_gate_verified",
        "authority_gate_verified",
        "rollback_gate_verified",
        "gates",
        "nonclaims",
    }
)
REPORT_KEYS = REPORT_CORE_KEYS | {"preflight_sha256"}

FORBIDDEN_RESULT_KEYS = frozenset(
    {
        "acceleration_ratio",
        "confidence_interval",
        "effect_estimate",
        "observed_outcome",
        "oracle_opening",
        "outcome",
        "outcomes",
        "p_value",
        "ranking",
        "result",
        "results",
        "reveal",
        "scientific_score",
        "score",
        "scores",
        "terminal_truth",
        "winner",
    }
)

NONCLAIMS = (
    "This preflight binds a goal-conformant plan; it does not execute a candidate or comparator.",
    "No outcome, result, oracle opening, winner, score, or acceleration ratio is accepted or computed.",
    "Declared domains, laboratories, controllers, and digest-separated implementations do not prove independence.",
    "Artifact digests other than the exact plan checkpoint are caller declarations; their preimage bytes are not "
    "supplied or verified.",
    "Declared analysis, gate, resource-meter, reproduction, and usability protocols have not been executed or "
    "validated.",
    "Control roles and identifiers do not verify semantic validity, independence, or expected behavior; controls "
    "have not been scored.",
    "Opaque case identifiers and digest declarations can encode known hindsight; prospective timing and training "
    "separation remain unverified.",
    "Equal input and meter digests prove declared equality only, not semantic symmetry or correct resource accounting.",
    "Domain labels, case counts, laboratory assignments, and cutoffs do not prove semantic domain validity, cohort "
    "admission, generator independence, or temporal admissibility.",
    "The external checkpoint proves exact caller-supplied bytes, not prospective time, custody, or monotonic "
    "currentness.",
    "No biological, clinical, health-impact, patient, wet-lab, material, publication, or release claim is authorized.",
)


def goal_claim_contract() -> dict[str, Any]:
    """Return a fresh copy of the immutable program-level success contract."""

    value = read_json_bytes(GOAL_CONTRACT_CANONICAL, "goal claim contract")
    if not isinstance(value, dict):  # pragma: no cover - immutable module constant
        raise CausalFrontierError("goal claim contract is not an object")
    return value


def goal_claim_contract_sha256() -> str:
    """Return the digest that every successor claim plan must bind."""

    return sha256_bytes(GOAL_CONTRACT_CANONICAL)


def _bounded_positive_integer(value: Any, field: str, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _require_artifact_sha256(value: Any, field: str) -> str:
    digest = require_sha256(value, field)
    if digest == "0" * 64:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return digest


def _sorted_unique_ids(value: Any, field: str, *, minimum: int = 1, maximum: int = 100_000) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise CausalFrontierError("%s must contain %d..%d identifiers" % (field, minimum, maximum))
    normalized = [require_id(item, "%s item" % field) for item in value]
    if normalized != sorted(set(normalized)):
        raise CausalFrontierError("%s must be unique and sorted" % field)
    return normalized


def _scan_forbidden_result_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() in FORBIDDEN_RESULT_KEYS:
                raise CausalFrontierError("claim plan contains forbidden post-outcome field")
            _scan_forbidden_result_keys(item)
    elif isinstance(value, list):
        for item in value:
            _scan_forbidden_result_keys(item)


def _read_checkpointed_plan(path: Path, expected_sha256: str) -> tuple[bytes, dict[str, Any]]:
    _require_artifact_sha256(expected_sha256, "claim-plan external checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError:
        raise CausalFrontierError("claim plan cannot be read safely") from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("claim-plan external checkpoint mismatch")
    receipt_io._screen(raw)
    value = read_json_bytes(raw, "goal claim plan")
    receipt_io._screen(canonical_bytes(value))
    if not isinstance(value, dict):
        raise CausalFrontierError("goal claim plan must be an object")
    return raw, value


def _validate_candidate(value: Any) -> dict[str, Any]:
    candidate = require_exact_keys(
        value,
        {
            "system_id",
            "version_id",
            "source_tree_sha256",
            "source_archive_sha256",
            "dependency_lock_sha256",
            "build_recipe_sha256",
            "license_spdx_id",
            "implementation_sha256",
            "execution_protocol_sha256",
            "environment_sha256",
            "resource_meter_contract_sha256",
            "controller_disclosure_sha256",
            "independence_protocol_sha256",
            "candidate_binding_sha256",
        },
        "candidate",
    )
    require_id(candidate["system_id"], "candidate system id")
    require_id(candidate["version_id"], "candidate version id")
    if candidate["license_spdx_id"] != "Apache-2.0":
        raise CausalFrontierError("candidate must bind the public Apache-2.0 source contract")
    for field in (
        "source_tree_sha256",
        "source_archive_sha256",
        "dependency_lock_sha256",
        "build_recipe_sha256",
        "implementation_sha256",
        "execution_protocol_sha256",
        "environment_sha256",
        "resource_meter_contract_sha256",
        "controller_disclosure_sha256",
        "independence_protocol_sha256",
    ):
        _require_artifact_sha256(candidate[field], "candidate %s" % field)
    _require_artifact_sha256(candidate["candidate_binding_sha256"], "candidate implementation binding")
    candidate_core = {key: value for key, value in candidate.items() if key != "candidate_binding_sha256"}
    expected_binding = sha256_bytes(CANDIDATE_BINDING_DOMAIN_TAG + canonical_bytes(candidate_core))
    if candidate["candidate_binding_sha256"] != expected_binding:
        raise CausalFrontierError("candidate implementation binding mismatch")
    return candidate


def _require_iso_date(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
        raise CausalFrontierError("%s must be an exact ISO calendar date" % field)
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise CausalFrontierError("%s must be an exact ISO calendar date" % field) from None
    if parsed.isoformat() != value:
        raise CausalFrontierError("%s must be an exact ISO calendar date" % field)
    return value


def _validate_domains(value: Any) -> tuple[list[dict[str, Any]], set[str], set[str], set[str]]:
    if not isinstance(value, list) or not MINIMUM_DOMAINS <= len(value) <= MAXIMUM_DOMAINS:
        raise CausalFrontierError("claim plan must contain at least three bounded domains")
    domains: list[dict[str, Any]] = []
    all_primary_cases: set[str] = set()
    all_calibration_cases: set[str] = set()
    all_laboratories: set[str] = set()
    for index, item in enumerate(value):
        domain = require_exact_keys(
            item,
            {
                "domain_id",
                "primary_case_ids",
                "calibration_cases",
                "laboratory_ids",
                "primary_case_laboratory_assignments",
                "case_registry_checkpoint_sha256",
                "knowledge_cutoff",
                "primary_resource_estimand",
                "currency_code",
                "price_basis_date",
                "common_horizon_minutes",
                "resource_basis_sha256",
                "resource_ledger_contract_sha256",
                "common_horizon_contract_sha256",
            },
            "domain[%d]" % index,
        )
        domain_id = require_id(domain["domain_id"], "domain id")
        primary_cases = _sorted_unique_ids(
            domain["primary_case_ids"],
            "%s primary case ids" % domain_id,
            minimum=MINIMUM_DECISION_POINTS_PER_DOMAIN,
        )
        laboratories = _sorted_unique_ids(
            domain["laboratory_ids"],
            "%s laboratory ids" % domain_id,
            minimum=MINIMUM_LABORATORIES_PER_DOMAIN,
        )
        calibration_items = domain["calibration_cases"]
        if not isinstance(calibration_items, list) or len(calibration_items) != len(CONTROL_ROLES):
            raise CausalFrontierError("each domain must bind exactly one case for every calibration control role")
        calibration_cases = []
        for role_index, calibration_item in enumerate(calibration_items):
            calibration = require_exact_keys(
                calibration_item,
                {"case_id", "control_role"},
                "%s calibration case[%d]" % (domain_id, role_index),
            )
            if calibration["control_role"] != CONTROL_ROLES[role_index]:
                raise CausalFrontierError("calibration controls must be complete and canonically role ordered")
            calibration_cases.append(require_id(calibration["case_id"], "%s calibration case id" % domain_id))
        if len(set(calibration_cases)) != len(calibration_cases):
            raise CausalFrontierError("calibration case identifiers must be unique")
        assignments = domain["primary_case_laboratory_assignments"]
        if not isinstance(assignments, list) or len(assignments) != len(primary_cases):
            raise CausalFrontierError("every primary case must have exactly one laboratory assignment")
        assignment_case_ids = []
        assigned_laboratories = set()
        for assignment_index, assignment_item in enumerate(assignments):
            assignment = require_exact_keys(
                assignment_item,
                {"case_id", "laboratory_id"},
                "%s primary assignment[%d]" % (domain_id, assignment_index),
            )
            assignment_case_ids.append(require_id(assignment["case_id"], "%s assigned case id" % domain_id))
            laboratory_id = require_id(assignment["laboratory_id"], "%s assigned laboratory id" % domain_id)
            if laboratory_id not in laboratories:
                raise CausalFrontierError("primary case assignment references an undeclared laboratory")
            assigned_laboratories.add(laboratory_id)
        if assignment_case_ids != primary_cases or assigned_laboratories != set(laboratories):
            raise CausalFrontierError(
                "primary assignments must cover every case once and use every declared laboratory"
            )
        submitted_cases = set(primary_cases) | set(calibration_cases)
        if set(primary_cases) & set(calibration_cases):
            raise CausalFrontierError("primary and calibration cases must be disjoint")
        if (all_primary_cases | all_calibration_cases) & submitted_cases:
            raise CausalFrontierError("case identifiers must be unique across domains")
        all_primary_cases.update(primary_cases)
        all_calibration_cases.update(calibration_cases)
        all_laboratories.update(laboratories)
        _require_artifact_sha256(domain["case_registry_checkpoint_sha256"], "%s case registry checkpoint" % domain_id)
        require_utc_timestamp(domain["knowledge_cutoff"], "%s knowledge cutoff" % domain_id)
        require_enum(
            domain["primary_resource_estimand"],
            set(PRIMARY_RESOURCE_ESTIMANDS),
            "%s primary resource estimand" % domain_id,
        )
        if domain["primary_resource_estimand"] == "CALENDAR_MINUTES":
            if domain["currency_code"] is not None or domain["price_basis_date"] is not None:
                raise CausalFrontierError("calendar-minute domains must not declare currency or price basis")
        else:
            if domain["currency_code"] != COST_CURRENCY:
                raise CausalFrontierError("v1 cost domains must use the standardized USD currency")
            _require_iso_date(domain["price_basis_date"], "%s price basis date" % domain_id)
        _bounded_positive_integer(domain["common_horizon_minutes"], "%s common horizon minutes" % domain_id)
        _require_artifact_sha256(domain["resource_basis_sha256"], "%s resource basis" % domain_id)
        _require_artifact_sha256(domain["resource_ledger_contract_sha256"], "%s resource ledger contract" % domain_id)
        _require_artifact_sha256(domain["common_horizon_contract_sha256"], "%s common horizon contract" % domain_id)
        domains.append(domain)
    domain_ids = [domain["domain_id"] for domain in domains]
    if domain_ids != sorted(set(domain_ids)):
        raise CausalFrontierError("domains must have unique sorted identifiers")
    if not MINIMUM_DECISION_POINTS <= len(all_primary_cases) <= MAXIMUM_DECISION_POINTS:
        raise CausalFrontierError("claim plan does not meet the precommitted decision-point minimum")
    if len(all_calibration_cases) > MAXIMUM_DECISION_POINTS:
        raise CausalFrontierError("claim plan contains too many calibration cases")
    if not MINIMUM_LABORATORIES <= len(all_laboratories) <= MAXIMUM_LABORATORIES:
        raise CausalFrontierError("claim plan does not meet the declared-laboratory minimum")
    return domains, all_primary_cases, all_calibration_cases, all_laboratories


def _validate_calibration(value: Any) -> dict[str, Any]:
    calibration = require_exact_keys(
        value,
        {
            "role_criteria",
            "control_failure_rule",
            "primary_separation_rule",
            "control_oracle_commitment_sha256",
            "control_scoring_protocol_sha256",
            "control_scoring_implementation_sha256",
            "semantic_validity_review_protocol_sha256",
            "current_control_semantic_validity_verified",
        },
        "calibration",
    )
    criteria = calibration["role_criteria"]
    if not isinstance(criteria, list) or len(criteria) != len(CONTROL_ROLES):
        raise CausalFrontierError("calibration must bind one criterion for every control role")
    for index, item in enumerate(criteria):
        criterion = require_exact_keys(item, {"control_role", "required_behavior"}, "control criterion")
        if (
            criterion["control_role"] != CONTROL_ROLES[index]
            or criterion["required_behavior"] != CONTROL_REQUIRED_BEHAVIORS[index]
        ):
            raise CausalFrontierError("calibration role criteria must be complete and canonical")
    if (
        calibration["control_failure_rule"] != CONTROL_FAILURE_RULE
        or calibration["primary_separation_rule"] != CONTROL_PRIMARY_SEPARATION_RULE
        or calibration["current_control_semantic_validity_verified"] is not False
    ):
        raise CausalFrontierError("calibration plan permits ignored controls or self-certifies semantic validity")
    for field in (
        "control_oracle_commitment_sha256",
        "control_scoring_protocol_sha256",
        "control_scoring_implementation_sha256",
        "semantic_validity_review_protocol_sha256",
    ):
        _require_artifact_sha256(calibration[field], "calibration %s" % field)
    return calibration


def _validate_comparators(value: Any, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(MANDATORY_COMPARATOR_FAMILIES):
        raise CausalFrontierError("claim plan must bind exactly the five mandatory comparator families")
    comparators = []
    system_ids = {candidate["system_id"]}
    implementation_digests = {candidate["implementation_sha256"]}
    policy_digests: set[str] = set()
    controller_digests = {candidate["controller_disclosure_sha256"]}
    independence_digests = {candidate["independence_protocol_sha256"]}
    conformance_protocol_digests: set[str] = set()
    conformance_implementation_digests: set[str] = set()
    binding_digests: set[str] = set()
    for index, item in enumerate(value):
        comparator = require_exact_keys(
            item,
            {
                "family",
                "system_id",
                "version_id",
                "policy_contract_sha256",
                "family_conformance_protocol_sha256",
                "family_conformance_implementation_sha256",
                "implementation_sha256",
                "execution_environment_sha256",
                "resource_meter_contract_sha256",
                "controller_disclosure_sha256",
                "independence_protocol_sha256",
                "comparator_binding_sha256",
            },
            "comparator[%d]" % index,
        )
        expected_family = MANDATORY_COMPARATOR_FAMILIES[index]
        if comparator["family"] != expected_family:
            raise CausalFrontierError("mandatory comparator families must be complete and canonically ordered")
        system_id = require_id(comparator["system_id"], "%s system id" % expected_family)
        require_id(comparator["version_id"], "%s version id" % expected_family)
        if system_id in system_ids:
            raise CausalFrontierError("candidate and comparator system identifiers must be distinct")
        system_ids.add(system_id)
        for field in (
            "policy_contract_sha256",
            "family_conformance_protocol_sha256",
            "family_conformance_implementation_sha256",
            "implementation_sha256",
            "execution_environment_sha256",
            "resource_meter_contract_sha256",
            "controller_disclosure_sha256",
            "independence_protocol_sha256",
        ):
            _require_artifact_sha256(comparator[field], "%s %s" % (expected_family, field))
        if comparator["implementation_sha256"] in implementation_digests:
            raise CausalFrontierError("candidate and comparator implementations must be structurally nonaliased")
        if comparator["policy_contract_sha256"] in policy_digests:
            raise CausalFrontierError("comparator family policies must be structurally nonaliased")
        if comparator["controller_disclosure_sha256"] in controller_digests:
            raise CausalFrontierError("candidate and comparator controller disclosures must be structurally nonaliased")
        if comparator["independence_protocol_sha256"] in independence_digests:
            raise CausalFrontierError("candidate and comparator independence protocols must be structurally nonaliased")
        if comparator["family_conformance_protocol_sha256"] in conformance_protocol_digests:
            raise CausalFrontierError("comparator conformance protocols must be structurally nonaliased")
        if comparator["family_conformance_implementation_sha256"] in conformance_implementation_digests:
            raise CausalFrontierError("comparator conformance implementations must be structurally nonaliased")
        if comparator["resource_meter_contract_sha256"] != candidate["resource_meter_contract_sha256"]:
            raise CausalFrontierError("candidate and comparators must bind the same resource meter contract")
        _require_artifact_sha256(comparator["comparator_binding_sha256"], "%s comparator binding" % expected_family)
        comparator_core = {key: value for key, value in comparator.items() if key != "comparator_binding_sha256"}
        expected_binding = sha256_bytes(COMPARATOR_BINDING_DOMAIN_TAG + canonical_bytes(comparator_core))
        if comparator["comparator_binding_sha256"] != expected_binding:
            raise CausalFrontierError("comparator implementation binding mismatch")
        if comparator["comparator_binding_sha256"] in binding_digests:
            raise CausalFrontierError("comparator bindings must be structurally nonaliased")
        implementation_digests.add(comparator["implementation_sha256"])
        policy_digests.add(comparator["policy_contract_sha256"])
        controller_digests.add(comparator["controller_disclosure_sha256"])
        independence_digests.add(comparator["independence_protocol_sha256"])
        conformance_protocol_digests.add(comparator["family_conformance_protocol_sha256"])
        conformance_implementation_digests.add(comparator["family_conformance_implementation_sha256"])
        binding_digests.add(comparator["comparator_binding_sha256"])
        comparators.append(comparator)
    return comparators


def _validate_analysis(value: Any) -> dict[str, Any]:
    analysis = require_exact_keys(
        value,
        {
            "primary_endpoint",
            "analysis_population",
            "effect_estimand",
            "claim_cells",
            "threshold_numerator",
            "threshold_denominator",
            "confidence_family",
            "familywise_confidence_basis_points",
            "multiplicity_scope",
            "multiplicity_method",
            "global_claim_inference_rule",
            "clustering_rule",
            "analysis_implementation_sha256",
            "sample_size_and_power_sha256",
            "abstention_contract_sha256",
            "false_exclusion_contract_sha256",
            "missing_cell_rule",
            "candidate_noncompletion_rule",
            "comparator_noncompletion_rule",
            "zero_resource_rule",
            "resource_choice_rule",
            "false_exclusion_rule",
            "false_exclusion_estimand",
            "false_exclusion_inference_rule",
            "false_exclusion_margin_basis_points",
            "authority_violation_rule",
            "no_best_selection_rule",
            "abstention_rule",
            "abstention_inference_rule",
            "minimum_coverage_basis_points",
            "maximum_selective_risk_basis_points",
        },
        "analysis",
    )
    expected = {
        "primary_endpoint": PRIMARY_ENDPOINT,
        "analysis_population": ANALYSIS_POPULATION,
        "effect_estimand": EFFECT_ESTIMAND,
        "claim_cells": CLAIM_CELLS,
        "threshold_numerator": 10,
        "threshold_denominator": 1,
        "confidence_family": CONFIDENCE_FAMILY,
        "familywise_confidence_basis_points": 9500,
        "multiplicity_scope": MULTIPLICITY_SCOPE,
        "multiplicity_method": MULTIPLICITY_METHOD,
        "global_claim_inference_rule": GLOBAL_CLAIM_INFERENCE_RULE,
        "clustering_rule": CLUSTERING_RULE,
        "missing_cell_rule": MISSING_CELL_RULE,
        "candidate_noncompletion_rule": CANDIDATE_NONCOMPLETION_RULE,
        "comparator_noncompletion_rule": COMPARATOR_NONCOMPLETION_RULE,
        "zero_resource_rule": ZERO_RESOURCE_RULE,
        "resource_choice_rule": RESOURCE_CHOICE_RULE,
        "false_exclusion_rule": FALSE_EXCLUSION_RULE,
        "false_exclusion_estimand": FALSE_EXCLUSION_ESTIMAND,
        "false_exclusion_inference_rule": FALSE_EXCLUSION_INFERENCE_RULE,
        "false_exclusion_margin_basis_points": 0,
        "authority_violation_rule": AUTHORITY_VIOLATION_RULE,
        "no_best_selection_rule": NO_BEST_SELECTION_RULE,
        "abstention_rule": ABSTENTION_RULE,
        "abstention_inference_rule": ABSTENTION_INFERENCE_RULE,
        "minimum_coverage_basis_points": MINIMUM_COVERAGE_BASIS_POINTS,
        "maximum_selective_risk_basis_points": MAXIMUM_SELECTIVE_RISK_BASIS_POINTS,
    }
    for field, expected_value in expected.items():
        if analysis[field] != expected_value:
            raise CausalFrontierError("analysis does not match the immutable goal contract")
    for field in (
        "analysis_implementation_sha256",
        "sample_size_and_power_sha256",
        "abstention_contract_sha256",
        "false_exclusion_contract_sha256",
    ):
        _require_artifact_sha256(analysis[field], "analysis %s" % field)
    return analysis


def _validate_execution(
    value: Any,
    primary_cases_n: int,
    domains_n: int,
    expected_common_input_sha256: str,
    expected_resource_meter_sha256: str,
) -> dict[str, Any]:
    execution = require_exact_keys(
        value,
        {
            "design",
            "assignment_protocol_sha256",
            "shared_input_contract_sha256",
            "endpoint_adjudication_contract_sha256",
            "resource_parity_contract_sha256",
            "complete_matrix_rule",
            "planned_primary_cells_n",
            "planned_claim_cells_n",
        },
        "execution",
    )
    if (
        execution["design"] not in EXECUTION_DESIGNS
        or execution["complete_matrix_rule"] != "EVERY_PRIMARY_CASE_TIMES_CANDIDATE_AND_ALL_FIVE_MANDATORY_COMPARATORS"
        or execution["planned_primary_cells_n"] != primary_cases_n * (1 + len(MANDATORY_COMPARATOR_FAMILIES))
        or execution["planned_claim_cells_n"] != (domains_n + 1) * len(MANDATORY_COMPARATOR_FAMILIES)
    ):
        raise CausalFrontierError("execution does not bind the complete goal-conformant matrix")
    if execution["shared_input_contract_sha256"] != expected_common_input_sha256:
        raise CausalFrontierError("execution and plan must bind the same common-input contract")
    if execution["resource_parity_contract_sha256"] != expected_resource_meter_sha256:
        raise CausalFrontierError("execution must bind the common candidate-comparator resource meter contract")
    for field in (
        "assignment_protocol_sha256",
        "shared_input_contract_sha256",
        "endpoint_adjudication_contract_sha256",
        "resource_parity_contract_sha256",
    ):
        _require_artifact_sha256(execution[field], "execution %s" % field)
    return execution


def _validate_leakage(value: Any) -> dict[str, Any]:
    leakage = require_exact_keys(
        value,
        {
            "primary_case_timing",
            "known_hindsight_role",
            "model_tool_freeze_manifest_sha256",
            "network_access_policy_sha256",
            "temporal_audit_protocol_sha256",
            "training_contamination_protocol_sha256",
            "post_cutoff_information_access_allowed",
        },
        "leakage",
    )
    if (
        leakage["primary_case_timing"] != "PROSPECTIVE_BLIND_ONLY"
        or leakage["known_hindsight_role"] != "CALIBRATION_ONLY_NEVER_PRIMARY_PERFORMANCE"
        or leakage["post_cutoff_information_access_allowed"] is not False
    ):
        raise CausalFrontierError("leakage plan permits hindsight or post-cutoff primary evidence")
    for field in (
        "model_tool_freeze_manifest_sha256",
        "network_access_policy_sha256",
        "temporal_audit_protocol_sha256",
        "training_contamination_protocol_sha256",
    ):
        _require_artifact_sha256(leakage[field], "leakage %s" % field)
    return leakage


def _validate_privacy_authority(value: Any) -> dict[str, Any]:
    privacy = require_exact_keys(
        value,
        {
            "allowed_data_classes",
            "patient_level_data_allowed",
            "privacy_review_protocol_sha256",
            "authority_boundary",
            "authority_violations_allowed",
        },
        "privacy and authority",
    )
    if (
        privacy["allowed_data_classes"] != ["PUBLIC_AGGREGATE", "SYNTHETIC"]
        or privacy["patient_level_data_allowed"] is not False
        or canonical_bytes(privacy["authority_boundary"]) != canonical_bytes(fixed_boundary())
        or type(privacy["authority_violations_allowed"]) is not int
        or privacy["authority_violations_allowed"] != 0
    ):
        raise CausalFrontierError("privacy or authority plan expands the fixed boundary")
    _require_artifact_sha256(privacy["privacy_review_protocol_sha256"], "privacy review protocol")
    return privacy


def _validate_provenance(value: Any) -> dict[str, Any]:
    provenance = require_exact_keys(
        value,
        {
            "evidence_receipt_contract_sha256",
            "source_inventory_contract_sha256",
            "transformation_lineage_contract_sha256",
            "execution_trace_contract_sha256",
            "analysis_artifact_lineage_contract_sha256",
            "independent_witness_protocol_sha256",
            "required_state",
            "current_provenance_verified",
        },
        "provenance",
    )
    for field in (
        "evidence_receipt_contract_sha256",
        "source_inventory_contract_sha256",
        "transformation_lineage_contract_sha256",
        "execution_trace_contract_sha256",
        "analysis_artifact_lineage_contract_sha256",
        "independent_witness_protocol_sha256",
    ):
        _require_artifact_sha256(provenance[field], "provenance %s" % field)
    if (
        provenance["required_state"] != PROVENANCE_REQUIRED_STATE
        or provenance["current_provenance_verified"] is not False
    ):
        raise CausalFrontierError("provenance plan is incomplete or self-certifies verification")
    return provenance


def _validate_openness(value: Any) -> dict[str, Any]:
    openness = require_exact_keys(
        value,
        {
            "public_source_required",
            "public_data_or_synthetic_only",
            "reproducible_build_required",
            "license_spdx_id",
            "publication_plan_sha256",
            "publication_authority_granted",
        },
        "openness",
    )
    if (
        openness["public_source_required"] is not True
        or openness["public_data_or_synthetic_only"] is not True
        or openness["reproducible_build_required"] is not True
        or openness["license_spdx_id"] != "Apache-2.0"
        or openness["publication_authority_granted"] is not False
    ):
        raise CausalFrontierError("openness plan is incomplete or grants publication authority")
    _require_artifact_sha256(openness["publication_plan_sha256"], "publication plan")
    return openness


def _validate_integrity_gates(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(REQUIRED_GATE_IDS):
        raise CausalFrontierError("claim plan must bind every required integrity gate")
    gates = []
    for index, item in enumerate(value):
        gate = require_exact_keys(
            item,
            {"gate_id", "verification_protocol_sha256", "verification_implementation_sha256", "required_state"},
            "integrity gate[%d]" % index,
        )
        if gate["gate_id"] != REQUIRED_GATE_IDS[index] or gate["required_state"] != GATE_REQUIRED_STATE:
            raise CausalFrontierError("integrity gates must be complete, canonical, and fail closed")
        _require_artifact_sha256(gate["verification_protocol_sha256"], "%s verification protocol" % gate["gate_id"])
        _require_artifact_sha256(
            gate["verification_implementation_sha256"], "%s verification implementation" % gate["gate_id"]
        )
        gates.append(gate)
    return gates


def _validate_reproduction(value: Any) -> dict[str, Any]:
    reproduction = require_exact_keys(
        value,
        {
            "reproducer_protocol_sha256",
            "clean_environment_spec_sha256",
            "build_recipe_sha256",
            "minimum_independent_reproducers",
            "minimum_independent_organizations",
            "controller_disjointness_required",
            "byte_identical_artifacts_required",
            "complete_matrix_reexecution_required",
            "analysis_replay_required",
            "independent_holdout_required",
            "independent_holdout_goal_contract_sha256",
            "complete_domain_by_comparator_conjunction_required",
            "current_independent_reproduction_verified",
        },
        "reproduction",
    )
    for field in ("reproducer_protocol_sha256", "clean_environment_spec_sha256", "build_recipe_sha256"):
        _require_artifact_sha256(reproduction[field], "reproduction %s" % field)
    _require_artifact_sha256(
        reproduction["independent_holdout_goal_contract_sha256"],
        "independent holdout goal contract",
    )
    if (
        reproduction["minimum_independent_reproducers"] != 1
        or reproduction["minimum_independent_organizations"] != 1
        or reproduction["controller_disjointness_required"] is not True
        or reproduction["byte_identical_artifacts_required"] is not True
        or reproduction["complete_matrix_reexecution_required"] is not True
        or reproduction["analysis_replay_required"] is not True
        or reproduction["independent_holdout_required"] is not True
        or reproduction["independent_holdout_goal_contract_sha256"] != goal_claim_contract_sha256()
        or reproduction["complete_domain_by_comparator_conjunction_required"] is not True
        or reproduction["current_independent_reproduction_verified"] is not False
    ):
        raise CausalFrontierError("reproduction plan overclaims or weakens the immutable contract")
    return reproduction


def _validate_usability(value: Any) -> dict[str, Any]:
    usability = require_exact_keys(
        value,
        {
            "population",
            "population_definition_sha256",
            "study_protocol_sha256",
            "minimum_participants",
            "minimum_domains_represented",
            "minimum_independent_organizations",
            "non_contributor_participants_required",
            "task",
            "minimum_unaided_completion_basis_points",
            "maximum_median_completion_minutes",
            "authority_errors_allowed",
            "current_usability_verified",
        },
        "usability",
    )
    _require_artifact_sha256(usability["population_definition_sha256"], "usability population definition")
    _require_artifact_sha256(usability["study_protocol_sha256"], "usability study protocol")
    expected = {
        "population": USABILITY_POPULATION,
        "minimum_participants": MINIMUM_EARLY_CAREER_PARTICIPANTS,
        "minimum_domains_represented": MINIMUM_DOMAINS,
        "minimum_independent_organizations": 2,
        "non_contributor_participants_required": True,
        "task": USABILITY_TASK,
        "minimum_unaided_completion_basis_points": 8000,
        "maximum_median_completion_minutes": 120,
        "authority_errors_allowed": 0,
        "current_usability_verified": False,
    }
    for field, expected_value in expected.items():
        if usability[field] != expected_value:
            raise CausalFrontierError("usability plan overclaims or weakens the immutable contract")
    return usability


def validate_goal_claim_plan(value: Any) -> dict[str, Any]:
    """Validate one closed, result-free plan and return it unchanged."""

    _scan_forbidden_result_keys(value)
    plan = require_exact_keys(value, set(PLAN_KEYS), "goal claim plan")
    if (
        plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
        or plan["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(plan["boundary"]) != canonical_bytes(fixed_boundary())
        or plan["goal_claim_contract_sha256"] != goal_claim_contract_sha256()
        or plan["designated_scientific_data_inputs_absent"] is not True
        or plan["scoring_disabled"] is not True
        or plan["scientific_claim_ready"] is not False
    ):
        raise CausalFrontierError("goal claim plan targets another contract or overclaims its state")
    require_id(plan["plan_id"], "plan id")
    _bounded_positive_integer(plan["sequence"], "plan sequence")
    _require_artifact_sha256(plan["cohort_checkpoint_sha256"], "cohort checkpoint")
    _require_artifact_sha256(plan["common_input_contract_sha256"], "common-input contract")
    candidate = _validate_candidate(plan["candidate"])
    domains, primary_cases, _calibration_cases, _laboratories = _validate_domains(plan["domains"])
    _validate_calibration(plan["calibration"])
    _validate_comparators(plan["comparators"], candidate)
    _validate_execution(
        plan["execution"],
        len(primary_cases),
        len(domains),
        plan["common_input_contract_sha256"],
        candidate["resource_meter_contract_sha256"],
    )
    _validate_analysis(plan["analysis"])
    _validate_leakage(plan["leakage"])
    _validate_privacy_authority(plan["privacy_authority"])
    _validate_provenance(plan["provenance"])
    _validate_integrity_gates(plan["integrity_gates"])
    _validate_reproduction(plan["reproduction"])
    _validate_usability(plan["usability"])
    _validate_openness(plan["openness"])
    _require_artifact_sha256(plan["plan_sha256"], "plan semantic digest")
    core = {key: plan[key] for key in PLAN_KEYS if key != "plan_sha256"}
    expected_plan_sha256 = sha256_bytes(PLAN_DOMAIN_TAG + canonical_bytes(core))
    if plan["plan_sha256"] != expected_plan_sha256:
        raise CausalFrontierError("goal claim plan semantic digest mismatch")
    return plan


def _report_gate(gate_id: str, state: str, reason: str) -> dict[str, str]:
    return {"id": gate_id, "state": state, "reason": reason}


def _expected_preflight_gates() -> list[dict[str, str]]:
    return [
        _report_gate("EXACT_PLAN_CHECKPOINT", "PASS", "Exact caller-checkpointed plan bytes were read safely."),
        _report_gate("IMMUTABLE_GOAL_CONTRACT", "PASS", "The plan binds the immutable successor goal contract."),
        _report_gate(
            "FULL_COMPARATOR_CONJUNCTION",
            "DIGEST_DECLARATIONS_ONLY_IMPLEMENTATIONS_NOT_SUPPLIED_OR_VERIFIED",
            "All five mandatory families have structurally distinct digest declarations; implementation bytes, "
            "semantic conformance, and independence remain unverified.",
        ),
        _report_gate(
            "DOMAIN_CASE_AND_LAB_MINIMA",
            "DECLARED_GEOMETRY_ONLY_SEMANTICS_GENERATOR_INDEPENDENCE_AND_TIMING_NOT_VERIFIED",
            "At least three domains with ten cases and two case-linked laboratories each are declared; domain "
            "semantics, cohort admission, generator independence, and timing are unverified.",
        ),
        _report_gate(
            "ANALYSIS_AND_FAILURE_SEMANTICS",
            "STRUCTURAL_RULE_LITERALS_ONLY_IMPLEMENTATION_NOT_SUPPLIED_OR_VERIFIED",
            "Tenfold, ITT, censoring, abstention, false-exclusion, clustering, and global-multiplicity literals "
            "match the contract; implementation bytes and statistical correctness are unverified.",
        ),
        _report_gate(
            "OUTCOME_AND_RESULT_CHANNEL_ABSENCE",
            "PASS",
            "The closed plan accepts no designated outcome, result, reveal, winner, or score field.",
        ),
        _report_gate(
            "PROSPECTIVE_BLIND_PRIMARY_CASE_PLAN",
            "PLAN_BOUND_NOT_VERIFIED",
            "Primary cases are declared prospective-blind and balanced hindsight controls calibration-only; "
            "timing is unverified.",
        ),
        _report_gate(
            "CALIBRATION_CONTROL_PLAN",
            "DIGEST_DECLARATIONS_ONLY_SEMANTICS_NOT_VERIFIED",
            "Positive, failed-translation, and ambiguous behavior criteria and fail-closed rules are declared; "
            "control artifacts, semantics, and results are unverified.",
        ),
        _report_gate(
            "PROVENANCE_PLAN",
            "DIGEST_DECLARATIONS_ONLY_ARTIFACT_BYTES_NOT_SUPPLIED_OR_VERIFIED",
            "Receipt, inventory, transformation, execution, analysis-lineage, and witness digests are declared; "
            "artifact bytes are not supplied or verified.",
        ),
        _report_gate(
            "PUBLIC_SYNTHETIC_DATA_AND_AUTHORITY_PLAN",
            "PLAN_BOUND_NOT_VERIFIED",
            "Public-aggregate/synthetic data and the fixed authority boundary are bound; external review is pending.",
        ),
        _report_gate(
            "OPEN_BUILD_PLAN",
            "PLAN_BOUND_NOT_VERIFIED",
            "A public Apache-2.0 reproducible-build plan is bound but publication is not authorized or verified.",
        ),
        _report_gate(
            "INTEGRITY_PROTOCOLS",
            "DIGEST_DECLARATIONS_ONLY_ARTIFACT_BYTES_NOT_SUPPLIED_OR_VERIFIED",
            "Every required gate has protocol and implementation digest declarations; artifact bytes and gate "
            "results are unverified.",
        ),
        _report_gate(
            "INDEPENDENT_REPRODUCTION",
            "DIGEST_DECLARATIONS_ONLY_PROTOCOL_NOT_SUPPLIED_OR_EXECUTED",
            "Independent clean-build and complete-conjunction holdout digests are declared; protocol bytes and "
            "execution are unverified.",
        ),
        _report_gate(
            "EARLY_CAREER_USABILITY",
            "DIGEST_DECLARATIONS_ONLY_PROTOCOL_NOT_SUPPLIED_OR_EXECUTED",
            "Non-contributor multi-organization usability digests are declared; protocol bytes and execution are "
            "unverified.",
        ),
        _report_gate(
            "SCIENTIFIC_CLAIM",
            "NO_CALL",
            "No outcome was accessed and no scientific or acceleration claim can be made.",
        ),
    ]


def _validate_goal_claim_plan_preflight_shape(
    value: Any,
    *,
    expected_plan_checkpoint_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate the closed report shape and self-hash without proving its plan projection."""

    report = require_exact_keys(value, set(REPORT_KEYS), "goal claim plan preflight")
    if (
        report["schema_version"] != PREFLIGHT_SCHEMA_VERSION
        or report["status"] != PREFLIGHT_STATUS
        or report["claim_state"] != "NO_CALL_PLAN_ONLY"
        or report["implementation_status"] != IMPLEMENTATION_STATUS
        or report["base_compiler_version"] != COMPILER_VERSION
        or report["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(report["boundary"]) != canonical_bytes(fixed_boundary())
        or report["goal_claim_contract_sha256"] != goal_claim_contract_sha256()
        or report["mandatory_comparator_families"] != list(MANDATORY_COMPARATOR_FAMILIES)
        or report["required_gate_ids"] != list(REQUIRED_GATE_IDS)
    ):
        raise CausalFrontierError("claim-plan preflight targets another contract")
    require_id(report["plan_id"], "preflight plan id")
    _bounded_positive_integer(report["plan_sequence"], "preflight plan sequence")
    _require_artifact_sha256(report["plan_checkpoint_sha256"], "preflight plan checkpoint")
    _require_artifact_sha256(report["plan_sha256"], "preflight plan semantic digest")
    if expected_plan_checkpoint_sha256 is not None:
        _require_artifact_sha256(expected_plan_checkpoint_sha256, "expected plan checkpoint")
        if report["plan_checkpoint_sha256"] != expected_plan_checkpoint_sha256:
            raise CausalFrontierError("claim-plan preflight binds another plan checkpoint")
    if (
        type(report["declared_domains_n"]) is not int
        or not MINIMUM_DOMAINS <= report["declared_domains_n"] <= MAXIMUM_DOMAINS
        or type(report["precommitted_decision_points_n"]) is not int
        or not MINIMUM_DECISION_POINTS <= report["precommitted_decision_points_n"] <= MAXIMUM_DECISION_POINTS
        or type(report["calibration_decision_points_n"]) is not int
        or report["calibration_decision_points_n"] != report["declared_domains_n"] * len(CONTROL_ROLES)
        or type(report["declared_laboratories_n"]) is not int
        or not MINIMUM_LABORATORIES <= report["declared_laboratories_n"] <= MAXIMUM_LABORATORIES
    ):
        raise CausalFrontierError("claim-plan preflight weakens benchmark minima")
    resource_map = report["primary_resource_estimands_by_domain"]
    if (
        not isinstance(resource_map, list)
        or len(resource_map) != report["declared_domains_n"]
        or any(not isinstance(item, dict) for item in resource_map)
    ):
        raise CausalFrontierError("claim-plan preflight resource map is invalid")
    previous_id = None
    for item in resource_map:
        mapping = require_exact_keys(item, {"domain_id", "primary_resource_estimand"}, "resource map")
        domain_id = require_id(mapping["domain_id"], "resource-map domain id")
        require_enum(mapping["primary_resource_estimand"], set(PRIMARY_RESOURCE_ESTIMANDS), "resource estimand")
        if previous_id is not None and domain_id <= previous_id:
            raise CausalFrontierError("resource map must be uniquely sorted")
        previous_id = domain_id
    fixed_false_fields = (
        "designated_scientific_data_input_accepted",
        "outcome_or_result_field_accepted",
        "scoring_performed",
        "scientific_scoring_ready",
        "scientific_claim_ready",
        "acceleration_verified",
        "independent_reproduction_verified",
        "early_career_usability_verified",
        "prospective_primary_cases_verified",
        "domain_semantic_validity_verified",
        "cohort_admission_verified",
        "generator_independence_verified",
        "control_semantic_validity_verified",
        "public_open_build_verified",
        "comparator_family_conformance_verified",
        "controller_independence_verified",
        "externally_registered",
        "comparators_executed",
        "endpoint_adjudicated",
        "privacy_certified",
        "provenance_verified",
        "real_resource_verified",
        "publication_claim_authorized",
        "temporal_leakage_gate_verified",
        "privacy_gate_verified",
        "authority_gate_verified",
        "rollback_gate_verified",
    )
    if any(report[field] is not False for field in fixed_false_fields):
        raise CausalFrontierError("claim-plan preflight overclaims verification or authority")
    expected_gates = _expected_preflight_gates()
    if canonical_bytes(report["gates"]) != canonical_bytes(expected_gates) or report["nonclaims"] != list(NONCLAIMS):
        raise CausalFrontierError("claim-plan preflight gate or nonclaim contract mismatch")
    _require_artifact_sha256(report["preflight_sha256"], "preflight semantic digest")
    core = {key: report[key] for key in REPORT_CORE_KEYS}
    expected_digest = sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    if report["preflight_sha256"] != expected_digest:
        raise CausalFrontierError("claim-plan preflight semantic digest mismatch")
    return report


def preflight_goal_claim_plan(path: Path, expected_plan_checkpoint_sha256: str) -> dict[str, Any]:
    """Bind a closed preregistration plan without accepting outcomes or scoring."""

    raw, plan_value = _read_checkpointed_plan(path, expected_plan_checkpoint_sha256)
    plan = validate_goal_claim_plan(plan_value)
    domains, primary_cases, calibration_cases, all_laboratories = _validate_domains(plan["domains"])
    second_raw, second_value = _read_checkpointed_plan(path, expected_plan_checkpoint_sha256)
    if raw != second_raw or canonical_bytes(plan_value) != canonical_bytes(second_value):
        raise CausalFrontierError("goal claim plan changed during preflight")
    gates = _expected_preflight_gates()
    core = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "status": PREFLIGHT_STATUS,
        "claim_state": "NO_CALL_PLAN_ONLY",
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "plan_id": plan["plan_id"],
        "plan_sequence": plan["sequence"],
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "goal_claim_contract_sha256": goal_claim_contract_sha256(),
        "mandatory_comparator_families": list(MANDATORY_COMPARATOR_FAMILIES),
        "declared_domains_n": len(domains),
        "precommitted_decision_points_n": len(primary_cases),
        "calibration_decision_points_n": len(calibration_cases),
        "declared_laboratories_n": len(all_laboratories),
        "primary_resource_estimands_by_domain": [
            {"domain_id": domain["domain_id"], "primary_resource_estimand": domain["primary_resource_estimand"]}
            for domain in domains
        ],
        "required_gate_ids": list(REQUIRED_GATE_IDS),
        "designated_scientific_data_input_accepted": False,
        "outcome_or_result_field_accepted": False,
        "scoring_performed": False,
        "scientific_scoring_ready": False,
        "scientific_claim_ready": False,
        "acceleration_verified": False,
        "independent_reproduction_verified": False,
        "early_career_usability_verified": False,
        "prospective_primary_cases_verified": False,
        "domain_semantic_validity_verified": False,
        "cohort_admission_verified": False,
        "generator_independence_verified": False,
        "control_semantic_validity_verified": False,
        "public_open_build_verified": False,
        "comparator_family_conformance_verified": False,
        "controller_independence_verified": False,
        "externally_registered": False,
        "comparators_executed": False,
        "endpoint_adjudicated": False,
        "privacy_certified": False,
        "provenance_verified": False,
        "real_resource_verified": False,
        "publication_claim_authorized": False,
        "temporal_leakage_gate_verified": False,
        "privacy_gate_verified": False,
        "authority_gate_verified": False,
        "rollback_gate_verified": False,
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    report = dict(core)
    report["preflight_sha256"] = sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    return _validate_goal_claim_plan_preflight_shape(
        report,
        expected_plan_checkpoint_sha256=expected_plan_checkpoint_sha256,
    )


def verify_goal_claim_plan_preflight(
    value: Any,
    path: Path,
    expected_plan_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Rebuild a preflight from its exact plan and reject any forged projection."""

    report = _validate_goal_claim_plan_preflight_shape(
        value,
        expected_plan_checkpoint_sha256=expected_plan_checkpoint_sha256,
    )
    expected = preflight_goal_claim_plan(path, expected_plan_checkpoint_sha256)
    if canonical_bytes(report) != canonical_bytes(expected):
        raise CausalFrontierError("claim-plan preflight differs from exact deterministic replay")
    return report
