"""Complete-matrix orchestration for the six-case synthetic rehearsal.

This successor closes one narrow but important validity hole: callers cannot
choose a favorable case, encoder lane, or policy after opening the synthetic
oracle.  It deliberately does not turn the v1 reference proxies into scientific
comparators or emit a winner, ranking, acceleration ratio, or scientific score.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import blind, challenge
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    require_exact_keys,
    require_id,
    require_sha256,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

PLAN_SCHEMA_VERSION = "causalfrontier.synthetic-horse-race-plan.v1"
REPORT_SCHEMA_VERSION = "causalfrontier.synthetic-horse-race-report.v1"
VERIFICATION_SCHEMA_VERSION = "causalfrontier.synthetic-horse-race-report-verification.v1"
PLAN_STATUS = "SIX_CASE_COMPLETE_MATRIX_HASH_BOUND_SCIENTIFIC_SCORING_DISABLED"
REPORT_STATUS = "SIX_CASE_COMPLETE_MATRIX_REPLAYED_DESCRIPTIVE_ONLY_SCIENTIFIC_SCORING_DISABLED"
INVALID_REPORT_STATUS = "SIX_CASE_MATRIX_INTEGRITY_INVALID_SCIENTIFIC_SCORING_DISABLED"
VALID_VERIFICATION_STATUS = "VALID_STRUCTURAL_REPORT_SCIENTIFIC_SCORING_DISABLED"
EXECUTION_SEMANTICS = "INDEPENDENT_REPLAY_FROM_SHARED_BASELINE_NO_CROSS_LANE_AGGREGATION"
EXPECTED_CASES = 6
EXPECTED_CONTROLS = 3
EXPECTED_DOMAINS = 3
EXPECTED_LANES_PER_CASE = 2
SYNTHETIC_PRIMARY_RESOURCE_DIMENSION = "calendar_minutes"
POLICY_EXECUTION_ORDER_CONTRACT = (
    {
        "policy_id": "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
        "rule": "LOCKED_ZERO_OR_ONE_ACTION_SELECTION",
    },
    {
        "policy_id": "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
        "rule": "LOCKED_TERMINAL_WITHOUT_ACTION",
    },
    {
        "policy_id": "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
        "rule": "LOCKED_SET_EXECUTED_IN_OPENED_CANONICAL_FROZEN_ACTION_ID_ORDER",
    },
)

NONCLAIMS = (
    "This is a synthetic descriptive protocol rehearsal, not a scientific horse race.",
    "The complete matrix prevents case, lane, and policy cherry-picking but does not prove prereveal custody.",
    "The entrant view is CausalFrontier-derived and is not a policy-neutral common input tier.",
    "Candidate compilation, preprocessing, retries, and tool overhead are not measured.",
    "Uniform action enumeration is deterministic and is not an empirical random baseline.",
    "No independently committed terminal-correctness oracle is available.",
    "The static depth-one oracle cannot evaluate adaptive or sequential policies.",
    "Synthetic tariffs are not measured time, cost, compute, or labor.",
    "Control and domain labels are declared synthetic fixtures, not independently validated phenomena.",
    "Encoder organizations and independence are self-declared and not independently verified.",
    "Expert, retrieval, graph, current-workflow, agent, OFAT, Bayesian, EIG, and oracle baselines are unexecuted.",
    "Encoder lanes remain separate sensitivity strata and are never pooled or winner-selected.",
    "No winner, ranking, composite score, calibration score, acceleration ratio, or 10x claim is produced.",
    "No patient, clinical, human-decision, biological, material, or wet-lab authority is granted.",
)

VERIFICATION_NONCLAIMS = (
    "This verifies exact report bytes and internal contract linkage, not scientific truth or execution custody.",
    "Replaying a report digest does not establish independent timestamping, authorship, resources, or correctness.",
    "Scientific scoring, ranking, calibration, acceleration, biological, clinical, and health claims remain disabled.",
)


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def _planning_gates() -> list[dict[str, str]]:
    return sorted(
        [
            _gate("authority", "PASS", "IMMUTABLE_ALPHA_BOUNDARY_READ_ONLY_SYNTHETIC_ONLY"),
            _gate("branch_totality", "PASS", "EVERY_ENCODING_PASSED_FROZEN_CASE_BRANCH_VALIDATION"),
            _gate("balanced_six_case_cohort", "PASS", "TWO_CASES_PER_CONTROL_AND_DOMAIN_UNIQUE_CELLS"),
            _gate("complete_matrix", "PASS", "EVERY_CASE_LANE_AND_LOCKED_REFERENCE_POLICY_HASH_BOUND"),
            _gate("execution_order", "PASS", "POLICY_SPECIFIC_EXECUTION_ORDER_RULES_HASH_BOUND"),
            _gate("encoder_pooling", "PASS", "TWO_LANES_RETAINED_AS_SEPARATE_SENSITIVITY_STRATA"),
            _gate("abstention", "PASS", "ABSTAIN_AND_NO_CALL_RETAINED_WITHOUT_IMPUTATION"),
            _gate("control_validity", "NO_CALL", "CONTROL_LABELS_DECLARED_NOT_INDEPENDENTLY_ADJUDICATED"),
            _gate("encoder_independence", "NO_CALL", "SELF_DECLARED_NOT_INDEPENDENTLY_VERIFIED"),
            _gate("encoding_agreement", "NO_CALL", "LABEL_INVARIANT_AGREEMENT_SCORER_NOT_IMPLEMENTED"),
            _gate(
                "synthetic_case_independence",
                "NO_CALL",
                "DOMAIN_LABELS_DO_NOT_PROVE_DISTINCT_GENERATORS_OR_INDEPENDENT_CASES",
            ),
            _gate(
                "replicate_independence",
                "NO_CALL",
                "COMMITTED_REPLICATE_COORDINATES_EXIST_BUT_INDEPENDENCE_IS_UNVERIFIED",
            ),
            _gate("policy_neutral_input", "NO_CALL", "VIEW_CONTAINS_CAUSALFRONTIER_DERIVED_ACTION_FILTERS"),
            _gate("fully_loaded_resources", "NO_CALL", "PREPROCESSING_AND_TOOL_OVERHEAD_UNMETERED"),
            _gate("true_random_baseline", "NO_CALL", "DETERMINISTIC_ENUMERATION_IS_NOT_RANDOM"),
            _gate("terminal_truth", "NO_CALL", "INDEPENDENT_CORRECTNESS_ORACLE_ABSENT"),
            _gate("adaptive_comparators", "NO_CALL", "HISTORY_KEYED_TRANSITION_ORACLE_ABSENT"),
            _gate("required_comparators", "NO_CALL", "FIFTEEN_REQUIRED_SCIENTIFIC_FAMILIES_UNEXECUTED"),
            _gate("calibration", "NO_CALL", "CONFIDENCE_AND_CORRECTNESS_CONTRACTS_ABSENT"),
            _gate("privacy", "NO_CALL", "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"),
            _gate("temporal_leakage", "NO_CALL", "PREREVEAL_CUSTODY_NOT_INDEPENDENTLY_ATTESTED"),
            _gate("rollback", "NO_CALL", "LOCAL_CHECKPOINTS_NOT_TWO_INDEPENDENT_APPEND_ONLY_WITNESSES"),
            _gate("scientific_scoring", "NO_CALL", "SCORING_WINNER_RANKING_AND_ACCELERATION_DISABLED"),
        ],
        key=lambda item: item["id"],
    )


def _bounded_count(value: Any, field: str, *, minimum: int = 0, maximum: int = 10_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded integer" % field)
    return value


def _validate_balance(manifest: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASES:
        raise CausalFrontierError("synthetic horse-race cohort must contain exactly six cases")
    controls: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    pairs: set[tuple[str, str]] = set()
    controls_by_domain: dict[str, set[str]] = {}
    domains_by_control: dict[str, set[str]] = {}
    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise CausalFrontierError("synthetic horse-race case metadata must be objects")
        case_id = require_id(case.get("id"), "horse-race case[%d] id" % index)
        control = case.get("control_class")
        domain = require_id(case.get("domain"), "horse-race case[%d] domain" % index)
        if control not in challenge.CONTROL_CLASSES:
            raise CausalFrontierError("synthetic horse-race control is unregistered")
        if case_id in case_ids or (domain, control) in pairs:
            raise CausalFrontierError("synthetic horse-race cases or domain-control cells are duplicated")
        case_ids.add(case_id)
        pairs.add((domain, control))
        controls[control] += 1
        domains[domain] += 1
        controls_by_domain.setdefault(domain, set()).add(control)
        domains_by_control.setdefault(control, set()).add(domain)
    if set(controls) != challenge.CONTROL_CLASSES or any(value != 2 for value in controls.values()):
        raise CausalFrontierError("synthetic horse-race requires exactly two cases per control class")
    if len(domains) != EXPECTED_DOMAINS or any(value != 2 for value in domains.values()):
        raise CausalFrontierError("synthetic horse-race requires exactly three domains with two cases each")
    if any(len(value) != 2 for value in controls_by_domain.values()) or any(
        len(value) != 2 for value in domains_by_control.values()
    ):
        raise CausalFrontierError("synthetic horse-race controls and domains are confounded")
    primary_resources = [
        {
            "domain": domain,
            "primary_resource_dimension": SYNTHETIC_PRIMARY_RESOURCE_DIMENSION,
            "declaration_state": "SYNTHETIC_HARNESS_DEFAULT_NOT_EMPIRICALLY_VALIDATED",
        }
        for domain in sorted(domains)
    ]
    return sorted(case_ids), primary_resources


def _bind_inputs(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    selection_path: Path,
    expected_selection_checkpoint_sha256: str,
    selection_envelope_path: Path,
    expected_selection_envelope_checkpoint_sha256: str,
    commitment_preflight_path: Path,
    expected_commitment_preflight_checkpoint_sha256: str,
    expected_opening_sha256: str,
) -> dict[str, Any]:
    require_sha256(expected_opening_sha256, "horse-race oracle opening checkpoint")
    preflight, case_lanes = challenge.load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    race = blind._load_race_spec(race_spec_path, expected_race_spec_sha256, preflight, case_lanes)
    _view_raw, view_value = blind._read_checkpointed_json(
        view_path, expected_view_checkpoint_sha256, "horse-race sanitized entrant view"
    )
    view = blind._validate_view(view_value)
    _selection_raw, selection_value = blind._read_checkpointed_json(
        selection_path, expected_selection_checkpoint_sha256, "horse-race blind selection lock"
    )
    selection = blind._validate_selection_lock(selection_value)
    replayed_selection = blind.lock_blind_reference_selections(view_path, expected_view_checkpoint_sha256)
    if canonical_bytes(selection) != canonical_bytes(replayed_selection):
        raise CausalFrontierError("horse-race selection lock does not replay from the entrant view")
    _envelope_raw, envelope_value = blind._read_checkpointed_json(
        selection_envelope_path,
        expected_selection_envelope_checkpoint_sha256,
        "horse-race selection envelope",
    )
    envelope = blind._validate_selection_envelope(envelope_value)
    _commitment_raw, commitment_value = blind._read_checkpointed_json(
        commitment_preflight_path,
        expected_commitment_preflight_checkpoint_sha256,
        "horse-race commitment preflight",
    )
    commitment = blind._validate_commitment_preflight(commitment_value)
    _manifest_raw, manifest = blind._read_checkpointed_json(
        root / challenge.MANIFEST, expected_manifest_sha256, "horse-race challenge manifest"
    )
    expected_actions_n = sum(len(case["action_batch_tariffs"]) for case in race["cases"])
    expected_observations_n = expected_actions_n * race["required_replicates"]
    if (
        preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or race["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or preflight["challenge_sequence"] != expected_sequence
        or view["challenge_sequence"] != expected_sequence
        or commitment["challenge_sequence"] != expected_sequence
        or commitment["challenge_registration_sha256"] != preflight["challenge_registration_sha256"]
        or commitment["race_spec_sha256"] != expected_race_spec_sha256
        or commitment["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256
        or commitment["entrant_view_sha256"] != view["view_sha256"]
        or commitment["policy_contract_sha256"] != view["policy_contract_sha256"]
        or commitment["required_replicates"] != race["required_replicates"]
        or view["required_replicates"] != race["required_replicates"]
        or commitment["actions_n"] != expected_actions_n
        or commitment["observations_n"] != expected_observations_n
        or commitment["reveal_commitment_sha256"] != preflight["reveal_commitment_sha256"]
        or commitment["oracle_opening_sha256"] != expected_opening_sha256
        or selection["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256
        or selection["entrant_view_sha256"] != view["view_sha256"]
        or envelope["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256
        or envelope["entrant_view_sha256"] != view["view_sha256"]
        or envelope["selection_checkpoint_sha256"] != expected_selection_checkpoint_sha256
        or envelope["selection_lock_sha256"] != selection["selection_lock_sha256"]
        or envelope["commitment_preflight_checkpoint_sha256"] != expected_commitment_preflight_checkpoint_sha256
    ):
        raise CausalFrontierError("horse-race artifacts target different registrations or checkpoints")
    if challenge.challenge_registration_sha256(manifest) != preflight["challenge_registration_sha256"]:
        raise CausalFrontierError("horse-race challenge registration digest changed")
    if len(case_lanes) != EXPECTED_CASES or commitment["cases_n"] != EXPECTED_CASES:
        raise CausalFrontierError("horse-race case counts differ across bound artifacts")
    return {
        "preflight": preflight,
        "case_lanes": case_lanes,
        "race": race,
        "view": view,
        "selection": selection,
        "envelope": envelope,
        "commitment": commitment,
        "manifest": manifest,
    }


def _complete_matrix(view: dict[str, Any], selection: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    policy_ids = sorted(policy["id"] for policy in view["policy_contract"]["policies"])
    if not policy_ids:
        raise CausalFrontierError("horse-race policy contract is empty")
    expected_coordinates: set[tuple[str, str]] = set()
    for case in view["cases"]:
        if len(case["lanes"]) != EXPECTED_LANES_PER_CASE:
            raise CausalFrontierError("every horse-race case must expose exactly two encoder lanes")
        for lane in case["lanes"]:
            coordinate = (case["entrant_case_id"], lane["entrant_lane_id"])
            if coordinate in expected_coordinates:
                raise CausalFrontierError("horse-race entrant lane coordinate is duplicated")
            expected_coordinates.add(coordinate)
    if len(expected_coordinates) != EXPECTED_CASES * EXPECTED_LANES_PER_CASE:
        raise CausalFrontierError("horse-race entrant matrix has the wrong lane count")
    locked: dict[tuple[str, str], dict[str, str]] = {}
    for lane in selection["reference_lanes"]:
        coordinate = (lane["entrant_case_id"], lane["entrant_lane_id"])
        if coordinate in locked:
            raise CausalFrontierError("horse-race selection lane is duplicated")
        traces = lane["reference_policy_traces"]
        trace_map = {trace["policy_id"]: trace["trace_sha256"] for trace in traces}
        if len(trace_map) != len(traces) or sorted(trace_map) != policy_ids:
            raise CausalFrontierError("horse-race lane does not lock every policy exactly once")
        for digest in trace_map.values():
            require_sha256(digest, "horse-race policy trace digest")
        locked[coordinate] = trace_map
    if set(locked) != expected_coordinates:
        raise CausalFrontierError("horse-race selection lanes are incomplete or surplus")
    cells = []
    for coordinate in sorted(expected_coordinates):
        for policy_id in policy_ids:
            cell_core = {
                "entrant_case_id": coordinate[0],
                "entrant_lane_id": coordinate[1],
                "policy_id": policy_id,
                "policy_trace_sha256": locked[coordinate][policy_id],
            }
            cells.append(
                {
                    "matrix_cell_id": "matrix-cell:%s" % sha256_bytes(canonical_bytes(cell_core)),
                    **cell_core,
                }
            )
    return policy_ids, cells


def _policy_execution_order_contract(policy_ids: list[str]) -> list[dict[str, str]]:
    contract = [dict(item) for item in POLICY_EXECUTION_ORDER_CONTRACT]
    if sorted(item["policy_id"] for item in contract) != policy_ids:
        raise CausalFrontierError("horse-race execution-order contract differs from the policy inventory")
    return sorted(contract, key=lambda item: item["policy_id"])


def _report_gates(plan: dict[str, Any], integrity_valid: bool, matrix_complete: bool) -> list[dict[str, str]]:
    return sorted(
        [
            *plan["gates"],
            _gate(
                "complete_matrix_execution",
                "PASS" if matrix_complete else "INVALID",
                "EVERY_HASH_BOUND_CELL_REPLAYED_ONCE" if matrix_complete else "MATRIX_INCOMPLETE_OR_SURPLUS",
            ),
            _gate(
                "episode_integrity",
                "PASS" if integrity_valid else "INVALID",
                "ALL_EPISODE_AND_CHALLENGE_BYTE_CHECKS_PASSED"
                if integrity_valid
                else "ONE_OR_MORE_EPISODE_OR_CHALLENGE_BYTE_CHECKS_FAILED",
            ),
        ],
        key=lambda item: item["id"],
    )


def prepare_synthetic_horse_race_plan(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    selection_path: Path,
    expected_selection_checkpoint_sha256: str,
    selection_envelope_path: Path,
    expected_selection_envelope_checkpoint_sha256: str,
    commitment_preflight_path: Path,
    expected_commitment_preflight_checkpoint_sha256: str,
    expected_opening_sha256: str,
) -> dict[str, Any]:
    """Freeze the complete six-case matrix without reading the oracle opening."""

    bound = _bind_inputs(
        root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        view_path,
        expected_view_checkpoint_sha256,
        selection_path,
        expected_selection_checkpoint_sha256,
        selection_envelope_path,
        expected_selection_envelope_checkpoint_sha256,
        commitment_preflight_path,
        expected_commitment_preflight_checkpoint_sha256,
        expected_opening_sha256,
    )
    _case_ids, primary_resources = _validate_balance(bound["manifest"])
    policy_ids, matrix = _complete_matrix(bound["view"], bound["selection"])
    core = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "status": PLAN_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_REHEARSAL",
        "audience": "STEWARD_ONLY_NOT_AN_ENTRANT_VIEW",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "challenge_manifest_sha256": expected_manifest_sha256,
        "challenge_registration_sha256": bound["preflight"]["challenge_registration_sha256"],
        "challenge_sequence": expected_sequence,
        "race_spec_sha256": expected_race_spec_sha256,
        "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
        "entrant_view_sha256": bound["view"]["view_sha256"],
        "selection_checkpoint_sha256": expected_selection_checkpoint_sha256,
        "selection_lock_sha256": bound["selection"]["selection_lock_sha256"],
        "selection_envelope_checkpoint_sha256": expected_selection_envelope_checkpoint_sha256,
        "selection_envelope_sha256": bound["envelope"]["selection_envelope_sha256"],
        "commitment_preflight_checkpoint_sha256": expected_commitment_preflight_checkpoint_sha256,
        "commitment_preflight_sha256": bound["commitment"]["commitment_preflight_sha256"],
        "oracle_opening_checkpoint_sha256": expected_opening_sha256,
        "oracle_opening_read_during_planning": False,
        "cases_n": EXPECTED_CASES,
        "controls_n": EXPECTED_CONTROLS,
        "domains_n": EXPECTED_DOMAINS,
        "lanes_per_case": EXPECTED_LANES_PER_CASE,
        "policies_n": len(policy_ids),
        "policy_ids": policy_ids,
        "policy_execution_order_contract": _policy_execution_order_contract(policy_ids),
        "policy_seed_schedule": [],
        "true_random_policy_registered": False,
        "primary_resource_by_domain": primary_resources,
        "resource_aggregation_semantics": EXECUTION_SEMANTICS,
        "matrix_cells_n": len(matrix),
        "matrix_cells": matrix,
        "scientific_baseline_families_executed": [],
        "required_scientific_baseline_families_unexecuted": sorted(challenge.BASELINE_FAMILIES),
        "winner_ranking_enabled": False,
        "acceleration_ratio_enabled": False,
        "scientific_scoring_ready": False,
        "gates": _planning_gates(),
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "plan_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_plan(value: Any) -> dict[str, Any]:
    keys = {
        "schema_version",
        "status",
        "implementation_status",
        "audience",
        "base_compiler_version",
        "fixed_parameter",
        "boundary",
        "challenge_manifest_sha256",
        "challenge_registration_sha256",
        "challenge_sequence",
        "race_spec_sha256",
        "entrant_view_checkpoint_sha256",
        "entrant_view_sha256",
        "selection_checkpoint_sha256",
        "selection_lock_sha256",
        "selection_envelope_checkpoint_sha256",
        "selection_envelope_sha256",
        "commitment_preflight_checkpoint_sha256",
        "commitment_preflight_sha256",
        "oracle_opening_checkpoint_sha256",
        "oracle_opening_read_during_planning",
        "cases_n",
        "controls_n",
        "domains_n",
        "lanes_per_case",
        "policies_n",
        "policy_ids",
        "policy_execution_order_contract",
        "policy_seed_schedule",
        "true_random_policy_registered",
        "primary_resource_by_domain",
        "resource_aggregation_semantics",
        "matrix_cells_n",
        "matrix_cells",
        "scientific_baseline_families_executed",
        "required_scientific_baseline_families_unexecuted",
        "winner_ranking_enabled",
        "acceleration_ratio_enabled",
        "scientific_scoring_ready",
        "gates",
        "nonclaims",
        "plan_sha256",
    }
    plan = require_exact_keys(value, keys, "synthetic horse-race plan")
    for field in (
        "challenge_manifest_sha256",
        "challenge_registration_sha256",
        "race_spec_sha256",
        "entrant_view_checkpoint_sha256",
        "entrant_view_sha256",
        "selection_checkpoint_sha256",
        "selection_lock_sha256",
        "selection_envelope_checkpoint_sha256",
        "selection_envelope_sha256",
        "commitment_preflight_checkpoint_sha256",
        "commitment_preflight_sha256",
        "oracle_opening_checkpoint_sha256",
        "plan_sha256",
    ):
        require_sha256(plan[field], "horse-race plan %s" % field)
    if (
        plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
        or plan["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_REHEARSAL"
        or plan["audience"] != "STEWARD_ONLY_NOT_AN_ENTRANT_VIEW"
        or plan["base_compiler_version"] != COMPILER_VERSION
        or plan["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(plan["boundary"]) != BOUNDARY_CANONICAL
        or plan["oracle_opening_read_during_planning"] is not False
        or plan["cases_n"] != EXPECTED_CASES
        or plan["controls_n"] != EXPECTED_CONTROLS
        or plan["domains_n"] != EXPECTED_DOMAINS
        or plan["lanes_per_case"] != EXPECTED_LANES_PER_CASE
        or plan["policy_seed_schedule"] != []
        or plan["true_random_policy_registered"] is not False
        or plan["resource_aggregation_semantics"] != EXECUTION_SEMANTICS
        or plan["scientific_baseline_families_executed"] != []
        or plan["required_scientific_baseline_families_unexecuted"] != sorted(challenge.BASELINE_FAMILIES)
        or plan["winner_ranking_enabled"] is not False
        or plan["acceleration_ratio_enabled"] is not False
        or plan["scientific_scoring_ready"] is not False
        or plan["gates"] != _planning_gates()
        or plan["nonclaims"] != list(NONCLAIMS)
    ):
        raise CausalFrontierError("synthetic horse-race plan overclaims or targets another contract")
    _bounded_count(plan["challenge_sequence"], "horse-race challenge sequence", minimum=1)
    policies_n = _bounded_count(plan["policies_n"], "horse-race policy count", minimum=1)
    matrix_n = _bounded_count(plan["matrix_cells_n"], "horse-race matrix count", minimum=1)
    if not isinstance(plan["policy_ids"], list):
        raise CausalFrontierError("synthetic horse-race policy inventory is invalid")
    validated_policy_ids = [require_id(item, "horse-race policy id") for item in plan["policy_ids"]]
    if (
        len(validated_policy_ids) != policies_n
        or len(set(validated_policy_ids)) != policies_n
        or validated_policy_ids != sorted(validated_policy_ids)
    ):
        raise CausalFrontierError("synthetic horse-race policy inventory is invalid")
    if plan["policy_execution_order_contract"] != _policy_execution_order_contract(validated_policy_ids):
        raise CausalFrontierError("synthetic horse-race execution-order contract is invalid")
    resources = plan["primary_resource_by_domain"]
    if not isinstance(resources, list) or len(resources) != EXPECTED_DOMAINS:
        raise CausalFrontierError("synthetic horse-race primary resource declarations are invalid")
    resource_domains: set[str] = set()
    for declaration in resources:
        declaration = require_exact_keys(
            declaration,
            {"domain", "primary_resource_dimension", "declaration_state"},
            "horse-race primary resource declaration",
        )
        domain = require_id(declaration["domain"], "horse-race primary resource domain")
        if (
            domain in resource_domains
            or declaration["primary_resource_dimension"] != SYNTHETIC_PRIMARY_RESOURCE_DIMENSION
            or declaration["declaration_state"] != "SYNTHETIC_HARNESS_DEFAULT_NOT_EMPIRICALLY_VALIDATED"
        ):
            raise CausalFrontierError("synthetic horse-race primary resource declarations are invalid")
        resource_domains.add(domain)
    if resources != sorted(resources, key=lambda item: item["domain"]):
        raise CausalFrontierError("synthetic horse-race primary resource declaration order is not canonical")
    if matrix_n != EXPECTED_CASES * EXPECTED_LANES_PER_CASE * policies_n:
        raise CausalFrontierError("synthetic horse-race matrix is not total")
    if not isinstance(plan["matrix_cells"], list) or len(plan["matrix_cells"]) != matrix_n:
        raise CausalFrontierError("synthetic horse-race matrix inventory differs")
    cell_ids: set[str] = set()
    coordinates: set[tuple[str, str, str]] = set()
    policies_by_lane: dict[tuple[str, str], set[str]] = {}
    lanes_by_case: dict[str, set[str]] = {}
    for cell in plan["matrix_cells"]:
        cell = require_exact_keys(
            cell,
            {"matrix_cell_id", "entrant_case_id", "entrant_lane_id", "policy_id", "policy_trace_sha256"},
            "horse-race matrix cell",
        )
        cell_id = require_id(cell["matrix_cell_id"], "horse-race matrix cell id")
        require_sha256(cell["policy_trace_sha256"], "horse-race matrix policy trace")
        case_id = blind._require_opaque_alias(cell["entrant_case_id"], "case", "horse-race matrix case")
        lane_id = blind._require_opaque_alias(cell["entrant_lane_id"], "lane", "horse-race matrix lane")
        policy_id = require_id(cell["policy_id"], "horse-race matrix policy")
        if policy_id not in validated_policy_ids:
            raise CausalFrontierError("synthetic horse-race matrix references an unknown policy")
        coordinate = (case_id, lane_id, policy_id)
        if cell_id in cell_ids or coordinate in coordinates:
            raise CausalFrontierError("synthetic horse-race matrix contains duplicate cells")
        expected_id = "matrix-cell:%s" % sha256_bytes(
            canonical_bytes(
                {
                    "entrant_case_id": cell["entrant_case_id"],
                    "entrant_lane_id": cell["entrant_lane_id"],
                    "policy_id": cell["policy_id"],
                    "policy_trace_sha256": cell["policy_trace_sha256"],
                }
            )
        )
        if cell_id != expected_id:
            raise CausalFrontierError("synthetic horse-race matrix cell digest differs")
        cell_ids.add(cell_id)
        coordinates.add(coordinate)
        policies_by_lane.setdefault((case_id, lane_id), set()).add(policy_id)
        lanes_by_case.setdefault(case_id, set()).add(lane_id)
    if (
        len(lanes_by_case) != EXPECTED_CASES
        or any(len(lanes) != EXPECTED_LANES_PER_CASE for lanes in lanes_by_case.values())
        or len(policies_by_lane) != EXPECTED_CASES * EXPECTED_LANES_PER_CASE
        or any(policies != set(validated_policy_ids) for policies in policies_by_lane.values())
    ):
        raise CausalFrontierError("synthetic horse-race matrix is not a complete Cartesian product")
    if plan["matrix_cells"] != sorted(
        plan["matrix_cells"], key=lambda item: (item["entrant_case_id"], item["entrant_lane_id"], item["policy_id"])
    ):
        raise CausalFrontierError("synthetic horse-race matrix order is not canonical")
    core = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if sha256_bytes(canonical_bytes(core)) != plan["plan_sha256"]:
        raise CausalFrontierError("synthetic horse-race plan semantic digest mismatch")
    return plan


def _validate_policy_trace(value: Any, cell: dict[str, Any]) -> dict[str, Any]:
    trace = require_exact_keys(
        value,
        {
            "policy_id",
            "status",
            "eligible_action_ids",
            "selections",
            "reason_codes",
            "trace_sha256",
        },
        "horse-race locked policy trace",
    )
    if trace["policy_id"] != cell["policy_id"] or trace["trace_sha256"] != cell["policy_trace_sha256"]:
        raise CausalFrontierError("horse-race execution trace targets another matrix cell")
    require_id(trace["policy_id"], "horse-race trace policy")
    require_id(trace["status"], "horse-race trace status")
    require_sha256(trace["trace_sha256"], "horse-race trace digest")
    eligible = trace["eligible_action_ids"]
    if not isinstance(eligible, list):
        raise CausalFrontierError("horse-race eligible action inventory is invalid")
    validated_eligible = [
        blind._require_opaque_alias(item, "action", "horse-race eligible action") for item in eligible
    ]
    if len(validated_eligible) != len(set(validated_eligible)) or validated_eligible != sorted(validated_eligible):
        raise CausalFrontierError("horse-race eligible action inventory is invalid")
    selections = trace["selections"]
    if not isinstance(selections, list) or not selections:
        raise CausalFrontierError("horse-race policy selection inventory is invalid")
    for selection in selections:
        selection = require_exact_keys(
            selection,
            {"action", "entrant_action_id", "enumeration_numerator", "enumeration_denominator"},
            "horse-race policy selection",
        )
        if selection["action"] not in {"SELECT", "ABSTAIN", "NO_CALL"}:
            raise CausalFrontierError("horse-race policy selection action is invalid")
        numerator = _bounded_count(selection["enumeration_numerator"], "horse-race selection numerator", minimum=1)
        denominator = _bounded_count(
            selection["enumeration_denominator"], "horse-race selection denominator", minimum=1
        )
        if numerator > denominator:
            raise CausalFrontierError("horse-race policy selection fraction is invalid")
        if selection["action"] == "SELECT":
            action_id = blind._require_opaque_alias(
                selection["entrant_action_id"], "action", "horse-race selected action"
            )
            if action_id not in validated_eligible:
                raise CausalFrontierError("horse-race policy selected an ineligible action")
        elif selection["entrant_action_id"] is not None:
            raise CausalFrontierError("horse-race terminal policy selection names an action")
    reasons = trace["reason_codes"]
    if not isinstance(reasons, list) or not reasons:
        raise CausalFrontierError("horse-race policy trace reasons are invalid")
    validated_reasons = [require_id(item, "horse-race policy reason") for item in reasons]
    if validated_reasons != sorted(validated_reasons) or len(validated_reasons) != len(set(validated_reasons)):
        raise CausalFrontierError("horse-race policy trace reasons are invalid")
    selected = [item for item in selections if item["action"] == "SELECT"]
    terminal = [item for item in selections if item["action"] != "SELECT"]
    if cell["policy_id"] == "CAUSALFRONTIER_UNIQUE_MINIMAX_V1":
        valid_selected = (
            trace["status"] == "SELECTED"
            and len(selected) == 1
            and not terminal
            and selected[0]["enumeration_numerator"] == 1
            and selected[0]["enumeration_denominator"] == 1
            and validated_reasons == ["UNIQUE_CO_MINIMAX_ACTION"]
        )
        valid_no_call = (
            trace["status"] == "NO_CALL"
            and not selected
            and len(terminal) == 1
            and terminal[0]["action"] == "NO_CALL"
            and terminal[0]["enumeration_numerator"] == 1
            and terminal[0]["enumeration_denominator"] == 1
            and validated_reasons
            in (
                ["CO_MINIMAX_TIE_NOT_BROKEN_BY_OPAQUE_DISPLAY_ID"],
                ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"],
            )
        )
        if not (valid_selected or valid_no_call):
            raise CausalFrontierError("CausalFrontier policy trace changes its locked semantics")
    elif cell["policy_id"] == "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1":
        if not (
            trace["status"] == "ABSTAINED"
            and not selected
            and len(terminal) == 1
            and terminal[0]["action"] == "ABSTAIN"
            and terminal[0]["enumeration_numerator"] == 1
            and terminal[0]["enumeration_denominator"] == 1
            and validated_reasons == ["POLICY_ALWAYS_ABSTAINS"]
        ):
            raise CausalFrontierError("abstention policy trace changes its locked semantics")
    elif cell["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1":
        if validated_eligible:
            denominator = len(validated_eligible)
            if not (
                trace["status"] == "ENUMERATED"
                and not terminal
                and [item["entrant_action_id"] for item in selected] == validated_eligible
                and all(
                    item["enumeration_numerator"] == 1 and item["enumeration_denominator"] == denominator
                    for item in selected
                )
                and validated_reasons == ["ALL_ELIGIBLE_ACTIONS_ENUMERATED_ONCE_WITHOUT_REPLACEMENT"]
            ):
                raise CausalFrontierError("uniform policy trace changes its locked enumeration")
        elif not (
            trace["status"] == "NO_CALL"
            and not selected
            and len(terminal) == 1
            and terminal[0]["action"] == "NO_CALL"
            and terminal[0]["enumeration_numerator"] == 1
            and terminal[0]["enumeration_denominator"] == 1
            and validated_reasons == ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"]
        ):
            raise CausalFrontierError("empty uniform policy trace changes its locked semantics")
    else:
        raise CausalFrontierError("horse-race policy trace names an unsupported policy")
    core = {key: item for key, item in trace.items() if key != "trace_sha256"}
    if sha256_bytes(canonical_bytes(core)) != trace["trace_sha256"]:
        raise CausalFrontierError("horse-race policy trace semantic digest mismatch")
    return trace


def _validate_action_report(value: Any) -> dict[str, Any]:
    report = require_exact_keys(
        value,
        {
            "entrant_action_id",
            "experiment_id",
            "branch_plan_sha256",
            "classifier_sha256",
            "classifier_results",
            "adjudication",
            "action_report_sha256",
        },
        "horse-race action report",
    )
    blind._require_opaque_alias(report["entrant_action_id"], "action", "horse-race action report alias")
    require_id(report["experiment_id"], "horse-race action report experiment")
    for field in ("branch_plan_sha256", "classifier_sha256", "action_report_sha256"):
        require_sha256(report[field], "horse-race action report %s" % field)
    results = report["classifier_results"]
    if not isinstance(results, list) or not results:
        raise CausalFrontierError("horse-race classifier result inventory is invalid")
    replicate_indices: set[int] = set()
    for result in results:
        result = require_exact_keys(
            result,
            {
                "schema_version",
                "replicate_index",
                "classifier_sha256",
                "adapter_contract_sha256",
                "branch_token",
                "outcome_id",
                "diagnostic_code",
                "group_keyed_metrics_omitted",
                "direct_observation_identifier_field_omitted",
                "direct_observation_digest_field_omitted",
                "redacted_result_sha256",
            },
            "horse-race redacted classifier result",
        )
        replicate_index = _bounded_count(
            result["replicate_index"], "horse-race classifier replicate", minimum=1, maximum=blind.MAX_REPLICATES
        )
        if replicate_index in replicate_indices:
            raise CausalFrontierError("horse-race classifier replicate is duplicated")
        replicate_indices.add(replicate_index)
        if (
            result["schema_version"] != "causalfrontier.redacted-observation-classifier-result.v1"
            or result["classifier_sha256"] != report["classifier_sha256"]
            or result["group_keyed_metrics_omitted"] is not True
            or result["direct_observation_identifier_field_omitted"] is not True
            or result["direct_observation_digest_field_omitted"] is not True
        ):
            raise CausalFrontierError("horse-race redacted classifier result overclaims or targets another action")
        for field in ("classifier_sha256", "adapter_contract_sha256", "redacted_result_sha256"):
            require_sha256(result[field], "horse-race classifier result %s" % field)
        require_id(result["branch_token"], "horse-race classifier branch token")
        require_id(result["outcome_id"], "horse-race classifier outcome")
        if result["diagnostic_code"] is not None:
            require_id(result["diagnostic_code"], "horse-race classifier diagnostic")
        result_core = {key: item for key, item in result.items() if key != "redacted_result_sha256"}
        if sha256_bytes(canonical_bytes(result_core)) != result["redacted_result_sha256"]:
            raise CausalFrontierError("horse-race redacted classifier result semantic digest mismatch")
    if sorted(replicate_indices) != list(range(1, len(results) + 1)):
        raise CausalFrontierError("horse-race classifier replicate inventory is not consecutive")
    adjudication = require_exact_keys(
        report["adjudication"],
        {
            "state",
            "aggregate_outcome_id",
            "replicate_tokens",
            "synthetic_decision_class_reduction",
            "replicate_bytes_distinct",
            "replicate_independence_verified",
            "adjudication_sha256",
        },
        "horse-race adjudication",
    )
    require_id(adjudication["state"], "horse-race adjudication state")
    if adjudication["aggregate_outcome_id"] is not None:
        require_id(adjudication["aggregate_outcome_id"], "horse-race aggregate outcome")
    tokens = adjudication["replicate_tokens"]
    if not isinstance(tokens, list) or not tokens:
        raise CausalFrontierError("horse-race replicate token inventory is invalid")
    validated_tokens = [require_id(item, "horse-race replicate token") for item in tokens]
    if validated_tokens != sorted(validated_tokens) or len(validated_tokens) != len(set(validated_tokens)):
        raise CausalFrontierError("horse-race replicate token inventory is invalid")
    reduction = _bounded_count(
        adjudication["synthetic_decision_class_reduction"],
        "horse-race synthetic decision-class reduction",
    )
    if (
        type(adjudication["replicate_bytes_distinct"]) is not bool
        or adjudication["replicate_independence_verified"] is not False
    ):
        raise CausalFrontierError("horse-race adjudication overclaims replicate independence")
    require_sha256(adjudication["adjudication_sha256"], "horse-race adjudication digest")
    adjudication_core = {key: item for key, item in adjudication.items() if key != "adjudication_sha256"}
    if sha256_bytes(canonical_bytes(adjudication_core)) != adjudication["adjudication_sha256"]:
        raise CausalFrontierError("horse-race adjudication semantic digest mismatch")
    allowed_states = {
        "CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED",
        "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
        "CONSISTENT_EXECUTION_FAILURE_BATCH_NO_UPDATE",
        "CONSISTENT_NO_CALL_BATCH_NO_UPDATE",
        "REPLICATION_DISCORDANT_PARTITION_INVALIDATED",
        "REPLICATION_DISCORDANT_NO_CALL",
    }
    consistent_states = {
        "CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED",
        "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
        "CONSISTENT_EXECUTION_FAILURE_BATCH_NO_UPDATE",
        "CONSISTENT_NO_CALL_BATCH_NO_UPDATE",
    }
    result_tokens = sorted({item["branch_token"] for item in results})
    result_outcomes = {item["outcome_id"] for item in results}
    consistent = len(result_tokens) == 1 and len(result_outcomes) == 1
    expected_aggregate = next(iter(result_outcomes)) if consistent else None
    if (
        adjudication["state"] not in allowed_states
        or validated_tokens != result_tokens
        or adjudication["aggregate_outcome_id"] != expected_aggregate
        or (adjudication["state"] in consistent_states) is not consistent
        or (adjudication["state"] != "CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED" and reduction)
    ):
        raise CausalFrontierError("horse-race adjudication differs from its redacted classifier results")
    report_core = {key: item for key, item in report.items() if key != "action_report_sha256"}
    if sha256_bytes(canonical_bytes(report_core)) != report["action_report_sha256"]:
        raise CausalFrontierError("horse-race action report semantic digest mismatch")
    return report


def _validate_execution_receipt(
    value: Any,
    plan: dict[str, Any],
    cell: dict[str, Any],
) -> dict[str, Any]:
    execution = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "audience",
            "public_unlinkable_projection_available",
            "base_compiler_version",
            "episode_id",
            "challenge_manifest_sha256",
            "challenge_registration_sha256",
            "race_spec_sha256",
            "entrant_view_checkpoint_sha256",
            "entrant_view_sha256",
            "commitment_preflight_checkpoint_sha256",
            "commitment_preflight_sha256",
            "selection_checkpoint_sha256",
            "selection_lock_sha256",
            "selection_envelope_checkpoint_sha256",
            "selection_envelope_sha256",
            "oracle_opening_checkpoint_sha256",
            "oracle_opening_sha256",
            "oracle_payload_sha256",
            "preflight_oracle_entries_n",
            "preflight_oracle_total_bytes_n",
            "preflight_oracle_total_bytes_matched_at_execution_start",
            "oracle_limit_contract_sha256",
            "entrant_case_id",
            "entrant_lane_id",
            "policy_id",
            "policy_trace_sha256",
            "terminal_kind",
            "terminal_reason_codes",
            "integrity_valid",
            "commitment_preflight_checkpoint_verified",
            "commitment_preflight_independent_attestation_verified",
            "preflight_prohibited_observation_field_marker_screen_passed",
            "patient_level_data_absence_independently_verified",
            "current_full_oracle_byte_readiness_verified",
            "blinding_nonce_entropy_verified",
            "blinding_nonce_uniqueness_verified",
            "blinding_nonce_secrecy_until_selection_verified",
            "selector_preflight_input_accepted",
            "precommitment_temporal_order_independently_verified",
            "resources_used",
            "resource_accounting_mode",
            "action_reports",
            "events",
            "ledger_head",
            "environment_isolation_verified",
            "replicate_independence_verified",
            "scientific_baseline_families_executed",
            "required_scientific_baseline_families_unexecuted",
            "scientific_scoring_ready",
            "nonclaims",
            "execution_report_sha256",
        },
        "synthetic horse-race execution receipt",
    )
    expected_bindings = {
        "challenge_manifest_sha256": plan["challenge_manifest_sha256"],
        "challenge_registration_sha256": plan["challenge_registration_sha256"],
        "race_spec_sha256": plan["race_spec_sha256"],
        "entrant_view_checkpoint_sha256": plan["entrant_view_checkpoint_sha256"],
        "entrant_view_sha256": plan["entrant_view_sha256"],
        "commitment_preflight_checkpoint_sha256": plan["commitment_preflight_checkpoint_sha256"],
        "commitment_preflight_sha256": plan["commitment_preflight_sha256"],
        "selection_checkpoint_sha256": plan["selection_checkpoint_sha256"],
        "selection_lock_sha256": plan["selection_lock_sha256"],
        "selection_envelope_checkpoint_sha256": plan["selection_envelope_checkpoint_sha256"],
        "selection_envelope_sha256": plan["selection_envelope_sha256"],
        "oracle_opening_checkpoint_sha256": plan["oracle_opening_checkpoint_sha256"],
        **{field: cell[field] for field in ("entrant_case_id", "entrant_lane_id", "policy_id", "policy_trace_sha256")},
    }
    if any(execution[field] != expected for field, expected in expected_bindings.items()):
        raise CausalFrontierError("synthetic horse-race execution receipt targets another bound artifact")
    for field in (
        *[key for key in expected_bindings if key.endswith("sha256")],
        "oracle_opening_sha256",
        "oracle_payload_sha256",
        "oracle_limit_contract_sha256",
        "ledger_head",
        "execution_report_sha256",
    ):
        require_sha256(execution[field], "horse-race execution %s" % field)
    if (
        execution["schema_version"] != blind.EXECUTION_SCHEMA_VERSION
        or execution["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or execution["audience"] != "STEWARD_ONLY_NOT_A_PUBLIC_UNLINKABLE_PROJECTION"
        or execution["public_unlinkable_projection_available"] is not False
        or execution["base_compiler_version"] != COMPILER_VERSION
        or execution["commitment_preflight_checkpoint_verified"] is not True
        or execution["commitment_preflight_independent_attestation_verified"] is not False
        or execution["preflight_prohibited_observation_field_marker_screen_passed"] is not True
        or execution["patient_level_data_absence_independently_verified"] is not False
        or execution["current_full_oracle_byte_readiness_verified"] is not False
        or execution["blinding_nonce_entropy_verified"] is not False
        or execution["blinding_nonce_uniqueness_verified"] is not False
        or execution["blinding_nonce_secrecy_until_selection_verified"] is not False
        or execution["selector_preflight_input_accepted"] is not False
        or execution["precommitment_temporal_order_independently_verified"] is not False
        or execution["resource_accounting_mode"] != blind.RESOURCE_ACCOUNTING_MODE
        or execution["oracle_opening_sha256"] != execution["oracle_opening_checkpoint_sha256"]
        or execution["oracle_limit_contract_sha256"] != blind._oracle_limit_contract_sha256()
        or type(execution["preflight_oracle_total_bytes_matched_at_execution_start"]) is not bool
        or execution["environment_isolation_verified"] is not False
        or execution["replicate_independence_verified"] is not False
        or execution["scientific_baseline_families_executed"] != []
        or execution["required_scientific_baseline_families_unexecuted"] != sorted(challenge.BASELINE_FAMILIES)
        or execution["scientific_scoring_ready"] is not False
        or execution["nonclaims"] != list(blind.EXECUTION_NONCLAIMS)
        or type(execution["integrity_valid"]) is not bool
    ):
        raise CausalFrontierError("synthetic horse-race execution receipt overclaims or changes its contract")
    _bounded_count(
        execution["preflight_oracle_entries_n"],
        "horse-race preflight oracle entry count",
        minimum=1,
        maximum=blind.MAX_ORACLE_FILES,
    )
    _bounded_count(
        execution["preflight_oracle_total_bytes_n"],
        "horse-race preflight oracle byte count",
        minimum=1,
        maximum=blind.MAX_ORACLE_TOTAL_BYTES,
    )
    require_id(execution["episode_id"], "horse-race execution episode")
    require_id(execution["terminal_kind"], "horse-race execution terminal")
    terminal_reasons = execution["terminal_reason_codes"]
    if not isinstance(terminal_reasons, list) or not terminal_reasons:
        raise CausalFrontierError("synthetic horse-race execution terminal reasons are invalid")
    validated_terminal_reasons = [require_id(item, "horse-race execution terminal reason") for item in terminal_reasons]
    if validated_terminal_reasons != sorted(validated_terminal_reasons) or len(validated_terminal_reasons) != len(
        set(validated_terminal_reasons)
    ):
        raise CausalFrontierError("synthetic horse-race execution terminal reasons are invalid")
    resources = blind._resource_vector(execution["resources_used"], "horse-race execution resources")
    if resources != execution["resources_used"]:
        raise CausalFrontierError("synthetic horse-race execution resources are not normalized")
    action_reports = execution["action_reports"]
    if not isinstance(action_reports, list):
        raise CausalFrontierError("synthetic horse-race action reports must be a list")
    validated_reports = [_validate_action_report(item) for item in action_reports]
    action_aliases = [item["entrant_action_id"] for item in validated_reports]
    if len(action_aliases) != len(set(action_aliases)):
        raise CausalFrontierError("synthetic horse-race execution repeated an action")
    events = execution["events"]
    if not isinstance(events, list) or len(events) < 3:
        raise CausalFrontierError("synthetic horse-race execution event chain is incomplete")
    previous = blind.GENESIS
    for index, event in enumerate(events, start=1):
        event = require_exact_keys(
            event,
            {"schema_version", "episode_id", "seq", "prev_digest", "type", "payload", "digest"},
            "horse-race execution event",
        )
        if (
            event["schema_version"] != blind.EVENT_SCHEMA_VERSION
            or event["episode_id"] != execution["episode_id"]
            or event["seq"] != index
            or event["prev_digest"] != previous
            or not isinstance(event["payload"], dict)
        ):
            raise CausalFrontierError("synthetic horse-race execution event chain is invalid")
        require_id(event["type"], "horse-race event type")
        require_sha256(event["digest"], "horse-race event digest")
        event_core = {key: item for key, item in event.items() if key != "digest"}
        if sha256_bytes(blind.EVENT_DOMAIN_TAG + canonical_bytes(event_core)) != event["digest"]:
            raise CausalFrontierError("synthetic horse-race execution event digest mismatch")
        previous = event["digest"]
    if (
        events[0]["type"] != "EPISODE_REGISTERED"
        or events[1]["type"] != "POLICY_OUTPUT"
        or events[-1]["type"] != "EPISODE_TERMINATED"
        or execution["ledger_head"] != events[-1]["digest"]
    ):
        raise CausalFrontierError("synthetic horse-race execution event boundary is invalid")
    episode_core = {
        "challenge_registration_sha256": execution["challenge_registration_sha256"],
        "challenge_manifest_sha256": execution["challenge_manifest_sha256"],
        "race_spec_sha256": execution["race_spec_sha256"],
        "entrant_view_checkpoint_sha256": execution["entrant_view_checkpoint_sha256"],
        "commitment_preflight_checkpoint_sha256": execution["commitment_preflight_checkpoint_sha256"],
        "commitment_preflight_sha256": execution["commitment_preflight_sha256"],
        "selection_checkpoint_sha256": execution["selection_checkpoint_sha256"],
        "selection_lock_sha256": execution["selection_lock_sha256"],
        "selection_envelope_checkpoint_sha256": execution["selection_envelope_checkpoint_sha256"],
        "selection_envelope_sha256": execution["selection_envelope_sha256"],
        "oracle_opening_checkpoint_sha256": execution["oracle_opening_checkpoint_sha256"],
        "entrant_case_id": execution["entrant_case_id"],
        "entrant_lane_id": execution["entrant_lane_id"],
        "policy_id": execution["policy_id"],
        "policy_trace_sha256": execution["policy_trace_sha256"],
    }
    expected_episode_id = "episode:%s" % sha256_bytes(canonical_bytes(episode_core))
    registration = require_exact_keys(
        events[0]["payload"],
        {*episode_core, "budget", "resource_accounting_mode"},
        "horse-race episode-registration event",
    )
    budget = blind._resource_vector(registration["budget"], "horse-race registered budget")
    if (
        execution["episode_id"] != expected_episode_id
        or any(registration[field] != expected for field, expected in episode_core.items())
        or registration["budget"] != budget
        or registration["resource_accounting_mode"] != blind.RESOURCE_ACCOUNTING_MODE
    ):
        raise CausalFrontierError("synthetic horse-race episode registration differs from its receipt")
    trace_payload = require_exact_keys(events[1]["payload"], {"trace"}, "horse-race policy-output event")
    trace = _validate_policy_trace(trace_payload["trace"], cell)
    selected_aliases = [item["entrant_action_id"] for item in trace["selections"] if item["action"] == "SELECT"]
    if len(selected_aliases) != len(set(selected_aliases)):
        raise CausalFrontierError("synthetic horse-race policy trace repeats a selected action")
    if any(alias not in selected_aliases for alias in action_aliases):
        raise CausalFrontierError("synthetic horse-race execution adjudicated an unlocked action")
    experiment_ids = [item["experiment_id"] for item in validated_reports]
    if len(experiment_ids) != len(set(experiment_ids)):
        raise CausalFrontierError("synthetic horse-race execution repeated an experiment")
    if cell["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1" and experiment_ids != sorted(experiment_ids):
        raise CausalFrontierError("uniform enumeration execution order differs from its bound rule")

    cursor = 2
    used = dict.fromkeys(blind.RESOURCE_DIMENSIONS, 0)
    remaining_aliases = set(selected_aliases)
    processed_aliases: list[str] = []
    report_index = 0
    derived_reasons: set[str] = set()
    derived_integrity = True

    def validate_abort_event(event: dict[str, Any], action_id: str | None, reason_code: str) -> None:
        payload = require_exact_keys(
            event["payload"],
            {"entrant_action_id", "reason_code", "resources_retained"},
            "horse-race integrity-abort event",
        )
        retained = blind._resource_vector(payload["resources_retained"], "horse-race retained resources")
        if (
            event["type"] != "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY"
            or payload["entrant_action_id"] != action_id
            or payload["reason_code"] != reason_code
            or retained != used
        ):
            raise CausalFrontierError("synthetic horse-race integrity-abort event is inconsistent")

    if not execution["preflight_oracle_total_bytes_matched_at_execution_start"]:
        if cursor >= len(events) - 1:
            raise CausalFrontierError("synthetic horse-race preflight mismatch lacks its abort event")
        validate_abort_event(events[cursor], None, "PREFLIGHT_ORACLE_TOTAL_BYTES_MISMATCH")
        cursor += 1
        derived_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
        derived_integrity = False
    else:
        if not selected_aliases:
            derived_reasons.add("ABSTAINED" if trace["selections"][0]["action"] == "ABSTAIN" else "NO_CALL")
        while remaining_aliases and cursor < len(events) - 1 and derived_integrity:
            event = events[cursor]
            if event["type"] == "ACTION_REJECTED":
                payload = require_exact_keys(
                    event["payload"],
                    {"entrant_action_id", "reason", "exceeded_dimensions"},
                    "horse-race action-rejected event",
                )
                action_id = blind._require_opaque_alias(
                    payload["entrant_action_id"], "action", "horse-race rejected action"
                )
                dimensions = payload["exceeded_dimensions"]
                if (
                    action_id not in remaining_aliases
                    or action_id in processed_aliases
                    or payload["reason"] != "BUDGET_EXCEEDED"
                    or not isinstance(dimensions, list)
                    or not dimensions
                    or dimensions != sorted(set(dimensions))
                    or any(dimension not in blind.RESOURCE_DIMENSIONS for dimension in dimensions)
                ):
                    raise CausalFrontierError("synthetic horse-race budget rejection is inconsistent")
                derived_reasons.add("BUDGET_EXHAUSTED_CENSORED")
                cursor += 1
                break
            if event["type"] != "ACTION_DEBITED":
                raise CausalFrontierError("synthetic horse-race action lifecycle is incomplete")
            payload = require_exact_keys(
                event["payload"],
                {"entrant_action_id", "tariff", "resources_before", "resources_after"},
                "horse-race action debit",
            )
            action_id = blind._require_opaque_alias(payload["entrant_action_id"], "action", "horse-race debit action")
            tariff = blind._resource_vector(payload["tariff"], "horse-race action tariff", action_batch=True)
            before = blind._resource_vector(payload["resources_before"], "horse-race resources before")
            after = blind._resource_vector(payload["resources_after"], "horse-race resources after")
            if (
                action_id not in remaining_aliases
                or action_id in processed_aliases
                or before != used
                or after != {key: before[key] + tariff[key] for key in blind.RESOURCE_DIMENSIONS}
                or any(after[key] > budget[key] for key in blind.RESOURCE_DIMENSIONS)
            ):
                raise CausalFrontierError("synthetic horse-race action resource debit is inconsistent")
            used = after
            processed_aliases.append(action_id)
            remaining_aliases.remove(action_id)
            cursor += 1

            classification_payloads = []
            while cursor < len(events) - 1 and events[cursor]["type"] == "OBSERVATION_CLASSIFIED":
                classified = require_exact_keys(
                    events[cursor]["payload"],
                    {"entrant_action_id", "replicate_index", "redacted_result_sha256", "branch_token", "outcome_id"},
                    "horse-race observation-classified event",
                )
                replicate_index = _bounded_count(
                    classified["replicate_index"],
                    "horse-race observation-classified replicate",
                    minimum=1,
                    maximum=blind.MAX_REPLICATES,
                )
                blind._require_opaque_alias(classified["entrant_action_id"], "action", "horse-race classified action")
                require_sha256(classified["redacted_result_sha256"], "horse-race classified result digest")
                require_id(classified["branch_token"], "horse-race classified branch token")
                require_id(classified["outcome_id"], "horse-race classified outcome")
                if classified["entrant_action_id"] != action_id or replicate_index != len(classification_payloads) + 1:
                    raise CausalFrontierError("synthetic horse-race observation events are out of order")
                classification_payloads.append(classified)
                cursor += 1
            if cursor >= len(events) - 1:
                raise CausalFrontierError("synthetic horse-race debited action lacks a terminal action event")
            if events[cursor]["type"] == "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY":
                validate_abort_event(
                    events[cursor],
                    action_id,
                    "SELECTED_OBSERVATION_INTEGRITY_PRIVACY_OR_CLASSIFIER_ABORT",
                )
                cursor += 1
                derived_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
                derived_integrity = False
                break
            if events[cursor]["type"] != "ACTION_ADJUDICATED" or report_index >= len(validated_reports):
                raise CausalFrontierError("synthetic horse-race debited action was not adjudicated")
            report = validated_reports[report_index]
            if report["entrant_action_id"] != action_id:
                raise CausalFrontierError("synthetic horse-race adjudication order differs from action reports")
            expected_classifications = [
                {
                    "entrant_action_id": action_id,
                    "replicate_index": result["replicate_index"],
                    "redacted_result_sha256": result["redacted_result_sha256"],
                    "branch_token": result["branch_token"],
                    "outcome_id": result["outcome_id"],
                }
                for result in report["classifier_results"]
            ]
            if (
                len(expected_classifications) < blind.MIN_REPLICATES
                or classification_payloads != expected_classifications
            ):
                raise CausalFrontierError("synthetic horse-race observation events differ from the action report")
            adjudicated = require_exact_keys(
                events[cursor]["payload"],
                {"entrant_action_id", "action_report_sha256", "adjudication_sha256", "state"},
                "horse-race action-adjudicated event",
            )
            expected_adjudication = {
                "entrant_action_id": action_id,
                "action_report_sha256": report["action_report_sha256"],
                "adjudication_sha256": report["adjudication"]["adjudication_sha256"],
                "state": report["adjudication"]["state"],
            }
            if adjudicated != expected_adjudication:
                raise CausalFrontierError("synthetic horse-race adjudication event differs from its action report")
            if report["adjudication"]["state"] in {
                "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
                "REPLICATION_DISCORDANT_PARTITION_INVALIDATED",
            }:
                derived_reasons.add("PARTITION_INVALIDATED_REQUIRES_NEW_CASE")
            report_index += 1
            cursor += 1

        if cursor < len(events) - 1:
            validate_abort_event(events[cursor], None, "POST_EXECUTION_ORACLE_INVENTORY_ABORT")
            cursor += 1
            derived_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
            derived_integrity = False

    if cursor != len(events) - 1:
        raise CausalFrontierError("synthetic horse-race execution contains a surplus lifecycle event")
    if report_index != len(validated_reports) or action_aliases != processed_aliases[:report_index]:
        raise CausalFrontierError("synthetic horse-race action reports differ from the event lifecycle")
    if derived_integrity and remaining_aliases and "BUDGET_EXHAUSTED_CENSORED" not in derived_reasons:
        raise CausalFrontierError("synthetic horse-race execution stopped before its locked policy completed")
    if not derived_reasons:
        derived_reasons.add("COMPLETED_REFERENCE_PROXY")
    expected_reasons = sorted(derived_reasons)
    expected_terminal = next(
        reason
        for reason in (
            "INTEGRITY_OR_AUTHORITY_ABORT_INVALID",
            "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
            "BUDGET_EXHAUSTED_CENSORED",
            "ABSTAINED",
            "NO_CALL",
            "COMPLETED_REFERENCE_PROXY",
        )
        if reason in derived_reasons
    )
    if (
        execution["integrity_valid"] is not derived_integrity
        or execution["terminal_reason_codes"] != expected_reasons
        or execution["terminal_kind"] != expected_terminal
        or execution["resources_used"] != used
    ):
        raise CausalFrontierError("synthetic horse-race terminal state differs from its event lifecycle")
    terminal_payload = require_exact_keys(
        events[-1]["payload"],
        {"terminal_kind", "terminal_reason_codes", "resources_used", "actions_adjudicated_n"},
        "horse-race terminal event",
    )
    if (
        terminal_payload["terminal_kind"] != execution["terminal_kind"]
        or terminal_payload["terminal_reason_codes"] != execution["terminal_reason_codes"]
        or terminal_payload["resources_used"] != execution["resources_used"]
        or terminal_payload["actions_adjudicated_n"] != len(action_reports)
    ):
        raise CausalFrontierError("synthetic horse-race terminal event differs from its receipt")
    expected_status = (
        "SYNTHETIC_POLICY_EXECUTION_ABORTED_INTEGRITY_INVALID_SCIENTIFIC_SCORING_DISABLED"
        if not derived_integrity
        else "SYNTHETIC_BLIND_OBSERVATIONS_CLASSIFIED_SCIENTIFIC_SCORING_DISABLED"
        if validated_reports
        else "SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED"
    )
    if execution["status"] != expected_status:
        raise CausalFrontierError("synthetic horse-race execution status differs from its receipt")
    core = {key: item for key, item in execution.items() if key != "execution_report_sha256"}
    if sha256_bytes(canonical_bytes(core)) != execution["execution_report_sha256"]:
        raise CausalFrontierError("synthetic horse-race execution receipt semantic digest mismatch")
    return execution


def _episode_summary(
    execution: dict[str, Any],
    cell: dict[str, Any],
    execution_order_rule: str,
) -> dict[str, Any]:
    state_counts = dict(
        sorted(Counter(report["adjudication"]["state"] for report in execution["action_reports"]).items())
    )
    core = {
        "matrix_cell_id": cell["matrix_cell_id"],
        "entrant_case_id": cell["entrant_case_id"],
        "entrant_lane_id": cell["entrant_lane_id"],
        "policy_id": cell["policy_id"],
        "policy_trace_sha256": cell["policy_trace_sha256"],
        "episode_id": execution["episode_id"],
        "execution_report_sha256": execution["execution_report_sha256"],
        "execution_status": execution["status"],
        "integrity_valid": execution["integrity_valid"],
        "terminal_kind": execution["terminal_kind"],
        "terminal_reason_codes": execution["terminal_reason_codes"],
        "resources_used": execution["resources_used"],
        "actions_adjudicated_n": len(execution["action_reports"]),
        "execution_order_rule": execution_order_rule,
        "executed_entrant_action_ids": [item["entrant_action_id"] for item in execution["action_reports"]],
        "adjudication_state_counts": state_counts,
        "replicate_independence_verified": execution["replicate_independence_verified"],
        "scientific_scoring_ready": False,
    }
    return {**core, "episode_summary_sha256": sha256_bytes(canonical_bytes(core))}


def execute_synthetic_horse_race(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    selection_path: Path,
    expected_selection_checkpoint_sha256: str,
    selection_envelope_path: Path,
    expected_selection_envelope_checkpoint_sha256: str,
    commitment_preflight_path: Path,
    expected_commitment_preflight_checkpoint_sha256: str,
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
    oracle_root: Path,
    expected_opening_sha256: str,
) -> dict[str, Any]:
    """Execute every hash-bound matrix cell; no coordinate is caller-selectable."""

    _plan_raw, plan_value = blind._read_checkpointed_json(
        plan_path, expected_plan_checkpoint_sha256, "synthetic horse-race plan"
    )
    plan = _validate_plan(plan_value)
    replayed_plan = prepare_synthetic_horse_race_plan(
        root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        view_path,
        expected_view_checkpoint_sha256,
        selection_path,
        expected_selection_checkpoint_sha256,
        selection_envelope_path,
        expected_selection_envelope_checkpoint_sha256,
        commitment_preflight_path,
        expected_commitment_preflight_checkpoint_sha256,
        expected_opening_sha256,
    )
    if canonical_bytes(plan) != canonical_bytes(replayed_plan):
        raise CausalFrontierError("synthetic horse-race plan does not replay from its bound artifacts")
    before = challenge.preflight_challenge(root, expected_manifest_sha256, expected_sequence)
    before_sha256 = sha256_bytes(canonical_bytes(before))
    episode_summaries = []
    episode_receipts = []
    all_integrity_valid = True
    execution_order_rules = {item["policy_id"]: item["rule"] for item in plan["policy_execution_order_contract"]}
    for cell in plan["matrix_cells"]:
        execution = blind.execute_blind_synthetic_policy(
            root,
            expected_manifest_sha256,
            expected_sequence,
            race_spec_path,
            expected_race_spec_sha256,
            view_path,
            expected_view_checkpoint_sha256,
            selection_path,
            expected_selection_checkpoint_sha256,
            selection_envelope_path,
            expected_selection_envelope_checkpoint_sha256,
            commitment_preflight_path,
            expected_commitment_preflight_checkpoint_sha256,
            oracle_root,
            expected_opening_sha256,
            cell["entrant_case_id"],
            cell["entrant_lane_id"],
            cell["policy_id"],
        )
        execution = _validate_execution_receipt(execution, plan, cell)
        episode_receipts.append(execution)
        episode_summaries.append(_episode_summary(execution, cell, execution_order_rules[cell["policy_id"]]))
        all_integrity_valid = all_integrity_valid and execution["integrity_valid"]
    after = challenge.preflight_challenge(root, expected_manifest_sha256, expected_sequence)
    after_sha256 = sha256_bytes(canonical_bytes(after))
    challenge_unchanged = canonical_bytes(before) == canonical_bytes(after)
    all_integrity_valid = all_integrity_valid and challenge_unchanged
    matrix_complete = len(episode_summaries) == plan["matrix_cells_n"]
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": REPORT_STATUS if all_integrity_valid else INVALID_REPORT_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_REHEARSAL",
        "audience": "STEWARD_ONLY_HASH_LINKABLE_REPORT",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "challenge_manifest_sha256": expected_manifest_sha256,
        "challenge_preflight_sha256_before": before_sha256,
        "challenge_preflight_sha256_after": after_sha256,
        "challenge_unchanged_during_matrix_execution": challenge_unchanged,
        "expected_matrix_cells_n": plan["matrix_cells_n"],
        "executed_matrix_cells_n": len(episode_summaries),
        "matrix_complete": matrix_complete,
        "all_episode_integrity_valid": all_integrity_valid,
        "episode_receipts": episode_receipts,
        "episode_summaries": episode_summaries,
        "resource_aggregation_semantics": EXECUTION_SEMANTICS,
        "scientific_baseline_families_executed": [],
        "required_scientific_baseline_families_unexecuted": sorted(challenge.BASELINE_FAMILIES),
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "calibration_evaluated": False,
        "scientific_scoring_ready": False,
        "gates": _report_gates(plan, all_integrity_valid, matrix_complete),
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "report_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_episode_summary(
    value: Any,
    cell: dict[str, Any],
    execution_order_rule: str,
) -> dict[str, Any]:
    summary = require_exact_keys(
        value,
        {
            "matrix_cell_id",
            "entrant_case_id",
            "entrant_lane_id",
            "policy_id",
            "policy_trace_sha256",
            "episode_id",
            "execution_report_sha256",
            "execution_status",
            "integrity_valid",
            "terminal_kind",
            "terminal_reason_codes",
            "resources_used",
            "actions_adjudicated_n",
            "execution_order_rule",
            "executed_entrant_action_ids",
            "adjudication_state_counts",
            "replicate_independence_verified",
            "scientific_scoring_ready",
            "episode_summary_sha256",
        },
        "synthetic horse-race episode summary",
    )
    if any(summary[field] != cell[field] for field in cell):
        raise CausalFrontierError("synthetic horse-race episode summary targets another matrix cell")
    for field in ("policy_trace_sha256", "execution_report_sha256", "episode_summary_sha256"):
        require_sha256(summary[field], "horse-race episode %s" % field)
    require_id(summary["episode_id"], "horse-race episode id")
    require_id(summary["execution_status"], "horse-race episode status")
    require_id(summary["terminal_kind"], "horse-race episode terminal kind")
    if type(summary["integrity_valid"]) is not bool:
        raise CausalFrontierError("horse-race episode integrity must be boolean")
    if (
        summary["execution_order_rule"] != execution_order_rule
        or summary["replicate_independence_verified"] is not False
        or summary["scientific_scoring_ready"] is not False
    ):
        raise CausalFrontierError("synthetic horse-race episode summary overclaims or changes execution semantics")
    reasons = summary["terminal_reason_codes"]
    if not isinstance(reasons, list) or not reasons:
        raise CausalFrontierError("synthetic horse-race terminal reasons are invalid")
    validated_reasons = [require_id(reason, "horse-race terminal reason") for reason in reasons]
    if validated_reasons != sorted(validated_reasons) or len(validated_reasons) != len(set(validated_reasons)):
        raise CausalFrontierError("synthetic horse-race terminal reasons are invalid")
    resources = blind._resource_vector(summary["resources_used"], "horse-race episode resources")
    if resources != summary["resources_used"]:
        raise CausalFrontierError("synthetic horse-race episode resources are not normalized")
    actions_n = _bounded_count(summary["actions_adjudicated_n"], "horse-race actions adjudicated")
    action_ids = summary["executed_entrant_action_ids"]
    if not isinstance(action_ids, list) or len(action_ids) != actions_n:
        raise CausalFrontierError("synthetic horse-race executed action inventory is invalid")
    validated_action_ids = [
        blind._require_opaque_alias(action_id, "action", "horse-race executed action id") for action_id in action_ids
    ]
    if len(validated_action_ids) != len(set(validated_action_ids)):
        raise CausalFrontierError("synthetic horse-race executed action inventory is invalid")
    state_counts = summary["adjudication_state_counts"]
    if not isinstance(state_counts, dict):
        raise CausalFrontierError("synthetic horse-race adjudication counts differ from executed actions")
    adjudications_n = 0
    for state, count in state_counts.items():
        require_id(state, "horse-race adjudication state")
        adjudications_n += _bounded_count(count, "horse-race adjudication state count", minimum=1)
    if adjudications_n != actions_n:
        raise CausalFrontierError("synthetic horse-race adjudication counts differ from executed actions")
    if state_counts != dict(sorted(state_counts.items())):
        raise CausalFrontierError("synthetic horse-race adjudication states are not canonical")
    core = {key: item for key, item in summary.items() if key != "episode_summary_sha256"}
    if sha256_bytes(canonical_bytes(core)) != summary["episode_summary_sha256"]:
        raise CausalFrontierError("synthetic horse-race episode summary semantic digest mismatch")
    return summary


def _validate_report(value: Any, plan: dict[str, Any]) -> dict[str, Any]:
    report = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "audience",
            "base_compiler_version",
            "fixed_parameter",
            "boundary",
            "plan_checkpoint_sha256",
            "plan_sha256",
            "challenge_manifest_sha256",
            "challenge_preflight_sha256_before",
            "challenge_preflight_sha256_after",
            "challenge_unchanged_during_matrix_execution",
            "expected_matrix_cells_n",
            "executed_matrix_cells_n",
            "matrix_complete",
            "all_episode_integrity_valid",
            "episode_receipts",
            "episode_summaries",
            "resource_aggregation_semantics",
            "scientific_baseline_families_executed",
            "required_scientific_baseline_families_unexecuted",
            "winner",
            "ranking",
            "acceleration_ratio",
            "calibration_evaluated",
            "scientific_scoring_ready",
            "gates",
            "nonclaims",
            "report_sha256",
        },
        "synthetic horse-race report",
    )
    for field in (
        "plan_checkpoint_sha256",
        "plan_sha256",
        "challenge_manifest_sha256",
        "challenge_preflight_sha256_before",
        "challenge_preflight_sha256_after",
        "report_sha256",
    ):
        require_sha256(report[field], "horse-race report %s" % field)
    if (
        report["schema_version"] != REPORT_SCHEMA_VERSION
        or report["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_REHEARSAL"
        or report["audience"] != "STEWARD_ONLY_HASH_LINKABLE_REPORT"
        or report["base_compiler_version"] != COMPILER_VERSION
        or report["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(report["boundary"]) != BOUNDARY_CANONICAL
        or report["plan_sha256"] != plan["plan_sha256"]
        or report["challenge_manifest_sha256"] != plan["challenge_manifest_sha256"]
        or report["resource_aggregation_semantics"] != EXECUTION_SEMANTICS
        or report["scientific_baseline_families_executed"] != []
        or report["required_scientific_baseline_families_unexecuted"] != sorted(challenge.BASELINE_FAMILIES)
        or report["winner"] is not None
        or report["ranking"] != []
        or report["acceleration_ratio"] is not None
        or report["calibration_evaluated"] is not False
        or report["scientific_scoring_ready"] is not False
        or report["nonclaims"] != list(NONCLAIMS)
    ):
        raise CausalFrontierError("synthetic horse-race report overclaims or targets another contract")
    expected_n = _bounded_count(report["expected_matrix_cells_n"], "horse-race expected matrix cells", minimum=1)
    executed_n = _bounded_count(report["executed_matrix_cells_n"], "horse-race executed matrix cells")
    if expected_n != plan["matrix_cells_n"]:
        raise CausalFrontierError("synthetic horse-race report expects another matrix")
    summaries = report["episode_summaries"]
    receipts = report["episode_receipts"]
    if (
        not isinstance(summaries, list)
        or not isinstance(receipts, list)
        or len(summaries) != executed_n
        or len(receipts) != executed_n
    ):
        raise CausalFrontierError("synthetic horse-race report episode inventory differs")
    order_rules = {item["policy_id"]: item["rule"] for item in plan["policy_execution_order_contract"]}
    if executed_n != expected_n or executed_n != len(plan["matrix_cells"]):
        raise CausalFrontierError("synthetic horse-race report is not a complete matrix receipt")
    for receipt, summary, cell in zip(receipts, summaries, plan["matrix_cells"], strict=True):
        validated_receipt = _validate_execution_receipt(receipt, plan, cell)
        validated_summary = _validate_episode_summary(summary, cell, order_rules[cell["policy_id"]])
        if canonical_bytes(validated_summary) != canonical_bytes(
            _episode_summary(validated_receipt, cell, order_rules[cell["policy_id"]])
        ):
            raise CausalFrontierError("synthetic horse-race episode summary differs from its execution receipt")
    matrix_complete = executed_n == expected_n == len(plan["matrix_cells"])
    challenge_unchanged = report["challenge_preflight_sha256_before"] == report["challenge_preflight_sha256_after"]
    episode_integrity = all(receipt["integrity_valid"] for receipt in receipts)
    integrity_valid = matrix_complete and challenge_unchanged and episode_integrity
    if (
        report["matrix_complete"] is not matrix_complete
        or report["challenge_unchanged_during_matrix_execution"] is not challenge_unchanged
        or report["all_episode_integrity_valid"] is not integrity_valid
        or report["status"] != (REPORT_STATUS if integrity_valid else INVALID_REPORT_STATUS)
        or report["gates"] != _report_gates(plan, integrity_valid, matrix_complete)
    ):
        raise CausalFrontierError("synthetic horse-race report status or integrity fields are inconsistent")
    core = {key: item for key, item in report.items() if key != "report_sha256"}
    if sha256_bytes(canonical_bytes(core)) != report["report_sha256"]:
        raise CausalFrontierError("synthetic horse-race report semantic digest mismatch")
    return report


def verify_synthetic_horse_race_report(
    report_path: Path,
    expected_report_checkpoint_sha256: str,
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Verify a saved no-score report against its exact hash-bound plan."""

    _plan_raw, plan_value = blind._read_checkpointed_json(
        plan_path, expected_plan_checkpoint_sha256, "synthetic horse-race plan"
    )
    plan = _validate_plan(plan_value)
    _report_raw, report_value = blind._read_checkpointed_json(
        report_path, expected_report_checkpoint_sha256, "synthetic horse-race report"
    )
    report = _validate_report(report_value, plan)
    if report["plan_checkpoint_sha256"] != expected_plan_checkpoint_sha256:
        raise CausalFrontierError("synthetic horse-race report targets another plan checkpoint")
    core = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": VALID_VERIFICATION_STATUS
        if report["all_episode_integrity_valid"]
        else "VALID_REPORT_CONTAINING_INTEGRITY_INVALID_EXECUTION_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_REHEARSAL",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "report_checkpoint_sha256": expected_report_checkpoint_sha256,
        "report_sha256": report["report_sha256"],
        "matrix_cells_n": report["executed_matrix_cells_n"],
        "contained_execution_integrity_valid": report["all_episode_integrity_valid"],
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "scientific_scoring_ready": False,
        "nonclaims": list(VERIFICATION_NONCLAIMS),
    }
    return {**core, "verification_sha256": sha256_bytes(canonical_bytes(core))}
