"""Policy-neutral action substrate and executable synthetic baseline protocols.

This module closes a narrow evaluation-design gap without making a scientific
claim.  It validates an organizer-frozen action catalog that rejects named
CausalFrontier eligibility, Pareto, and minimax fields without claiming semantic
exclusion; preregisters multiple seed commitments; opens portable SHA-256 random
orders; proves OFAT geometry from complete assignments; and derives deterministic
protocol-cost receipts.

The substrate is deliberately case-level.  Random and OFAT baselines execute
once per case, while a future CausalFrontier adapter may emit encoder-stratified
candidate outputs from the same common-input checkpoint.  Observational timing
is isolated from the replay-stable protocol-cost core and is never score-relevant.
"""

from __future__ import annotations

import platform
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Sequence

from . import receipts as receipt_io
from .canonical import (
    MAX_JSON_BYTES,
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    require_text,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

CATALOG_SCHEMA_VERSION = "causalfrontier.neutral-action-catalog.v1"
COMMON_INPUT_SCHEMA_VERSION = "causalfrontier.common-policy-input.v1"
PRIOR_SCHEMA_VERSION = "causalfrontier.informed-ofat-prior.v1"
PLAN_SCHEMA_VERSION = "causalfrontier.neutral-baseline-plan.v1"
LOCK_SCHEMA_VERSION = "causalfrontier.neutral-baseline-order-lock.v1"
TRACE_SCHEMA_VERSION = "causalfrontier.neutral-baseline-order-trace.v1"
SCORE_CORE_SCHEMA_VERSION = "causalfrontier.synthetic-protocol-cost-core.v1"
TELEMETRY_SCHEMA_VERSION = "causalfrontier.observational-telemetry.v1"
RECEIPT_SCHEMA_VERSION = "causalfrontier.neutral-baseline-receipt.v1"
REPORT_SCHEMA_VERSION = "causalfrontier.neutral-baseline-exercise.v1"
VERIFICATION_SCHEMA_VERSION = "causalfrontier.neutral-baseline-verification.v1"

CATALOG_STATUS = "STRUCTURALLY_NEUTRAL_ACTION_AND_AUTHORITY_INPUT_FROZEN_SCIENTIFIC_SCORING_DISABLED"
COMMON_INPUT_STATUS = "DECLARED_PRECOMPILATION_SYNTHETIC_COMMON_POLICY_INPUT_STRUCTURAL_NEUTRALITY_ONLY"
PLAN_STATUS = "SEEDS_AND_COMPLETE_CASE_LEVEL_BASELINE_MATRIX_PRECOMMITTED_NO_ORACLE_READ"
LOCK_STATUS = "SEEDS_OPENED_AND_PORTABLE_BASELINE_ORDERS_LOCKED_NO_OUTCOMES"
REPORT_STATUS = "SYNTHETIC_BASELINE_PROTOCOL_COSTS_REPLAYED_SCIENTIFIC_SCORING_DISABLED"
VERIFICATION_STATUS = "VALID_NEUTRAL_BASELINE_PROTOCOL_EXERCISE_SCIENTIFIC_SCORING_DISABLED"

SEED_COMMITMENT_DOMAIN_TAG = b"causalfrontier.seed-commitment.v1\0"
RANDOM_ORDER_DOMAIN_TAG = b"causalfrontier.seeded-uniform-shuffle.v1\0"
AUTHORIZED_ACTION_UNIVERSE_DOMAIN_TAG = b"causalfrontier.authorized-action-universe.v1\0"
FACTOR_SPACE_DOMAIN_TAG = b"causalfrontier.neutral-factor-space.v1\0"
ACTION_PAYLOAD_DOMAIN_TAG = b"causalfrontier.neutral-action-payload.v1\0"
COST_EVENT_DOMAIN_TAG = b"causalfrontier.protocol-cost-event.v1\0"
SCORE_CORE_DOMAIN_TAG = b"causalfrontier.protocol-cost-core.v1\0"
TELEMETRY_DOMAIN_TAG = b"causalfrontier.observational-telemetry.v1\0"
RECEIPT_DOMAIN_TAG = b"causalfrontier.neutral-baseline-receipt.v1\0"
GENESIS = "0" * 64

POLICY_IDS = (
    "SEEDED_SHA256_REJECTION_FISHER_YATES_WITHOUT_REPLACEMENT_V1",
    "BLIND_OFAT_V1",
    "INFORMED_OFAT_V1",
)
RANDOM_POLICY_ID, BLIND_OFAT_POLICY_ID, INFORMED_OFAT_POLICY_ID = POLICY_IDS

COST_DIMENSIONS = (
    "policy_invocations",
    "selection_operations",
    "reset_batches",
    "action_batches",
    "authorized_tool_units",
    "oracle_bytes_delivered",
    "classifier_invocations",
)
RESOURCE_ACCOUNTING_MODE = "SYNTHETIC_STEWARD_DERIVED_PROTOCOL_COUNTERS_NOT_REAL_RESOURCES"
INPUT_TIER = "EXACT_EMBEDDED_DECLARED_PRECOMPILATION_ACTION_AND_AUTHORITY_INPUT_STRUCTURAL_NEUTRALITY_ONLY"
EXECUTION_UNIT = "CASE_LEVEL_ARTIFACT_WITHOUT_ENCODER_DIMENSION_COHORT_UNIQUENESS_UNVERIFIED"
RESET_RULE = "RESET_TO_COMMON_BASELINE_BEFORE_EVERY_ACTION"
MIN_SEEDS = 2
MAX_SEEDS = 128
MAX_FACTORS = 32
MAX_VALUES_PER_FACTOR = 64
MAX_ACTIONS = 2048
MAX_ORDERED_ACTION_REFERENCES = 768
MAX_COUNTER = 10**18

FORBIDDEN_CANDIDATE_DERIVED_KEYS = frozenset(
    {
        "analysis_sha256",
        "co_minimax_action_ids",
        "current_status",
        "decision_separating",
        "eligible_action_ids",
        "frontier",
        "minimax",
        "pareto",
        "selection_projection_sha256",
    }
)

CATALOG_NONCLAIMS = (
    "This catalog is synthetic protocol plumbing, not a scientific baseline result.",
    "The embedded common input proves exact structural action and authority parity, not scientific-dossier format "
    "neutrality, semantic blinding, authorship, or custody.",
    "Execution gates replay from the embedded organizer structure; the truth of its authority declarations remains "
    "unattested.",
    "Factor assignments prove software-level OFAT geometry; they do not prove a valid biological intervention design.",
    "The informed prior is visible to every policy; its authorship, source bytes, and temporal admissibility are "
    "self-declared and unverified.",
    "Protocol counters are not elapsed time, labor, compute consumption, money, or fully loaded real resources.",
    "No outcome, patient datum, material, wet-lab operation, winner, acceleration ratio, or scientific score "
    "is produced.",
)

PLAN_NONCLAIMS = (
    "Seed commitments are bound to the authorized action universe but do not prove when, how, or by whom entropy "
    "was generated or kept secret.",
    "All seed cells are mandatory and no best-seed selection or winner aggregation is permitted.",
    "The artifact has no encoder dimension, but a cohort registry has not yet prevented relabeling or repeated "
    "counting of one case.",
    "The plan binds no oracle, reveal, outcome, patient datum, material action, scientific score, or "
    "acceleration claim.",
)

LOCK_NONCLAIMS = (
    "Opened orders are deterministic software artifacts, not scientific baseline outcomes.",
    "Universe-bound SHA-256 ordering avoids Python RNG drift but does not prove seed custody or unbiased seed "
    "generation.",
    "Blind OFAT uses neutral geometry only; informed OFAT uses the common precommitted prior visible to all policies.",
    "No outcome-adaptive stopping, terminal correctness, winner, ranking, or acceleration ratio is evaluated.",
)

REPORT_NONCLAIMS = (
    "The exercise materializes budgeted action orders without reading or classifying outcomes.",
    "Deterministic protocol counters are synthetic and cannot support a real-resource or 10x acceleration claim.",
    "Observational telemetry is environment-dependent, same-process, incomplete, and excluded from score-core hashes.",
    "No seed, policy, case, or encoder is selected as best; every precommitted seed receipt is retained.",
    "No scientific baseline family is counted as executed and no biological, clinical, patient, or material "
    "claim is made.",
)

VERIFICATION_NONCLAIMS = (
    "Verification proves exact checkpoint and deterministic protocol replay, not scientific validity or impact.",
    "The embedded action, factor, authority, and gate structures agree byte-for-byte through domain-separated "
    "digests; semantic policy neutrality is not established.",
    "No independent witness establishes precompilation timing, source custody, currentness, or rollback protection.",
    "Authority declarations, seed entropy, observational telemetry, real resources, and cohort uniqueness remain "
    "unattested.",
    "No outcome was read and no winner, scientific score, or acceleration ratio was verified.",
)


def _bounded_integer(value: Any, field: str, *, minimum: int = 0, maximum: int = MAX_COUNTER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded integer" % field)
    return value


def _read_checkpointed_json(path: Path, expected_sha256: str, label: str) -> tuple[bytes, dict[str, Any]]:
    require_sha256(expected_sha256, "%s external checkpoint" % label)
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError as exc:
        raise io_error(exc, "%s cannot be read safely" % label, operation="neutral._read_checkpointed_json") from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("%s external checkpoint mismatch" % label)
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    receipt_io._screen(canonical_bytes(value))
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    return raw, value


def _cost_vector(value: Any, field: str) -> dict[str, int]:
    vector = require_exact_keys(value, set(COST_DIMENSIONS), field)
    return {
        dimension: _bounded_integer(vector[dimension], "%s.%s" % (field, dimension)) for dimension in COST_DIMENSIONS
    }


def _zero_cost() -> dict[str, int]:
    return dict.fromkeys(COST_DIMENSIONS, 0)


def _add_cost(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    result = {}
    for dimension in COST_DIMENSIONS:
        total = left[dimension] + right[dimension]
        if total > MAX_COUNTER:
            raise CausalFrontierError("protocol cost counter overflow")
        result[dimension] = total
    return result


def _within_budget(value: dict[str, int], budget: dict[str, int]) -> bool:
    return all(value[dimension] <= budget[dimension] for dimension in COST_DIMENSIONS)


def _increment_fits_budget(used: dict[str, int], debit: dict[str, int], budget: dict[str, int]) -> bool:
    return all(debit[dimension] <= budget[dimension] - used[dimension] for dimension in COST_DIMENSIONS)


def _ensure_checkpointable(value: dict[str, Any], field: str) -> None:
    if len(canonical_bytes(value)) + 1 > MAX_JSON_BYTES:
        raise CausalFrontierError("%s exceeds the exact checkpoint JSON limit" % field)


def _candidate_key_scan(value: Any, field: str = "neutral catalog") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() in FORBIDDEN_CANDIDATE_DERIVED_KEYS:
                raise CausalFrontierError("%s contains forbidden candidate-derived field %s" % (field, key))
            _candidate_key_scan(item, field)
    elif isinstance(value, list):
        for item in value:
            _candidate_key_scan(item, field)


def _validate_common_input(value: Any, case_id: str, knowledge_cutoff: str) -> dict[str, Any]:
    common = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "scope",
            "case_id",
            "knowledge_cutoff",
            "fixed_parameter",
            "boundary",
            "dossier_sha256",
            "source_artifact_sha256s",
            "granted_authorities",
            "gates",
            "factor_space_sha256",
            "actions",
            "candidate_derived_fields_absence_declared",
            "semantic_blinding_verified",
            "common_input_sha256",
        },
        "common policy input",
    )
    if (
        common["schema_version"] != COMMON_INPUT_SCHEMA_VERSION
        or common["status"] != COMMON_INPUT_STATUS
        or common["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or common["case_id"] != case_id
        or common["knowledge_cutoff"] != knowledge_cutoff
        or common["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(common["boundary"]) != canonical_bytes(fixed_boundary())
        or common["candidate_derived_fields_absence_declared"] is not True
        or common["semantic_blinding_verified"] is not False
    ):
        raise CausalFrontierError("common policy input targets another contract or overclaims its boundary")
    require_sha256(common["dossier_sha256"], "common input dossier digest")
    source_digests = common["source_artifact_sha256s"]
    if (
        not isinstance(source_digests, list)
        or not source_digests
        or any(not isinstance(item, str) for item in source_digests)
    ):
        raise CausalFrontierError("common input must bind source artifact digests")
    for digest in source_digests:
        require_sha256(digest, "common input source artifact digest")
    if source_digests != sorted(set(source_digests)):
        raise CausalFrontierError("common input source artifact digests must be unique and canonical")
    granted = common["granted_authorities"]
    if (
        not isinstance(granted, list)
        or not granted
        or any(not isinstance(item, str) for item in granted)
        or granted != sorted(set(granted))
        or not set(granted) <= {"SOFTWARE", "SYNTHETIC_DATA"}
    ):
        raise CausalFrontierError("common input granted authorities are invalid")
    require_sha256(common["factor_space_sha256"], "common input factor-space digest")
    gates_value = common["gates"]
    if not isinstance(gates_value, list) or not gates_value or any(not isinstance(item, dict) for item in gates_value):
        raise CausalFrontierError("common input must declare authority gates")
    gates = []
    gate_ids: set[str] = set()
    for item in gates_value:
        gate = require_exact_keys(item, {"gate_id", "status", "authority"}, "common input gate")
        gate_id = require_id(gate["gate_id"], "common input gate id")
        if gate_id in gate_ids:
            raise CausalFrontierError("common input contains duplicate gates")
        gate_ids.add(gate_id)
        status = require_enum(gate["status"], {"PASS", "OPEN"}, "common input gate status")
        authority = require_enum(gate["authority"], {"SOFTWARE", "SYNTHETIC_DATA"}, "common input gate authority")
        if status == "PASS" and authority not in granted:
            raise CausalFrontierError("common input passes a gate without its authority")
        gates.append({"gate_id": gate_id, "status": status, "authority": authority})
    gates.sort(key=lambda item: item["gate_id"])
    if gates != gates_value:
        raise CausalFrontierError("common input gates must use canonical order")
    actions_value = common["actions"]
    if (
        not isinstance(actions_value, list)
        or not 2 <= len(actions_value) <= MAX_ACTIONS
        or any(not isinstance(item, dict) for item in actions_value)
    ):
        raise CausalFrontierError("common input action inventory must be bounded and nonempty")
    actions = []
    action_ids: set[str] = set()
    for item in actions_value:
        action = require_exact_keys(
            item,
            {
                "action_id",
                "neutral_order_index",
                "execution_class",
                "required_gate_ids",
                "required_authorities",
                "action_payload_sha256",
            },
            "common input action",
        )
        action_id = require_id(action["action_id"], "common input action id")
        if action_id in action_ids:
            raise CausalFrontierError("common input contains duplicate actions")
        action_ids.add(action_id)
        order = _bounded_integer(action["neutral_order_index"], "common input action order", minimum=1)
        execution_class = require_enum(
            action["execution_class"], {"READ_ONLY_COMPUTATION"}, "common input action execution class"
        )
        required_gates = action["required_gate_ids"]
        if (
            not isinstance(required_gates, list)
            or not required_gates
            or any(not isinstance(item, str) for item in required_gates)
            or required_gates != sorted(set(required_gates))
            or not set(required_gates) <= gate_ids
        ):
            raise CausalFrontierError("common input action required gates are invalid")
        required_authorities = action["required_authorities"]
        if (
            not isinstance(required_authorities, list)
            or not required_authorities
            or any(not isinstance(item, str) for item in required_authorities)
            or required_authorities != sorted(set(required_authorities))
            or not set(required_authorities) <= {"SOFTWARE", "SYNTHETIC_DATA"}
        ):
            raise CausalFrontierError("common input action required authorities are invalid")
        action_payload_sha256 = require_sha256(action["action_payload_sha256"], "common input action payload digest")
        actions.append(
            {
                "action_id": action_id,
                "neutral_order_index": order,
                "execution_class": execution_class,
                "required_gate_ids": required_gates,
                "required_authorities": required_authorities,
                "action_payload_sha256": action_payload_sha256,
            }
        )
    _contiguous([item["neutral_order_index"] for item in actions], "common input action order")
    actions.sort(key=lambda item: item["neutral_order_index"])
    if actions != actions_value:
        raise CausalFrontierError("common input actions must use neutral canonical order")
    core = {key: common[key] for key in common if key != "common_input_sha256"}
    require_sha256(common["common_input_sha256"], "common policy input semantic digest")
    if common["common_input_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("common policy input semantic digest mismatch")
    return common


def _derived_execution_gates(common: dict[str, Any]) -> dict[str, dict[str, str]]:
    gate_map = {item["gate_id"]: item for item in common["gates"]}
    granted = set(common["granted_authorities"])
    result = {}
    for action in common["actions"]:
        allowed = set(action["required_authorities"]) <= granted and all(
            gate_map[gate_id]["status"] == "PASS" for gate_id in action["required_gate_ids"]
        )
        result[action["action_id"]] = {
            "status": "PASS" if allowed else "BLOCKED",
            "reason": "DECLARED_AUTHORITY_AND_GATES_PASS" if allowed else "DECLARED_AUTHORITY_OR_GATE_BLOCKED",
        }
    return result


def _contiguous(values: list[int], field: str) -> None:
    if sorted(values) != list(range(1, len(values) + 1)):
        raise CausalFrontierError("%s must be unique contiguous one-based integers" % field)


def _validate_prior(value: Any, factors: list[dict[str, Any]], knowledge_cutoff: str) -> dict[str, Any]:
    prior = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "authorship",
            "knowledge_cutoff",
            "rubric_sha256",
            "source_receipt_sha256s",
            "parameter_priorities",
            "value_priorities",
            "independence_verified",
            "prior_sha256",
        },
        "informed OFAT prior",
    )
    if (
        prior["schema_version"] != PRIOR_SCHEMA_VERSION
        or prior["status"] != "DECLARED_PRE_CUTOFF_SOURCE_DIGESTS_TEMPORAL_VALIDITY_UNVERIFIED"
        or prior["authorship"] != "INDEPENDENT_ORGANIZER_DECLARED_NOT_VERIFIED"
        or prior["independence_verified"] is not False
    ):
        raise CausalFrontierError("informed OFAT prior overclaims its contract")
    cutoff = require_utc_timestamp(prior["knowledge_cutoff"], "informed prior knowledge cutoff")
    if cutoff > knowledge_cutoff:
        raise CausalFrontierError("informed OFAT prior follows the catalog knowledge cutoff")
    require_sha256(prior["rubric_sha256"], "informed prior rubric digest")
    receipts = prior["source_receipt_sha256s"]
    if not isinstance(receipts, list) or not receipts or any(not isinstance(item, str) for item in receipts):
        raise CausalFrontierError("informed prior must bind unique source receipts")
    if len(receipts) != len(set(receipts)):
        raise CausalFrontierError("informed prior must bind unique source receipts")
    for item in receipts:
        require_sha256(item, "informed prior source receipt")
    if receipts != sorted(receipts):
        raise CausalFrontierError("informed prior source receipts must use canonical order")

    factor_map = {item["factor_id"]: item for item in factors}
    parameter_priorities = prior["parameter_priorities"]
    if not isinstance(parameter_priorities, list) or len(parameter_priorities) != len(factors):
        raise CausalFrontierError("informed prior must rank every factor")
    normalized_parameters = []
    seen_factors: set[str] = set()
    for item in parameter_priorities:
        row = require_exact_keys(item, {"factor_id", "rank"}, "informed parameter priority")
        factor_id = require_id(row["factor_id"], "informed priority factor id")
        if factor_id in seen_factors or factor_id not in factor_map:
            raise CausalFrontierError("informed prior contains duplicate or unknown factor")
        seen_factors.add(factor_id)
        normalized_parameters.append({"factor_id": factor_id, "rank": _bounded_integer(row["rank"], "rank", minimum=1)})
    _contiguous([item["rank"] for item in normalized_parameters], "informed parameter ranks")

    value_priorities = prior["value_priorities"]
    expected_pairs = {
        (factor["factor_id"], value["value_id"])
        for factor in factors
        for value in factor["values"]
        if value["value_id"] != factor["baseline_value_id"]
    }
    if not isinstance(value_priorities, list) or len(value_priorities) != len(expected_pairs):
        raise CausalFrontierError("informed prior must rank every nonbaseline factor value")
    normalized_values = []
    seen_pairs: set[tuple[str, str]] = set()
    for item in value_priorities:
        row = require_exact_keys(item, {"factor_id", "value_id", "rank"}, "informed value priority")
        factor_id = require_id(row["factor_id"], "informed value factor id")
        value_id = require_id(row["value_id"], "informed priority value id")
        pair = (factor_id, value_id)
        if pair in seen_pairs or pair not in expected_pairs:
            raise CausalFrontierError("informed prior contains duplicate, baseline, or unknown factor value")
        seen_pairs.add(pair)
        normalized_values.append(
            {"factor_id": factor_id, "value_id": value_id, "rank": _bounded_integer(row["rank"], "rank", minimum=1)}
        )
    for factor in factors:
        ranks = [item["rank"] for item in normalized_values if item["factor_id"] == factor["factor_id"]]
        _contiguous(ranks, "informed value ranks for %s" % factor["factor_id"])

    core = {key: prior[key] for key in prior if key != "prior_sha256"}
    require_sha256(prior["prior_sha256"], "informed prior semantic digest")
    if prior["prior_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("informed OFAT prior semantic digest mismatch")
    normalized = {
        **prior,
        "source_receipt_sha256s": receipts,
        "parameter_priorities": sorted(normalized_parameters, key=lambda item: item["factor_id"]),
        "value_priorities": sorted(normalized_values, key=lambda item: (item["factor_id"], item["value_id"])),
    }
    if canonical_bytes(normalized) != canonical_bytes(prior):
        raise CausalFrontierError("informed OFAT prior inventories must use canonical order")
    return normalized


def validate_neutral_action_catalog(value: Any) -> dict[str, Any]:
    """Validate a complete, organizer-authorized, policy-neutral action substrate."""

    _candidate_key_scan(value)
    catalog = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "scope",
            "base_compiler_version",
            "fixed_parameter",
            "boundary",
            "case_id",
            "knowledge_cutoff",
            "common_input",
            "common_input_sha256",
            "input_tier",
            "execution_unit",
            "execution_gate_basis",
            "reset_rule",
            "resource_accounting_mode",
            "cost_dimensions",
            "budget",
            "factors",
            "baseline_assignment",
            "actions",
            "informed_prior",
            "authorized_action_universe_sha256",
            "candidate_derived_fields_absence_declared",
            "common_input_structural_neutrality_verified",
            "execution_gate_derivation_verified",
            "semantic_policy_neutrality_verified",
            "real_resource_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "catalog_sha256",
        },
        "neutral action catalog",
    )
    if (
        catalog["schema_version"] != CATALOG_SCHEMA_VERSION
        or catalog["status"] != CATALOG_STATUS
        or catalog["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or catalog["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or catalog["base_compiler_version"] != COMPILER_VERSION
        or catalog["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(catalog["boundary"]) != canonical_bytes(fixed_boundary())
        or catalog["input_tier"] != INPUT_TIER
        or catalog["execution_unit"] != EXECUTION_UNIT
        or catalog["execution_gate_basis"] != "ORGANIZER_PRECOMMITTED_AUTHORITY_AND_GATE_CHECKS_ONLY"
        or catalog["reset_rule"] != RESET_RULE
        or catalog["resource_accounting_mode"] != RESOURCE_ACCOUNTING_MODE
        or catalog["cost_dimensions"] != list(COST_DIMENSIONS)
        or catalog["candidate_derived_fields_absence_declared"] is not True
        or catalog["common_input_structural_neutrality_verified"] is not True
        or catalog["execution_gate_derivation_verified"] is not True
        or catalog["semantic_policy_neutrality_verified"] is not False
        or catalog["real_resource_verified"] is not False
        or catalog["scientific_scoring_ready"] is not False
        or catalog["nonclaims"] != list(CATALOG_NONCLAIMS)
    ):
        raise CausalFrontierError("neutral action catalog targets another contract or overclaims its boundary")
    case_id = require_id(catalog["case_id"], "neutral catalog case id")
    knowledge_cutoff = require_utc_timestamp(catalog["knowledge_cutoff"], "neutral catalog knowledge cutoff")
    common = _validate_common_input(catalog["common_input"], case_id, knowledge_cutoff)
    require_sha256(catalog["common_input_sha256"], "common input semantic digest")
    if catalog["common_input_sha256"] != common["common_input_sha256"]:
        raise CausalFrontierError("catalog common-input digest differs from its embedded bytes")
    budget = _cost_vector(catalog["budget"], "neutral catalog budget")

    factors_value = catalog["factors"]
    if (
        not isinstance(factors_value, list)
        or not 1 <= len(factors_value) <= MAX_FACTORS
        or any(not isinstance(item, dict) for item in factors_value)
    ):
        raise CausalFrontierError("neutral catalog factors must be a bounded nonempty object list")
    factors = []
    factor_ids: set[str] = set()
    value_ids_global: set[str] = set()
    for item in factors_value:
        factor = require_exact_keys(
            item,
            {"factor_id", "neutral_order_index", "value_kind", "baseline_value_id", "values"},
            "neutral factor",
        )
        factor_id = require_id(factor["factor_id"], "neutral factor id")
        if factor_id in factor_ids:
            raise CausalFrontierError("neutral catalog contains duplicate factors")
        factor_ids.add(factor_id)
        factor_order = _bounded_integer(factor["neutral_order_index"], "factor neutral order", minimum=1)
        value_kind = require_enum(
            factor["value_kind"],
            {"CATEGORICAL", "ORDINAL"},
            "neutral factor value kind",
        )
        values_value = factor["values"]
        if (
            not isinstance(values_value, list)
            or not 2 <= len(values_value) <= MAX_VALUES_PER_FACTOR
            or any(not isinstance(value, dict) for value in values_value)
        ):
            raise CausalFrontierError("every neutral factor must declare at least two bounded values")
        values = []
        local_ids: set[str] = set()
        for value in values_value:
            row = require_exact_keys(value, {"value_id", "neutral_order_index"}, "neutral factor value")
            value_id = require_id(row["value_id"], "neutral factor value id")
            if value_id in local_ids or value_id in value_ids_global:
                raise CausalFrontierError("neutral value identifiers must be globally unique")
            local_ids.add(value_id)
            value_ids_global.add(value_id)
            values.append(
                {
                    "value_id": value_id,
                    "neutral_order_index": _bounded_integer(
                        row["neutral_order_index"], "value neutral order", minimum=1
                    ),
                }
            )
        _contiguous([value["neutral_order_index"] for value in values], "neutral value order")
        baseline_value_id = require_id(factor["baseline_value_id"], "neutral baseline value id")
        if baseline_value_id not in local_ids:
            raise CausalFrontierError("neutral factor baseline value is absent")
        factors.append(
            {
                "factor_id": factor_id,
                "neutral_order_index": factor_order,
                "value_kind": value_kind,
                "baseline_value_id": baseline_value_id,
                "values": sorted(values, key=lambda value: value["neutral_order_index"]),
            }
        )
    _contiguous([factor["neutral_order_index"] for factor in factors], "neutral factor order")
    factors.sort(key=lambda factor: factor["neutral_order_index"])
    if factors != factors_value:
        raise CausalFrontierError("neutral factors and values must use neutral canonical order")

    baseline_value = catalog["baseline_assignment"]
    if not isinstance(baseline_value, list) or len(baseline_value) != len(factors):
        raise CausalFrontierError("neutral baseline assignment must cover every factor")
    baseline = {}
    normalized_baseline = []
    factor_by_id = {factor["factor_id"]: factor for factor in factors}
    for item in baseline_value:
        row = require_exact_keys(item, {"factor_id", "value_id"}, "neutral baseline assignment")
        factor_id = require_id(row["factor_id"], "neutral baseline factor id")
        value_id = require_id(row["value_id"], "neutral baseline value id")
        if factor_id in baseline or factor_id not in factor_by_id:
            raise CausalFrontierError("neutral baseline contains duplicate or unknown factor")
        if value_id != factor_by_id[factor_id]["baseline_value_id"]:
            raise CausalFrontierError("neutral baseline assignment differs from factor baseline")
        baseline[factor_id] = value_id
        normalized_baseline.append({"factor_id": factor_id, "value_id": value_id})
    normalized_baseline.sort(key=lambda item: factor_by_id[item["factor_id"]]["neutral_order_index"])
    if normalized_baseline != baseline_value:
        raise CausalFrontierError("neutral baseline assignment must use factor order")
    factor_space_core = {"factors": factors, "baseline_assignment": normalized_baseline}
    if common["factor_space_sha256"] != sha256_bytes(FACTOR_SPACE_DOMAIN_TAG + canonical_bytes(factor_space_core)):
        raise CausalFrontierError("neutral factor space differs from the common input")

    actions_value = catalog["actions"]
    if (
        not isinstance(actions_value, list)
        or not 2 <= len(actions_value) <= MAX_ACTIONS
        or any(not isinstance(item, dict) for item in actions_value)
    ):
        raise CausalFrontierError("neutral catalog actions must be a bounded object list")
    actions = []
    action_ids: set[str] = set()
    assignments: set[tuple[tuple[str, str], ...]] = set()
    ofat_coordinates: dict[tuple[str, str], str] = {}
    common_action_by_id = {action["action_id"]: action for action in common["actions"]}
    expected_execution_gates = _derived_execution_gates(common)
    for item in actions_value:
        action = require_exact_keys(
            item,
            {
                "action_id",
                "neutral_order_index",
                "assignment",
                "execution_gate",
                "action_tariff",
                "reset_tariff",
            },
            "neutral action",
        )
        action_id = require_id(action["action_id"], "neutral action id")
        if action_id in action_ids:
            raise CausalFrontierError("neutral catalog contains duplicate actions")
        action_ids.add(action_id)
        order = _bounded_integer(action["neutral_order_index"], "action neutral order", minimum=1)
        assignment_value = action["assignment"]
        if not isinstance(assignment_value, list) or len(assignment_value) != len(factors):
            raise CausalFrontierError("every neutral action assignment must cover every factor")
        assignment = {}
        normalized_assignment = []
        for coordinate in assignment_value:
            row = require_exact_keys(coordinate, {"factor_id", "value_id"}, "neutral action assignment")
            factor_id = require_id(row["factor_id"], "neutral action factor id")
            value_id = require_id(row["value_id"], "neutral action value id")
            factor = factor_by_id.get(factor_id)
            legal_values = set() if factor is None else {value["value_id"] for value in factor["values"]}
            if factor_id in assignment or factor is None or value_id not in legal_values:
                raise CausalFrontierError("neutral action assignment has duplicate or unknown coordinate")
            assignment[factor_id] = value_id
            normalized_assignment.append({"factor_id": factor_id, "value_id": value_id})
        normalized_assignment.sort(key=lambda row: factor_by_id[row["factor_id"]]["neutral_order_index"])
        if normalized_assignment != assignment_value:
            raise CausalFrontierError("neutral action assignments must use factor order")
        assignment_key = tuple((row["factor_id"], row["value_id"]) for row in normalized_assignment)
        if assignment_key in assignments:
            raise CausalFrontierError("neutral action catalog contains duplicate assignments")
        assignments.add(assignment_key)
        gate = require_exact_keys(action["execution_gate"], {"status", "reason"}, "neutral execution gate")
        gate_status = require_enum(gate["status"], {"PASS", "BLOCKED"}, "neutral execution gate status")
        gate_reason = require_id(gate["reason"], "neutral execution gate reason")
        expected_gate = expected_execution_gates.get(action_id)
        if expected_gate is None:
            raise CausalFrontierError("neutral catalog action is absent from the common input")
        if {"status": gate_status, "reason": gate_reason} != expected_gate:
            raise CausalFrontierError("neutral execution gate does not replay from the common input")
        action_tariff = _cost_vector(action["action_tariff"], "neutral action tariff")
        reset_tariff = _cost_vector(action["reset_tariff"], "neutral reset tariff")
        if (
            action_tariff["action_batches"] != 1
            or action_tariff["reset_batches"] != 0
            or action_tariff["policy_invocations"] != 0
            or action_tariff["selection_operations"] != 0
            or reset_tariff["reset_batches"] != 1
            or reset_tariff["action_batches"] != 0
            or reset_tariff["policy_invocations"] != 0
            or reset_tariff["selection_operations"] != 0
            or action_tariff["oracle_bytes_delivered"] != 0
            or action_tariff["classifier_invocations"] != 0
            or reset_tariff["oracle_bytes_delivered"] != 0
            or reset_tariff["classifier_invocations"] != 0
        ):
            raise CausalFrontierError("action and reset tariffs must charge exactly their declared batch")
        _add_cost(reset_tariff, action_tariff)
        action_payload_core = {
            "action_id": action_id,
            "assignment": normalized_assignment,
            "action_tariff": action_tariff,
            "reset_tariff": reset_tariff,
        }
        if common_action_by_id[action_id]["action_payload_sha256"] != sha256_bytes(
            ACTION_PAYLOAD_DOMAIN_TAG + canonical_bytes(action_payload_core)
        ):
            raise CausalFrontierError("neutral action payload differs from the common input")
        changed = [factor_id for factor_id in baseline if assignment[factor_id] != baseline[factor_id]]
        if not changed:
            raise CausalFrontierError("neutral action cannot duplicate the common baseline assignment")
        if gate_status == "PASS" and len(changed) == 1:
            coordinate = (changed[0], assignment[changed[0]])
            if coordinate in ofat_coordinates:
                raise CausalFrontierError("authorized OFAT coordinate has more than one action")
            ofat_coordinates[coordinate] = action_id
        actions.append(
            {
                "action_id": action_id,
                "neutral_order_index": order,
                "assignment": normalized_assignment,
                "execution_gate": {"status": gate_status, "reason": gate_reason},
                "action_tariff": action_tariff,
                "reset_tariff": reset_tariff,
            }
        )
    _contiguous([action["neutral_order_index"] for action in actions], "neutral action order")
    actions.sort(key=lambda action: action["neutral_order_index"])
    if actions != actions_value:
        raise CausalFrontierError("neutral actions must use neutral canonical order")
    if [
        {"action_id": action["action_id"], "neutral_order_index": action["neutral_order_index"]} for action in actions
    ] != [
        {"action_id": action["action_id"], "neutral_order_index": action["neutral_order_index"]}
        for action in common["actions"]
    ]:
        raise CausalFrontierError("neutral catalog action inventory differs from the common input")
    expected_ofat = {
        (factor["factor_id"], value["value_id"])
        for factor in factors
        for value in factor["values"]
        if value["value_id"] != factor["baseline_value_id"]
    }
    if set(ofat_coordinates) != expected_ofat:
        raise CausalFrontierError(
            "authorized catalog must contain exactly one single-factor action for every nonbaseline value"
        )
    if len([action for action in actions if action["execution_gate"]["status"] == "PASS"]) < 2:
        raise CausalFrontierError("neutral catalog needs at least two organizer-authorized actions")

    authorized_action_universe_core = {
        "case_id": catalog["case_id"],
        "factor_space_sha256": common["factor_space_sha256"],
        "authorized_actions": sorted(
            (
                {
                    "action_id": action["action_id"],
                    "action_payload_sha256": common_action_by_id[action["action_id"]]["action_payload_sha256"],
                }
                for action in actions
                if action["execution_gate"]["status"] == "PASS"
            ),
            key=lambda item: item["action_id"],
        ),
    }
    require_sha256(catalog["authorized_action_universe_sha256"], "authorized action universe digest")
    if catalog["authorized_action_universe_sha256"] != sha256_bytes(
        AUTHORIZED_ACTION_UNIVERSE_DOMAIN_TAG + canonical_bytes(authorized_action_universe_core)
    ):
        raise CausalFrontierError("authorized action universe digest mismatch")

    overhead = _zero_cost()
    overhead["policy_invocations"] = 1
    overhead["selection_operations"] = len(actions)
    if not _within_budget(overhead, budget):
        raise CausalFrontierError("neutral catalog budget cannot fund one full policy scan")

    action_by_id = {action["action_id"]: action for action in actions}
    full_ofat_cost = overhead
    for action_id in ofat_coordinates.values():
        action = action_by_id[action_id]
        full_ofat_cost = _add_cost(full_ofat_cost, _add_cost(action["reset_tariff"], action["action_tariff"]))
    if not _within_budget(full_ofat_cost, budget):
        raise CausalFrontierError("neutral catalog budget must fund the complete blind and informed OFAT set")

    prior = _validate_prior(catalog["informed_prior"], factors, knowledge_cutoff)
    core = {key: catalog[key] for key in catalog if key != "catalog_sha256"}
    require_sha256(catalog["catalog_sha256"], "neutral catalog semantic digest")
    if catalog["catalog_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("neutral action catalog semantic digest mismatch")
    normalized = {
        **catalog,
        "budget": budget,
        "factors": factors,
        "baseline_assignment": normalized_baseline,
        "actions": actions,
        "informed_prior": prior,
    }
    if canonical_bytes(normalized) != canonical_bytes(catalog):
        raise CausalFrontierError("neutral action catalog is not canonical")
    return normalized


def load_neutral_action_catalog(path: Path, expected_checkpoint_sha256: str) -> dict[str, Any]:
    """Load and validate exact checkpointed catalog bytes."""

    _raw, value = _read_checkpointed_json(path, expected_checkpoint_sha256, "neutral action catalog")
    return validate_neutral_action_catalog(value)


def seed_commitment_sha256(seed: bytes, authorized_action_universe_sha256: str) -> str:
    """Commit one exact 256-bit seed to one authorized action universe."""

    if not isinstance(seed, bytes) or len(seed) != 32:
        raise CausalFrontierError("baseline seed must be exactly 32 bytes")
    universe = require_sha256(authorized_action_universe_sha256, "authorized action universe digest")
    return sha256_bytes(SEED_COMMITMENT_DOMAIN_TAG + bytes.fromhex(universe) + seed)


def _seed_schedule(value: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not MIN_SEEDS <= len(value) <= MAX_SEEDS
        or any(not isinstance(item, dict) for item in value)
    ):
        raise CausalFrontierError("seed schedule must contain a bounded multi-seed commitment set")
    result = []
    commitments: set[str] = set()
    for item in value:
        row = require_exact_keys(item, {"seed_index", "seed_commitment_sha256"}, "seed schedule item")
        index = _bounded_integer(row["seed_index"], "seed index", minimum=1, maximum=MAX_SEEDS)
        commitment = require_sha256(row["seed_commitment_sha256"], "seed commitment")
        if commitment in commitments:
            raise CausalFrontierError("seed commitments must be unique")
        commitments.add(commitment)
        result.append({"seed_index": index, "seed_commitment_sha256": commitment})
    _contiguous([item["seed_index"] for item in result], "seed schedule indices")
    result.sort(key=lambda item: item["seed_index"])
    if result != value:
        raise CausalFrontierError("seed schedule must use seed-index order")
    return result


def prepare_neutral_baseline_plan(
    catalog_path: Path,
    expected_catalog_checkpoint_sha256: str,
    seed_commitments: Sequence[str],
) -> dict[str, Any]:
    """Freeze the case-level baseline matrix without opening seeds or an oracle."""

    catalog = load_neutral_action_catalog(catalog_path, expected_catalog_checkpoint_sha256)
    if isinstance(seed_commitments, (str, bytes)):
        raise CausalFrontierError("seed commitments must be a sequence of digests")
    schedule = _seed_schedule(
        [
            {"seed_index": index, "seed_commitment_sha256": require_sha256(value, "seed commitment")}
            for index, value in enumerate(seed_commitments, start=1)
        ]
    )
    matrix = [
        {
            "policy_id": RANDOM_POLICY_ID,
            "seed_index": item["seed_index"],
            "seed_commitment_sha256": item["seed_commitment_sha256"],
        }
        for item in schedule
    ] + [
        {"policy_id": BLIND_OFAT_POLICY_ID, "seed_index": None, "seed_commitment_sha256": None},
        {"policy_id": INFORMED_OFAT_POLICY_ID, "seed_index": None, "seed_commitment_sha256": None},
    ]
    ordered_references = len(_authorized_actions(catalog)) * len(schedule) + 2 * len(_ofat_action_map(catalog))
    if ordered_references > MAX_ORDERED_ACTION_REFERENCES:
        raise CausalFrontierError("neutral baseline matrix exceeds the checkpointable action-reference limit")
    core = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "status": PLAN_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "case_id": catalog["case_id"],
        "catalog_checkpoint_sha256": expected_catalog_checkpoint_sha256,
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "input_tier": INPUT_TIER,
        "execution_unit": EXECUTION_UNIT,
        "reset_rule": RESET_RULE,
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "cost_dimensions": list(COST_DIMENSIONS),
        "budget": catalog["budget"],
        "policy_ids": list(POLICY_IDS),
        "seed_schedule": schedule,
        "seeds_opened_during_planning": False,
        "oracle_read_during_planning": False,
        "matrix_cells": matrix,
        "matrix_cells_n": len(matrix),
        "random_aggregation_rule": "REPORT_EVERY_SEED_NO_BEST_SEED_SELECTION",
        "scientific_baseline_families_executed": [],
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "real_resource_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(PLAN_NONCLAIMS),
    }
    result = {**core, "plan_sha256": sha256_bytes(canonical_bytes(core))}
    _ensure_checkpointable(result, "neutral baseline plan")
    return result


def _validate_plan(value: Any, catalog: dict[str, Any], checkpoint_sha256: str) -> dict[str, Any]:
    plan = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "fixed_parameter",
            "boundary",
            "case_id",
            "catalog_checkpoint_sha256",
            "catalog_sha256",
            "common_input_sha256",
            "input_tier",
            "execution_unit",
            "reset_rule",
            "resource_accounting_mode",
            "cost_dimensions",
            "budget",
            "policy_ids",
            "seed_schedule",
            "seeds_opened_during_planning",
            "oracle_read_during_planning",
            "matrix_cells",
            "matrix_cells_n",
            "random_aggregation_rule",
            "scientific_baseline_families_executed",
            "winner",
            "ranking",
            "acceleration_ratio",
            "real_resource_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "plan_sha256",
        },
        "neutral baseline plan",
    )
    if (
        plan["schema_version"] != PLAN_SCHEMA_VERSION
        or plan["status"] != PLAN_STATUS
        or plan["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or plan["base_compiler_version"] != COMPILER_VERSION
        or plan["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(plan["boundary"]) != canonical_bytes(fixed_boundary())
        or plan["case_id"] != catalog["case_id"]
        or plan["catalog_checkpoint_sha256"] != checkpoint_sha256
        or plan["catalog_sha256"] != catalog["catalog_sha256"]
        or plan["common_input_sha256"] != catalog["common_input_sha256"]
        or plan["input_tier"] != INPUT_TIER
        or plan["execution_unit"] != EXECUTION_UNIT
        or plan["reset_rule"] != RESET_RULE
        or plan["resource_accounting_mode"] != RESOURCE_ACCOUNTING_MODE
        or plan["cost_dimensions"] != list(COST_DIMENSIONS)
        or plan["budget"] != catalog["budget"]
        or plan["policy_ids"] != list(POLICY_IDS)
        or plan["seeds_opened_during_planning"] is not False
        or plan["oracle_read_during_planning"] is not False
        or plan["random_aggregation_rule"] != "REPORT_EVERY_SEED_NO_BEST_SEED_SELECTION"
        or plan["scientific_baseline_families_executed"] != []
        or plan["winner"] is not None
        or plan["ranking"] != []
        or plan["acceleration_ratio"] is not None
        or plan["real_resource_verified"] is not False
        or plan["scientific_scoring_ready"] is not False
        or plan["nonclaims"] != list(PLAN_NONCLAIMS)
    ):
        raise CausalFrontierError("neutral baseline plan targets another contract or overclaims its boundary")
    schedule = _seed_schedule(plan["seed_schedule"])
    expected_matrix = [
        {
            "policy_id": RANDOM_POLICY_ID,
            "seed_index": item["seed_index"],
            "seed_commitment_sha256": item["seed_commitment_sha256"],
        }
        for item in schedule
    ] + [
        {"policy_id": BLIND_OFAT_POLICY_ID, "seed_index": None, "seed_commitment_sha256": None},
        {"policy_id": INFORMED_OFAT_POLICY_ID, "seed_index": None, "seed_commitment_sha256": None},
    ]
    if plan["matrix_cells"] != expected_matrix or plan["matrix_cells_n"] != len(expected_matrix):
        raise CausalFrontierError("neutral baseline plan matrix is incomplete or reordered")
    ordered_references = len(_authorized_actions(catalog)) * len(schedule) + 2 * len(_ofat_action_map(catalog))
    if ordered_references > MAX_ORDERED_ACTION_REFERENCES:
        raise CausalFrontierError("neutral baseline matrix exceeds the checkpointable action-reference limit")
    _cost_vector(plan["budget"], "neutral baseline plan budget")
    require_sha256(plan["plan_sha256"], "neutral baseline plan semantic digest")
    core = {key: plan[key] for key in plan if key != "plan_sha256"}
    if plan["plan_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("neutral baseline plan semantic digest mismatch")
    return plan


def _load_plan(
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
    catalog: dict[str, Any],
    catalog_checkpoint_sha256: str,
) -> dict[str, Any]:
    _raw, value = _read_checkpointed_json(plan_path, expected_plan_checkpoint_sha256, "neutral baseline plan")
    return _validate_plan(value, catalog, catalog_checkpoint_sha256)


def _authorized_actions(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return [action for action in catalog["actions"] if action["execution_gate"]["status"] == "PASS"]


def _ofat_action_map(catalog: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    baseline = {item["factor_id"]: item["value_id"] for item in catalog["baseline_assignment"]}
    result = {}
    for action in _authorized_actions(catalog):
        assignment = {item["factor_id"]: item["value_id"] for item in action["assignment"]}
        changed = [factor_id for factor_id in baseline if assignment[factor_id] != baseline[factor_id]]
        if len(changed) == 1:
            result[(changed[0], assignment[changed[0]])] = action
    return result


def _draw_below(seed: bytes, universe: bytes, bound: int, counter: int) -> tuple[int, int]:
    if not 1 <= bound <= MAX_ACTIONS:
        raise CausalFrontierError("random shuffle bound is invalid")
    modulus = 1 << 256
    rejection_limit = modulus - (modulus % bound)
    while True:
        if counter >= 1 << 64:
            raise CausalFrontierError("random shuffle counter exhausted")
        block = bytes.fromhex(sha256_bytes(RANDOM_ORDER_DOMAIN_TAG + seed + universe + counter.to_bytes(8, "big")))
        counter += 1
        candidate = int.from_bytes(block, "big")
        if candidate < rejection_limit:
            return candidate % bound, counter


def _random_order(catalog: dict[str, Any], seed: bytes) -> list[str]:
    universe = bytes.fromhex(catalog["authorized_action_universe_sha256"])
    result = sorted(action["action_id"] for action in _authorized_actions(catalog))
    counter = 0
    for index in range(len(result) - 1, 0, -1):
        swap_index, counter = _draw_below(seed, universe, index + 1, counter)
        result[index], result[swap_index] = result[swap_index], result[index]
    return result


def _blind_ofat_order(catalog: dict[str, Any]) -> list[str]:
    actions = _ofat_action_map(catalog)
    result = []
    for factor in catalog["factors"]:
        for value in factor["values"]:
            if value["value_id"] != factor["baseline_value_id"]:
                result.append(actions[(factor["factor_id"], value["value_id"])]["action_id"])
    return result


def _informed_ofat_order(catalog: dict[str, Any]) -> list[str]:
    actions = _ofat_action_map(catalog)
    prior = catalog["informed_prior"]
    parameter_rank = {item["factor_id"]: item["rank"] for item in prior["parameter_priorities"]}
    value_rank = {(item["factor_id"], item["value_id"]): item["rank"] for item in prior["value_priorities"]}
    factor_order = {item["factor_id"]: item["neutral_order_index"] for item in catalog["factors"]}
    value_order = {
        (factor["factor_id"], value["value_id"]): value["neutral_order_index"]
        for factor in catalog["factors"]
        for value in factor["values"]
    }
    coordinates = sorted(
        actions,
        key=lambda item: (
            parameter_rank[item[0]],
            value_rank[item],
            factor_order[item[0]],
            value_order[item],
        ),
    )
    return [actions[item]["action_id"] for item in coordinates]


def _trace(
    catalog: dict[str, Any],
    plan: dict[str, Any],
    policy_id: str,
    ordered_action_ids: list[str],
    seed_index: int | None,
    seed_commitment: str | None,
    seed_hex: str | None,
) -> dict[str, Any]:
    core = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "case_id": catalog["case_id"],
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "policy_id": policy_id,
        "seed_index": seed_index,
        "seed_commitment_sha256": seed_commitment,
        "seed_hex": seed_hex,
        "ordered_action_ids": ordered_action_ids,
        "reset_rule": RESET_RULE,
        "outcome_read": False,
        "winner_selection_enabled": False,
        "scientific_scoring_ready": False,
    }
    return {**core, "trace_sha256": sha256_bytes(canonical_bytes(core))}


def lock_neutral_baseline_orders(
    catalog_path: Path,
    expected_catalog_checkpoint_sha256: str,
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
    seed_openings: Sequence[bytes],
) -> dict[str, Any]:
    """Open every committed seed and lock random, blind-OFAT, and informed-OFAT orders."""

    catalog = load_neutral_action_catalog(catalog_path, expected_catalog_checkpoint_sha256)
    plan = _load_plan(plan_path, expected_plan_checkpoint_sha256, catalog, expected_catalog_checkpoint_sha256)
    if isinstance(seed_openings, (str, bytes)) or len(seed_openings) != len(plan["seed_schedule"]):
        raise CausalFrontierError("seed openings must exactly match the precommitted schedule")
    traces = []
    seen_seeds: set[bytes] = set()
    for schedule, seed in zip(plan["seed_schedule"], seed_openings, strict=True):
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise CausalFrontierError("every baseline seed opening must be exactly 32 bytes")
        if seed in seen_seeds:
            raise CausalFrontierError("baseline seed openings must be unique")
        seen_seeds.add(seed)
        commitment = seed_commitment_sha256(seed, catalog["authorized_action_universe_sha256"])
        if commitment != schedule["seed_commitment_sha256"]:
            raise CausalFrontierError("baseline seed opening does not match its precommitment")
        traces.append(
            _trace(
                catalog,
                plan,
                RANDOM_POLICY_ID,
                _random_order(catalog, seed),
                schedule["seed_index"],
                commitment,
                seed.hex(),
            )
        )
    traces.append(_trace(catalog, plan, BLIND_OFAT_POLICY_ID, _blind_ofat_order(catalog), None, None, None))
    traces.append(_trace(catalog, plan, INFORMED_OFAT_POLICY_ID, _informed_ofat_order(catalog), None, None, None))
    core = {
        "schema_version": LOCK_SCHEMA_VERSION,
        "status": LOCK_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "case_id": catalog["case_id"],
        "catalog_checkpoint_sha256": expected_catalog_checkpoint_sha256,
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "seed_openings_n": len(seed_openings),
        "all_precommitted_seeds_opened": True,
        "oracle_read": False,
        "traces": traces,
        "traces_n": len(traces),
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "scientific_scoring_ready": False,
        "nonclaims": list(LOCK_NONCLAIMS),
    }
    result = {**core, "lock_sha256": sha256_bytes(canonical_bytes(core))}
    _ensure_checkpointable(result, "neutral baseline order lock")
    return result


def _expected_traces(
    catalog: dict[str, Any], plan: dict[str, Any], value: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(plan["matrix_cells"]):
        raise CausalFrontierError("neutral baseline order lock has an incomplete trace matrix")
    expected = []
    for schedule, supplied in zip(plan["seed_schedule"], value[: len(plan["seed_schedule"])], strict=True):
        if not isinstance(supplied, dict):
            raise CausalFrontierError("neutral baseline traces must be objects")
        seed_hex = supplied.get("seed_hex")
        if not isinstance(seed_hex, str) or len(seed_hex) != 64:
            raise CausalFrontierError("random trace must reveal one lowercase 256-bit seed")
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise CausalFrontierError("random trace seed opening is invalid") from None
        if (
            seed.hex() != seed_hex
            or seed_commitment_sha256(seed, catalog["authorized_action_universe_sha256"])
            != schedule["seed_commitment_sha256"]
        ):
            raise CausalFrontierError("random trace seed opening does not match its precommitment")
        expected.append(
            _trace(
                catalog,
                plan,
                RANDOM_POLICY_ID,
                _random_order(catalog, seed),
                schedule["seed_index"],
                schedule["seed_commitment_sha256"],
                seed_hex,
            )
        )
    expected.extend(
        [
            _trace(catalog, plan, BLIND_OFAT_POLICY_ID, _blind_ofat_order(catalog), None, None, None),
            _trace(catalog, plan, INFORMED_OFAT_POLICY_ID, _informed_ofat_order(catalog), None, None, None),
        ]
    )
    if canonical_bytes(expected) != canonical_bytes(value):
        raise CausalFrontierError("neutral baseline traces do not replay from catalog, plan, and opened seeds")
    return expected


def _validate_lock(
    value: Any,
    catalog: dict[str, Any],
    catalog_checkpoint_sha256: str,
    plan: dict[str, Any],
    plan_checkpoint_sha256: str,
) -> dict[str, Any]:
    lock = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "fixed_parameter",
            "boundary",
            "case_id",
            "catalog_checkpoint_sha256",
            "catalog_sha256",
            "common_input_sha256",
            "plan_checkpoint_sha256",
            "plan_sha256",
            "seed_openings_n",
            "all_precommitted_seeds_opened",
            "oracle_read",
            "traces",
            "traces_n",
            "winner",
            "ranking",
            "acceleration_ratio",
            "scientific_scoring_ready",
            "nonclaims",
            "lock_sha256",
        },
        "neutral baseline order lock",
    )
    if (
        lock["schema_version"] != LOCK_SCHEMA_VERSION
        or lock["status"] != LOCK_STATUS
        or lock["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or lock["base_compiler_version"] != COMPILER_VERSION
        or lock["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(lock["boundary"]) != canonical_bytes(fixed_boundary())
        or lock["case_id"] != catalog["case_id"]
        or lock["catalog_checkpoint_sha256"] != catalog_checkpoint_sha256
        or lock["catalog_sha256"] != catalog["catalog_sha256"]
        or lock["common_input_sha256"] != catalog["common_input_sha256"]
        or lock["plan_checkpoint_sha256"] != plan_checkpoint_sha256
        or lock["plan_sha256"] != plan["plan_sha256"]
        or lock["seed_openings_n"] != len(plan["seed_schedule"])
        or lock["all_precommitted_seeds_opened"] is not True
        or lock["oracle_read"] is not False
        or lock["traces_n"] != len(plan["matrix_cells"])
        or lock["winner"] is not None
        or lock["ranking"] != []
        or lock["acceleration_ratio"] is not None
        or lock["scientific_scoring_ready"] is not False
        or lock["nonclaims"] != list(LOCK_NONCLAIMS)
    ):
        raise CausalFrontierError("neutral baseline order lock targets another contract or overclaims its boundary")
    _expected_traces(catalog, plan, lock["traces"])
    require_sha256(lock["lock_sha256"], "neutral baseline lock semantic digest")
    core = {key: lock[key] for key in lock if key != "lock_sha256"}
    if lock["lock_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("neutral baseline order lock semantic digest mismatch")
    return lock


def _load_lock(
    lock_path: Path,
    expected_lock_checkpoint_sha256: str,
    catalog: dict[str, Any],
    catalog_checkpoint_sha256: str,
    plan: dict[str, Any],
    plan_checkpoint_sha256: str,
) -> dict[str, Any]:
    _raw, value = _read_checkpointed_json(lock_path, expected_lock_checkpoint_sha256, "neutral baseline order lock")
    return _validate_lock(value, catalog, catalog_checkpoint_sha256, plan, plan_checkpoint_sha256)


def _cost_event(
    events: list[dict[str, Any]],
    kind: str,
    action_id: str | None,
    debit: dict[str, int],
    before: dict[str, int],
    after: dict[str, int],
) -> None:
    previous = GENESIS if not events else events[-1]["digest"]
    core = {
        "seq": len(events) + 1,
        "prev_digest": previous,
        "kind": kind,
        "action_id": action_id,
        "debit": debit,
        "resources_before": before,
        "resources_after": after,
    }
    events.append({**core, "digest": sha256_bytes(COST_EVENT_DOMAIN_TAG + canonical_bytes(core))})


def _score_core(
    catalog: dict[str, Any], plan: dict[str, Any], lock: dict[str, Any], trace: dict[str, Any]
) -> dict[str, Any]:
    budget = catalog["budget"]
    action_map = {action["action_id"]: action for action in _authorized_actions(catalog)}
    used = _zero_cost()
    events: list[dict[str, Any]] = []
    overhead = _zero_cost()
    overhead["policy_invocations"] = 1
    overhead["selection_operations"] = len(catalog["actions"])
    after_overhead = _add_cost(used, overhead)
    if not _within_budget(after_overhead, budget):
        raise CausalFrontierError("validated catalog cannot fund its policy overhead")
    _cost_event(events, "POLICY_SELECTION", None, overhead, used, after_overhead)
    used = after_overhead
    executed = []
    skipped = []
    for action_id in trace["ordered_action_ids"]:
        action = action_map.get(action_id)
        if action is None:
            raise CausalFrontierError("neutral baseline trace references unauthorized action")
        pair_cost = _add_cost(action["reset_tariff"], action["action_tariff"])
        if not _increment_fits_budget(used, pair_cost, budget):
            skipped.append({"action_id": action_id, "reason": "BUDGET_NOT_AFFORDABLE"})
            continue
        after_reset = _add_cost(used, action["reset_tariff"])
        _cost_event(events, "RESET_TO_COMMON_BASELINE", action_id, action["reset_tariff"], used, after_reset)
        after_action = _add_cost(after_reset, action["action_tariff"])
        _cost_event(events, "ACTION_PROTOCOL_BATCH", action_id, action["action_tariff"], after_reset, after_action)
        used = after_action
        executed.append(action_id)
    if skipped and not executed:
        terminal = "BUDGET_CENSORED_NO_ACTION_AFFORDABLE"
    elif skipped:
        terminal = "ORDER_EXHAUSTED_WITH_BUDGET_SKIPS"
    else:
        terminal = "ORDER_EXHAUSTED"
    return {
        "schema_version": SCORE_CORE_SCHEMA_VERSION,
        "case_id": catalog["case_id"],
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "lock_sha256": lock["lock_sha256"],
        "trace_sha256": trace["trace_sha256"],
        "policy_id": trace["policy_id"],
        "seed_index": trace["seed_index"],
        "seed_commitment_sha256": trace["seed_commitment_sha256"],
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "budget": budget,
        "events": events,
        "event_ledger_head": events[-1]["digest"],
        "ordered_action_ids": trace["ordered_action_ids"],
        "executed_action_ids": executed,
        "skipped_actions": skipped,
        "resources_used": used,
        "terminal_kind": terminal,
        "outcome_read": False,
        "protocol_replay_eligible": True,
        "real_resource_verified": False,
        "scientific_acceleration_eligible": False,
        "scientific_scoring_ready": False,
    }


def _resource_snapshot() -> tuple[int | None, int | None, int | None, str]:
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
    except (ImportError, OSError, ValueError):
        return None, None, None, "UNAVAILABLE"
    system = platform.system()
    unit = "BYTES" if system == "Darwin" else "KIBIBYTES" if system == "Linux" else "PLATFORM_DEFINED_UNKNOWN"
    return int(usage.ru_utime * 1_000_000), int(usage.ru_stime * 1_000_000), int(usage.ru_maxrss), unit


def _empty_telemetry() -> dict[str, Any]:
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "status": "NOT_CAPTURED",
        "score_relevant": False,
        "provider": "NONE",
        "scope": "NONE",
        "platform": "NOT_RECORDED",
        "python_implementation": "NOT_RECORDED",
        "python_version": "NOT_RECORDED",
        "wall_elapsed_ns": None,
        "process_cpu_elapsed_ns": None,
        "self_user_cpu_us": None,
        "self_system_cpu_us": None,
        "max_rss_raw_start": None,
        "max_rss_raw_end": None,
        "max_rss_raw_unit": "UNAVAILABLE",
        "process_tree_complete": False,
        "measurement_trust": "UNVERIFIED",
    }


def _captured_telemetry(
    wall_start: int,
    cpu_start: int,
    resource_start: tuple[int | None, int | None, int | None, str],
    wall_end: int,
    cpu_end: int,
    resource_end: tuple[int | None, int | None, int | None, str],
) -> dict[str, Any]:
    if wall_end < wall_start or cpu_end < cpu_start:
        raise CausalFrontierError("observational telemetry clock moved backwards")
    start_user, start_system, start_rss, start_unit = resource_start
    end_user, end_system, end_rss, end_unit = resource_end
    if start_unit != end_unit:
        raise CausalFrontierError("observational RSS unit changed during capture")
    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "status": "DECLARED_SAME_PROCESS_OBSERVATION_AUTHENTICITY_UNVERIFIED",
        "score_relevant": False,
        "provider": "PYTHON_STDLIB_TIME_AND_OPTIONAL_RESOURCE",
        "scope": "CURRENT_PROCESS_CUMULATIVE_NOT_ISOLATED",
        "platform": platform.system() or "UNKNOWN",
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "wall_elapsed_ns": wall_end - wall_start,
        "process_cpu_elapsed_ns": cpu_end - cpu_start,
        "self_user_cpu_us": None if start_user is None or end_user is None else end_user - start_user,
        "self_system_cpu_us": None if start_system is None or end_system is None else end_system - start_system,
        "max_rss_raw_start": start_rss,
        "max_rss_raw_end": end_rss,
        "max_rss_raw_unit": start_unit,
        "process_tree_complete": False,
        "measurement_trust": "UNVERIFIED",
    }


def _validate_optional_counter(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _bounded_integer(value, field)


def _validate_telemetry(value: Any) -> dict[str, Any]:
    telemetry = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "score_relevant",
            "provider",
            "scope",
            "platform",
            "python_implementation",
            "python_version",
            "wall_elapsed_ns",
            "process_cpu_elapsed_ns",
            "self_user_cpu_us",
            "self_system_cpu_us",
            "max_rss_raw_start",
            "max_rss_raw_end",
            "max_rss_raw_unit",
            "process_tree_complete",
            "measurement_trust",
        },
        "observational telemetry",
    )
    if telemetry["schema_version"] != TELEMETRY_SCHEMA_VERSION or telemetry["score_relevant"] is not False:
        raise CausalFrontierError("observational telemetry cannot be score-relevant")
    status = require_enum(
        telemetry["status"],
        {"NOT_CAPTURED", "DECLARED_SAME_PROCESS_OBSERVATION_AUTHENTICITY_UNVERIFIED"},
        "telemetry status",
    )
    require_text(telemetry["provider"], "telemetry provider", 128)
    require_text(telemetry["scope"], "telemetry scope", 128)
    require_text(telemetry["platform"], "telemetry platform", 128)
    require_text(telemetry["python_implementation"], "telemetry Python implementation", 128)
    require_text(telemetry["python_version"], "telemetry Python version", 128)
    for field in (
        "wall_elapsed_ns",
        "process_cpu_elapsed_ns",
        "self_user_cpu_us",
        "self_system_cpu_us",
        "max_rss_raw_start",
        "max_rss_raw_end",
    ):
        _validate_optional_counter(telemetry[field], "telemetry %s" % field)
    require_enum(
        telemetry["max_rss_raw_unit"],
        {"BYTES", "KIBIBYTES", "PLATFORM_DEFINED_UNKNOWN", "UNAVAILABLE"},
        "telemetry RSS unit",
    )
    if telemetry["process_tree_complete"] is not False or telemetry["measurement_trust"] != "UNVERIFIED":
        raise CausalFrontierError("same-process telemetry cannot claim complete or trusted measurement")
    if status == "NOT_CAPTURED" and telemetry != _empty_telemetry():
        raise CausalFrontierError("uncaptured telemetry must use the exact null projection")
    if status != "NOT_CAPTURED" and (
        telemetry["wall_elapsed_ns"] is None or telemetry["process_cpu_elapsed_ns"] is None
    ):
        raise CausalFrontierError("captured telemetry must contain wall and process CPU observations")
    if status != "NOT_CAPTURED":
        if telemetry["provider"] != "PYTHON_STDLIB_TIME_AND_OPTIONAL_RESOURCE" or telemetry["scope"] != (
            "CURRENT_PROCESS_CUMULATIVE_NOT_ISOLATED"
        ):
            raise CausalFrontierError("captured telemetry provider or scope is unregistered")
        if (telemetry["self_user_cpu_us"] is None) != (telemetry["self_system_cpu_us"] is None):
            raise CausalFrontierError("captured telemetry CPU resource fields must be paired")
        if (telemetry["max_rss_raw_start"] is None) != (telemetry["max_rss_raw_end"] is None):
            raise CausalFrontierError("captured telemetry RSS fields must be paired")
        if telemetry["max_rss_raw_start"] is not None and telemetry["max_rss_raw_end"] < telemetry["max_rss_raw_start"]:
            raise CausalFrontierError("captured telemetry RSS high-water mark regressed")
    return telemetry


def _receipt(score_core: dict[str, Any], telemetry: dict[str, Any]) -> dict[str, Any]:
    score_sha = sha256_bytes(SCORE_CORE_DOMAIN_TAG + canonical_bytes(score_core))
    telemetry_sha = sha256_bytes(TELEMETRY_DOMAIN_TAG + canonical_bytes(telemetry))
    core = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "score_core": score_core,
        "score_core_sha256": score_sha,
        "telemetry": telemetry,
        "telemetry_sha256": telemetry_sha,
    }
    return {**core, "receipt_sha256": sha256_bytes(RECEIPT_DOMAIN_TAG + canonical_bytes(core))}


def _with_telemetry(factory: Callable[[], dict[str, Any]], capture: bool) -> dict[str, Any]:
    if not capture:
        return _receipt(factory(), _empty_telemetry())
    wall_start = time.monotonic_ns()
    cpu_start = time.process_time_ns()
    resource_start = _resource_snapshot()
    score_core = factory()
    resource_end = _resource_snapshot()
    cpu_end = time.process_time_ns()
    wall_end = time.monotonic_ns()
    telemetry = _captured_telemetry(wall_start, cpu_start, resource_start, wall_end, cpu_end, resource_end)
    return _receipt(score_core, telemetry)


def exercise_neutral_baselines(
    catalog_path: Path,
    expected_catalog_checkpoint_sha256: str,
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
    lock_path: Path,
    expected_lock_checkpoint_sha256: str,
    *,
    capture_observational_telemetry: bool = False,
) -> dict[str, Any]:
    """Materialize every locked order under one exact synthetic protocol budget."""

    if type(capture_observational_telemetry) is not bool:
        raise CausalFrontierError("telemetry capture flag must be boolean")
    catalog = load_neutral_action_catalog(catalog_path, expected_catalog_checkpoint_sha256)
    plan = _load_plan(plan_path, expected_plan_checkpoint_sha256, catalog, expected_catalog_checkpoint_sha256)
    lock = _load_lock(
        lock_path,
        expected_lock_checkpoint_sha256,
        catalog,
        expected_catalog_checkpoint_sha256,
        plan,
        expected_plan_checkpoint_sha256,
    )
    receipts = [
        _with_telemetry(lambda trace=trace: _score_core(catalog, plan, lock, trace), capture_observational_telemetry)
        for trace in lock["traces"]
    ]
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": REPORT_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "case_id": catalog["case_id"],
        "catalog_checkpoint_sha256": expected_catalog_checkpoint_sha256,
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "lock_checkpoint_sha256": expected_lock_checkpoint_sha256,
        "lock_sha256": lock["lock_sha256"],
        "execution_unit": EXECUTION_UNIT,
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "receipts": receipts,
        "receipts_n": len(receipts),
        "all_precommitted_seed_receipts_retained": True,
        "best_seed_selected": False,
        "scientific_baseline_families_executed": [],
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "real_resource_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(REPORT_NONCLAIMS),
    }
    result = {**core, "report_sha256": sha256_bytes(canonical_bytes(core))}
    _ensure_checkpointable(result, "neutral baseline exercise report")
    return result


def _validate_receipt(value: Any, expected_score_core: dict[str, Any]) -> dict[str, Any]:
    receipt = require_exact_keys(
        value,
        {
            "schema_version",
            "score_core",
            "score_core_sha256",
            "telemetry",
            "telemetry_sha256",
            "receipt_sha256",
        },
        "neutral baseline receipt",
    )
    if receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise CausalFrontierError("neutral baseline receipt has wrong schema")
    if canonical_bytes(receipt["score_core"]) != canonical_bytes(expected_score_core):
        raise CausalFrontierError("neutral baseline score core does not replay")
    expected_score_sha = sha256_bytes(SCORE_CORE_DOMAIN_TAG + canonical_bytes(expected_score_core))
    if receipt["score_core_sha256"] != expected_score_sha:
        raise CausalFrontierError("neutral baseline score-core digest mismatch")
    telemetry = _validate_telemetry(receipt["telemetry"])
    expected_telemetry_sha = sha256_bytes(TELEMETRY_DOMAIN_TAG + canonical_bytes(telemetry))
    if receipt["telemetry_sha256"] != expected_telemetry_sha:
        raise CausalFrontierError("neutral baseline telemetry digest mismatch")
    core = {key: receipt[key] for key in receipt if key != "receipt_sha256"}
    require_sha256(receipt["receipt_sha256"], "neutral baseline receipt digest")
    if receipt["receipt_sha256"] != sha256_bytes(RECEIPT_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("neutral baseline full receipt digest mismatch")
    return receipt


def _validate_report(
    value: Any,
    catalog: dict[str, Any],
    catalog_checkpoint_sha256: str,
    plan: dict[str, Any],
    plan_checkpoint_sha256: str,
    lock: dict[str, Any],
    lock_checkpoint_sha256: str,
) -> dict[str, Any]:
    report = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "fixed_parameter",
            "boundary",
            "case_id",
            "catalog_checkpoint_sha256",
            "catalog_sha256",
            "common_input_sha256",
            "plan_checkpoint_sha256",
            "plan_sha256",
            "lock_checkpoint_sha256",
            "lock_sha256",
            "execution_unit",
            "resource_accounting_mode",
            "receipts",
            "receipts_n",
            "all_precommitted_seed_receipts_retained",
            "best_seed_selected",
            "scientific_baseline_families_executed",
            "winner",
            "ranking",
            "acceleration_ratio",
            "real_resource_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "report_sha256",
        },
        "neutral baseline exercise report",
    )
    if (
        report["schema_version"] != REPORT_SCHEMA_VERSION
        or report["status"] != REPORT_STATUS
        or report["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or report["base_compiler_version"] != COMPILER_VERSION
        or report["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(report["boundary"]) != canonical_bytes(fixed_boundary())
        or report["case_id"] != catalog["case_id"]
        or report["catalog_checkpoint_sha256"] != catalog_checkpoint_sha256
        or report["catalog_sha256"] != catalog["catalog_sha256"]
        or report["common_input_sha256"] != catalog["common_input_sha256"]
        or report["plan_checkpoint_sha256"] != plan_checkpoint_sha256
        or report["plan_sha256"] != plan["plan_sha256"]
        or report["lock_checkpoint_sha256"] != lock_checkpoint_sha256
        or report["lock_sha256"] != lock["lock_sha256"]
        or report["execution_unit"] != EXECUTION_UNIT
        or report["resource_accounting_mode"] != RESOURCE_ACCOUNTING_MODE
        or report["receipts_n"] != len(lock["traces"])
        or report["all_precommitted_seed_receipts_retained"] is not True
        or report["best_seed_selected"] is not False
        or report["scientific_baseline_families_executed"] != []
        or report["winner"] is not None
        or report["ranking"] != []
        or report["acceleration_ratio"] is not None
        or report["real_resource_verified"] is not False
        or report["scientific_scoring_ready"] is not False
        or report["nonclaims"] != list(REPORT_NONCLAIMS)
    ):
        raise CausalFrontierError("neutral baseline report targets another contract or overclaims its boundary")
    receipts = report["receipts"]
    if not isinstance(receipts, list) or len(receipts) != len(lock["traces"]):
        raise CausalFrontierError("neutral baseline report receipt matrix is incomplete")
    for receipt, trace in zip(receipts, lock["traces"], strict=True):
        _validate_receipt(receipt, _score_core(catalog, plan, lock, trace))
    require_sha256(report["report_sha256"], "neutral baseline report semantic digest")
    core = {key: report[key] for key in report if key != "report_sha256"}
    if report["report_sha256"] != sha256_bytes(canonical_bytes(core)):
        raise CausalFrontierError("neutral baseline report semantic digest mismatch")
    return report


def verify_neutral_baseline_exercise(
    catalog_path: Path,
    expected_catalog_checkpoint_sha256: str,
    plan_path: Path,
    expected_plan_checkpoint_sha256: str,
    lock_path: Path,
    expected_lock_checkpoint_sha256: str,
    report_path: Path,
    expected_report_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Verify an exact report and replay every deterministic protocol-cost core."""

    catalog = load_neutral_action_catalog(catalog_path, expected_catalog_checkpoint_sha256)
    plan = _load_plan(plan_path, expected_plan_checkpoint_sha256, catalog, expected_catalog_checkpoint_sha256)
    lock = _load_lock(
        lock_path,
        expected_lock_checkpoint_sha256,
        catalog,
        expected_catalog_checkpoint_sha256,
        plan,
        expected_plan_checkpoint_sha256,
    )
    _raw, value = _read_checkpointed_json(
        report_path, expected_report_checkpoint_sha256, "neutral baseline exercise report"
    )
    report = _validate_report(
        value,
        catalog,
        expected_catalog_checkpoint_sha256,
        plan,
        expected_plan_checkpoint_sha256,
        lock,
        expected_lock_checkpoint_sha256,
    )
    core = {
        "schema_version": VERIFICATION_SCHEMA_VERSION,
        "status": VERIFICATION_STATUS,
        "catalog_checkpoint_sha256": expected_catalog_checkpoint_sha256,
        "catalog_sha256": catalog["catalog_sha256"],
        "common_input_sha256": catalog["common_input_sha256"],
        "plan_checkpoint_sha256": expected_plan_checkpoint_sha256,
        "plan_sha256": plan["plan_sha256"],
        "lock_checkpoint_sha256": expected_lock_checkpoint_sha256,
        "lock_sha256": lock["lock_sha256"],
        "report_checkpoint_sha256": expected_report_checkpoint_sha256,
        "report_sha256": report["report_sha256"],
        "score_cores_replayed_n": len(report["receipts"]),
        "telemetry_score_separation_valid": True,
        "all_precommitted_seed_receipts_retained": True,
        "common_input_structural_neutrality_verified": True,
        "factor_space_and_action_payloads_replayed": True,
        "execution_gate_derivation_verified": True,
        "semantic_policy_neutrality_verified": False,
        "precompilation_timing_and_currentness_verified": False,
        "rollback_protection_verified": False,
        "authority_declarations_attested": False,
        "telemetry_authenticity_verified": False,
        "cohort_uniqueness_verified": False,
        "real_resource_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(VERIFICATION_NONCLAIMS),
    }
    return {**core, "verification_sha256": sha256_bytes(canonical_bytes(core))}
