"""Pre-reveal deterministic reference selections for synthetic protocol exercises.

This module deliberately has no reveal, outcome, environment, network, dynamic
import, subprocess, or material-execution interface. It locks only auditable
selection traces. The required scientific comparator families remain unexecuted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import CausalFrontierError, canonical_bytes, read_json_bytes, sha256_bytes
from .challenge import BASELINE_FAMILIES, load_protocol_cases
from .frontier import compile_case
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

SELECTION_SCHEMA_VERSION = "causalfrontier.reference-selection-lock.v1"
POLICY_CONTRACT_VERSION = "causalfrontier.reference-policy-contract.v1"

_POLICY_CONTRACT_TEMPLATE = {
    "schema_version": POLICY_CONTRACT_VERSION,
    "policies": [
        {
            "id": "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "role": "CANDIDATE_POLICY",
            "rule": "SELECT_ONLY_ONE_STRUCTURALLY_ADMISSIBLE_CO_MINIMAX_ACTION_ELSE_NO_CALL",
            "scientific_baseline_family": None,
        },
        {
            "id": "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
            "role": "REFERENCE_PROXY",
            "rule": "ALWAYS_ABSTAIN",
            "scientific_baseline_family": "DO_NOTHING_OR_ABSTAIN",
        },
        {
            "id": "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "role": "REFERENCE_PROXY",
            "rule": (
                "ENUMERATE_EVERY_STRUCTURALLY_ADMISSIBLE_ACTION_ONCE_WITHOUT_REPLACEMENT_"
                "IN_CANONICAL_FROZEN_ACTION_ID_ORDER"
            ),
            "scientific_baseline_family": "RANDOM",
        },
    ],
}
POLICY_CONTRACT_CANONICAL = canonical_bytes(_POLICY_CONTRACT_TEMPLATE)

NONCLAIMS = (
    "Reference selection is a synthetic software protocol exercise, not scientific baseline execution.",
    "The selector reads the steward challenge bundle; entrant blinding and control-label withholding are unverified.",
    "Encoder worlds and prediction relations remain separate sensitivity strata and are not reconciled.",
    "Uniform enumeration is a deterministic reference distribution, not an empirical random-policy run.",
    "No outcome, reveal, observation, experiment, patient datum, or material is accessed or executed.",
    "No resource ledger is audited and no acceleration, biological, clinical, or health claim is produced.",
)


def fixed_policy_contract() -> dict[str, Any]:
    return read_json_bytes(POLICY_CONTRACT_CANONICAL, "fixed reference policy contract")


def policy_contract_sha256() -> str:
    return sha256_bytes(POLICY_CONTRACT_CANONICAL)


def _action(experiment: dict[str, Any], numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "action": "SELECT",
        "experiment_id": experiment["id"],
        "branch_plan_sha256": experiment["branch_plan_sha256"],
        "enumeration_numerator": numerator,
        "enumeration_denominator": denominator,
    }


def _terminal(action: str) -> dict[str, Any]:
    return {
        "action": action,
        "experiment_id": None,
        "branch_plan_sha256": None,
        "enumeration_numerator": 1,
        "enumeration_denominator": 1,
    }


def _trace(
    policy_id: str,
    status: str,
    eligible_ids: list[str],
    selections: list[dict[str, Any]],
    reason_codes: list[str],
) -> dict[str, Any]:
    core = {
        "policy_id": policy_id,
        "status": status,
        "eligible_action_ids": eligible_ids,
        "selections": selections,
        "reason_codes": reason_codes,
    }
    return {**core, "trace_sha256": sha256_bytes(canonical_bytes(core))}


def _lane_selections(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    experiments = {item["id"]: item for item in analysis["experiments"]}
    eligible = sorted(
        item["id"]
        for item in analysis["experiments"]
        if item["current_status"] == "STRUCTURALLY_ADMISSIBLE_UNEXECUTED" and item["decision_separating"]
    )

    minimax = analysis["minimax"]["structurally_admissible_unexecuted"]
    co_minimax = [] if minimax is None else [item for item in minimax["co_minimax_experiment_ids"] if item in eligible]
    if len(co_minimax) == 1:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "SELECTED",
            eligible,
            [_action(experiments[co_minimax[0]], 1, 1)],
            ["UNIQUE_CO_MINIMAX_ACTION"],
        )
    elif co_minimax:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["CO_MINIMAX_TIE_NOT_BROKEN_BY_LEXICOGRAPHIC_DISPLAY_ID"],
        )
    else:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"],
        )

    abstain = _trace(
        "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
        "ABSTAINED",
        eligible,
        [_terminal("ABSTAIN")],
        ["POLICY_ALWAYS_ABSTAINS"],
    )
    if eligible:
        uniform = _trace(
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "ENUMERATED",
            eligible,
            [_action(experiments[identity], 1, len(eligible)) for identity in eligible],
            ["ALL_ELIGIBLE_ACTIONS_ENUMERATED_ONCE_WITHOUT_REPLACEMENT"],
        )
    else:
        uniform = _trace(
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"],
        )
    return [candidate, abstain, uniform]


def lock_reference_selections(root: Path, expected_manifest_sha256: str, expected_sequence: int) -> dict[str, Any]:
    """Lock three deterministic pre-reveal reference policies for both encoders."""

    preflight, cases = load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    if preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST":
        raise CausalFrontierError("reference selection v1 is restricted to synthetic protocol tests")
    lanes = []
    for case_id, encodings in cases.items():
        shared_action_input = preflight["case_shared_action_input_sha256"].get(case_id)
        if shared_action_input is None:
            raise CausalFrontierError("case lacks one shared action input contract")
        for encoding in encodings:
            analysis = compile_case(encoding["case"])
            lanes.append(
                {
                    "case_id": case_id,
                    "encoding_id": encoding["encoding_id"],
                    "encoder_id": encoding["encoder_id"],
                    "frozen_case_sha256": encoding["frozen_case_sha256"],
                    "shared_action_input_sha256": shared_action_input,
                    "analysis_sha256": analysis["analysis_sha256"],
                    "reference_policy_traces": _lane_selections(analysis),
                }
            )

    core = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "status": "PRE_REVEAL_REFERENCE_SELECTIONS_LOCKED_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "challenge_id": preflight["challenge_id"],
        "challenge_sequence": preflight["challenge_sequence"],
        "challenge_manifest_sha256": preflight["challenge_manifest_sha256"],
        "challenge_registration_sha256": preflight["challenge_registration_sha256"],
        "scope": preflight["scope"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "policy_contract": fixed_policy_contract(),
        "policy_contract_sha256": policy_contract_sha256(),
        "reveal_input_accepted": False,
        "reference_lanes": sorted(lanes, key=lambda item: (item["case_id"], item["encoding_id"])),
        "reference_proxy_families": ["DO_NOTHING_OR_ABSTAIN", "RANDOM"],
        "scientific_baseline_families_executed": [],
        "required_scientific_baseline_families_unexecuted": sorted(BASELINE_FAMILIES),
        "combined_encoder_case_selection_ready": False,
        "scientific_scoring_ready": False,
        "gates": [
            {
                "id": "action_contract",
                "status": "PASS",
                "reason": "SHARED_DOSSIER_GATES_AND_ACTIONS_BOUND_ENCODER_WORLDS_RETAINED_AS_SEPARATE_STRATA",
            },
            {
                "id": "baseline_execution",
                "status": "NO_CALL",
                "reason": "REFERENCE_SELECTION_PROXIES_ONLY_REQUIRED_BASELINE_IMPLEMENTATIONS_UNEXECUTED",
            },
            {
                "id": "entrant_blinding",
                "status": "NO_CALL",
                "reason": "STEWARD_BUNDLE_CONTAINS_CONTROL_LABELS_SANITIZED_ENTRANT_VIEW_NOT_IMPLEMENTED",
            },
            {
                "id": "encoder_decision_model_agreement",
                "status": "NO_CALL",
                "reason": "WORLD_AND_PREDICTION_RELATIONS_RETAINED_AS_SEPARATE_UNADJUDICATED_STRATA",
            },
            {
                "id": "pre_reveal_interface",
                "status": "PASS",
                "reason": "SELECTION_API_HAS_NO_REVEAL_OUTCOME_OBSERVATION_OR_ENVIRONMENT_ARGUMENT",
            },
            {"id": "scientific_scoring", "status": "NO_CALL", "reason": "NO_OUTCOME_OR_RESOURCE_LEDGER_ACCESSED"},
        ],
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "selection_lock_sha256": sha256_bytes(canonical_bytes(core))}
