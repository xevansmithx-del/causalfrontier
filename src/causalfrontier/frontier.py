"""Prior-free causal discriminator analysis, Pareto filtering, and minimax selection."""

from __future__ import annotations

from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

from .canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from .model import (
    COMPILER_VERSION,
    GRANTED_AUTHORITIES,
    RESOURCE_FIELDS,
    fixed_boundary,
    validate_case,
)


def _substantive_options(world: Dict[str, Any], defer_id: str) -> Set[str]:
    return set(world["admissible_option_ids"]) - {defer_id}


def _decision_class_id(world: Dict[str, Any], defer_id: str) -> str:
    substantive = sorted(_substantive_options(world, defer_id))
    return substantive[0] if substantive else defer_id


def _decision_classes(worlds: List[Dict[str, Any]], defer_id: str) -> Dict[str, List[str]]:
    classes: Dict[str, List[str]] = {}
    for world in worlds:
        classes.setdefault(_decision_class_id(world, defer_id), []).append(world["id"])
    return {identity: sorted(world_ids) for identity, world_ids in sorted(classes.items())}


def _decision_class_relation(relations: List[str]) -> str:
    if "SURVIVES" in relations:
        return "SURVIVES"
    if "UNKNOWN" in relations:
        return "UNKNOWN"
    return "EXCLUDES"


def _outcome_analysis(
    outcome: Dict[str, Any],
    relation_map: Dict[Tuple[str, str], str],
    worlds: List[Dict[str, Any]],
    decision_classes: Dict[str, List[str]],
    decision_class_pairs: List[Tuple[str, str]],
    defer_id: str,
) -> Dict[str, Any]:
    relations = {world["id"]: relation_map[(world["id"], outcome["id"])] for world in worlds}
    predicted_survivors = sorted(world_id for world_id, relation in relations.items() if relation != "EXCLUDES")
    is_informative = outcome["class"] == "INFORMATIVE"
    if is_informative and predicted_survivors:
        effective_survivors = predicted_survivors
        resolution = "PREDECLARED_INFORMATIVE_UPDATE"
    elif outcome["class"] == "CONTRADICTION":
        effective_survivors = sorted(
            world_id for world_id, world in ((item["id"], item) for item in worlds) if world["is_residual"]
        )
        resolution = "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
    elif outcome["class"] == "FAILURE":
        effective_survivors = sorted(relations)
        resolution = "EXECUTION_FAILURE_NO_UPDATE"
    elif outcome["class"] == "NO_CALL":
        effective_survivors = sorted(relations)
        resolution = "NO_CALL_NO_UPDATE"
    else:
        effective_survivors = sorted(relations)
        resolution = "MODEL_MISSPECIFICATION_NO_UPDATE"
    world_map = {world["id"]: world for world in worlds}
    remaining_options = sorted(
        {option for identity in effective_survivors for option in _substantive_options(world_map[identity], defer_id)}
    )
    class_relations = {
        identity: _decision_class_relation([relations[world_id] for world_id in world_ids])
        for identity, world_ids in decision_classes.items()
    }
    predicted_classes = sorted(identity for identity, relation in class_relations.items() if relation != "EXCLUDES")
    effective_classes = sorted({_decision_class_id(world_map[world_id], defer_id) for world_id in effective_survivors})
    separated_pairs = []
    if is_informative:
        for left, right in decision_class_pairs:
            if {class_relations[left], class_relations[right]} == {
                "SURVIVES",
                "EXCLUDES",
            }:
                separated_pairs.append([left, right])
    return {
        "id": outcome["id"],
        "label": outcome["label"],
        "class": outcome["class"],
        "relations": relations,
        "predicted_surviving_world_ids": predicted_survivors,
        "effective_surviving_world_ids": effective_survivors,
        "remaining_world_count": len(effective_survivors),
        "decision_class_relations": class_relations,
        "predicted_surviving_decision_class_ids": predicted_classes,
        "effective_surviving_decision_class_ids": effective_classes,
        "remaining_decision_class_count": len(effective_classes),
        "mixed_relation_decision_class_ids": sorted(
            identity
            for identity, world_ids in decision_classes.items()
            if len({relations[world_id] for world_id in world_ids}) > 1
        ),
        "remaining_substantive_option_ids": remaining_options,
        "remaining_substantive_option_count": len(remaining_options),
        "resolution": resolution,
        "separated_decision_class_pairs": separated_pairs,
        "evidence_update_authority": "NONE_COUNTERFACTUAL_ONLY",
    }


def _experiment_analysis(
    experiment: Dict[str, Any],
    worlds: List[Dict[str, Any]],
    decision_classes: Dict[str, List[str]],
    decision_class_pairs: List[Tuple[str, str]],
    defer_id: str,
    gate_map: Dict[str, Dict[str, Any]],
    partition_invalidated: bool,
) -> Dict[str, Any]:
    relation_map = {(item["world_id"], item["outcome_id"]): item["relation"] for item in experiment["predictions"]}
    outcomes = [
        _outcome_analysis(
            outcome,
            relation_map,
            worlds,
            decision_classes,
            decision_class_pairs,
            defer_id,
        )
        for outcome in experiment["outcomes"]
    ]
    informative = [item for item in outcomes if item["class"] == "INFORMATIVE"]
    noninformative = [item for item in outcomes if item["class"] != "INFORMATIVE"]
    worst_remaining_worlds = max(item["remaining_world_count"] for item in informative)
    baseline_world_count = len(worlds)
    worst_remaining_classes = max(item["remaining_decision_class_count"] for item in informative)
    baseline_class_count = len(decision_classes)
    minimax_class_reduction = baseline_class_count - worst_remaining_classes
    possible_pairs = {tuple(pair) for outcome in informative for pair in outcome["separated_decision_class_pairs"]}
    guaranteed_pairs = set(decision_class_pairs)
    for outcome in informative:
        guaranteed_pairs &= {tuple(pair) for pair in outcome["separated_decision_class_pairs"]}
    blockers = []
    for gate_id in experiment["required_gate_ids"]:
        gate = gate_map[gate_id]
        if gate["state"] != "SATISFIED":
            blockers.append("OPEN_GATE:%s" % gate_id)
        if gate["authority"] not in GRANTED_AUTHORITIES:
            blockers.append("UNGRANTED_GATE_AUTHORITY:%s" % gate["authority"])
    for authority in experiment["required_authorities"]:
        if authority not in GRANTED_AUTHORITIES:
            blockers.append("UNGRANTED_AUTHORITY:%s" % authority)
    if experiment["execution_class"] != "READ_ONLY_COMPUTATION":
        blockers.append("ALPHA_READ_ONLY_EXECUTION_BOUNDARY")
    if partition_invalidated:
        blockers.append("PARTITION_INVALIDATED_REQUIRES_NEW_CASE")
    blockers = sorted(set(blockers))
    return {
        "id": experiment["id"],
        "label": experiment["label"],
        "protocol": experiment["protocol"],
        "protocol_sha256": sha256_bytes(experiment["protocol"].encode("utf-8")),
        "classifier": experiment["classifier"],
        "classifier_sha256": experiment["classifier_sha256"],
        "branch_plan_sha256": experiment["branch_plan_sha256"],
        "execution_class": experiment["execution_class"],
        "required_gate_ids": experiment["required_gate_ids"],
        "required_authorities": experiment["required_authorities"],
        "resources": experiment["resources"],
        "current_status": "STRUCTURALLY_ADMISSIBLE_UNEXECUTED" if not blockers else "BLOCKED",
        "blocked_reasons": blockers,
        "baseline_world_count": baseline_world_count,
        "conditional_worst_remaining_world_count": worst_remaining_worlds,
        "conditional_minimax_world_reduction": baseline_world_count - worst_remaining_worlds,
        "baseline_decision_class_count": baseline_class_count,
        "conditional_worst_remaining_decision_class_count": worst_remaining_classes,
        "conditional_minimax_decision_class_reduction": minimax_class_reduction,
        "decision_class_pair_count": len(decision_class_pairs),
        "conditional_guaranteed_decision_class_pairs": [list(item) for item in sorted(guaranteed_pairs)],
        "conditional_guaranteed_decision_class_pair_count": len(guaranteed_pairs),
        "conditional_possible_decision_class_pairs": [list(item) for item in sorted(possible_pairs)],
        "conditional_possible_decision_class_pair_count": len(possible_pairs),
        "decision_separating": minimax_class_reduction > 0 and bool(possible_pairs),
        "failure_and_no_call_branches_preserve_worlds": all(
            item["effective_surviving_world_ids"] == sorted(world["id"] for world in worlds)
            for item in noninformative
            if item["class"] in {"FAILURE", "NO_CALL"}
        ),
        "contradiction_branches_invalidate_partition": all(
            item["resolution"] == "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
            for item in noninformative
            if item["class"] == "CONTRADICTION"
        ),
        "outcomes": outcomes,
    }


def _resource_tuple(item: Dict[str, Any]) -> Tuple[int, ...]:
    return tuple(item["resources"][field] for field in RESOURCE_FIELDS)


def _dominates(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_max = (
        left["conditional_minimax_decision_class_reduction"],
        left["conditional_guaranteed_decision_class_pair_count"],
        left["conditional_possible_decision_class_pair_count"],
    )
    right_max = (
        right["conditional_minimax_decision_class_reduction"],
        right["conditional_guaranteed_decision_class_pair_count"],
        right["conditional_possible_decision_class_pair_count"],
    )
    left_min = (
        left["conditional_worst_remaining_decision_class_count"],
        *_resource_tuple(left),
    )
    right_min = (
        right["conditional_worst_remaining_decision_class_count"],
        *_resource_tuple(right),
    )
    no_worse = all(a >= b for a, b in zip(left_max, right_max, strict=True)) and all(
        a <= b for a, b in zip(left_min, right_min, strict=True)
    )
    strict = any(a > b for a, b in zip(left_max, right_max, strict=True)) or any(
        a < b for a, b in zip(left_min, right_min, strict=True)
    )
    return no_worse and strict


def _pareto(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    frontier = []
    for candidate in items:
        if not any(_dominates(other, candidate) for other in items if other["id"] != candidate["id"]):
            frontier.append(candidate)
    return sorted(frontier, key=lambda item: item["id"])


def _minimax(frontier: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not frontier:
        return None

    def epistemic_key(item: Dict[str, Any]) -> Tuple[int, int, int]:
        return (
            item["conditional_worst_remaining_decision_class_count"],
            -item["conditional_guaranteed_decision_class_pair_count"],
            -item["conditional_possible_decision_class_pair_count"],
        )

    best = min(epistemic_key(item) for item in frontier)
    tied = sorted((item for item in frontier if epistemic_key(item) == best), key=lambda item: item["id"])
    display = tied[0]
    return {
        "experiment_id": display["id"],
        "co_minimax_experiment_ids": [item["id"] for item in tied],
        "policy": "EPISTEMIC_MINIMAX_WITHIN_PRIOR_FREE_PARETO_FRONTIER",
        "display_tie_breaker": "LEXICOGRAPHIC_ID_NOT_SCIENTIFIC_PREFERENCE",
        "conditional_worst_remaining_decision_class_count": display["conditional_worst_remaining_decision_class_count"],
        "conditional_guaranteed_decision_class_pair_count": display["conditional_guaranteed_decision_class_pair_count"],
        "conditional_possible_decision_class_pair_count": display["conditional_possible_decision_class_pair_count"],
        "resources_remain_pareto_not_scalarized": True,
    }


def _compile_validated(
    case: Dict[str, Any],
    active_world_ids: Optional[List[str]] = None,
    partition_invalidated: bool = False,
) -> Dict[str, Any]:
    world_map = {world["id"]: world for world in case["worlds"]}
    if active_world_ids is None:
        active_world_ids = sorted(world_map)
        mode = "BASELINE"
    else:
        if not active_world_ids or len(active_world_ids) != len(set(active_world_ids)):
            raise CausalFrontierError("active world set must be nonempty and unique")
        if not set(active_world_ids) <= set(world_map):
            raise CausalFrontierError("active world set references an unknown world")
        residual_ids = {world["id"] for world in case["worlds"] if world["is_residual"]}
        if not residual_ids <= set(active_world_ids):
            raise CausalFrontierError("counterfactual branch cannot remove the open-world residual")
        active_world_ids = sorted(active_world_ids)
        mode = "COUNTERFACTUAL_REHEARSAL"
    if partition_invalidated:
        mode = "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
    worlds = [world_map[identity] for identity in active_world_ids]
    defer_id = case["decision"]["defer_option_id"]
    decision_classes = _decision_classes(worlds, defer_id)
    decision_class_pairs = sorted(combinations(decision_classes, 2))
    gate_map = {gate["id"]: gate for gate in case["gates"]}
    experiments = [
        _experiment_analysis(
            experiment,
            worlds,
            decision_classes,
            decision_class_pairs,
            defer_id,
            gate_map,
            partition_invalidated,
        )
        for experiment in case["experiments"]
    ]
    separating = [item for item in experiments if item["decision_separating"]]
    structurally_admissible = _pareto(
        [item for item in separating if item["current_status"] == "STRUCTURALLY_ADMISSIBLE_UNEXECUTED"]
    )
    conditional = [] if partition_invalidated else _pareto(separating)
    case_sha = sha256_bytes(canonical_bytes(case))
    core = {
        "schema_version": "causalfrontier.analysis.v1",
        "compiler": {"name": "causalfrontier", "version": COMPILER_VERSION},
        "case_id": case["case_id"],
        "case_sha256": case_sha,
        "analysis_mode": mode,
        "case_state": (
            "PARTITION_INVALIDATED_REQUIRES_NEW_CASE" if partition_invalidated else "DECLARED_PARTITION_ACTIVE"
        ),
        "fixed_parameter": case["fixed_parameter"],
        "evidence_cutoff": case["evidence_cutoff"],
        "boundary": fixed_boundary(),
        "scientific_status": "PROTOTYPE_COUNTERFACTUAL_PLAN_ONLY",
        "verification_scope": "SOFTWARE_STRUCTURE_DECLARED_PROVENANCE_AND_PREDECLARED_COUNTERFACTUALS_ONLY",
        "provenance_binding_status": "DECLARED_DIGESTS_CASE_ROOT_LOADER_MUST_VERIFY_FILES",
        "temporal_provenance_status": "DECLARED_TEMPORAL_METADATA_UNATTESTED",
        "historical_benchmark_eligible": False,
        "world_partition": case["world_partition"],
        "active_world_ids": active_world_ids,
        "residual_world_id": next(world["id"] for world in case["worlds"] if world["is_residual"]),
        "decision": case["decision"],
        "decision_classes": decision_classes,
        "decision_class_pairs": [list(item) for item in decision_class_pairs],
        "gates": case["gates"],
        "source_bindings": {
            item["id"]: {
                "sha256": item["sha256"],
                "data_class": item["data_class"],
                "authority": item["authority"],
                "knowledge_date": item["knowledge_date"],
                "retrieved_at": item["retrieved_at"],
                "temporal_basis": item["temporal_basis"],
                "retrieval_state": item["retrieval_state"],
                "semantic_state": item["semantic_state"],
                "coverage_complete": item["coverage_complete"],
                "source_locator": item["source_locator"],
                "submitted_query": item["submitted_query"],
                "executed_query": item["executed_query"],
            }
            for item in case["provenance"]
        },
        "experiments": experiments,
        "frontiers": {
            "structurally_admissible_unexecuted": [item["id"] for item in structurally_admissible],
            "conditional_scientific_structure": [item["id"] for item in conditional],
        },
        "minimax": {
            "structurally_admissible_unexecuted": _minimax(structurally_admissible),
            "conditional_scientific_structure": _minimax(conditional),
        },
        "selection_policy": {
            "priors_used": False,
            "probabilities_used": False,
            "likelihoods_used": False,
            "scalar_scores_used": False,
            "maximize": [
                "conditional_minimax_decision_class_reduction",
                "conditional_guaranteed_decision_class_pair_count",
                "conditional_possible_decision_class_pair_count",
            ],
            "minimize": [
                "conditional_worst_remaining_decision_class_count",
                *RESOURCE_FIELDS,
            ],
            "resource_tradeoffs": "PARETO_ONLY_NOT_SCALARIZED",
            "minimax_scope": "INFORMATIVE_BRANCH_CONDITIONAL_MINIMAX",
            "partition_refinement_policy": ("SELECTION_USES_DECISION_EQUIVALENCE_CLASSES_NOT_RAW_WORLD_COUNTS"),
        },
        "nonclaims": case["nonclaims"],
    }
    digest = sha256_bytes(canonical_bytes(core))
    return dict(core, analysis_sha256=digest, run_id=digest)


def compile_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and compile a frozen case into a deterministic frontier."""

    return _compile_validated(validate_case(case))


def simulate_branch(
    case: Dict[str, Any],
    experiment_id: str,
    outcome_id: str,
    branch_plan_sha256: Optional[str] = None,
    active_world_ids: Optional[List[str]] = None,
    case_state: str = "DECLARED_PARTITION_ACTIVE",
) -> Dict[str, Any]:
    """Rehearse one predeclared outcome; this never records or asserts an observation."""

    if case_state not in {"DECLARED_PARTITION_ACTIVE", "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"}:
        raise CausalFrontierError("unknown predecessor case state")
    if case_state == "PARTITION_INVALIDATED_REQUIRES_NEW_CASE":
        raise CausalFrontierError("partition is invalidated; freeze a new case before another rehearsal")
    normalized = validate_case(case)
    baseline = _compile_validated(normalized, active_world_ids)
    experiment_map = {item["id"]: item for item in baseline["experiments"]}
    if experiment_id not in experiment_map:
        raise CausalFrontierError("unknown or post-hoc experiment: %s" % experiment_id)
    experiment = experiment_map[experiment_id]
    if branch_plan_sha256 is not None and branch_plan_sha256 != experiment["branch_plan_sha256"]:
        raise CausalFrontierError("branch plan digest does not match the frozen experiment")
    outcome_map = {item["id"]: item for item in experiment["outcomes"]}
    if outcome_id not in outcome_map:
        raise CausalFrontierError("unknown or post-hoc outcome branch: %s" % outcome_id)
    outcome = outcome_map[outcome_id]
    successor_invalidated = outcome["class"] == "CONTRADICTION"
    successor = _compile_validated(
        normalized,
        outcome["effective_surviving_world_ids"],
        partition_invalidated=successor_invalidated,
    )
    return {
        "schema_version": "causalfrontier.branch-rehearsal.v1",
        "status": "COUNTERFACTUAL_REHEARSAL_NOT_AN_OBSERVATION",
        "authority": "NONE",
        "predecessor_run_id": baseline["run_id"],
        "predecessor_active_world_ids": baseline["active_world_ids"],
        "predecessor_case_state": baseline["case_state"],
        "experiment_id": experiment_id,
        "outcome_id": outcome_id,
        "branch_plan_sha256": experiment["branch_plan_sha256"],
        "outcome_effect": outcome,
        "successor_active_world_ids": successor["active_world_ids"],
        "successor_case_state": successor["case_state"],
        "successor_analysis": successor,
    }
