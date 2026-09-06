"""Known, exploratory synthetic witness; no prospective or biological evidence.

The oracle uses a finite Boolean truth table, not compiler aggregation, Pareto,
minimax, or audit helpers. Production validation/digest helpers below are used
only to prepare contract-valid inputs and bind their declared manifests.
"""

from __future__ import annotations

from copy import deepcopy

from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import branch_plan_sha256, validate_case

EXPERIMENTS = ("experiment:alpha", "experiment:beta")
OUTCOMES = ("outcome:global-context", "outcome:global-invariant")
CONTEXT = "world:context-confounding"
REFINEMENT = "world:context-refinement"
INVARIANT = "world:invariant-mechanism"
RESIDUAL = "world:residual"
CONTEXT_CLASS = "option:audit-context"
INVARIANT_CLASS = "option:test-invariance"
RESIDUAL_CLASS = "option:defer"
SCOPES = ("structurally_admissible_unexecuted", "conditional_scientific_structure")


def rebind(case):
    for experiment in case["experiments"]:
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    return case


def build_case(raw_case, *, refined=True):
    case = deepcopy(raw_case)
    case["case_id"] = "synthetic-group-oracle-refined" if refined else "synthetic-group-oracle-coarse"
    case["title"] = "Known exploratory synthetic grouped-withdrawal truth table"
    case["purpose"] = (
        "Software-only finite oracle witness. Both informative branches share a declared relation pattern; "
        "no classifier is executed and no biological, prospective or historical assertion is made."
    )
    case["nonclaims"].append(
        "Present-day synthetic transformation of a known fixture; inherited dates are not a new historical commitment."
    )
    template = next(item for item in case["experiments"] if item["id"] == "experiment:global-recompute")
    if refined:
        original = next(item for item in case["worlds"] if item["id"] == CONTEXT)
        case["worlds"].append(
            {**deepcopy(original), "id": REFINEMENT, "label": "Synthetic decision-equivalent context refinement"}
        )
    case["experiments"] = []
    for experiment_id in EXPERIMENTS:
        experiment = deepcopy(template)
        experiment["id"] = experiment_id
        experiment["label"] = "Synthetic equal-resource candidate " + experiment_id
        if refined:
            experiment["predictions"].extend(
                {**deepcopy(item), "world_id": REFINEMENT}
                for item in list(experiment["predictions"])
                if item["world_id"] == CONTEXT
            )
        for prediction in experiment["predictions"]:
            if prediction["outcome_id"] in OUTCOMES:
                prediction["relation"] = (
                    "UNKNOWN"
                    if prediction["world_id"] == RESIDUAL
                    else "EXCLUDES"
                    if prediction["world_id"] == INVARIANT
                    else "SURVIVES"
                )
        case["experiments"].append(experiment)
    return rebind(case)


def coordinates(*, refined=True):
    return [
        {"experiment_id": experiment, "outcome_id": outcome, "world_id": world}
        for experiment in EXPERIMENTS
        for outcome in OUTCOMES
        for world in ((CONTEXT, REFINEMENT) if refined else (CONTEXT,))
    ]


def withdraw(case, members):
    variant = deepcopy(case)
    targets = {(row["experiment_id"], row["outcome_id"], row["world_id"]) for row in members}
    for experiment in variant["experiments"]:
        for prediction in experiment["predictions"]:
            if (experiment["id"], prediction["outcome_id"], prediction["world_id"]) in targets:
                prediction["relation"] = "UNKNOWN"
    return rebind(variant)


def masked_case(case, mask, *, refined=True):
    return withdraw(case, [row for bit, row in enumerate(coordinates(refined=refined)) if mask & (1 << bit)])


def refined_mask_from_coarse(mask):
    return sum(3 << (2 * bit) for bit in range(4) if mask & (1 << bit))


def expected_from_mask(mask, *, refined=True):
    """Exhaustive finite truth-table oracle, specialized to the declared witness.

    A branch's context class survives strictly iff any copy still has S. U
    preserves that class too, so the retained classes always remain context and
    residual. Only the context/invariant pair can be strictly separated. Both
    candidates have equal costs and identical class-retention metrics; Pareto
    comparison therefore reduces exactly to the two pair-count coordinates.
    """
    copies = 2 if refined else 1
    experiments = {}
    for index, experiment in enumerate(EXPERIMENTS):
        branches = []
        for branch in range(2):
            first_bit = (index * 2 + branch) * copies
            withdrawn = [(mask >> (first_bit + copy)) & 1 for copy in range(copies)]
            branches.append(not all(withdrawn))
        experiments[experiment] = {
            "branch_has_strict_survivor": branches,
            "guaranteed_pairs": int(all(branches)),
            "possible_pairs": int(any(branches)),
            "worst_remaining_classes": 2,
            "class_reduction": 1,
            "decision_separating": any(branches),
        }
    candidates = [identity for identity in EXPERIMENTS if experiments[identity]["decision_separating"]]
    frontier = []
    for candidate in candidates:
        candidate_pair = tuple(experiments[candidate][field] for field in ("guaranteed_pairs", "possible_pairs"))
        dominated = False
        for other in candidates:
            other_pair = tuple(experiments[other][field] for field in ("guaranteed_pairs", "possible_pairs"))
            if (
                all(left >= right for left, right in zip(other_pair, candidate_pair, strict=True))
                and other_pair != candidate_pair
            ):
                dominated = True
        if not dominated:
            frontier.append(candidate)
    # In this finite equal-resource family all nondominated candidates have the
    # same class count and pair tuple. Thus every frontier member is co-minimax.
    return {"experiments": experiments, "frontier": frontier, "co_minimax": list(frontier)}


def build_manifest(case):
    groups = []
    for experiment_index, experiment in enumerate(EXPERIMENTS):
        for outcome_index, outcome in enumerate(OUTCOMES):
            groups.append(
                {
                    "id": "group:paired-%d-%d" % (experiment_index, outcome_index),
                    "rationale": "Declared synthetic support shared by the two context copies on this branch.",
                    "members": [
                        {"experiment_id": experiment, "outcome_id": outcome, "world_id": world}
                        for world in (CONTEXT, REFINEMENT)
                    ],
                }
            )
    groups.append(
        {
            "id": "group:unchanged",
            "rationale": "Synthetic negative control: one copy withdrawn in each candidate, other copies retain S.",
            "members": [
                {"experiment_id": experiment, "outcome_id": OUTCOMES[0], "world_id": CONTEXT}
                for experiment in EXPERIMENTS
            ],
        }
    )
    groups.append(
        {
            "id": "group:requires-reauthoring",
            "rationale": "Synthetic rejected control: withdraw the only named exclusion on both alpha branches.",
            "members": [
                {"experiment_id": EXPERIMENTS[0], "outcome_id": outcome, "world_id": INVARIANT} for outcome in OUTCOMES
            ],
        }
    )
    return {
        "schema_version": "causalfrontier.assumption-groups.v1",
        "case_sha256": sha256_bytes(canonical_bytes(validate_case(case))),
        "groups": groups,
    }
