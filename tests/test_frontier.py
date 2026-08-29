from __future__ import annotations

from copy import deepcopy

import pytest

from causalfrontier.canonical import CausalFrontierError, canonical_bytes
from causalfrontier.frontier import compile_case, simulate_branch
from causalfrontier.model import load_case


def test_compile_is_byte_deterministic(case_root):
    case = load_case(case_root)
    assert canonical_bytes(compile_case(case)) == canonical_bytes(compile_case(deepcopy(case)))


def test_pareto_frontier_drops_dominated_global_recompute(case_root):
    analysis = compile_case(load_case(case_root))
    assert analysis["frontiers"]["structurally_admissible_unexecuted"] == [
        "experiment:held-out-invariance",
        "experiment:negative-control",
    ]


def test_minimax_exposes_resource_incomparable_tie(case_root):
    selected = compile_case(load_case(case_root))["minimax"]["structurally_admissible_unexecuted"]
    assert selected["experiment_id"] == "experiment:held-out-invariance"
    assert selected["co_minimax_experiment_ids"] == [
        "experiment:held-out-invariance",
        "experiment:negative-control",
    ]
    assert selected["resources_remain_pareto_not_scalarized"] is True


def test_selection_policy_is_explicitly_prior_free(case_root):
    policy = compile_case(load_case(case_root))["selection_policy"]
    assert policy["priors_used"] is False
    assert policy["probabilities_used"] is False
    assert policy["likelihoods_used"] is False
    assert policy["scalar_scores_used"] is False
    assert policy["minimax_scope"] == "INFORMATIVE_BRANCH_CONDITIONAL_MINIMAX"


def test_unknown_relation_never_counts_as_strict_class_separation(case_root):
    analysis = compile_case(load_case(case_root))
    for experiment in analysis["experiments"]:
        for pair in experiment["conditional_possible_decision_class_pairs"]:
            assert "option:defer" not in pair


def test_informative_rehearsal_retains_residual(case_root):
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    rehearsal = simulate_branch(
        case,
        experiment["id"],
        "outcome:held-invariant",
        branch_plan_sha256=experiment["branch_plan_sha256"],
    )
    assert rehearsal["status"] == "COUNTERFACTUAL_REHEARSAL_NOT_AN_OBSERVATION"
    assert rehearsal["outcome_effect"]["effective_surviving_world_ids"] == [
        "world:invariant-mechanism",
        "world:residual",
    ]


@pytest.mark.parametrize(
    "outcome_id,resolution",
    [
        ("outcome:held-failure", "EXECUTION_FAILURE_NO_UPDATE"),
        ("outcome:held-no-call", "NO_CALL_NO_UPDATE"),
    ],
)
def test_noninformative_rehearsals_preserve_uncertainty(case_root, outcome_id, resolution):
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    rehearsal = simulate_branch(
        case,
        experiment["id"],
        outcome_id,
        branch_plan_sha256=experiment["branch_plan_sha256"],
    )
    assert rehearsal["outcome_effect"]["resolution"] == resolution
    assert rehearsal["outcome_effect"]["effective_surviving_world_ids"] == sorted(item["id"] for item in case["worlds"])


def test_contradiction_invalidates_partition_and_clears_frontier(case_root):
    case = load_case(case_root)
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:held-out-invariance")
    rehearsal = simulate_branch(
        case,
        experiment["id"],
        "outcome:held-contradiction",
        branch_plan_sha256=experiment["branch_plan_sha256"],
    )
    assert rehearsal["outcome_effect"]["resolution"] == "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
    assert rehearsal["successor_active_world_ids"] == ["world:residual"]
    assert rehearsal["successor_case_state"] == "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
    assert rehearsal["successor_analysis"]["frontiers"] == {
        "conditional_scientific_structure": [],
        "structurally_admissible_unexecuted": [],
    }


def test_posthoc_outcome_branch_is_rejected(case_root):
    case = load_case(case_root)
    with pytest.raises(CausalFrontierError, match="post-hoc outcome"):
        simulate_branch(case, "experiment:held-out-invariance", "outcome:invented-afterward")


def test_wrong_branch_plan_digest_is_rejected(case_root):
    case = load_case(case_root)
    with pytest.raises(CausalFrontierError, match="branch plan digest"):
        simulate_branch(
            case,
            "experiment:held-out-invariance",
            "outcome:held-invariant",
            branch_plan_sha256="0" * 64,
        )


def test_open_gate_removes_currently_admissible_frontier(raw_case):
    raw_case["gates"][0]["state"] = "OPEN"
    analysis = compile_case(raw_case)
    assert analysis["frontiers"]["structurally_admissible_unexecuted"] == []
    assert analysis["frontiers"]["conditional_scientific_structure"]


def test_material_execution_is_blocked_by_alpha_boundary(raw_case):
    for experiment in raw_case["experiments"]:
        experiment["execution_class"] = "MATERIAL_PERTURBATION"
    analysis = compile_case(raw_case)
    assert analysis["frontiers"]["structurally_admissible_unexecuted"] == []
    assert all("ALPHA_READ_ONLY_EXECUTION_BOUNDARY" in item["blocked_reasons"] for item in analysis["experiments"])
