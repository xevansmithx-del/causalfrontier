"""Independent finite oracle checks; known synthetic controls, not new biology."""

from collections import Counter
from copy import deepcopy

import pytest
from group_oracle_fixture import (
    CONTEXT_CLASS,
    EXPERIMENTS,
    INVARIANT_CLASS,
    OUTCOMES,
    RESIDUAL_CLASS,
    SCOPES,
    build_case,
    build_manifest,
    expected_from_mask,
    masked_case,
    refined_mask_from_coarse,
    withdraw,
)

from causalfrontier.canonical import CausalFrontierError, canonical_bytes
from causalfrontier.frontier import compile_case


def assert_compiler_matches_oracle(analysis, expected, *, refined):
    for scope in SCOPES:
        assert analysis["frontiers"][scope] == expected["frontier"]
        minimax = analysis["minimax"][scope]
        assert (minimax["co_minimax_experiment_ids"] if minimax else []) == expected["co_minimax"]
    for experiment in analysis["experiments"]:
        truth = expected["experiments"][experiment["id"]]
        assert experiment["conditional_worst_remaining_decision_class_count"] == truth["worst_remaining_classes"]
        assert experiment["conditional_minimax_decision_class_reduction"] == truth["class_reduction"]
        assert experiment["conditional_guaranteed_decision_class_pair_count"] == truth["guaranteed_pairs"]
        assert experiment["conditional_possible_decision_class_pair_count"] == truth["possible_pairs"]
        assert experiment["decision_separating"] is truth["decision_separating"]
        outcomes = {row["id"]: row for row in experiment["outcomes"]}
        for index, outcome_id in enumerate(OUTCOMES):
            outcome = outcomes[outcome_id]
            separated = truth["branch_has_strict_survivor"][index]
            assert outcome["decision_class_relations"] == {
                CONTEXT_CLASS: "SURVIVES" if separated else "UNKNOWN",
                INVARIANT_CLASS: "EXCLUDES",
                RESIDUAL_CLASS: "UNKNOWN",
            }
            assert outcome["effective_surviving_decision_class_ids"] == [CONTEXT_CLASS, RESIDUAL_CLASS]
            assert outcome["remaining_world_count"] == (3 if refined else 2)
            assert outcome["remaining_decision_class_count"] == 2
            assert outcome["separated_decision_class_pairs"] == (
                [[CONTEXT_CLASS, INVARIANT_CLASS]] if separated else []
            )


def test_all_256_refined_masks_match_independent_finite_oracle(raw_case):
    case = build_case(raw_case)
    original_bytes = canonical_bytes(case)
    observed = Counter()
    for mask in range(256):
        expected = expected_from_mask(mask)
        result = compile_case(masked_case(case, mask))
        assert_compiler_matches_oracle(result, expected, refined=True)
        observed[tuple(result["frontiers"][SCOPES[0]])] += 1
    assert observed == {
        EXPERIMENTS: 117,
        (EXPERIMENTS[0],): 69,
        (EXPERIMENTS[1],): 69,
        (): 1,
    }
    assert canonical_bytes(case) == original_bytes


def test_all_16_coarse_masks_match_oracle_and_mapped_refinements(raw_case):
    coarse, refined = build_case(raw_case, refined=False), build_case(raw_case)
    observed = Counter()
    for mask in range(16):
        expected = expected_from_mask(mask, refined=False)
        result = compile_case(masked_case(coarse, mask, refined=False))
        assert_compiler_matches_oracle(result, expected, refined=False)
        corresponding = compile_case(masked_case(refined, refined_mask_from_coarse(mask)))
        assert_compiler_matches_oracle(corresponding, expected, refined=True)
        assert result["frontiers"] == corresponding["frontiers"]
        assert result["minimax"] == corresponding["minimax"]
        observed[tuple(result["frontiers"][SCOPES[0]])] += 1
    assert observed == {EXPERIMENTS: 5, (EXPERIMENTS[0],): 5, (EXPERIMENTS[1],): 5, (): 1}


def test_exact_baseline_refinement_preserves_selection_not_raw_counts(raw_case):
    coarse = compile_case(build_case(raw_case, refined=False))
    refined = compile_case(build_case(raw_case))
    assert coarse["frontiers"] == refined["frontiers"]
    assert coarse["minimax"] == refined["minimax"]
    assert coarse["analysis_sha256"] != refined["analysis_sha256"]
    assert len(coarse["active_world_ids"]) == 3
    assert len(refined["active_world_ids"]) == 4


def test_declared_joint_controls_have_exact_singleton_and_joint_truth(raw_case):
    case = build_case(raw_case)
    groups = build_manifest(case)["groups"]
    baseline = compile_case(case)
    paired = [row for row in groups if row["id"].startswith("group:paired-")]
    assert len(paired) == 4
    for group in paired:
        for member in group["members"]:
            singleton = compile_case(withdraw(case, [member]))
            assert singleton["frontiers"] == baseline["frontiers"]
            assert singleton["minimax"] == baseline["minimax"]
        joint = compile_case(withdraw(case, group["members"]))
        survivor = next(identity for identity in EXPERIMENTS if identity != group["members"][0]["experiment_id"])
        for scope in SCOPES:
            assert joint["frontiers"][scope] == [survivor]
            assert joint["minimax"][scope]["co_minimax_experiment_ids"] == [survivor]
    unchanged = next(group for group in groups if group["id"] == "group:unchanged")
    negative = compile_case(withdraw(case, unchanged["members"]))
    assert negative["frontiers"] == baseline["frontiers"]
    assert negative["minimax"] == baseline["minimax"]
    rejected = next(group for group in groups if group["id"] == "group:requires-reauthoring")
    with pytest.raises(CausalFrontierError, match="informative branch must discriminate"):
        compile_case(withdraw(case, rejected["members"]))


def test_grouped_api_matches_finite_oracle_and_retains_rejected_control(raw_case):
    from causalfrontier.group_assumptions import audit_assumption_groups, verify_group_assumption_audit

    case = build_case(raw_case)
    manifest = build_manifest(case)
    originals = canonical_bytes(case), canonical_bytes(manifest)
    report = audit_assumption_groups(case, manifest)
    rows = {row["group_id"]: row for row in report["group_rows"]}
    assert set(rows) == {group["id"] for group in manifest["groups"]}
    # Eight SURVIVES cells and two alpha EXCLUDES cells occur in these groups.
    # Overlap with the negative-control group must not duplicate singleton rows.
    assert len(report["singleton_rows"]) == 10
    assert Counter(row["status"] for row in report["singleton_rows"]) == {
        "VALID_HYPOTHETICAL_VARIANT": 8,
        "REQUIRES_REAUTHORING": 2,
    }
    for experiment_index in range(2):
        for outcome_index in range(2):
            identity = "group:paired-%d-%d" % (experiment_index, outcome_index)
            row = rows[identity]
            mask = 3 << (4 * experiment_index + 2 * outcome_index)
            expected = expected_from_mask(mask)
            assert row["status"] == "VALID_HYPOTHETICAL_VARIANT"
            assert row["singleton_masked_joint_selection_change"] is True
            assert row["masking_applicability"]["applicable"] is True
            assert row["masking_applicability"]["all_member_singletons_valid"] is True
            assert row["masking_applicability"]["all_member_singleton_selections_unchanged"] is True
            assert row["masking_applicability"]["joint_selection_membership_changed"] is True
            for scope in SCOPES:
                assert row["selection"]["frontiers"][scope] == expected["frontier"]
                assert row["selection"]["minimax"][scope]["co_minimax_experiment_ids"] == expected["co_minimax"]
    unchanged = rows["group:unchanged"]
    assert unchanged["status"] == "VALID_HYPOTHETICAL_VARIANT"
    assert unchanged["singleton_masked_joint_selection_change"] is False
    assert unchanged["selection"] == report["baseline"]["selection"]
    rejected = rows["group:requires-reauthoring"]
    assert rejected["status"] == "REQUIRES_REAUTHORING"
    assert rejected["case_contract"]["status"] == "REJECTED_BY_CASE_CONTRACT"
    assert rejected["singleton_masked_joint_selection_change"] is False
    assert rejected["masking_applicability"]["applicable"] is False
    for field in (
        "selection",
        "differences",
        "analysis_sha256",
        "epistemic_by_experiment",
        "epistemic_differences_by_experiment",
    ):
        assert rejected[field] is None
    assert sum(row["singleton_masked_joint_selection_change"] for row in rows.values()) == 4
    assert verify_group_assumption_audit(case, manifest, report)["verified"] is True
    assert (canonical_bytes(case), canonical_bytes(manifest)) == originals


def test_group_and_member_order_preserve_whole_report_with_overlapping_groups(raw_case):
    from causalfrontier.group_assumptions import audit_assumption_groups

    case = build_case(raw_case)
    manifest = build_manifest(case)
    reordered = deepcopy(manifest)
    reordered["groups"].reverse()
    for group in reordered["groups"]:
        group["members"].reverse()
    assert canonical_bytes(audit_assumption_groups(case, manifest)) == canonical_bytes(
        audit_assumption_groups(case, reordered)
    )
