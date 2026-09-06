from __future__ import annotations

import builtins
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier import assumptions
from causalfrontier import group_assumptions as groups
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.frontier import compile_case
from causalfrontier.model import branch_plan_sha256, fixed_boundary, validate_case


def _rebind(case):
    for experiment in case["experiments"]:
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    return case


def _coords(case, relation=None):
    named = {world["id"] for world in case["worlds"] if not world["is_residual"]}
    values = []
    for experiment in case["experiments"]:
        informative = {outcome["id"] for outcome in experiment["outcomes"] if outcome["class"] == "INFORMATIVE"}
        for prediction in experiment["predictions"]:
            if (
                prediction["world_id"] in named
                and prediction["outcome_id"] in informative
                and prediction["relation"] in {"SURVIVES", "EXCLUDES"}
                and (relation is None or prediction["relation"] == relation)
            ):
                values.append(
                    {
                        "experiment_id": experiment["id"],
                        "outcome_id": prediction["outcome_id"],
                        "world_id": prediction["world_id"],
                    }
                )
    return sorted(values, key=lambda item: tuple(item[key] for key in groups.COORDINATE_FIELDS))


def _manifest(case, member_groups):
    return {
        "schema_version": groups.MANIFEST_SCHEMA_VERSION,
        "case_sha256": sha256_bytes(canonical_bytes(validate_case(case))),
        "groups": [
            {
                "id": "group:synthetic-%03d" % index,
                "rationale": "Explicit synthetic joint dependence.",
                "members": deepcopy(members),
            }
            for index, members in enumerate(member_groups)
        ],
    }


def _witness(raw_case):
    case = deepcopy(raw_case)
    context = next(world for world in case["worlds"] if world["id"] == "world:context-confounding")
    case["worlds"].append({**deepcopy(context), "id": "world:context-refinement"})
    template = deepcopy(case["experiments"][0])
    case["experiments"] = []
    for identity in ("experiment:alpha", "experiment:beta"):
        experiment = deepcopy(template)
        experiment["id"] = identity
        experiment["predictions"].extend(
            [
                {**deepcopy(prediction), "world_id": "world:context-refinement"}
                for prediction in list(experiment["predictions"])
                if prediction["world_id"] == context["id"]
            ]
        )
        informative = {item["id"] for item in experiment["outcomes"] if item["class"] == "INFORMATIVE"}
        for prediction in experiment["predictions"]:
            if prediction["outcome_id"] in informative:
                prediction["relation"] = (
                    "UNKNOWN"
                    if prediction["world_id"] == "world:residual"
                    else "EXCLUDES"
                    if prediction["world_id"] == "world:invariant-mechanism"
                    else "SURVIVES"
                )
        case["experiments"].append(experiment)
    return validate_case(_rebind(case))


def _cap_case(raw_case, *, extra=False):
    case = deepcopy(raw_case)
    template = case["experiments"][0]
    case["experiments"] = [{**deepcopy(template), "id": "experiment:copy-%03d" % index} for index in range(32)]
    if extra:
        world = next(item for item in case["worlds"] if item["id"] == "world:context-confounding")
        case["worlds"].append({**deepcopy(world), "id": "world:extra-unknown"})
        selected = False
        for experiment in case["experiments"]:
            informative = {item["id"] for item in experiment["outcomes"] if item["class"] == "INFORMATIVE"}
            for prediction in list(experiment["predictions"]):
                if prediction["world_id"] != world["id"]:
                    continue
                addition = {**deepcopy(prediction), "world_id": "world:extra-unknown"}
                if addition["outcome_id"] in informative:
                    addition["relation"] = "UNKNOWN" if selected else "SURVIVES"
                    selected = True
                experiment["predictions"].append(addition)
    return validate_case(_rebind(case))


def _rehash(report):
    core = {key: value for key, value in report.items() if key != "audit_sha256"}
    report["audit_sha256"] = sha256_bytes(groups.AUDIT_DOMAIN + canonical_bytes(core))
    return report


def test_two_cell_witness_masks_singletons_but_changes_joint_selection(raw_case):
    case = _witness(raw_case)
    members = [
        item
        for item in _coords(case, "SURVIVES")
        if item["experiment_id"] == "experiment:alpha" and item["outcome_id"] == "outcome:global-context"
    ]
    manifest = _manifest(case, [members])
    before = canonical_bytes({"case": case, "manifest": manifest})
    report = groups.audit_assumption_groups(case, manifest)
    assert canonical_bytes({"case": case, "manifest": manifest}) == before
    assert report["counts"]["eligible_cells_in_case"] == 12
    assert report["counts"]["distinct_selected_cells"] == report["counts"]["singleton_variants"] == 2
    assert report["counts"]["total_variants"] == report["counts"]["valid_variants"] == 3
    assert report["counts"]["singleton_masked_joint_selection_change_groups"] == 1
    for row in report["singleton_rows"]:
        assert row["selection"] == report["baseline"]["selection"]
        assert row["epistemic_differences_by_experiment"]["experiment:alpha"]["strict_pair_separation_changed"] is False
    joint = report["group_rows"][0]
    assert joint["singleton_masked_joint_selection_change"] is True
    assert joint["masking_applicability"] == {
        "applicable": True,
        "status": "APPLICABLE_ALL_VARIANTS_VALID",
        "all_member_singletons_valid": True,
        "all_member_singleton_selections_unchanged": True,
        "joint_selection_membership_changed": True,
    }
    for scope in assumptions.SCOPES:
        assert report["baseline"]["selection"]["frontiers"][scope] == ["experiment:alpha", "experiment:beta"]
        assert joint["selection"]["frontiers"][scope] == ["experiment:beta"]
        assert joint["selection"]["minimax"][scope]["co_minimax_experiment_ids"] == ["experiment:beta"]
    difference = joint["epistemic_differences_by_experiment"]["experiment:alpha"]
    assert difference["strict_pair_separation_changed"] is True
    assert difference["retained_worlds_changed"] is False
    assert difference["retained_decision_classes_changed"] is False
    assert _rehash(deepcopy(report)) == report
    verified = groups.verify_group_assumption_audit(case, manifest, report)
    assert verified["variants_replayed"] == 3
    assert verified["canonical_report_sha256"] == sha256_bytes(canonical_bytes(report))


def test_overlapping_identical_and_cross_experiment_groups_are_not_deduplicated(raw_case):
    case = _witness(raw_case)
    all_members = _coords(case, "SURVIVES")
    alpha = all_members[:2]
    beta = next(item for item in all_members if item["experiment_id"] == "experiment:beta")
    manifest = _manifest(case, [alpha, alpha, [alpha[0], beta]])
    report = groups.audit_assumption_groups(case, manifest)
    assert report["counts"]["declared_groups"] == 3
    assert report["counts"]["memberships"] == 6
    assert report["counts"]["distinct_selected_cells"] == 3
    assert report["counts"]["total_variants"] == 6
    first, second, cross = report["group_rows"]
    assert first["hypothetical_case_sha256"] == second["hypothetical_case_sha256"]
    assert first["singleton_masked_joint_selection_change"] is second["singleton_masked_joint_selection_change"] is True
    assert cross["selection"] == report["baseline"]["selection"]
    assert cross["singleton_masked_joint_selection_change"] is False
    assert cross["masking_applicability"]["applicable"] is True
    assert set(cross["epistemic_by_experiment"]) == {"experiment:alpha", "experiment:beta"}
    assert len(cross["affected_branch_plans"]) == 2


def test_rejected_singletons_and_group_do_not_fabricate_empty_valid_selection(raw_case):
    manifest = _manifest(raw_case, [_coords(raw_case, "EXCLUDES")[:2]])
    report = groups.audit_assumption_groups(raw_case, manifest)
    assert report["counts"]["requires_reauthoring"] == report["counts"]["total_variants"] == 3
    for row in report["singleton_rows"] + report["group_rows"]:
        assert row["status"] == "REQUIRES_REAUTHORING"
        assert row["case_contract"]["status"] == "REJECTED_BY_CASE_CONTRACT"
        for field in (
            "analysis_sha256",
            "selection",
            "differences",
            "epistemic_by_experiment",
            "epistemic_differences_by_experiment",
        ):
            assert row[field] is None
    group = report["group_rows"][0]
    assert group["singleton_masked_joint_selection_change"] is False
    assert group["masking_applicability"] == {
        "applicable": False,
        "status": "NOT_APPLICABLE_JOINT_AND_MEMBER_SINGLETON_REJECTED",
        "all_member_singletons_valid": False,
        "all_member_singleton_selections_unchanged": None,
        "joint_selection_membership_changed": None,
    }


def test_joint_can_require_reauthoring_when_each_singleton_is_valid(raw_case):
    case = deepcopy(raw_case)
    original = next(world for world in case["worlds"] if world["id"] == "world:invariant-mechanism")
    case["worlds"].append({**deepcopy(original), "id": "world:invariant-copy"})
    for experiment in case["experiments"]:
        experiment["predictions"].extend(
            [
                {**deepcopy(prediction), "world_id": "world:invariant-copy"}
                for prediction in list(experiment["predictions"])
                if prediction["world_id"] == original["id"]
            ]
        )
    case = validate_case(_rebind(case))
    members = [
        item
        for item in _coords(case, "EXCLUDES")
        if item["experiment_id"] == "experiment:global-recompute" and item["outcome_id"] == "outcome:global-context"
    ]
    report = groups.audit_assumption_groups(case, _manifest(case, [members]))
    assert all(row["status"] == "VALID_HYPOTHETICAL_VARIANT" for row in report["singleton_rows"])
    joint = report["group_rows"][0]
    assert joint["status"] == "REQUIRES_REAUTHORING"
    assert joint["masking_applicability"]["status"] == "NOT_APPLICABLE_JOINT_REJECTED"
    assert joint["singleton_masked_joint_selection_change"] is False


def test_selection_change_not_masked_if_a_member_singleton_already_changes_selection(raw_case):
    survivors = _coords(raw_case, "SURVIVES")
    members = [item for item in survivors if item["experiment_id"] == "experiment:held-out-invariance"]
    report = groups.audit_assumption_groups(raw_case, _manifest(raw_case, [members]))
    group = report["group_rows"][0]
    assert group["masking_applicability"]["applicable"] is True
    assert group["masking_applicability"]["all_member_singleton_selections_unchanged"] is False
    assert group["masking_applicability"]["joint_selection_membership_changed"] is True
    assert group["singleton_masked_joint_selection_change"] is False


def test_only_selected_cells_and_affected_branch_hashes_change(raw_case, monkeypatch):
    case = _witness(raw_case)
    survivors = _coords(case, "SURVIVES")
    members = [survivors[0], next(item for item in survivors if item["experiment_id"] == "experiment:beta")]
    manifest = _manifest(case, [members])
    captured, compilations = [], []

    def validated(value):
        captured.append(deepcopy(value))
        return validate_case(value)

    def compiled(value):
        compilations.append(deepcopy(value))
        return compile_case(value)

    monkeypatch.setattr(groups, "validate_case", validated)
    monkeypatch.setattr(groups, "compile_case", compiled)
    report = groups.audit_assumption_groups(case, manifest)
    assert len(captured) == len(compilations) == 4
    for variant, row in zip(captured[1:], report["singleton_rows"] + report["group_rows"], strict=True):
        assert row["hypothetical_case_sha256"] == sha256_bytes(canonical_bytes(variant))
        compiled_variant = compile_case(variant)
        assert row["analysis_sha256"] == compiled_variant["analysis_sha256"]
        assert row["selection"]["minimax"] == compiled_variant["minimax"]
        for member in row["members"]:
            coordinate = member["coordinate"]
            experiment = next(item for item in variant["experiments"] if item["id"] == coordinate["experiment_id"])
            prediction = next(
                item
                for item in experiment["predictions"]
                if item["outcome_id"] == coordinate["outcome_id"] and item["world_id"] == coordinate["world_id"]
            )
            assert prediction["relation"] == member["withdrawn_relation"] == "UNKNOWN"
            assert prediction["source_ids"] == member["source_ids"]
            prediction["relation"] = member["original_relation"]
        for plan in row["affected_branch_plans"]:
            experiment = next(item for item in variant["experiments"] if item["id"] == plan["experiment_id"])
            assert experiment["branch_plan_sha256"] == plan["hypothetical_branch_plan_sha256"]
            experiment["branch_plan_sha256"] = plan["original_branch_plan_sha256"]
        assert canonical_bytes(variant) == canonical_bytes(case)


def test_group_and_case_set_order_normalization_is_byte_deterministic(raw_case):
    case = _witness(raw_case)
    members = _coords(case, "SURVIVES")
    manifest = _manifest(case, [members[:2], [members[1], members[-1]]])
    expected = groups.audit_assumption_groups(case, manifest)
    reversed_case = deepcopy(case)
    for field in ("worlds", "experiments", "gates", "provenance"):
        reversed_case[field].reverse()
    reversed_case["decision"]["options"].reverse()
    for experiment in reversed_case["experiments"]:
        for field in ("outcomes", "predictions", "required_gate_ids", "required_authorities"):
            experiment[field].reverse()
    reordered = deepcopy(manifest)
    reordered["groups"].reverse()
    for group in reordered["groups"]:
        group["members"].reverse()
    reordered = dict(reversed(list(reordered.items())))
    actual = groups.audit_assumption_groups(reversed_case, reordered)
    assert canonical_bytes(actual) == canonical_bytes(expected)
    assert groups.verify_group_assumption_audit(reversed_case, reordered, expected)["verified"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "case-hash",
        "empty",
        "extra",
        "group-extra",
        "coordinate-extra",
        "duplicate-id",
        "duplicate-member",
        "unknown",
        "residual",
        "failure",
        "unknown-relation",
        "id",
        "rationale",
        "private-rationale",
    ],
)
def test_invalid_manifest_rejected_before_compile(raw_case, monkeypatch, mutation):
    manifest = _manifest(raw_case, [_coords(raw_case)[:2]])
    group = manifest["groups"][0]
    if mutation == "schema":
        manifest["schema_version"] = "invented"
    elif mutation == "case-hash":
        manifest["case_sha256"] = "0" * 64
    elif mutation == "empty":
        manifest["groups"] = []
    elif mutation == "extra":
        manifest["automatic_source_grouping"] = True
    elif mutation == "group-extra":
        group["source_ids"] = ["source:invented"]
    elif mutation == "coordinate-extra":
        group["members"][0]["confidence"] = 1
    elif mutation == "duplicate-id":
        manifest["groups"].append(deepcopy(group))
    elif mutation == "duplicate-member":
        group["members"] = [deepcopy(group["members"][0])] * 2
    elif mutation == "unknown":
        group["members"][0]["world_id"] = "world:not-present"
    elif mutation == "residual":
        group["members"][0]["world_id"] = "world:residual"
    elif mutation == "failure":
        group["members"][0]["outcome_id"] = "outcome:global-failure"
    elif mutation == "unknown-relation":
        case = deepcopy(raw_case)
        coordinate = group["members"][0]
        experiment = next(item for item in case["experiments"] if item["id"] == coordinate["experiment_id"])
        prediction = next(
            item
            for item in experiment["predictions"]
            if item["world_id"] == coordinate["world_id"] and item["outcome_id"] == coordinate["outcome_id"]
        )
        prediction["relation"] = "UNKNOWN"
        raw_case = validate_case(_rebind(case))
        manifest["case_sha256"] = sha256_bytes(canonical_bytes(raw_case))
    elif mutation == "id":
        group["id"] = "not an identifier"
    elif mutation == "private-rationale":
        group["rationale"] = "/".join(("", "Users", "synthetic", "private-file"))
    else:
        group["rationale"] = ""

    def forbidden(_):
        pytest.fail("invalid manifest must be rejected before compilation")

    monkeypatch.setattr(groups, "compile_case", forbidden)
    with pytest.raises(CausalFrontierError):
        groups.audit_assumption_groups(raw_case, manifest)


@pytest.mark.parametrize("bound", ["groups", "minimum", "maximum", "memberships", "distinct", "variants"])
def test_declared_group_work_caps_fail_closed_before_compile(raw_case, monkeypatch, bound):
    case = _cap_case(raw_case, extra=bound == "distinct")
    coordinates = _coords(case)
    if bound == "groups":
        member_groups = [coordinates[:2] for _ in range(33)]
    elif bound == "minimum":
        member_groups = [coordinates[:1]]
    elif bound == "maximum":
        member_groups = [coordinates[:17]]
    elif bound == "memberships":
        member_groups = [coordinates[:16] for _ in range(15)] + [coordinates[:15], coordinates[:2]]
        assert sum(map(len, member_groups)) == 257
    elif bound == "distinct":
        assert len(coordinates) == 129
        member_groups = [coordinates[index : index + 16] for index in range(0, 128, 16)] + [
            [coordinates[128], coordinates[0]]
        ]
    else:
        monkeypatch.setattr(groups, "MAX_VARIANTS", 2)
        member_groups = [coordinates[:2]]
    manifest = _manifest(case, member_groups)

    def forbidden(_):
        pytest.fail("work bound must reject before any compilation")

    monkeypatch.setattr(groups, "compile_case", forbidden)
    with pytest.raises(CausalFrontierError):
        groups.audit_assumption_groups(case, manifest)


def test_exact_160_variants_and_128_distinct_members_are_not_truncated(raw_case):
    case = _cap_case(raw_case)
    coordinates = _coords(case)
    manifest = _manifest(case, [coordinates[index : index + 4] for index in range(0, 128, 4)])
    report = groups.audit_assumption_groups(case, manifest)
    assert report["counts"]["declared_groups"] == 32
    assert report["counts"]["distinct_selected_cells"] == 128
    assert report["counts"]["total_variants"] == 160
    assert len(report["singleton_rows"]) == 128 and len(report["group_rows"]) == 32
    assert len(canonical_bytes(report)) + 1 <= assumptions.MAX_JSON_BYTES
    assert groups.verify_group_assumption_audit(case, manifest, report)["variants_replayed"] == 160


def test_exact_256_memberships_and_16_members_per_group_are_accepted(raw_case):
    case = _cap_case(raw_case)
    coordinates = _coords(case)[:16]
    manifest = _manifest(case, [coordinates for _ in range(16)])
    report = groups.audit_assumption_groups(case, manifest)
    assert report["counts"]["memberships"] == 256
    assert report["counts"]["distinct_selected_cells"] == report["counts"]["declared_groups"] == 16
    assert report["counts"]["total_variants"] == 32


def test_unselected_case_cells_are_not_subject_to_the_selected_128_cap(raw_case):
    case = _cap_case(raw_case, extra=True)
    manifest = _manifest(case, [_coords(case, "SURVIVES")[:2]])
    report = groups.audit_assumption_groups(case, manifest)
    assert report["counts"]["eligible_cells_in_case"] == 129
    assert report["counts"]["distinct_selected_cells"] == 2
    assert report["counts"]["total_variants"] == 3


def test_case_work_bounds_and_hostile_manifest_structures_are_reused(raw_case):
    manifest = _manifest(raw_case, [_coords(raw_case)[:2]])
    case = deepcopy(raw_case)
    case["experiments"] = [deepcopy(case["experiments"][0]) for _ in range(33)]
    with pytest.raises(CausalFrontierError):
        groups.audit_assumption_groups(case, manifest)
    cycle = {}
    cycle["self"] = cycle
    for value in (cycle, {"float": 1.5}, {"big": "x" * (assumptions.MAX_JSON_BYTES + 1)}, {1: "bad-key"}):
        with pytest.raises(CausalFrontierError):
            groups.audit_assumption_groups(raw_case, value)


def test_no_source_or_process_access_and_blocked_gates_remain_blocked(raw_case, monkeypatch):
    case = _witness(raw_case)
    case["gates"][0]["state"] = "OPEN"
    manifest = _manifest(case, [_coords(case, "SURVIVES")[:2]])

    def forbidden(*args, **kwargs):
        pytest.fail("pure grouped audit must not access source files or processes")

    with monkeypatch.context() as scope:
        scope.setattr(builtins, "open", forbidden)
        scope.setattr(Path, "open", forbidden)
        scope.setattr(subprocess, "run", forbidden)
        report = groups.audit_assumption_groups(case, manifest)
        verification = groups.verify_group_assumption_audit(case, manifest, report)
    selections = [report["baseline"]["selection"]] + [
        row["selection"] for row in report["singleton_rows"] + report["group_rows"]
    ]
    for selection in selections:
        assert selection["frontiers"]["structurally_admissible_unexecuted"] == []
        assert selection["minimax"]["structurally_admissible_unexecuted"] is None
        assert all(item["current_status"] == "BLOCKED" for item in selection["experiment_admissibility"])
    for value in (report, verification):
        assert value["boundary"] == fixed_boundary()
        for field in (
            "source_files_opened",
            "classifier_executed",
            "empirical_evidence",
            "scoring_enabled",
            "authority_granted",
        ):
            assert value[field] is False
    assert report["group_rows"][0]["singleton_masked_joint_selection_change"] is True
    assert any("not inferred source dependencies" in text for text in report["nonclaims"])


@pytest.mark.parametrize(
    "mutation",
    [
        "count",
        "mask",
        "applicability",
        "coordinate",
        "source",
        "selection",
        "plan-hash",
        "epistemic",
        "missing-singleton",
        "reorder-rows",
        "manifest",
        "authority",
        "nonclaims",
        "extra",
    ],
)
def test_self_rehashed_report_forgeries_fail_exact_replay(raw_case, mutation):
    case = _witness(raw_case)
    manifest = _manifest(case, [_coords(case, "SURVIVES")[:2]])
    report = groups.audit_assumption_groups(case, manifest)
    row = report["group_rows"][0]
    if mutation == "count":
        report["counts"]["distinct_selected_cells"] = 0
    elif mutation == "mask":
        row["singleton_masked_joint_selection_change"] = False
    elif mutation == "applicability":
        row["masking_applicability"]["status"] = "invented"
    elif mutation == "coordinate":
        row["members"][0]["coordinate"]["world_id"] = "world:invented"
    elif mutation == "source":
        row["members"][0]["source_ids"] = []
    elif mutation == "selection":
        row["selection"]["frontiers"]["structurally_admissible_unexecuted"] = []
    elif mutation == "plan-hash":
        row["affected_branch_plans"][0]["hypothetical_branch_plan_sha256"] = "0" * 64
    elif mutation == "epistemic":
        row["epistemic_differences_by_experiment"] = {}
    elif mutation == "missing-singleton":
        report["singleton_rows"].pop()
    elif mutation == "reorder-rows":
        report["singleton_rows"].reverse()
    elif mutation == "manifest":
        report["manifest"]["groups"][0]["rationale"] = "Edited declaration."
        report["manifest_sha256"] = sha256_bytes(canonical_bytes(report["manifest"]))
    elif mutation == "authority":
        report["authority_granted"] = True
    elif mutation == "nonclaims":
        report["nonclaims"] = []
    else:
        report["extra"] = True
    _rehash(report)
    with pytest.raises(CausalFrontierError, match="fresh exact replay"):
        groups.verify_group_assumption_audit(case, manifest, report)


def test_report_and_manifest_inputs_are_bound_in_replay(raw_case, monkeypatch):
    case = _witness(raw_case)
    manifest = _manifest(case, [_coords(case, "SURVIVES")[:2]])
    report = groups.audit_assumption_groups(case, manifest)
    revised = deepcopy(manifest)
    revised["groups"][0]["rationale"] = "Different explicit synthetic declaration."
    with pytest.raises(CausalFrontierError, match="fresh exact replay"):
        groups.verify_group_assumption_audit(case, revised, report)
    monkeypatch.setattr(assumptions, "MAX_JSON_BYTES", len(canonical_bytes(report)))
    with pytest.raises(CausalFrontierError):
        groups.verify_group_assumption_audit(case, manifest, report)


def test_compiler_failure_aborts_instead_of_becoming_a_rejected_group(raw_case, monkeypatch):
    manifest = _manifest(raw_case, [_coords(raw_case, "SURVIVES")[:2]])
    calls = 0

    def compiled(value):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise CausalFrontierError("synthetic compiler fault", reason_code="SYNTHETIC_COMPILER_FAULT")
        return compile_case(value)

    monkeypatch.setattr(groups, "compile_case", compiled)
    with pytest.raises(CausalFrontierError) as caught:
        groups.audit_assumption_groups(raw_case, manifest)
    assert caught.value.reason_code == "SYNTHETIC_COMPILER_FAULT"


def test_normal_and_optimized_report_bytes_are_identical(raw_case, case_root, project_root):
    manifest = _manifest(raw_case, [_coords(raw_case, "SURVIVES")[:2]])
    code = (
        "import json,sys; from causalfrontier.group_assumptions import audit_assumption_groups; "
        "from causalfrontier.canonical import canonical_bytes; "
        "case=json.load(open(sys.argv[1], encoding='utf-8')); manifest=json.loads(sys.argv[2]); "
        "sys.stdout.buffer.write(canonical_bytes(audit_assumption_groups(case,manifest)))"
    )
    environment = {**os.environ, "PYTHONPATH": str(project_root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    outputs = [
        subprocess.run(
            [sys.executable, *flags, "-B", "-c", code, str(case_root / "case.json"), json.dumps(manifest)],
            check=True,
            capture_output=True,
            env=environment,
            timeout=30,
        ).stdout
        for flags in ([], ["-O"])
    ]
    assert outputs[0] == outputs[1]
    assert json.loads(outputs[0])["counts"]["total_variants"] == 3
