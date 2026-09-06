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
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.frontier import compile_case
from causalfrontier.model import branch_plan_sha256, fixed_boundary, validate_case


def _rebind(case):
    for experiment in case["experiments"]:
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    return case


def _eligible(case):
    coordinates = []
    named = {world["id"] for world in case["worlds"] if not world["is_residual"]}
    for experiment in case["experiments"]:
        informative = {outcome["id"] for outcome in experiment["outcomes"] if outcome["class"] == "INFORMATIVE"}
        for prediction in experiment["predictions"]:
            if (
                prediction["world_id"] in named
                and prediction["outcome_id"] in informative
                and prediction["relation"] in {"SURVIVES", "EXCLUDES"}
            ):
                coordinates.append((experiment["id"], prediction["outcome_id"], prediction["world_id"]))
    return sorted(coordinates)


def _variant(case, row):
    variant = deepcopy(case)
    coordinate = row["coordinate"]
    experiment = next(item for item in variant["experiments"] if item["id"] == coordinate["experiment_id"])
    prediction = next(
        item
        for item in experiment["predictions"]
        if item["outcome_id"] == coordinate["outcome_id"] and item["world_id"] == coordinate["world_id"]
    )
    prediction["relation"] = "UNKNOWN"
    experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    return variant


def _duplicate_named_worlds(case):
    originals = [world for world in case["worlds"] if not world["is_residual"]]
    for world in originals:
        duplicate = {**deepcopy(world), "id": world["id"] + "-duplicate"}
        case["worlds"].append(duplicate)
        for experiment in case["experiments"]:
            extra = [
                {**deepcopy(prediction), "world_id": duplicate["id"]}
                for prediction in experiment["predictions"]
                if prediction["world_id"] == world["id"]
            ]
            experiment["predictions"].extend(extra)
    return _rebind(case)


def _cap_case(case):
    template = case["experiments"][0]
    case["experiments"] = []
    for index in range(32):
        experiment = deepcopy(template)
        experiment["id"] = "experiment:copy-%03d" % index
        case["experiments"].append(experiment)
    return _rebind(case)


def _rehash(report):
    core = {key: value for key, value in report.items() if key != "audit_sha256"}
    report["audit_sha256"] = sha256_bytes(assumptions.AUDIT_DOMAIN + canonical_bytes(core))
    return report


def test_all_eligible_rows_are_accounted_for_with_exact_hashes(raw_case):
    normalized = validate_case(raw_case)
    before = canonical_bytes(raw_case)
    report = assumptions.audit_assumptions(raw_case)
    baseline = compile_case(normalized)
    assert canonical_bytes(raw_case) == before
    assert report["case_sha256"] == baseline["case_sha256"]
    assert report["baseline"]["analysis_sha256"] == baseline["analysis_sha256"]
    for field in ("frontiers", "minimax", "selection_policy"):
        assert report["baseline"]["selection"][field] == baseline[field]
    assert [
        tuple(row["coordinate"][key] for key in ("experiment_id", "outcome_id", "world_id")) for row in report["rows"]
    ] == _eligible(normalized)
    assert report["counts"]["eligible_cells"] == report["counts"]["reported_rows"] == 12
    assert report["counts"]["valid_variants"] == report["counts"]["requires_reauthoring"] == 6
    assert report["counts"]["selection_changed_valid_variants"] == 4
    assert report["counts"]["selection_unchanged_valid_variants"] == 2
    assert _rehash(deepcopy(report)) == report
    for row in report["rows"]:
        variant = _variant(normalized, row)
        assert row["hypothetical_case_sha256"] == sha256_bytes(canonical_bytes(variant))
        experiment = next(item for item in variant["experiments"] if item["id"] == row["coordinate"]["experiment_id"])
        assert row["hypothetical_branch_plan_sha256"] == experiment["branch_plan_sha256"]
        assert row["original_branch_plan_sha256"] != row["hypothetical_branch_plan_sha256"]
        if row["status"] == "VALID_HYPOTHETICAL_VARIANT":
            analysis = compile_case(variant)
            assert row["analysis_sha256"] == analysis["analysis_sha256"]
            assert row["selection"]["frontiers"] == analysis["frontiers"]
            assert row["selection"]["minimax"] == analysis["minimax"]
    verified = assumptions.verify_assumption_audit(raw_case, report)
    assert verified["verified"] is True
    assert verified["rows_replayed"] == 12
    assert verified["canonical_report_sha256"] == sha256_bytes(canonical_bytes(report))


def test_rejected_authoring_contract_is_not_a_valid_empty_frontier(raw_case):
    report = assumptions.audit_assumptions(raw_case)
    for row in report["rows"]:
        if row["original_relation"] == "EXCLUDES":
            assert row["status"] == "REQUIRES_REAUTHORING"
            assert row["case_contract"]["status"] == "REJECTED_BY_CASE_CONTRACT"
            assert row["case_contract"]["diagnostic"]["reason_code"] == "VALIDATION_REJECTED"
            for field in (
                "analysis_sha256",
                "selection",
                "differences",
                "epistemic_projection",
                "epistemic_differences",
            ):
                assert row[field] is None
            with pytest.raises(CausalFrontierError):
                validate_case(_variant(validate_case(raw_case), row))
        else:
            assert row["status"] == "VALID_HYPOTHETICAL_VARIANT"
            assert row["case_contract"] == {"status": "ACCEPTED_BY_CASE_CONTRACT", "diagnostic": None, "detail": None}


def test_strict_separation_can_change_without_world_or_class_reduction(raw_case):
    report = assumptions.audit_assumptions(raw_case)
    for row in report["rows"]:
        if row["status"] != "VALID_HYPOTHETICAL_VARIANT":
            continue
        difference = row["epistemic_differences"]
        assert difference["strict_pair_separation_changed"] is True
        assert difference["retained_worlds_changed"] is False
        assert difference["retained_decision_classes_changed"] is False
        assert difference["conditional_class_reduction_changed"] is False
        assert difference["conditional_world_reduction_changed"] is False
    assert report["counts"]["strict_pair_separation_changed_valid_variants"] == 6
    assert report["counts"]["retained_worlds_changed_valid_variants"] == 0


def test_duplicated_decision_equivalent_worlds_change_counts_and_effects(raw_case):
    case = _duplicate_named_worlds(deepcopy(raw_case))
    report = assumptions.audit_assumptions(case)
    assert report["counts"]["eligible_cells"] == report["counts"]["valid_variants"] == 24
    assert report["counts"]["requires_reauthoring"] == 0
    for row in report["rows"]:
        difference = row["epistemic_differences"]
        if row["original_relation"] == "SURVIVES":
            assert difference["strict_pair_separation_changed"] is False
            assert difference["retained_worlds_changed"] is False
        else:
            assert difference["retained_worlds_changed"] is True
            assert difference["retained_decision_classes_changed"] is True
            assert difference["strict_pair_separation_changed"] is True
            assert difference["conditional_class_reduction_changed"] is True
    assert any("encoding-dependent" in text and "confidence percentages" in text for text in report["nonclaims"])


def test_only_one_relation_and_its_branch_digest_change(raw_case, monkeypatch):
    normalized = validate_case(raw_case)
    validations, compilations = [], []

    def validated(value):
        validations.append(deepcopy(value))
        return validate_case(value)

    def compiled(value):
        compilations.append(deepcopy(value))
        validate_case(value)
        return compile_case(value)

    monkeypatch.setattr(assumptions, "validate_case", validated)
    monkeypatch.setattr(assumptions, "compile_case", compiled)
    report = assumptions.audit_assumptions(raw_case)
    assert len(validations) == 13
    assert len(compilations) == 7
    for variant, row in zip(validations[1:], report["rows"], strict=True):
        coordinate = row["coordinate"]
        experiment = next(item for item in variant["experiments"] if item["id"] == coordinate["experiment_id"])
        prediction = next(
            item
            for item in experiment["predictions"]
            if item["world_id"] == coordinate["world_id"] and item["outcome_id"] == coordinate["outcome_id"]
        )
        assert prediction["relation"] == "UNKNOWN"
        prediction["relation"] = row["original_relation"]
        experiment["branch_plan_sha256"] = row["original_branch_plan_sha256"]
        assert canonical_bytes(variant) == canonical_bytes(normalized)


def test_source_ids_are_preserved_not_removed_or_reinterpreted(raw_case):
    case = deepcopy(raw_case)
    source = deepcopy(case["provenance"][0])
    source.update(id="source:second-synthetic", path="evidence/second.tsv", source_locator="synthetic:second")
    case["provenance"].append(source)
    source_ids = sorted(item["id"] for item in case["provenance"])
    for experiment in case["experiments"]:
        for prediction in experiment["predictions"]:
            prediction["source_ids"] = list(source_ids)
    _rebind(case)
    report = assumptions.audit_assumptions(case)
    assert all(row["source_ids"] == source_ids for row in report["rows"])
    assert case["provenance"] == [raw_case["provenance"][0], source]
    assert any("shared-source dependency" in text for text in report["nonclaims"])


def test_open_gates_never_become_authorized_admissible_actions(raw_case):
    case = deepcopy(raw_case)
    case["gates"][0]["state"] = "OPEN"
    report = assumptions.audit_assumptions(case)
    selections = [report["baseline"]["selection"]]
    selections.extend(row["selection"] for row in report["rows"] if row["selection"] is not None)
    for selection in selections:
        assert selection["frontiers"]["structurally_admissible_unexecuted"] == []
        assert selection["minimax"]["structurally_admissible_unexecuted"] is None
        assert selection["frontiers"]["conditional_scientific_structure"]
        assert all(
            item["current_status"] == "BLOCKED" and item["blocked_reasons"]
            for item in selection["experiment_admissibility"]
        )
    assert report["boundary"] == fixed_boundary()
    for field in (
        "source_files_opened",
        "classifier_executed",
        "empirical_evidence",
        "scoring_enabled",
        "authority_granted",
    ):
        assert report[field] is False
    assert report["experiments_executed_n"] == 0


def test_reordering_normalized_sets_and_objects_is_deterministic(raw_case):
    case = deepcopy(raw_case)
    for key in ("worlds", "experiments", "gates", "provenance"):
        case[key].reverse()
    case["decision"]["options"].reverse()
    for world in case["worlds"]:
        world["admissible_option_ids"].reverse()
        world["source_ids"].reverse()
    for experiment in case["experiments"]:
        for key in ("outcomes", "predictions", "required_gate_ids", "required_authorities"):
            experiment[key].reverse()
    case = dict(reversed(list(case.items())))
    assert canonical_bytes(assumptions.audit_assumptions(case)) == canonical_bytes(
        assumptions.audit_assumptions(raw_case)
    )


@pytest.mark.parametrize("mode", ["no-experiments", "all-unknown"])
def test_current_contract_does_not_admit_zero_eligible_cases(raw_case, mode):
    case = deepcopy(raw_case)
    if mode == "no-experiments":
        case["experiments"] = []
    else:
        for experiment in case["experiments"]:
            informative = {item["id"] for item in experiment["outcomes"] if item["class"] == "INFORMATIVE"}
            for prediction in experiment["predictions"]:
                if prediction["outcome_id"] in informative:
                    prediction["relation"] = "UNKNOWN"
        _rebind(case)
    assert _eligible(case) == []
    with pytest.raises(CausalFrontierError):
        assumptions.audit_assumptions(case)


def test_exact_128_cell_cap_produces_every_row_without_truncation(raw_case):
    case = _cap_case(deepcopy(raw_case))
    report = assumptions.audit_assumptions(case)
    assert report["counts"]["eligible_cells"] == report["counts"]["reported_rows"] == 128
    assert report["counts"]["valid_variants"] == report["counts"]["requires_reauthoring"] == 64
    assert len(canonical_bytes(report)) + 1 <= assumptions.MAX_JSON_BYTES
    assert assumptions.verify_assumption_audit(case, report)["rows_replayed"] == 128


def test_129_cells_rejected_before_any_compilation(raw_case, monkeypatch):
    case = _cap_case(deepcopy(raw_case))
    original = case["worlds"][0]
    duplicate = {**deepcopy(original), "id": "world:extra-unknown"}
    case["worlds"].append(duplicate)
    extra_survives = False
    for experiment in case["experiments"]:
        classes = {item["id"]: item["class"] for item in experiment["outcomes"]}
        for prediction in list(experiment["predictions"]):
            if prediction["world_id"] != original["id"]:
                continue
            extra = {**deepcopy(prediction), "world_id": duplicate["id"]}
            if classes[extra["outcome_id"]] == "INFORMATIVE":
                if not extra_survives:
                    extra["relation"], extra_survives = "SURVIVES", True
                else:
                    extra["relation"] = "UNKNOWN"
            experiment["predictions"].append(extra)
    _rebind(case)
    assert len(_eligible(validate_case(case))) == 129

    def forbidden(_):
        pytest.fail("cap rejection must precede compile")

    monkeypatch.setattr(assumptions, "compile_case", forbidden)
    with pytest.raises(CausalFrontierError) as caught:
        assumptions.audit_assumptions(case)
    assert caught.value.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED"


@pytest.mark.parametrize("bound", ["experiments", "outcomes", "predictions"])
def test_explicit_work_bounds_reject_before_validation(raw_case, monkeypatch, bound):
    case = deepcopy(raw_case)
    if bound == "experiments":
        case["experiments"] = [deepcopy(case["experiments"][0]) for _ in range(33)]
    else:
        limit = assumptions.MAX_TOTAL_OUTCOMES if bound == "outcomes" else assumptions.MAX_TOTAL_PREDICTIONS
        case["experiments"][0][bound] = [None] * (limit + 1)

    def forbidden(_):
        pytest.fail("work rejection must precede model validation")

    monkeypatch.setattr(assumptions, "validate_case", forbidden)
    with pytest.raises(CausalFrontierError) as caught:
        assumptions.audit_assumptions(case)
    assert caught.value.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED"


@pytest.mark.parametrize("value", [1.0, float("nan"), {1: "bad-key"}, {"bad": "\ud800"}, (1, 2), 1 << 214])
def test_hostile_non_json_values_are_rejected(value):
    with pytest.raises(CausalFrontierError):
        assumptions.audit_assumptions(value)


def test_cyclic_deep_and_oversized_inputs_have_bounded_rejections(raw_case):
    cycle = {}
    cycle["cycle"] = cycle
    for value in (
        cycle,
        {"large": "x" * (assumptions.MAX_JSON_BYTES + 1)},
        {"large": [None] * (assumptions.MAX_CONTAINER_ITEMS + 1)},
    ):
        with pytest.raises(CausalFrontierError) as caught:
            assumptions.audit_assumptions(value)
        assert caught.value.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED"
    case = deepcopy(raw_case)
    case["title"] = "changed without touching the contract digest"
    case["boundary"]["clinical_authority"] = True
    with pytest.raises(CausalFrontierError):
        assumptions.audit_assumptions(case)


def test_report_limit_reserves_the_cli_newline(raw_case, monkeypatch):
    report = assumptions.audit_assumptions(raw_case)
    payload_size = len(canonical_bytes(report))
    monkeypatch.setattr(assumptions, "MAX_JSON_BYTES", payload_size)
    with pytest.raises(CausalFrontierError) as caught:
        assumptions.verify_assumption_audit(raw_case, report)
    assert caught.value.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED"


def test_cumulative_key_bound_stops_before_traversing_more_input(monkeypatch):
    monkeypatch.setattr(assumptions, "MAX_JSON_BYTES", 15)
    value = {"x" * 8: None, "y" * 8: None, "\ud800": None}
    with pytest.raises(CausalFrontierError) as caught:
        assumptions.audit_assumptions(value)
    assert caught.value.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED"


def test_pure_api_does_not_open_files_or_launch_classifiers(raw_case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("pure audit must not open files or launch programs")

    with monkeypatch.context() as scope:
        scope.setattr(builtins, "open", forbidden)
        scope.setattr(Path, "open", forbidden)
        scope.setattr(subprocess, "run", forbidden)
        report = assumptions.audit_assumptions(raw_case)
        verified = assumptions.verify_assumption_audit(raw_case, report)
    assert verified["verified"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "counts",
        "coordinate",
        "source",
        "selection",
        "missing-row",
        "row-order",
        "authority",
        "nonclaims",
        "extra-field",
    ],
)
def test_rehashed_forgery_cannot_pass_fresh_whole_report_replay(raw_case, mutation):
    report = assumptions.audit_assumptions(raw_case)
    if mutation == "counts":
        report["counts"]["eligible_cells"] -= 1
    elif mutation == "coordinate":
        report["rows"][0]["coordinate"]["world_id"] = "world:invented"
    elif mutation == "source":
        report["rows"][0]["source_ids"] = []
    elif mutation == "selection":
        valid = next(row for row in report["rows"] if row["selection"] is not None)
        valid["selection"]["frontiers"]["structurally_admissible_unexecuted"] = []
    elif mutation == "missing-row":
        report["rows"].pop()
    elif mutation == "row-order":
        report["rows"].reverse()
    elif mutation == "authority":
        report["authority_granted"] = True
    elif mutation == "nonclaims":
        report["nonclaims"] = []
    else:
        report["unrecognized"] = "added"
    _rehash(report)
    with pytest.raises(CausalFrontierError, match="fresh exact replay"):
        assumptions.verify_assumption_audit(raw_case, report)


def test_valid_but_different_case_cannot_verify_a_report(raw_case):
    report = assumptions.audit_assumptions(raw_case)
    different = deepcopy(raw_case)
    different["title"] += " revised"
    validate_case(different)
    with pytest.raises(CausalFrontierError, match="fresh exact replay"):
        assumptions.verify_assumption_audit(different, report)


def test_compiler_failure_is_not_mislabeled_case_contract_rejection(raw_case, monkeypatch):
    calls = 0

    def fail_on_variant(value):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise CausalFrontierError("synthetic compiler fault", reason_code="SYNTHETIC_COMPILER_FAULT")
        return compile_case(value)

    monkeypatch.setattr(assumptions, "compile_case", fail_on_variant)
    with pytest.raises(CausalFrontierError) as caught:
        assumptions.audit_assumptions(raw_case)
    assert caught.value.reason_code == "SYNTHETIC_COMPILER_FAULT"


def test_normal_and_optimized_full_report_bytes_match(case_root, project_root):
    code = (
        "import json,sys; from causalfrontier.assumptions import audit_assumptions; "
        "from causalfrontier.canonical import canonical_bytes; "
        "case=json.load(open(sys.argv[1], encoding='utf-8')); "
        "sys.stdout.buffer.write(canonical_bytes(audit_assumptions(case)))"
    )
    environment = {**os.environ, "PYTHONPATH": str(project_root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    outputs = [
        subprocess.run(
            [sys.executable, *flags, "-B", "-c", code, str(case_root / "case.json")],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
        ).stdout
        for flags in ([], ["-O"])
    ]
    assert outputs[0] == outputs[1]
    assert json.loads(outputs[0])["counts"]["eligible_cells"] == 12
