from __future__ import annotations

import json
from pathlib import Path

import pytest

from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_file
from causalfrontier.classifier import execute_classifiers
from causalfrontier.model import load_case, validate_case


def _rewrite_case_source_digest(case_root: Path) -> None:
    case_path = case_root / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    source = case["provenance"][0]
    source["sha256"] = sha256_file(case_root / source["path"])
    case_path.write_bytes(canonical_bytes(case) + b"\n")


def _execute(copied_case: Path):
    case = load_case(copied_case)
    return execute_classifiers(case, copied_case)["results"]


def test_bound_classifiers_execute_expected_synthetic_branches(case_root: Path):
    case = load_case(case_root)
    first = execute_classifiers(case, case_root)
    second = execute_classifiers(case, case_root)
    assert canonical_bytes(first) == canonical_bytes(second)
    assert {item["experiment_id"]: item["outcome_id"] for item in first["results"]} == {
        "experiment:global-recompute": "outcome:global-invariant",
        "experiment:held-out-invariance": "outcome:held-invariant",
        "experiment:negative-control": "outcome:control-tracks-context",
    }
    assert {item["semantic_scope"] for item in first["results"]} == {"SYNTHETIC_FIXTURE_ONLY"}
    assert {item["authority"] for item in first["results"]} == {"SOFTWARE_ONLY"}


def test_execution_reauthenticates_bytes_after_case_validation(copied_case: Path):
    case = load_case(copied_case)
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(source.read_text(encoding="utf-8") + "context_z\tcandidate\t9\t9\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="digest changed after case validation"):
        execute_classifiers(case, copied_case)


def test_syntax_failure_precedence_is_independent_of_row_order(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    header = "context\tintervention\tresponse_index\tnegative_control_index\n"
    rows = [
        "context_a\tcandidate\tnot-an-integer\tnot-an-integer",
        "context_b\tundeclared\t4\t1",
    ]
    observed = []
    for ordered_rows in (rows, list(reversed(rows))):
        source.write_text(header + "\n".join(ordered_rows) + "\n", encoding="utf-8")
        _rewrite_case_source_digest(copied_case)
        observed.append({(item["branch_token"], item["metrics"]["reason"]) for item in _execute(copied_case)})
    assert observed == [
        {("FAILURE", "VALUE_IS_NOT_CANONICAL_INTEGER")},
        {("FAILURE", "VALUE_IS_NOT_CANONICAL_INTEGER")},
    ]


def test_classifier_rule_edit_requires_new_classifier_digest(mutable_case):
    mutable_case["experiments"][0]["classifier"]["rule"]["low_max"] = 1
    mutable_case["experiments"][0]["classifier"]["rule"]["high_min"] = 2
    with pytest.raises(CausalFrontierError, match="classifier digest mismatch"):
        validate_case(mutable_case)


def test_classifier_outcome_map_must_be_bijective(mutable_case):
    classifier = mutable_case["experiments"][0]["classifier"]
    classifier["outcome_map"]["HIGH"] = classifier["outcome_map"]["LOW"]
    with pytest.raises(CausalFrontierError, match="every declared outcome exactly once"):
        validate_case(mutable_case)


def test_classifier_role_columns_must_be_distinct(mutable_case):
    classifier = mutable_case["experiments"][0]["classifier"]
    classifier["rule"]["group_column"] = classifier["rule"]["intervention_column"]
    with pytest.raises(CausalFrontierError, match="role columns must be distinct"):
        validate_case(mutable_case)


def test_header_drift_resolves_to_predeclared_failure(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(source.read_text(encoding="utf-8").replace("response_index", "response"), encoding="utf-8")
    _rewrite_case_source_digest(copied_case)
    results = _execute(copied_case)
    assert {item["branch_token"] for item in results} == {"FAILURE"}
    assert {item["metrics"]["reason"] for item in results} == {"INPUT_HEADER_SCHEMA_MISMATCH"}


def test_duplicate_cell_resolves_to_predeclared_failure(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(source.read_text(encoding="utf-8") + "context_a\tcandidate\t8\t1\n", encoding="utf-8")
    _rewrite_case_source_digest(copied_case)
    results = _execute(copied_case)
    assert {item["branch_token"] for item in results} == {"FAILURE"}
    assert {item["metrics"]["reason"] for item in results} == {"DUPLICATE_GROUP_INTERVENTION_CELL"}


def test_undeclared_intervention_resolves_to_predeclared_failure(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(source.read_text(encoding="utf-8") + "context_z\tundeclared\t8\t1\n", encoding="utf-8")
    _rewrite_case_source_digest(copied_case)
    results = _execute(copied_case)
    assert {item["branch_token"] for item in results} == {"FAILURE"}
    assert {item["metrics"]["reason"] for item in results} == {"UNDECLARED_INTERVENTION_VALUE"}


def test_incomplete_pair_precedes_scientific_contradiction_independent_of_group_id(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    header = "context\tintervention\tresponse_index\tnegative_control_index\n"
    complete = ["middle\tcandidate\t5\t1", "middle\tcomparator\t2\t1"]
    anomaly_sets = (
        ["a\tcandidate\t1\t1", "a\tcomparator\t2\t1", "z\tcandidate\t4\t1"],
        ["a\tcandidate\t4\t1", "z\tcandidate\t1\t1", "z\tcomparator\t2\t1"],
    )
    observed = []
    for anomalies in anomaly_sets:
        source.write_text(header + "\n".join(anomalies + complete) + "\n", encoding="utf-8")
        _rewrite_case_source_digest(copied_case)
        result = next(item for item in _execute(copied_case) if item["experiment_id"] == "experiment:global-recompute")
        observed.append((result["branch_token"], result["metrics"]["reason"]))
    assert observed == [
        ("NO_CALL", "GROUP_PAIR_INCOMPLETE"),
        ("NO_CALL", "GROUP_PAIR_INCOMPLETE"),
    ]


def test_valid_measurement_can_reach_predeclared_contradiction(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(
        source.read_text(encoding="utf-8").replace("context_a\tcandidate\t8\t1", "context_a\tcandidate\t1\t1"),
        encoding="utf-8",
    )
    _rewrite_case_source_digest(copied_case)
    results = {item["experiment_id"]: item for item in _execute(copied_case)}
    for experiment_id in ("experiment:global-recompute", "experiment:held-out-invariance"):
        assert results[experiment_id]["branch_token"] == "CONTRADICTION"
        assert results[experiment_id]["metrics"]["reason"] == "CANDIDATE_COMPARATOR_DIRECTION_REVERSED"


def test_missing_heldout_pair_resolves_to_predeclared_no_call(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    lines = [line for line in source.read_text(encoding="utf-8").splitlines() if not line.startswith("held_out\t")]
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _rewrite_case_source_digest(copied_case)
    results = {item["experiment_id"]: item for item in _execute(copied_case)}
    assert results["experiment:global-recompute"]["branch_token"] == "NO_CALL"
    assert results["experiment:held-out-invariance"]["branch_token"] == "NO_CALL"


def test_adjacent_threshold_high_branch_has_no_numeric_gap(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    text = source.read_text(encoding="utf-8").replace("context_a\tcandidate\t8\t1", "context_a\tcandidate\t9\t1")
    source.write_text(text, encoding="utf-8")
    _rewrite_case_source_digest(copied_case)
    results = {item["experiment_id"]: item for item in _execute(copied_case)}
    global_result = results["experiment:global-recompute"]
    assert global_result["metrics"]["range"] == 3
    assert global_result["branch_token"] == "HIGH"
    assert global_result["outcome_id"] == "outcome:global-context"


def test_heldout_classifier_fails_on_silently_ignored_extra_group(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(
        source.read_text(encoding="utf-8") + "undeclared\tcandidate\t5\t2\n" + "undeclared\tcomparator\t2\t2\n",
        encoding="utf-8",
    )
    _rewrite_case_source_digest(copied_case)
    results = {item["experiment_id"]: item for item in _execute(copied_case)}
    heldout = results["experiment:held-out-invariance"]
    assert heldout["branch_token"] == "FAILURE"
    assert heldout["metrics"]["reason"] == "DECLARED_GROUP_SET_MISMATCH"
