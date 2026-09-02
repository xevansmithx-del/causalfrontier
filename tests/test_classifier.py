from __future__ import annotations

import csv
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes, sha256_file
from causalfrontier.classifier import (
    CLASSIFIER_CELL_MAX_BYTES,
    INTEGER_BOUND,
    classifier_parser_contract,
    classifier_sha256,
    execute_classifier_observation,
    execute_classifiers,
)
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


def _observation_result(case, raw: bytes):
    return execute_classifier_observation(
        case,
        "experiment:global-recompute",
        "observation:test",
        "replicate:1",
        raw,
        sha256_bytes(raw),
    )


def test_observation_adapter_derives_all_five_tokens_from_authenticated_bytes(case_root: Path):
    case = load_case(case_root)
    header = b"context\tintervention\tresponse_index\tnegative_control_index\n"
    low = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    high = low.replace(b"held_out\tcandidate\t6\t2", b"held_out\tcandidate\t12\t2")
    contradiction = low.replace(b"context_a\tcandidate\t8\t1", b"context_a\tcandidate\t1\t1")
    failure = b"wrong\theader\ncommitted\tmeasurement\n"
    no_call = header
    observed = {
        token: _observation_result(case, raw)["branch_token"]
        for token, raw in {
            "LOW": low,
            "HIGH": high,
            "CONTRADICTION": contradiction,
            "FAILURE": failure,
            "NO_CALL": no_call,
        }.items()
    }
    assert observed == {token: token for token in ("LOW", "HIGH", "CONTRADICTION", "FAILURE", "NO_CALL")}


def test_observation_adapter_uses_hidden_bytes_not_frozen_source(case_root: Path):
    case = load_case(case_root)
    frozen = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    hidden = frozen.replace(b"held_out\tcandidate\t6\t2", b"held_out\tcandidate\t12\t2")
    assert _observation_result(case, frozen)["branch_token"] == "LOW"
    result = _observation_result(case, hidden)
    assert result["branch_token"] == "HIGH"
    assert result["execution_status"] == "EXECUTED_DIGEST_AUTHENTICATED_SYNTHETIC_OBSERVATION_BYTES"
    assert result["observation_sha256"] == sha256_bytes(hidden)
    assert result["authority"] == "SOFTWARE_ONLY"


def test_observation_digest_mismatch_aborts_instead_of_deriving_failure(case_root: Path):
    case = load_case(case_root)
    raw = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    with pytest.raises(CausalFrontierError, match="digest changed"):
        execute_classifier_observation(
            case,
            "experiment:global-recompute",
            "observation:test",
            "replicate:1",
            raw,
            "0" * 64,
        )


def test_observation_adapter_reauthenticates_classifier_logic(case_root: Path):
    case = deepcopy(load_case(case_root))
    case["experiments"][0]["classifier"]["rule"]["low_max"] = 1
    case["experiments"][0]["classifier"]["rule"]["high_min"] = 2
    raw = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    with pytest.raises(CausalFrontierError, match="classifier digest mismatch"):
        _observation_result(case, raw)


def test_observation_adapter_revalidates_outcome_class_mapping_after_coherent_rehash(case_root: Path):
    case = deepcopy(load_case(case_root))
    experiment = next(item for item in case["experiments"] if item["id"] == "experiment:global-recompute")
    mapping = experiment["classifier"]["outcome_map"]
    mapping["LOW"], mapping["CONTRADICTION"] = mapping["CONTRADICTION"], mapping["LOW"]
    experiment["classifier_sha256"] = classifier_sha256(experiment["classifier"])
    raw = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    with pytest.raises(CausalFrontierError, match="wrong outcome class"):
        _observation_result(case, raw)


def test_observation_parser_is_independent_of_process_global_csv_field_limit(case_root: Path):
    case = load_case(case_root)
    raw = (
        b"context\tintervention\tresponse_index\tnegative_control_index\n"
        + b"x" * (CLASSIFIER_CELL_MAX_BYTES + 1)
        + b"\tcandidate\t1\t0\n"
    )
    original_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(1)
        first = _observation_result(case, raw)
        csv.field_size_limit(10_000_000)
        second = _observation_result(case, raw)
    finally:
        csv.field_size_limit(original_limit)
    assert first == second
    assert first["branch_token"] == "FAILURE"
    assert first["metrics"] == {"reason": "INPUT_FIELD_EXCEEDS_LIMIT"}


@pytest.mark.parametrize("value", ["9" * 5000, "-" + "9" * 5000])
def test_observation_integer_lexical_bound_is_independent_of_python_global_limit(case_root: Path, value: str):
    case = load_case(case_root)
    raw = b"context\tintervention\tresponse_index\tnegative_control_index\n" + (
        "context_a\tcandidate\t%s\t0\n" % value
    ).encode("ascii")
    original_limit = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else None
    observed = []
    try:
        for limit in (640, 10_000):
            if hasattr(sys, "set_int_max_str_digits"):
                sys.set_int_max_str_digits(limit)
            observed.append(_observation_result(case, raw))
    finally:
        if original_limit is not None:
            sys.set_int_max_str_digits(original_limit)
    assert observed[0] == observed[1]
    assert observed[0]["branch_token"] == "FAILURE"
    assert observed[0]["metrics"] == {"reason": "INTEGER_OUT_OF_BOUNDS"}


@pytest.mark.parametrize("value", ["-0", str(INTEGER_BOUND + 1), str(-(INTEGER_BOUND + 1))])
def test_observation_integer_canonicality_and_bound_are_total(case_root: Path, value: str):
    case = load_case(case_root)
    raw = b"context\tintervention\tresponse_index\tnegative_control_index\n" + (
        "context_a\tcandidate\t%s\t0\n" % value
    ).encode("ascii")
    result = _observation_result(case, raw)
    assert result["branch_token"] == "FAILURE"
    expected = "VALUE_IS_NOT_CANONICAL_INTEGER" if value == "-0" else "INTEGER_OUT_OF_BOUNDS"
    assert result["metrics"] == {"reason": expected}


@pytest.mark.parametrize(
    "raw",
    [
        b"context\tintervention\tresponse_index\tnegative_control_index\r\n",
        "context\tintervention\tresponse_index\tnegative_control_index\u0085".encode(),
        b"context\tintervention\tresponse_index\tnegative_control_index",
    ],
)
def test_observation_parser_enforces_one_exact_record_grammar(case_root: Path, raw: bytes):
    result = _observation_result(load_case(case_root), raw)
    assert result["branch_token"] == "FAILURE"
    assert result["metrics"] == {"reason": "INPUT_RECORD_DELIMITER_MISMATCH"}


def test_parser_contract_binds_transport_and_integer_grammar():
    contract = classifier_parser_contract()
    assert contract["encoding"] == "UTF-8"
    assert contract["record_delimiter"] == "U+000A_LINE_FEED_ONLY"
    assert contract["terminal_record_delimiter_required"] is True
    assert contract["integer_absolute_bound"] == INTEGER_BOUND
    assert contract["integer_negative_zero_allowed"] is False


@pytest.mark.parametrize("mutation", ["public-data", "material-execution"])
def test_observation_adapter_cannot_cross_synthetic_read_only_authority(case_root: Path, mutation):
    case = deepcopy(load_case(case_root))
    if mutation == "public-data":
        case["provenance"][0]["data_class"] = "PUBLIC_AGGREGATE"
        error = "restricted to synthetic"
    else:
        case["experiments"][0]["execution_class"] = "MATERIAL_PERTURBATION"
        error = "read-only synthetic authority"
    raw = (case_root / "evidence/aggregate_response.tsv").read_bytes()
    with pytest.raises(CausalFrontierError, match=error):
        _observation_result(case, raw)
