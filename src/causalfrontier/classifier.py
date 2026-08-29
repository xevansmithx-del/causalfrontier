"""Digest-bound, deterministic classifiers for the synthetic pre-alpha slice."""

from __future__ import annotations

import csv
import io
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    contained_file,
    require_exact_keys,
    require_id,
    require_id_list,
    require_text,
    sha256_bytes,
)

CLASSIFIER_SCHEMA = "causalfrontier.classifier.v1"
CLASSIFIER_ENGINE = "BUILTIN_TSV_INTEGER_V1"
CLASSIFIER_INPUT_MAX_BYTES = 1024 * 1024
BRANCH_TOKENS = {"CONTRADICTION", "FAILURE", "NO_CALL", "LOW", "HIGH"}
RULE_KINDS = {
    "GROUPED_CONTRAST_RANGE_V1",
    "GROUPED_SHARED_VALUE_RANGE_V1",
    "HELDOUT_CONTRAST_ENVELOPE_V1",
}
INTEGER = re.compile(r"-?(0|[1-9][0-9]*)\Z")
INTEGER_BOUND = 1_000_000_000


class _Branch(Exception):
    def __init__(self, token: str, reason: str):
        self.token = token
        self.reason = reason


def classifier_sha256(classifier: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(classifier))


def _bounded_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= INTEGER_BOUND:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def validate_classifier(
    value: Any,
    experiment_id: str,
    outcomes: Dict[str, Dict[str, Any]],
    usable_source_ids: Set[str],
) -> Dict[str, Any]:
    """Validate one closed built-in classifier contract."""

    classifier = deepcopy(value)
    require_exact_keys(
        classifier,
        {"schema_version", "engine", "source_id", "input_columns", "rule", "outcome_map"},
        "classifier %s" % experiment_id,
    )
    if classifier["schema_version"] != CLASSIFIER_SCHEMA:
        raise CausalFrontierError("experiment %s classifier schema mismatch" % experiment_id)
    if classifier["engine"] != CLASSIFIER_ENGINE:
        raise CausalFrontierError("experiment %s classifier engine is not registered" % experiment_id)
    classifier["source_id"] = require_id(classifier["source_id"], "classifier source_id")
    if classifier["source_id"] not in usable_source_ids:
        raise CausalFrontierError("experiment %s classifier source is unavailable or unusable" % experiment_id)
    classifier["input_columns"] = require_id_list(classifier["input_columns"], "classifier input_columns", False)
    if not 2 <= len(classifier["input_columns"]) <= 16:
        raise CausalFrontierError("classifier input_columns must contain 2-16 exact columns")

    outcome_map = require_exact_keys(classifier["outcome_map"], BRANCH_TOKENS, "classifier outcome_map")
    for token in BRANCH_TOKENS:
        outcome_map[token] = require_id(outcome_map[token], "classifier outcome_map.%s" % token)
    if set(outcome_map.values()) != set(outcomes):
        raise CausalFrontierError("classifier outcome_map must bind every declared outcome exactly once")
    expected_classes = {
        "CONTRADICTION": "CONTRADICTION",
        "FAILURE": "FAILURE",
        "NO_CALL": "NO_CALL",
        "LOW": "INFORMATIVE",
        "HIGH": "INFORMATIVE",
    }
    for token, expected_class in expected_classes.items():
        if outcomes[outcome_map[token]]["class"] != expected_class:
            raise CausalFrontierError("classifier token %s maps to the wrong outcome class" % token)

    rule = classifier["rule"]
    if not isinstance(rule, dict) or "kind" not in rule:
        raise CausalFrontierError("classifier rule must be an object with a registered kind")
    kind = rule["kind"]
    if kind not in RULE_KINDS:
        raise CausalFrontierError("unsupported classifier rule kind")
    common = {
        "kind",
        "group_column",
        "intervention_column",
        "value_column",
        "candidate_value",
        "comparator_value",
    }
    if kind in {"GROUPED_CONTRAST_RANGE_V1", "GROUPED_SHARED_VALUE_RANGE_V1"}:
        require_exact_keys(rule, common | {"minimum_groups", "low_max", "high_min"}, "classifier rule")
        rule["minimum_groups"] = _bounded_nonnegative_int(rule["minimum_groups"], "classifier minimum_groups")
        if rule["minimum_groups"] < 2:
            raise CausalFrontierError("classifier minimum_groups must be at least two")
        rule["low_max"] = _bounded_nonnegative_int(rule["low_max"], "classifier low_max")
        rule["high_min"] = _bounded_nonnegative_int(rule["high_min"], "classifier high_min")
        if rule["high_min"] != rule["low_max"] + 1:
            raise CausalFrontierError("range classifier thresholds must be adjacent and total")
    else:
        require_exact_keys(
            rule,
            common | {"training_groups", "heldout_group", "outside_margin_min"},
            "classifier rule",
        )
        rule["training_groups"] = require_id_list(rule["training_groups"], "classifier training_groups", False)
        if len(rule["training_groups"]) < 2:
            raise CausalFrontierError("held-out classifier needs at least two training groups")
        rule["heldout_group"] = require_id(rule["heldout_group"], "classifier heldout_group")
        if rule["heldout_group"] in rule["training_groups"]:
            raise CausalFrontierError("held-out group cannot be a training group")
        rule["outside_margin_min"] = _bounded_nonnegative_int(
            rule["outside_margin_min"], "classifier outside_margin_min"
        )
        if rule["outside_margin_min"] < 1:
            raise CausalFrontierError("classifier outside_margin_min must be positive")

    for field in ("group_column", "intervention_column", "value_column"):
        rule[field] = require_id(rule[field], "classifier %s" % field)
        if rule[field] not in classifier["input_columns"]:
            raise CausalFrontierError("classifier %s is absent from the exact input schema" % field)
    role_columns = [rule[field] for field in ("group_column", "intervention_column", "value_column")]
    if len(set(role_columns)) != len(role_columns):
        raise CausalFrontierError("classifier role columns must be distinct")
    for field in ("candidate_value", "comparator_value"):
        rule[field] = require_text(rule[field], "classifier %s" % field, 200)
    if rule["candidate_value"] == rule["comparator_value"]:
        raise CausalFrontierError("classifier candidate and comparator values must differ")
    classifier["outcome_map"] = outcome_map
    classifier["rule"] = rule
    return classifier


def _read_rows(path: Path, columns: List[str], expected_sha256: str) -> List[Dict[str, str]]:
    """Read, authenticate, decode, and parse one exact byte snapshot."""

    try:
        with path.open("rb") as handle:
            raw = handle.read(CLASSIFIER_INPUT_MAX_BYTES + 1)
    except OSError:
        raise _Branch("FAILURE", "INPUT_TRANSPORT_OR_PARSE_FAILURE") from None
    if len(raw) > CLASSIFIER_INPUT_MAX_BYTES:
        raise CausalFrontierError("classifier source exceeds the frozen input size limit")
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("classifier source digest changed after case validation")
    try:
        text = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t")
        if reader.fieldnames != columns:
            raise _Branch("FAILURE", "INPUT_HEADER_SCHEMA_MISMATCH")
        rows = list(reader)
    except (UnicodeError, csv.Error):
        raise _Branch("FAILURE", "INPUT_TRANSPORT_OR_PARSE_FAILURE") from None
    if not rows:
        raise _Branch("NO_CALL", "INPUT_HAS_NO_ROWS")
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise _Branch("FAILURE", "INPUT_ROW_WIDTH_MISMATCH")
    return rows


def _integer(value: str) -> int:
    if not INTEGER.fullmatch(value):
        raise _Branch("FAILURE", "VALUE_IS_NOT_CANONICAL_INTEGER")
    parsed = int(value)
    if not -INTEGER_BOUND <= parsed <= INTEGER_BOUND:
        raise _Branch("FAILURE", "INTEGER_OUT_OF_BOUNDS")
    return parsed


def _paired_values(rows: List[Dict[str, str]], rule: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    prepared = []
    failure_reasons = set()
    for row in rows:
        group = row[rule["group_column"]]
        intervention = row[rule["intervention_column"]]
        if not group:
            failure_reasons.add("EMPTY_GROUP_IDENTIFIER")
        try:
            value = _integer(row[rule["value_column"]])
        except _Branch as branch:
            failure_reasons.add(branch.reason)
            value = 0
        prepared.append((group, intervention, value))

    # Syntax failures take deterministic precedence over semantic contradictions,
    # independent of TSV row order.
    for reason in (
        "EMPTY_GROUP_IDENTIFIER",
        "VALUE_IS_NOT_CANONICAL_INTEGER",
        "INTEGER_OUT_OF_BOUNDS",
    ):
        if reason in failure_reasons:
            raise _Branch("FAILURE", reason)

    groups: Dict[str, Dict[str, int]] = {}
    contract_failure_reasons = set()
    for group, intervention, value in prepared:
        if not group:
            raise _Branch("FAILURE", "EMPTY_GROUP_IDENTIFIER")
        if intervention not in {rule["candidate_value"], rule["comparator_value"]}:
            contract_failure_reasons.add("UNDECLARED_INTERVENTION_VALUE")
            continue
        bucket = groups.setdefault(group, {})
        if intervention in bucket:
            contract_failure_reasons.add("DUPLICATE_GROUP_INTERVENTION_CELL")
            continue
        bucket[intervention] = value
    for reason in ("UNDECLARED_INTERVENTION_VALUE", "DUPLICATE_GROUP_INTERVENTION_CELL"):
        if reason in contract_failure_reasons:
            raise _Branch("FAILURE", reason)
    return groups


def _contrasts(
    groups: Dict[str, Dict[str, int]], rule: Dict[str, Any], required: Optional[Set[str]] = None
) -> Dict[str, int]:
    identities = set(groups) if required is None else required
    if not identities <= set(groups):
        raise _Branch("NO_CALL", "REQUIRED_GROUP_MISSING")
    for group in sorted(identities):
        if set(groups[group]) != {rule["candidate_value"], rule["comparator_value"]}:
            raise _Branch("NO_CALL", "GROUP_PAIR_INCOMPLETE")
    result = {}
    for group in sorted(identities):
        values = groups[group]
        contrast = values[rule["candidate_value"]] - values[rule["comparator_value"]]
        if contrast < 0:
            raise _Branch("CONTRADICTION", "CANDIDATE_COMPARATOR_DIRECTION_REVERSED")
        result[group] = contrast
    return result


def _classify(rows: List[Dict[str, str]], rule: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    groups = _paired_values(rows, rule)
    kind = rule["kind"]
    if kind == "GROUPED_CONTRAST_RANGE_V1":
        if len(groups) < rule["minimum_groups"]:
            raise _Branch("NO_CALL", "INSUFFICIENT_GROUPS")
        contrasts = _contrasts(groups, rule)
        spread = max(contrasts.values()) - min(contrasts.values())
        token = "LOW" if spread <= rule["low_max"] else "HIGH"
        return token, {"contrasts": contrasts, "range": spread}
    if kind == "GROUPED_SHARED_VALUE_RANGE_V1":
        if len(groups) < rule["minimum_groups"]:
            raise _Branch("NO_CALL", "INSUFFICIENT_GROUPS")
        for values in groups.values():
            if set(values) != {rule["candidate_value"], rule["comparator_value"]}:
                raise _Branch("NO_CALL", "GROUP_PAIR_INCOMPLETE")
        shared = {}
        for group, values in sorted(groups.items()):
            if values[rule["candidate_value"]] != values[rule["comparator_value"]]:
                raise _Branch("CONTRADICTION", "WITHIN_GROUP_CONTROL_VALUES_DIFFER")
            shared[group] = values[rule["candidate_value"]]
        spread = max(shared.values()) - min(shared.values())
        token = "LOW" if spread <= rule["low_max"] else "HIGH"
        return token, {"group_values": shared, "range": spread}

    required = set(rule["training_groups"]) | {rule["heldout_group"]}
    if not required <= set(groups):
        raise _Branch("NO_CALL", "REQUIRED_GROUP_MISSING")
    if set(groups) != required:
        raise _Branch("FAILURE", "DECLARED_GROUP_SET_MISMATCH")
    contrasts = _contrasts(groups, rule, required)
    training = [contrasts[group] for group in rule["training_groups"]]
    heldout = contrasts[rule["heldout_group"]]
    lower = min(training)
    upper = max(training)
    if lower <= heldout <= upper:
        return "LOW", {"training_min": lower, "training_max": upper, "heldout": heldout, "distance": 0}
    distance = lower - heldout if heldout < lower else heldout - upper
    token = "HIGH" if distance >= rule["outside_margin_min"] else "NO_CALL"
    return token, {"training_min": lower, "training_max": upper, "heldout": heldout, "distance": distance}


def execute_classifier(case: Dict[str, Any], root: Path, experiment_id: str) -> Dict[str, Any]:
    """Execute one already-validated classifier against its exact frozen source."""

    experiments = {item["id"]: item for item in case["experiments"]}
    if experiment_id not in experiments:
        raise CausalFrontierError("unknown classifier experiment: %s" % experiment_id)
    experiment = experiments[experiment_id]
    classifier = experiment["classifier"]
    sources = {item["id"]: item for item in case["provenance"]}
    source = sources[classifier["source_id"]]
    token = "FAILURE"
    metrics: Dict[str, Any] = {"reason": "UNREACHED"}
    try:
        source_path = contained_file(root, source["path"], "classifier source path")
        rows = _read_rows(source_path, classifier["input_columns"], source["sha256"])
        token, metrics = _classify(rows, classifier["rule"])
    except _Branch as branch:
        token = branch.token
        metrics = {"reason": branch.reason}
    core = {
        "schema_version": "causalfrontier.classifier-result.v1",
        "case_id": case["case_id"],
        "case_sha256": sha256_bytes(canonical_bytes(case)),
        "experiment_id": experiment_id,
        "classifier_sha256": experiment["classifier_sha256"],
        "engine": CLASSIFIER_ENGINE,
        "source_id": source["id"],
        "source_sha256": source["sha256"],
        "execution_status": "EXECUTED_FROZEN_INPUT",
        "semantic_scope": (
            "SYNTHETIC_FIXTURE_ONLY" if source["data_class"] == "SYNTHETIC" else "DECLARED_PUBLIC_SCOPE_UNATTESTED"
        ),
        "authority": "SOFTWARE_ONLY",
        "branch_token": token,
        "outcome_id": classifier["outcome_map"][token],
        "metrics": metrics,
    }
    return dict(core, result_sha256=sha256_bytes(canonical_bytes(core)))


def execute_classifiers(case: Dict[str, Any], root: Path) -> Dict[str, Any]:
    results = [execute_classifier(case, root, item["id"]) for item in case["experiments"]]
    core = {
        "schema_version": "causalfrontier.classifier-results.v1",
        "case_id": case["case_id"],
        "case_sha256": sha256_bytes(canonical_bytes(case)),
        "results": results,
        "scientific_authority": "NONE_SYNTHETIC_OR_DECLARED_INPUT_REPLAY_ONLY",
    }
    return dict(core, results_sha256=sha256_bytes(canonical_bytes(core)))
