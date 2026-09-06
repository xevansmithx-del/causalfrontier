"""Bounded, hypothetical single-relation uncertainty-withdrawal audit.

Every eligible authored prediction is replaced by UNKNOWN in its own copied
case. Ordinary model validation and compilation remain authoritative. A variant
that no longer satisfies the case contract is retained as requiring reauthoring,
not silently relabeled, compiled through a private path, or treated as an empty
valid frontier. No evidence file, classifier, experiment, or network is opened.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .canonical import MAX_JSON_BYTES, CausalFrontierError, canonical_bytes, sha256_bytes
from .frontier import compile_case
from .model import branch_plan_sha256, fixed_boundary, validate_case

SCHEMA_VERSION = "causalfrontier.assumption-audit.v1"
AUDIT_DOMAIN = b"causalfrontier.assumption-audit.v1\x00"
MAX_ELIGIBLE_CELLS = 128
MAX_EXPERIMENTS = 32
MAX_TOTAL_OUTCOMES = 256
MAX_TOTAL_PREDICTIONS = 4096
MAX_JSON_NODES = 65_536
MAX_REPORT_JSON_NODES = 262_144
MAX_JSON_DEPTH = 32
MAX_CONTAINER_ITEMS = 8192
SCOPES = ("structurally_admissible_unexecuted", "conditional_scientific_structure")
NONCLAIMS = (
    "Each row is a hypothetical withdrawal of one authored relation, not an observation, source deletion, "
    "source refutation, or a confidence estimate.",
    "All other authored predictions, source IDs, worlds, outcome classes, gates, authorities, classifiers, and "
    "resources are held fixed; only the selected relation and its hypothetical branch-plan digest change.",
    "A rejected variant requires a newly authored and separately reviewed case; rejection is not an empty valid "
    "frontier or evidence that a biological claim failed.",
    "Multiple relations may depend on the same source. Joint withdrawals and shared-source dependency effects "
    "are not tested by this one-cell-at-a-time audit.",
    "Withdrawal cells are encoding-dependent: duplicating decision-equivalent worlds can change their count and "
    "individual effects. Cell counts are not counts of independent scientific assumptions, and change frequencies "
    "are not confidence percentages.",
    "Selection changes and unchanged selections are conditional on the supplied model and the bounded withdrawal "
    "family, not semantic robustness, causal truth, calibrated uncertainty, or empirical superiority.",
    "Conditional scientific structure is kept separate from the structurally admissible unexecuted frontier; "
    "no gate or authority is granted by this audit.",
    "No source files or classifiers are executed or reverified here. Source-byte verification requires the "
    "ordinary case-root loader; declared provenance is not independent authentication.",
    "Scientific scoring, empirical evidence, clinical use, human decision authority, material execution, and "
    "prospective experiments remain absent.",
)


def _reject(message: str, *, limit: bool = False) -> None:
    raise CausalFrontierError(
        message,
        reason_code="ASSUMPTION_AUDIT_LIMIT_EXCEEDED" if limit else "ASSUMPTION_AUDIT_REJECTED",
        operation="assumptions",
    )


def _bounded_json(value: Any, label: str, *, max_nodes: int = MAX_JSON_NODES, reserve_bytes: int = 0) -> bytes:
    """Bound traversal before deep copies/serialization; reject non-JSON objects."""
    pending = [(value, 0)]
    visited = 0
    text_bytes = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > max_nodes or depth > MAX_JSON_DEPTH:
            _reject("%s exceeds the audit JSON node/depth bound" % label, limit=True)
        kind = type(item)
        if kind is dict:
            if len(item) > MAX_CONTAINER_ITEMS:
                _reject("%s exceeds the audit container bound" % label, limit=True)
            for key, child in item.items():
                if type(key) is not str:
                    _reject("%s requires string JSON object keys" % label)
                if len(key) > MAX_JSON_BYTES:
                    _reject("%s exceeds the audit JSON text bound" % label, limit=True)
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeError:
                    _reject("%s contains invalid Unicode" % label)
                if text_bytes > MAX_JSON_BYTES:
                    _reject("%s exceeds the audit JSON work bound" % label, limit=True)
                pending.append((child, depth + 1))
        elif kind is list:
            if len(item) > MAX_CONTAINER_ITEMS:
                _reject("%s exceeds the audit container bound" % label, limit=True)
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item) > MAX_JSON_BYTES:
                _reject("%s exceeds the audit JSON text bound" % label, limit=True)
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                _reject("%s contains invalid Unicode" % label)
        elif kind is int:
            if item.bit_length() > 213:
                _reject("%s exceeds the audit integer bound" % label, limit=True)
        elif kind is not bool and item is not None:
            _reject("%s must contain only strict JSON values without floats" % label)
        if text_bytes > MAX_JSON_BYTES or visited + len(pending) > max_nodes:
            _reject("%s exceeds the audit JSON work bound" % label, limit=True)
    raw = canonical_bytes(value)
    if len(raw) + reserve_bytes > MAX_JSON_BYTES:
        _reject("%s exceeds the audit canonical byte bound" % label, limit=True)
    return raw


def _case_work_bounds(case: Any) -> None:
    if type(case) is not dict:
        _reject("assumption audit requires a case object")
    experiments = case.get("experiments")
    if type(experiments) is not list:
        _reject("assumption audit requires an experiment list")
    if len(experiments) > MAX_EXPERIMENTS:
        _reject("case exceeds the audit experiment bound", limit=True)
    outcomes_n = predictions_n = 0
    for experiment in experiments:
        if type(experiment) is not dict:
            _reject("assumption audit requires experiment objects")
        outcomes, predictions = experiment.get("outcomes"), experiment.get("predictions")
        if type(outcomes) is not list or type(predictions) is not list:
            _reject("assumption audit requires outcome and prediction lists")
        outcomes_n += len(outcomes)
        predictions_n += len(predictions)
    if outcomes_n > MAX_TOTAL_OUTCOMES or predictions_n > MAX_TOTAL_PREDICTIONS:
        _reject("case exceeds the audit outcome/prediction work bound", limit=True)


def _selection(analysis: dict[str, Any]) -> dict[str, Any]:
    """Exact selection contract, excluding hashes that change for every variant."""
    return {
        "frontiers": deepcopy(analysis["frontiers"]),
        "minimax": deepcopy(analysis["minimax"]),
        "selection_policy": deepcopy(analysis["selection_policy"]),
        "experiment_admissibility": [
            {
                "experiment_id": item["id"],
                "current_status": item["current_status"],
                "blocked_reasons": list(item["blocked_reasons"]),
                "decision_separating": item["decision_separating"],
            }
            for item in analysis["experiments"]
        ],
    }


def _members(selection: dict[str, Any], scope: str, *, minimax: bool) -> list[str]:
    if not minimax:
        return selection["frontiers"][scope]
    result = selection["minimax"][scope]
    return [] if result is None else result["co_minimax_experiment_ids"]


def _difference(baseline: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "selection_projection_changed": canonical_bytes(baseline) != canonical_bytes(variant),
        "frontiers": {},
        "co_minimax_experiment_ids": {},
    }
    for field, minimax in (("frontiers", False), ("co_minimax_experiment_ids", True)):
        for scope in SCOPES:
            before, after = (
                set(_members(baseline, scope, minimax=minimax)),
                set(_members(variant, scope, minimax=minimax)),
            )
            result[field][scope] = {
                "changed": before != after,
                "added": sorted(after - before),
                "removed": sorted(before - after),
            }
    return result


def _epistemic(experiment: dict[str, Any]) -> dict[str, Any]:
    """Keep strict pair separation distinct from survival and class reduction."""
    fields = (
        "id",
        "decision_separating",
        "baseline_world_count",
        "baseline_decision_class_count",
        "conditional_worst_remaining_world_count",
        "conditional_minimax_world_reduction",
        "conditional_worst_remaining_decision_class_count",
        "conditional_minimax_decision_class_reduction",
        "conditional_guaranteed_decision_class_pairs",
        "conditional_guaranteed_decision_class_pair_count",
        "conditional_possible_decision_class_pairs",
        "conditional_possible_decision_class_pair_count",
    )
    outcome_fields = (
        "id",
        "relations",
        "decision_class_relations",
        "mixed_relation_decision_class_ids",
        "effective_surviving_world_ids",
        "effective_surviving_decision_class_ids",
        "remaining_world_count",
        "remaining_decision_class_count",
        "separated_decision_class_pairs",
    )
    return {
        **{field: deepcopy(experiment[field]) for field in fields},
        "informative_outcomes": [
            {field: deepcopy(outcome[field]) for field in outcome_fields}
            for outcome in experiment["outcomes"]
            if outcome["class"] == "INFORMATIVE"
        ],
    }


def _epistemic_difference(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    original = {row["id"]: row for row in before["informative_outcomes"]}
    changed = []
    for row in after["informative_outcomes"]:
        old = original[row["id"]]
        detail = {"outcome_id": row["id"]}
        for field, label in (
            ("effective_surviving_world_ids", "retained_world_ids"),
            ("effective_surviving_decision_class_ids", "retained_decision_class_ids"),
            ("separated_decision_class_pairs", "strict_separated_pairs"),
        ):
            first = {tuple(value) if isinstance(value, list) else value for value in old[field]}
            second = {tuple(value) if isinstance(value, list) else value for value in row[field]}
            detail[label] = {
                "changed": first != second,
                "added": [list(value) if isinstance(value, tuple) else value for value in sorted(second - first)],
                "removed": [list(value) if isinstance(value, tuple) else value for value in sorted(first - second)],
            }
        detail["decision_class_relations_changed"] = old["decision_class_relations"] != row["decision_class_relations"]
        changed.append(detail)
    return {
        "strict_pair_separation_changed": any(row["strict_separated_pairs"]["changed"] for row in changed),
        "retained_worlds_changed": any(row["retained_world_ids"]["changed"] for row in changed),
        "retained_decision_classes_changed": any(row["retained_decision_class_ids"]["changed"] for row in changed),
        "conditional_class_reduction_changed": before["conditional_minimax_decision_class_reduction"]
        != after["conditional_minimax_decision_class_reduction"],
        "conditional_world_reduction_changed": before["conditional_minimax_world_reduction"]
        != after["conditional_minimax_world_reduction"],
        "informative_outcomes": changed,
    }


def audit_assumptions(case: dict) -> dict:
    """Audit every eligible single-cell withdrawal, or reject the entire bound.

    Validation without a root checks declared case structure, not source bytes.
    The caller should use load_case for filesystem-bound evidence before this
    pure API when source verification is required. Even previously validated
    inputs are revalidated; no private compiler bypass is used.
    """
    _bounded_json(case, "case")
    _case_work_bounds(case)
    normalized = validate_case(case)
    residual_ids = {world["id"] for world in normalized["worlds"] if world["is_residual"]}
    eligible = []
    for experiment in normalized["experiments"]:
        informative_ids = {outcome["id"] for outcome in experiment["outcomes"] if outcome["class"] == "INFORMATIVE"}
        for prediction in experiment["predictions"]:
            if (
                prediction["world_id"] not in residual_ids
                and prediction["outcome_id"] in informative_ids
                and prediction["relation"] in {"SURVIVES", "EXCLUDES"}
            ):
                eligible.append((experiment["id"], prediction["outcome_id"], prediction["world_id"]))
    if len(eligible) > MAX_ELIGIBLE_CELLS:
        _reject("case exceeds 128 eligible uncertainty-withdrawal cells; no rows were audited", limit=True)
    baseline_analysis = compile_case(normalized)
    baseline_selection = _selection(baseline_analysis)
    baseline_epistemic = {item["id"]: _epistemic(item) for item in baseline_analysis["experiments"]}
    rows = []
    for experiment_id, outcome_id, world_id in sorted(eligible):
        variant = deepcopy(normalized)
        experiment = next(item for item in variant["experiments"] if item["id"] == experiment_id)
        prediction = next(
            item
            for item in experiment["predictions"]
            if item["outcome_id"] == outcome_id and item["world_id"] == world_id
        )
        original_relation = prediction["relation"]
        original_plan = experiment["branch_plan_sha256"]
        prediction["relation"] = "UNKNOWN"
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
        row = {
            "coordinate": {"experiment_id": experiment_id, "outcome_id": outcome_id, "world_id": world_id},
            "original_relation": original_relation,
            "withdrawn_relation": "UNKNOWN",
            "source_ids": list(prediction["source_ids"]),
            "original_branch_plan_sha256": original_plan,
            "hypothetical_branch_plan_sha256": experiment["branch_plan_sha256"],
            "hypothetical_case_sha256": sha256_bytes(canonical_bytes(variant)),
            "status": "REQUIRES_REAUTHORING",
            "case_contract": None,
            "analysis_sha256": None,
            "selection": None,
            "differences": None,
            "epistemic_projection": None,
            "epistemic_differences": None,
        }
        try:
            validated_variant = validate_case(variant)
        except CausalFrontierError as exc:
            row["case_contract"] = {
                "status": "REJECTED_BY_CASE_CONTRACT",
                "diagnostic": exc.diagnostic(),
                "detail": str(exc),
            }
        else:
            # A compiler failure is not mislabeled as rejection by model validation.
            analysis = compile_case(validated_variant)
            selection = _selection(analysis)
            epistemic = _epistemic(next(item for item in analysis["experiments"] if item["id"] == experiment_id))
            row.update(
                status="VALID_HYPOTHETICAL_VARIANT",
                case_contract={"status": "ACCEPTED_BY_CASE_CONTRACT", "diagnostic": None, "detail": None},
                analysis_sha256=analysis["analysis_sha256"],
                selection=selection,
                differences=_difference(baseline_selection, selection),
                epistemic_projection=epistemic,
                epistemic_differences=_epistemic_difference(baseline_epistemic[experiment_id], epistemic),
            )
        rows.append(row)
    valid = [row for row in rows if row["status"] == "VALID_HYPOTHETICAL_VARIANT"]
    counts = {
        "eligible_cells": len(eligible),
        "reported_rows": len(rows),
        "valid_variants": len(valid),
        "requires_reauthoring": len(rows) - len(valid),
        "selection_changed_valid_variants": sum(row["differences"]["selection_projection_changed"] for row in valid),
        "selection_unchanged_valid_variants": sum(
            not row["differences"]["selection_projection_changed"] for row in valid
        ),
    }
    for scope in SCOPES:
        counts[scope] = {
            field + "_changed_valid_variants": sum(row["differences"][field][scope]["changed"] for row in valid)
            for field in ("frontiers", "co_minimax_experiment_ids")
        }
    for field in (
        "strict_pair_separation_changed",
        "retained_worlds_changed",
        "retained_decision_classes_changed",
        "conditional_class_reduction_changed",
        "conditional_world_reduction_changed",
    ):
        counts[field + "_valid_variants"] = sum(row["epistemic_differences"][field] for row in valid)
    core = {
        "schema_version": SCHEMA_VERSION,
        "status": "COMPLETE_HYPOTHETICAL_REAUTHORING_AUDIT",
        "audit_kind": "SINGLE_RELATION_UNCERTAINTY_WITHDRAWAL",
        "case_id": normalized["case_id"],
        "case_sha256": baseline_analysis["case_sha256"],
        "fixed_parameter": normalized["fixed_parameter"],
        "compiler": deepcopy(baseline_analysis["compiler"]),
        "limits": {
            "eligible_cells": MAX_ELIGIBLE_CELLS,
            "experiments": MAX_EXPERIMENTS,
            "total_outcomes": MAX_TOTAL_OUTCOMES,
            "total_predictions": MAX_TOTAL_PREDICTIONS,
            "canonical_json_bytes": MAX_JSON_BYTES,
            "json_nodes": MAX_JSON_NODES,
            "report_trailing_newline_bytes": 1,
            "report_json_nodes": MAX_REPORT_JSON_NODES,
            "json_depth": MAX_JSON_DEPTH,
            "container_items": MAX_CONTAINER_ITEMS,
            "policy": "REJECT_EXCESS_NO_TRUNCATION",
        },
        "baseline": {
            "analysis_sha256": baseline_analysis["analysis_sha256"],
            "selection": baseline_selection,
            "epistemic_by_experiment": baseline_epistemic,
        },
        "rows": rows,
        "counts": counts,
        "boundary": fixed_boundary(),
        "hypothetical": True,
        "source_files_opened": False,
        "classifier_executed": False,
        "experiments_executed_n": 0,
        "empirical_evidence": False,
        "scoring_enabled": False,
        "authority_granted": False,
        "nonclaims": list(NONCLAIMS),
    }
    report = {**core, "audit_sha256": sha256_bytes(AUDIT_DOMAIN + canonical_bytes(core))}
    _bounded_json(report, "audit report", max_nodes=MAX_REPORT_JSON_NODES, reserve_bytes=1)
    return report


def verify_assumption_audit(case: dict, report: dict) -> dict:
    """Require whole-report canonical equality with a fresh bounded audit.

    A self-consistent digest on edited rows, counts, nonclaims, or authority flags
    is insufficient. This checks deterministic replay only, not scientific truth.
    """
    supplied = _bounded_json(report, "audit report", max_nodes=MAX_REPORT_JSON_NODES, reserve_bytes=1)
    expected = audit_assumptions(case)
    expected_bytes = canonical_bytes(expected)
    if supplied != expected_bytes:
        _reject("assumption audit differs from a fresh exact replay")
    return {
        "schema_version": "causalfrontier.assumption-audit-verification.v1",
        "status": "VERIFIED_EXACT_HYPOTHETICAL_REPLAY",
        "verified": True,
        "case_sha256": expected["case_sha256"],
        "audit_sha256": expected["audit_sha256"],
        "canonical_report_sha256": sha256_bytes(expected_bytes),
        "rows_replayed": expected["counts"]["reported_rows"],
        "verification_scope": "EXACT_BOUNDED_HYPOTHETICAL_REPLAY_NOT_SEMANTIC_VALIDATION",
        "source_files_opened": False,
        "classifier_executed": False,
        "empirical_evidence": False,
        "scoring_enabled": False,
        "authority_granted": False,
        "boundary": fixed_boundary(),
    }
