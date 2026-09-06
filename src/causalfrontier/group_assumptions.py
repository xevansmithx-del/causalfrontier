"""Bounded, explicitly authored grouped-cell uncertainty-withdrawal audit.

Groups are declarations, not dependencies inferred from co-citation. Each unique
selected singleton and each complete declared group is normally validated and
compiled. A rejected authoring contract remains a rejected variant, not an empty
valid frontier. This pure API opens no evidence, classifiers, or network.
"""

from __future__ import annotations

from copy import deepcopy

from . import assumptions as _base
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    require_exact_keys,
    require_id,
    require_sha256,
    require_text,
    sha256_bytes,
)
from .frontier import compile_case
from .model import branch_plan_sha256, fixed_boundary, validate_case

MANIFEST_SCHEMA_VERSION = "causalfrontier.assumption-groups.v1"
SCHEMA_VERSION = "causalfrontier.group-assumption-audit.v1"
AUDIT_DOMAIN = b"causalfrontier.group-assumption-audit.v1\x00"
MAX_GROUPS = 32
MIN_GROUP_MEMBERS = 2
MAX_GROUP_MEMBERS = 16
MAX_DISTINCT_MEMBERS = 128
MAX_MEMBERSHIPS = 256
MAX_VARIANTS = 160
COORDINATE_FIELDS = ("experiment_id", "outcome_id", "world_id")
NONCLAIMS = (
    "Groups and rationales are explicit author declarations, not inferred source dependencies, source deletions, "
    "verified shared premises, or biological facts. Shared source IDs alone do not establish dependence.",
    "Only the declared groups and their unique member singletons are tested. Undeclared groups, larger combinations, "
    "and dependencies outside the manifest remain untested; this is not an exhaustive interaction search.",
    "Each variant changes only its selected relations to UNKNOWN and rebinds affected hypothetical branch-plan "
    "digests. Worlds, source IDs, outcome classes, classifiers, resources, gates, and authorities remain fixed.",
    "A case-contract rejection requires separately reviewed reauthoring. It is not biological impossibility, "
    "empirical falsification, or an empty valid frontier.",
    "The masking flag is applicable only when the group and every member singleton are valid. It requires exact "
    "unchanged singleton selection projections and changed joint frontier or co-minimax membership, not just a hash.",
    "Cells, groups, overlap, and withdrawal effects depend on the authored encoding. Counts and masking flags are "
    "not independent scientific assumption counts, confidence percentages, calibrated uncertainty, or causal truth.",
    "Conditional scientific structure stays separate from structurally admissible unexecuted selection. No "
    "group, changed selection, or verification grants authority or authorizes an experiment.",
    "No source files or classifiers are opened, executed, or reverified here. The ordinary case-root loader is "
    "required for source-byte verification; declared provenance is not independent authentication.",
    "Scientific scoring, empirical evidence, clinical use, human decision authority, material execution, and "
    "prospective experiments remain absent.",
)


def _reject(message: str, *, limit: bool = False) -> None:
    raise CausalFrontierError(
        message,
        reason_code="GROUP_ASSUMPTION_AUDIT_LIMIT_EXCEEDED" if limit else "GROUP_ASSUMPTION_AUDIT_REJECTED",
        operation="group_assumptions",
    )


def _coordinate_key(value: dict) -> tuple[str, str, str]:
    return tuple(value[field] for field in COORDINATE_FIELDS)


def _coordinate(value: tuple[str, str, str]) -> dict:
    return dict(zip(COORDINATE_FIELDS, value, strict=True))


def _eligible_cells(case: dict) -> dict:
    named = {world["id"] for world in case["worlds"] if not world["is_residual"]}
    cells = {}
    for experiment in case["experiments"]:
        informative = {item["id"] for item in experiment["outcomes"] if item["class"] == "INFORMATIVE"}
        for prediction in experiment["predictions"]:
            if (
                prediction["world_id"] in named
                and prediction["outcome_id"] in informative
                and prediction["relation"] in {"SURVIVES", "EXCLUDES"}
            ):
                key = (experiment["id"], prediction["outcome_id"], prediction["world_id"])
                cells[key] = {
                    "coordinate": _coordinate(key),
                    "original_relation": prediction["relation"],
                    "withdrawn_relation": "UNKNOWN",
                    "source_ids": list(prediction["source_ids"]),
                }
    return cells


def _validate_manifest(manifest: dict, case_sha256: str, eligible: dict) -> dict:
    _base._bounded_json(manifest, "group manifest")
    result = deepcopy(require_exact_keys(manifest, {"schema_version", "case_sha256", "groups"}, "group manifest"))
    if result["schema_version"] != MANIFEST_SCHEMA_VERSION:
        _reject("unsupported group manifest schema")
    if require_sha256(result["case_sha256"], "group manifest case_sha256") != case_sha256:
        _reject("group manifest is bound to a different normalized case")
    groups = result["groups"]
    if type(groups) is not list or not groups:
        _reject("group manifest requires a nonempty group list")
    if len(groups) > MAX_GROUPS:
        _reject("group manifest exceeds the group count bound", limit=True)
    group_ids, distinct, memberships = set(), set(), 0
    for group in groups:
        require_exact_keys(group, {"id", "rationale", "members"}, "assumption group")
        group_id = require_id(group["id"], "assumption group id")
        if group_id in group_ids:
            _reject("duplicate assumption group id")
        group_ids.add(group_id)
        group["rationale"] = require_text(group["rationale"], "assumption group rationale", 2000)
        members = group["members"]
        if type(members) is not list or len(members) < MIN_GROUP_MEMBERS:
            _reject("each assumption group requires at least two members")
        if len(members) > MAX_GROUP_MEMBERS:
            _reject("assumption group exceeds the member count bound", limit=True)
        keys = set()
        for member in members:
            require_exact_keys(member, set(COORDINATE_FIELDS), "group member coordinate")
            for field in COORDINATE_FIELDS:
                require_id(member[field], "group member " + field)
            key = _coordinate_key(member)
            if key in keys:
                _reject("duplicate member coordinate within an assumption group")
            if key not in eligible:
                _reject("group member is not a known nonresidual informative SURVIVES or EXCLUDES cell")
            keys.add(key)
        memberships += len(keys)
        distinct.update(keys)
        if memberships > MAX_MEMBERSHIPS or len(distinct) > MAX_DISTINCT_MEMBERS:
            _reject("group manifest exceeds the membership or distinct-cell bound", limit=True)
        group["members"] = [_coordinate(key) for key in sorted(keys)]
    if len(distinct) + len(groups) > MAX_VARIANTS:
        _reject("group manifest exceeds the singleton-plus-group variant bound", limit=True)
    result["groups"] = sorted(groups, key=lambda item: item["id"])
    return result


def _variant(case: dict, members: list[dict], baseline_selection: dict, baseline_epistemic: dict) -> dict:
    variant = deepcopy(case)
    experiments = {item["id"]: item for item in variant["experiments"]}
    affected = sorted({member["coordinate"]["experiment_id"] for member in members})
    plans = [
        {"experiment_id": identity, "original_branch_plan_sha256": experiments[identity]["branch_plan_sha256"]}
        for identity in affected
    ]
    for member in members:
        coordinate = member["coordinate"]
        prediction = next(
            item
            for item in experiments[coordinate["experiment_id"]]["predictions"]
            if item["outcome_id"] == coordinate["outcome_id"] and item["world_id"] == coordinate["world_id"]
        )
        prediction["relation"] = "UNKNOWN"
    for plan in plans:
        experiment = experiments[plan["experiment_id"]]
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
        plan["hypothetical_branch_plan_sha256"] = experiment["branch_plan_sha256"]
    row = {
        "members": deepcopy(members),
        "affected_branch_plans": plans,
        "hypothetical_case_sha256": sha256_bytes(canonical_bytes(variant)),
        "status": "REQUIRES_REAUTHORING",
        "case_contract": None,
        "analysis_sha256": None,
        "selection": None,
        "differences": None,
        "epistemic_by_experiment": None,
        "epistemic_differences_by_experiment": None,
    }
    try:
        validated = validate_case(variant)
    except CausalFrontierError as exc:
        row["case_contract"] = {
            "status": "REJECTED_BY_CASE_CONTRACT",
            "diagnostic": exc.diagnostic(),
            "detail": str(exc),
        }
    else:
        # Compiler failures abort the audit, rather than posing as a case rejection.
        analysis = compile_case(validated)
        selection = _base._selection(analysis)
        epistemic = {item["id"]: _base._epistemic(item) for item in analysis["experiments"] if item["id"] in affected}
        row.update(
            status="VALID_HYPOTHETICAL_VARIANT",
            case_contract={"status": "ACCEPTED_BY_CASE_CONTRACT", "diagnostic": None, "detail": None},
            analysis_sha256=analysis["analysis_sha256"],
            selection=selection,
            differences=_base._difference(baseline_selection, selection),
            epistemic_by_experiment=epistemic,
            epistemic_differences_by_experiment={
                identity: _base._epistemic_difference(baseline_epistemic[identity], epistemic[identity])
                for identity in affected
            },
        )
    return row


def _membership_changed(row: dict) -> bool | None:
    if row["differences"] is None:
        return None
    return any(
        row["differences"][field][scope]["changed"]
        for field in ("frontiers", "co_minimax_experiment_ids")
        for scope in _base.SCOPES
    )


def _masking(group_row: dict, singleton_rows: list[dict]) -> dict:
    joint_valid = group_row["status"] == "VALID_HYPOTHETICAL_VARIANT"
    members_valid = all(row["status"] == "VALID_HYPOTHETICAL_VARIANT" for row in singleton_rows)
    unchanged = (
        all(not row["differences"]["selection_projection_changed"] for row in singleton_rows) if members_valid else None
    )
    membership_changed = _membership_changed(group_row)
    if joint_valid and members_valid:
        status = "APPLICABLE_ALL_VARIANTS_VALID"
    elif not joint_valid and not members_valid:
        status = "NOT_APPLICABLE_JOINT_AND_MEMBER_SINGLETON_REJECTED"
    elif not joint_valid:
        status = "NOT_APPLICABLE_JOINT_REJECTED"
    else:
        status = "NOT_APPLICABLE_MEMBER_SINGLETON_REJECTED"
    return {
        "singleton_masked_joint_selection_change": bool(
            joint_valid and members_valid and unchanged and membership_changed
        ),
        "masking_applicability": {
            "applicable": joint_valid and members_valid,
            "status": status,
            "all_member_singletons_valid": members_valid,
            "all_member_singleton_selections_unchanged": unchanged,
            "joint_selection_membership_changed": membership_changed,
        },
    }


def audit_assumption_groups(case: dict, manifest: dict) -> dict:
    """Audit declared groups plus unique member singletons; no other variants.

    Case-root loading is the caller's responsibility when source-byte verification
    is required. Even previously validated cases and each hypothetical variant
    pass the normal public validation and compilation paths again.
    """
    _base._bounded_json(case, "case")
    _base._case_work_bounds(case)
    normalized_case = validate_case(case)
    case_digest = sha256_bytes(canonical_bytes(normalized_case))
    eligible = _eligible_cells(normalized_case)
    normalized_manifest = _validate_manifest(manifest, case_digest, eligible)
    groups = normalized_manifest["groups"]
    selected = sorted({_coordinate_key(member) for group in groups for member in group["members"]})
    baseline_analysis = compile_case(normalized_case)
    baseline_selection = _base._selection(baseline_analysis)
    baseline_epistemic = {item["id"]: _base._epistemic(item) for item in baseline_analysis["experiments"]}
    singletons = {}
    for key in selected:
        singletons[key] = {
            "coordinate": _coordinate(key),
            **_variant(normalized_case, [eligible[key]], baseline_selection, baseline_epistemic),
        }
    group_rows = []
    for group in groups:
        members = [_coordinate_key(member) for member in group["members"]]
        row = {
            "group_id": group["id"],
            "rationale": group["rationale"],
            **_variant(normalized_case, [eligible[key] for key in members], baseline_selection, baseline_epistemic),
        }
        row.update(_masking(row, [singletons[key] for key in members]))
        group_rows.append(row)
    singleton_rows = list(singletons.values())
    rows = singleton_rows + group_rows
    valid = sum(row["status"] == "VALID_HYPOTHETICAL_VARIANT" for row in rows)
    core = {
        "schema_version": SCHEMA_VERSION,
        "status": "COMPLETE_DECLARED_GROUP_HYPOTHETICAL_AUDIT",
        "audit_kind": "DECLARED_GROUP_AND_SELECTED_SINGLETON_UNCERTAINTY_WITHDRAWAL",
        "case_id": normalized_case["case_id"],
        "case_sha256": case_digest,
        "fixed_parameter": normalized_case["fixed_parameter"],
        "compiler": deepcopy(baseline_analysis["compiler"]),
        "manifest": normalized_manifest,
        "manifest_sha256": sha256_bytes(canonical_bytes(normalized_manifest)),
        "baseline": {
            "analysis_sha256": baseline_analysis["analysis_sha256"],
            "selection": baseline_selection,
            "epistemic_by_experiment": baseline_epistemic,
        },
        "singleton_rows": singleton_rows,
        "group_rows": group_rows,
        "counts": {
            "eligible_cells_in_case": len(eligible),
            "declared_groups": len(groups),
            "memberships": sum(len(group["members"]) for group in groups),
            "distinct_selected_cells": len(selected),
            "singleton_variants": len(singleton_rows),
            "group_variants": len(group_rows),
            "total_variants": len(rows),
            "valid_variants": valid,
            "requires_reauthoring": len(rows) - valid,
            "singleton_selection_membership_changes": sum(_membership_changed(row) is True for row in singleton_rows),
            "group_selection_membership_changes": sum(_membership_changed(row) is True for row in group_rows),
            "masking_applicable_groups": sum(row["masking_applicability"]["applicable"] for row in group_rows),
            "singleton_masked_joint_selection_change_groups": sum(
                row["singleton_masked_joint_selection_change"] for row in group_rows
            ),
        },
        "limits": {
            "groups": MAX_GROUPS,
            "minimum_group_members": MIN_GROUP_MEMBERS,
            "maximum_group_members": MAX_GROUP_MEMBERS,
            "distinct_selected_cells": MAX_DISTINCT_MEMBERS,
            "memberships": MAX_MEMBERSHIPS,
            "singleton_plus_group_variants": MAX_VARIANTS,
            "case_experiments": _base.MAX_EXPERIMENTS,
            "case_total_outcomes": _base.MAX_TOTAL_OUTCOMES,
            "case_total_predictions": _base.MAX_TOTAL_PREDICTIONS,
            "canonical_json_bytes": _base.MAX_JSON_BYTES,
            "report_trailing_newline_bytes": 1,
            "case_and_manifest_json_nodes": _base.MAX_JSON_NODES,
            "report_json_nodes": _base.MAX_REPORT_JSON_NODES,
            "json_depth": _base.MAX_JSON_DEPTH,
            "container_items": _base.MAX_CONTAINER_ITEMS,
            "policy": "REJECT_EXCESS_NO_TRUNCATION",
        },
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
    _base._bounded_json(report, "group audit report", max_nodes=_base.MAX_REPORT_JSON_NODES, reserve_bytes=1)
    return report


def verify_group_assumption_audit(case: dict, manifest: dict, report: dict) -> dict:
    """Require exact canonical equality to a fresh replay, not just a valid hash."""
    supplied = _base._bounded_json(report, "group audit report", max_nodes=_base.MAX_REPORT_JSON_NODES, reserve_bytes=1)
    expected = audit_assumption_groups(case, manifest)
    if supplied != canonical_bytes(expected):
        _reject("group assumption audit differs from a fresh exact replay")
    return {
        "schema_version": "causalfrontier.group-assumption-audit-verification.v1",
        "status": "VERIFIED_EXACT_DECLARED_GROUP_HYPOTHETICAL_REPLAY",
        "verified": True,
        "case_sha256": expected["case_sha256"],
        "manifest_sha256": expected["manifest_sha256"],
        "audit_sha256": expected["audit_sha256"],
        "canonical_report_sha256": sha256_bytes(supplied),
        "variants_replayed": expected["counts"]["total_variants"],
        "verification_scope": "EXACT_BOUNDED_DECLARED_GROUP_REPLAY_NOT_SEMANTIC_VALIDATION",
        "source_files_opened": False,
        "classifier_executed": False,
        "empirical_evidence": False,
        "scoring_enabled": False,
        "authority_granted": False,
        "boundary": fixed_boundary(),
    }
