"""Transparent table-rule comparator for the protocol's shared projection only.

This is a program, not measured human spreadsheet performance. It imports no
CausalFrontier source, generator, oracle, receipt validator or evidence-fit code.
It expects the protocol's already well-formed synthetic inputs, reads the same
declared labels/date metadata, and does not authenticate their semantic meaning.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

LABEL_COLUMNS = ("endpoint", "population", "analysis_population")


def compare(left: object, right: object) -> str:
    if left is None or right is None:
        return "UNKNOWN"
    return "DECLARED_MATCH" if left == right else "DECLARED_MISMATCH"


def date_rule(source: dict, selected_field: str | None, cutoff: str, required_role: str) -> dict:
    selected = None if selected_field is None else source["dates"][selected_field]
    lower = upper = None
    if selected is not None and selected["precision"] != "UNKNOWN":
        parts = [int(part) for part in selected["value"].split("-")]
        year, month, day = [*parts, 1, 1][:3]
        beginning = datetime(year, month, day, tzinfo=timezone.utc)
        if selected["precision"] == "YEAR":
            next_period = beginning.replace(year=year + 1)
        elif selected["precision"] == "MONTH":
            next_period = beginning.replace(year=year + (month == 12), month=month % 12 + 1)
        else:
            next_period = beginning + timedelta(days=1)
        lower = beginning.strftime("%Y-%m-%dT%H:%M:%SZ")
        upper = (next_period - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    relation = "UNKNOWN"
    if lower is not None:
        relation = (
            "DECLARED_BY_CUTOFF"
            if upper <= cutoff
            else "DECLARED_AFTER_CUTOFF"
            if lower > cutoff
            else "DECLARED_INTERVAL_SPANS_CUTOFF"
        )
    fit = "UNKNOWN"
    if required_role == "INPUT":
        if relation == "DECLARED_BY_CUTOFF":
            fit = "DECLARED_MATCH"
        elif relation == "DECLARED_AFTER_CUTOFF":
            fit = "DECLARED_MISMATCH"
    return {
        "declared_date_relation": relation,
        "input_date_fit": fit,
        "input_date_constraint_applies": required_role == "INPUT",
        "historical_eligible": False,
        "interval": {"lower": lower, "upper": upper},
    }


def evaluate(document: dict, extraction: dict) -> dict:
    """Return only declared columns included in the protocol's paired comparison."""
    target = extraction["target"]
    rows = []
    for record in extraction["records"]:
        requirement = next(
            item
            for item in target["source_requirements"]
            if (item["receipt_id"], item["source_id"]) == (record["receipt_id"], record["source_id"])
        )
        receipt = next(item for item in document["receipts"] if item["id"] == record["receipt_id"])
        source = next(item for item in receipt["source_records"] if item["id"] == record["source_id"])
        fit = {column: compare(target["dimensions"][column], record["dimensions"][column]) for column in LABEL_COLUMNS}
        fit.update(
            estimate_kind=compare(target["estimate_kind"], record["estimate"]["kind"]),
            study_version=compare(requirement["study_version"], record["study_version"]),
            role=compare(requirement["role"], record["role"]),
        )
        rows.append(
            {
                "id": record["id"],
                "fit": fit,
                "availability": date_rule(
                    source, record["availability_date_field"], document["evidence_cutoff"], requirement["role"]
                ),
            }
        )
    missing = [
        item
        for item in target["source_requirements"]
        if not any(
            (item["receipt_id"], item["source_id"]) == (row["receipt_id"], row["source_id"])
            for row in extraction["records"]
        )
    ]
    return {
        "records": sorted(rows, key=lambda row: row["id"]),
        "missing_source_requirements": sorted(missing, key=lambda row: (row["receipt_id"], row["source_id"])),
    }
