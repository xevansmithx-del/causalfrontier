"""Finite, authored synthetic cases; no tool or comparator imports."""

from __future__ import annotations

import hashlib
import itertools
import json
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples/synthetic-evidence-fit"
FACTORS = ("endpoint", "population", "analysis_population", "estimate_kind")
STATES = ("match", "mismatch", "missing")
STATE_LABELS = {"match": "DECLARED_MATCH", "mismatch": "DECLARED_MISMATCH", "missing": "UNKNOWN"}
CUTOFF = "2012-06-15T12:00:00Z"
FIXTURE_HASHES = {
    "extraction.json": "dd6a8c0b71efee41d1d3ee7d4d4ea42280c372f0cb2ca547fb70890e231b1635",
    "receipt-root/receipt-set.json": "144c406e7474b6e90365a3c13fc7da3cd19026a27023ab68cd5175343e4cc27b",
    "receipt-root/raw/response.json": "3c541918378ab005f181c52398b32f3652ddef9e05427f74efc6c651e480a059",
}


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fixture_inputs() -> tuple[dict, dict, bytes]:
    for relative, expected in FIXTURE_HASHES.items():
        if digest((FIXTURE / relative).read_bytes()) != expected:
            raise ValueError(f"Synthetic predecessor fixture changed: {relative}")
    return (
        json.loads((FIXTURE / "receipt-root/receipt-set.json").read_bytes()),
        json.loads((FIXTURE / "extraction.json").read_bytes()),
        (FIXTURE / "receipt-root/raw/response.json").read_bytes(),
    )


def make_case(identifier: str, stratum: str, document: dict, extraction: dict) -> dict:
    """Author an all-matched selected projection, keeping SYNTHETIC authority."""
    document, extraction = deepcopy(document), deepcopy(extraction)
    document["evidence_cutoff"] = CUTOFF
    extraction["id"] = "extraction:" + identifier
    extraction["records"] = extraction["records"][:1]
    extraction["target"]["source_requirements"] = extraction["target"]["source_requirements"][:1]
    return {
        "id": identifier,
        "stratum": stratum,
        "design": {},
        "semantic_stipulation": None,
        "receipt_set": document,
        "extraction": extraction,
        "expected": {
            "records": [
                {
                    "id": "record:hr",
                    "fit": dict.fromkeys((*FACTORS, "study_version", "role"), "DECLARED_MATCH"),
                    "availability": {
                        "declared_date_relation": "DECLARED_BY_CUTOFF",
                        "input_date_fit": "DECLARED_MATCH",
                        "input_date_constraint_applies": True,
                        "historical_eligible": False,
                        "interval": {"lower": "2012-06-01T00:00:00Z", "upper": "2012-06-01T23:59:59Z"},
                    },
                }
            ],
            "missing_source_requirements": [],
        },
    }


# Explicit authored date answers. No baseline date routine is used as an oracle.
DATE_CASES = (
    ("day-before", "DAY", "2012-06-14", "2012-06-14", "2012-06-14", "DECLARED_BY_CUTOFF"),
    ("day-after", "DAY", "2012-06-16", "2012-06-16", "2012-06-16", "DECLARED_AFTER_CUTOFF"),
    ("day-spans", "DAY", "2012-06-15", "2012-06-15", "2012-06-15", "DECLARED_INTERVAL_SPANS_CUTOFF"),
    ("month-before", "MONTH", "2012-05", "2012-05-01", "2012-05-31", "DECLARED_BY_CUTOFF"),
    ("month-after", "MONTH", "2012-07", "2012-07-01", "2012-07-31", "DECLARED_AFTER_CUTOFF"),
    ("month-spans", "MONTH", "2012-06", "2012-06-01", "2012-06-30", "DECLARED_INTERVAL_SPANS_CUTOFF"),
    ("year-before", "YEAR", "2011", "2011-01-01", "2011-12-31", "DECLARED_BY_CUTOFF"),
    ("year-after", "YEAR", "2013", "2013-01-01", "2013-12-31", "DECLARED_AFTER_CUTOFF"),
    ("year-spans", "YEAR", "2012", "2012-01-01", "2012-12-31", "DECLARED_INTERVAL_SPANS_CUTOFF"),
    ("unknown", "UNKNOWN", None, None, None, "UNKNOWN"),
    ("unselected", "DAY", "2012-06-01", None, None, "UNKNOWN"),
)


def generate_cases() -> list[dict]:
    document, extraction, _ = fixture_inputs()
    cases = []
    for states in itertools.product(STATES, repeat=len(FACTORS)):
        case = make_case("factorial-" + "-".join(states), "factorial", document, extraction)
        target, record = case["extraction"]["target"], case["extraction"]["records"][0]
        case["design"] = dict(zip(FACTORS, states, strict=True))
        for factor, state in zip(FACTORS, states, strict=True):
            if factor == "estimate_kind":
                if state == "mismatch":
                    record["estimate"]["kind"] = "RATE_RATIO"
                elif state == "missing":
                    target["estimate_kind"] = None  # Record kind is required by the public schema.
            elif state != "match":
                record["dimensions"][factor] = "Synthetic other " + factor if state == "mismatch" else None
            case["expected"]["records"][0]["fit"][factor] = STATE_LABELS[state]
        cases.append(case)

    for name, precision, value, lower, upper, relation in DATE_CASES:
        for role in ("INPUT", "REVEAL_ONLY", "CONTEXT_ONLY"):
            case = make_case(f"temporal-{name}-{role.lower()}", "temporal", document, extraction)
            case["design"] = {"date_variant": name, "required_role": role}
            record = case["extraction"]["records"][0]
            record["role"] = role
            case["extraction"]["target"]["source_requirements"][0]["role"] = role
            date_item = case["receipt_set"]["receipts"][0]["source_records"][0]["dates"]["snapshot_created"]
            date_item.update(precision=precision, value=value)
            date_item["source_field"] = None if value is None else "Authored synthetic evaluation date"
            if name == "unselected":
                record["availability_date_field"] = None
            availability = case["expected"]["records"][0]["availability"]
            availability.update(
                declared_date_relation=relation,
                input_date_constraint_applies=role == "INPUT",
                input_date_fit=(
                    {"DECLARED_BY_CUTOFF": "DECLARED_MATCH", "DECLARED_AFTER_CUTOFF": "DECLARED_MISMATCH"}.get(
                        relation, "UNKNOWN"
                    )
                    if role == "INPUT"
                    else "UNKNOWN"
                ),
                interval={
                    "lower": None if lower is None else lower + "T00:00:00Z",
                    "upper": None if upper is None else upper + "T23:59:59Z",
                },
            )
            cases.append(case)

    for side in ("target", "record", "both"):
        case = make_case("missingness-endpoint-" + side, "missingness", document, extraction)
        case["design"] = {"missing_endpoint_side": side}
        if side in ("target", "both"):
            case["extraction"]["target"]["dimensions"]["endpoint"] = None
        if side in ("record", "both"):
            case["extraction"]["records"][0]["dimensions"]["endpoint"] = None
        case["expected"]["records"][0]["fit"]["endpoint"] = "UNKNOWN"
        cases.append(case)

    for variant in (
        "version-missing-record",
        "version-missing-target",
        "version-mismatch",
        "role-missing-record",
        "role-mismatch-record",
        "source-absent",
    ):
        case = make_case("source-" + variant, "source_conditions", document, extraction)
        case["design"] = {"variant": variant}
        record = case["extraction"]["records"][0]
        requirement = case["extraction"]["target"]["source_requirements"][0]
        expected = case["expected"]["records"][0]
        if variant.startswith("version"):
            if variant == "version-missing-target":
                requirement["study_version"] = None
            else:
                record["study_version"] = "Synthetic version 2" if variant.endswith("mismatch") else None
            expected["fit"]["study_version"] = "DECLARED_MISMATCH" if variant.endswith("mismatch") else "UNKNOWN"
        elif variant.startswith("role"):
            record["role"] = None if variant == "role-missing-record" else "CONTEXT_ONLY"
            expected["fit"]["role"] = "UNKNOWN" if record["role"] is None else "DECLARED_MISMATCH"
            # Missing/mismatched observed role never switches off the required INPUT constraint.
        else:
            case["extraction"]["records"] = []
            case["expected"]["records"] = []
            case["expected"]["missing_source_requirements"] = [deepcopy(requirement)]
        cases.append(case)

    semantic_cases = (
        (
            "endpoint-synonym",
            "EQUIVALENT_CONCEPT_UNEQUAL_LABELS",
            "For this fictional case, 'Synthetic endpoint' and 'Synthetic outcome' denote the same event.",
        ),
        (
            "population-synonym",
            "EQUIVALENT_CONCEPT_UNEQUAL_LABELS",
            "For this fictional case, 'Synthetic population' and 'Synthetic cohort' denote the same participants.",
        ),
        (
            "endpoint-concealed",
            "DIFFERENT_CONCEPT_EQUAL_LABELS",
            "The target endpoint means a first event; the record endpoint means recurrent events under the same label.",
        ),
        (
            "population-concealed",
            "DIFFERENT_CONCEPT_EQUAL_LABELS",
            "The target population means all randomized persons; the record population means a safety subset.",
        ),
        (
            "source-field-false",
            "FALSE_SOURCE_COORDINATE",
            "The authored source_field points to a nonexistent raw row. Literal-fit auditing does not resolve it.",
        ),
        (
            "source-value-false",
            "FALSE_SOURCE_QUANTITY",
            "The fixture hr row says 0.80; the extraction says 0.81. Byte binding does not authenticate extraction.",
        ),
    )
    for name, kind, statement in semantic_cases:
        case = make_case("semantic-" + name, "semantic_counterexamples", document, extraction)
        case["semantic_stipulation"] = {"kind": kind, "statement": statement, "empirical_truth": False}
        record = case["extraction"]["records"][0]
        if name.endswith("synonym"):
            field = name.split("-")[0]
            record["dimensions"][field] = "Synthetic outcome" if field == "endpoint" else "Synthetic cohort"
            case["expected"]["records"][0]["fit"][field] = "DECLARED_MISMATCH"
        elif name == "source-field-false":
            record["source_field"] = "rows[id=nonexistent].reported; intentionally false authored coordinate"
        elif name == "source-value-false":
            record["estimate"]["value"] = "0.81"
            record["estimate"]["reported_text"] = "HR 0.81 (95% CI 0.60 to 1.20); intentionally false extraction"
        cases.append(case)

    for variant in ("missing-value-and-ci", "unsupported-text", "precision-and-counts"):
        case = make_case("quantity-" + variant, "quantity_preservation", document, extraction)
        case["design"] = {"variant": variant}
        record = case["extraction"]["records"][0]
        if variant in ("missing-value-and-ci", "unsupported-text"):
            record["estimate"].update(value=None, ci=None)
            if variant == "unsupported-text":
                record["estimate"]["kind"] = "UNSUPPORTED"
                record["estimate"]["reported_text"] = "Invented unsupported measure; no numeric conversion"
                case["expected"]["records"][0]["fit"]["estimate_kind"] = "DECLARED_MISMATCH"
        else:
            record["estimate"]["ci"] = {"lower": "0.60000", "upper": "1.20000", "level": "0.9751"}
            record["aggregate_counts"] = {
                "analysis_population": None,
                "counting_unit": "Synthetic counting_unit",
                "arms": [
                    {
                        "label": "Synthetic candidate",
                        "events": 101,
                        "denominator": "90.2500",
                        "denominator_type": "PERSON_TIME",
                        "denominator_unit": "synthetic person-years",
                    }
                ],
            }
        cases.append(case)

    for case in cases:
        case["extraction"]["receipt_set_sha256"] = digest(encoded(case["receipt_set"]))
    if len(cases) != 132 or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Finite design cardinality or identity changed")
    return cases
