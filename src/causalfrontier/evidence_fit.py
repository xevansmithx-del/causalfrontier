"""Source-bound, read-only audit of declared aggregate-evidence compatibility.

Reported quantities are retained as decimal strings. This is neither a clinical
classifier nor semantic extraction/authentication: literal declarations and date
metadata are compared, without inference, pooling, scoring, or world updates.
"""

from __future__ import annotations

import calendar
import re
from contextlib import ExitStack
from copy import deepcopy
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

from . import receipts
from .assumptions import _bounded_json
from .canonical import CausalFrontierError, canonical_bytes, read_json_bytes, require_id, require_sha256, sha256_bytes
from .model import BOUNDARY_CANONICAL, FIXED_PARAMETER, fixed_boundary

EXTRACTION_SCHEMA = "causalfrontier.evidence-extraction.v1"
REPORT_SCHEMA = "causalfrontier.evidence-fit.v1"
REPORT_DOMAIN = b"causalfrontier.evidence-fit.v1\x00"
MAX_RECORDS = 128
MAX_SOURCE_REQUIREMENTS = 128
MAX_ARMS = 16
MAX_COUNT = 1_000_000_000
DIMENSIONS = (
    "endpoint",
    "population",
    "intervention",
    "comparator",
    "timepoint",
    "estimand",
    "evidence_kind",
    "analysis_population",
    "counting_unit",
    "unit",
)
ROLES = frozenset({"INPUT", "REVEAL_ONLY", "CONTEXT_ONLY"})
ESTIMATE_KINDS = frozenset({"HAZARD_RATIO", "RISK_RATIO", "RATE_RATIO", "MEAN_DIFFERENCE", "UNSUPPORTED"})
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
NONCLAIMS = (
    "Literal declared matches are not independently verified semantic equivalence or correct source extraction.",
    "Source locators, fields, study versions, analysis populations and roles remain authored declarations.",
    "Selected source-date intervals are metadata, not independently attested historical public availability.",
    "Known hindsight is not erased by hashes, replay, source retrieval, or a local freeze.",
    "No estimate pooling, significance judgment, efficacy or safety score, causal-world update "
    "or classifier execution.",
    "No historical eligibility, scientific scoring, patient-level data, clinical or material authority is granted.",
    "Privacy checks are bounded pattern screening, not privacy certification; whole-host mutation is not excluded.",
    "Record and dimension counts are encoding-dependent diagnostics, not independent study counts or confidence.",
)


def _reject(*, limit: bool = False) -> None:
    raise CausalFrontierError(
        "evidence-fit input exceeds bounded limits" if limit else "evidence-fit input rejected",
        reason_code="EVIDENCE_FIT_LIMIT_EXCEEDED" if limit else "EVIDENCE_FIT_REJECTED",
        operation="evidence_fit",
    )


def _shape(value: Any, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        _reject()
    return value


def _text(value: Any, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if type(value) is not str or not 1 <= len(value) <= 2000 or any(ord(char) < 32 for char in value):
        _reject()


def _decimal(value: Any, *, nullable: bool = False) -> Decimal | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) > 64 or DECIMAL.fullmatch(value) is None:
        _reject()
    return Decimal(value)


def _list(value: Any, maximum: int, *, nonempty: bool = False) -> list:
    if type(value) is not list:
        _reject()
    if len(value) > maximum:
        _reject(limit=True)
    if nonempty and not value:
        _reject()
    return value


def _bounded(value: Any, *, report: bool = False) -> bytes:
    try:
        raw = _bounded_json(value, "evidence fit", max_nodes=262_144 if report else 65_536, reserve_bytes=1)
        receipts._screen(raw)
        return raw
    except CausalFrontierError as exc:
        _reject(limit=exc.reason_code == "ASSUMPTION_AUDIT_LIMIT_EXCEEDED")


def _parse(raw: bytes, expected: str, *, report: bool = False) -> dict:
    if type(raw) is not bytes:
        _reject()
    require_sha256(expected, "evidence-fit checkpoint")
    if len(raw) > receipts.MAX_FILE_BYTES:
        _reject(limit=True)
    if sha256_bytes(raw) != expected:
        _reject()
    receipts._screen(raw)
    value = read_json_bytes(raw, "evidence-fit input")
    _bounded(value, report=report)
    if type(value) is not dict:
        _reject()
    return value


def _compare(expected: Any, observed: Any) -> str:
    if expected is None or observed is None:
        return "UNKNOWN"
    return "DECLARED_MATCH" if expected == observed else "DECLARED_MISMATCH"


def _dimensions(value: Any) -> None:
    _shape(value, set(DIMENSIONS))
    for item in value.values():
        _text(item, nullable=True)


def _estimate(value: Any) -> list[str]:
    _shape(value, {"kind", "value", "ci", "unit", "contrast", "reported_text"})
    if type(value["kind"]) is not str or value["kind"] not in ESTIMATE_KINDS:
        _reject()
    _text(value["reported_text"])
    _text(value["unit"], nullable=True)
    _shape(value["contrast"], {"numerator", "denominator"})
    for label in value["contrast"].values():
        _text(label, nullable=True)
    number = _decimal(value["value"], nullable=True)
    if value["kind"] == "UNSUPPORTED":
        if number is not None or value["ci"] is not None:
            _reject()
        return ["ESTIMATE_KIND_UNSUPPORTED_REPORTED_TEXT_RETAINED"]
    reasons = [] if number is not None else ["ESTIMATE_VALUE_UNREPORTED"]
    ratio = value["kind"] != "MEAN_DIFFERENCE"
    if ratio and number is not None and number < 0:
        reasons.append("NEGATIVE_REPORTED_RATIO")
    if value["ci"] is None:
        reasons.append("CONFIDENCE_INTERVAL_UNREPORTED")
    else:
        ci = _shape(value["ci"], {"lower", "upper", "level"})
        lower, upper, level = (_decimal(ci[key]) for key in ("lower", "upper", "level"))
        if lower > upper:
            reasons.append("REPORTED_CI_BOUNDS_REVERSED")
        if number is not None and not lower <= number <= upper:
            reasons.append("REPORTED_POINT_OUTSIDE_CI")
        if not 0 < level < 1:
            reasons.append("REPORTED_CI_LEVEL_OUTSIDE_UNIT_INTERVAL")
        if ratio and (lower < 0 or upper < 0):
            reasons.append("NEGATIVE_REPORTED_RATIO_CI_BOUND")
    return sorted(reasons)


def _counts(value: Any) -> None:
    if value is None:
        return
    _shape(value, {"analysis_population", "counting_unit", "arms"})
    _text(value["analysis_population"], nullable=True)
    _text(value["counting_unit"], nullable=True)
    names = set()
    for arm in _list(value["arms"], MAX_ARMS, nonempty=True):
        _shape(arm, {"label", "events", "denominator", "denominator_type", "denominator_unit"})
        _text(arm["label"])
        if arm["label"] in names:
            _reject()
        names.add(arm["label"])
        _text(arm["denominator_unit"], nullable=True)
        events = arm["events"]
        if events is not None and (type(events) is not int or not 0 <= events <= MAX_COUNT):
            _reject()
        kind, denominator = arm["denominator_type"], arm["denominator"]
        if kind in ("PARTICIPANTS", "OBSERVATIONS"):
            if denominator is not None and (type(denominator) is not int or not 0 <= denominator <= MAX_COUNT):
                _reject()
        elif kind == "PERSON_TIME":
            parsed = _decimal(denominator, nullable=True)
            if parsed is not None and (parsed < 0 or arm["denominator_unit"] is None):
                _reject()
        elif kind != "UNKNOWN" or denominator is not None:
            _reject()
    # Recurrent events may exceed participants. No derived rate, risk, or assumed
    # participant-level interpretation is manufactured from these counts.


def _date_interval(item: dict) -> dict:
    precision, value = item["precision"], item["value"]
    if precision == "UNKNOWN":
        return {"lower": None, "upper": None}
    parts = [int(part) for part in value.split("-")]
    if precision == "YEAR":
        lower, upper = date(parts[0], 1, 1), date(parts[0], 12, 31)
    elif precision == "MONTH":
        year, month = parts
        lower, upper = date(year, month, 1), date(year, month, calendar.monthrange(year, month)[1])
    else:
        lower = upper = date(*parts)
    return {"lower": lower.isoformat() + "T00:00:00Z", "upper": upper.isoformat() + "T23:59:59Z"}


def _availability(record: dict, source: dict, cutoff: str, role: str) -> dict:
    field = record["availability_date_field"]
    selected = None if field is None else source["dates"][field]
    interval = {"lower": None, "upper": None} if selected is None else _date_interval(selected)
    if interval["lower"] is None:
        relation = "UNKNOWN"
    elif interval["upper"] <= cutoff:
        relation = "DECLARED_BY_CUTOFF"
    elif interval["lower"] > cutoff:
        relation = "DECLARED_AFTER_CUTOFF"
    else:
        relation = "DECLARED_INTERVAL_SPANS_CUTOFF"
    state = "UNKNOWN"
    if role == "INPUT":
        state = {"DECLARED_BY_CUTOFF": "DECLARED_MATCH", "DECLARED_AFTER_CUTOFF": "DECLARED_MISMATCH"}.get(
            relation, "UNKNOWN"
        )
    return {
        "selected_date_field": field,
        "selected_date": deepcopy(selected),
        "interval": interval,
        "evidence_cutoff": cutoff,
        "declared_date_relation": relation,
        "input_date_fit": state,
        "input_date_constraint_applies": role == "INPUT",
        "historical_eligible": False,
        "interpretation": "SELECTED_DATE_METADATA_ONLY_NOT_ATTESTED_PUBLIC_AVAILABILITY",
    }


def _receipt_document(root: Path, expected: str) -> tuple[dict, dict]:
    with ExitStack() as stack:
        descriptor = receipts._root_descriptor(stack, root)
        raw = receipts._snapshot(descriptor, receipts.MANIFEST)
    document = _parse(raw, expected)
    preflight = receipts.preflight_receipts(root, expected)
    if preflight["canonical_receipt_set_sha256"] != sha256_bytes(canonical_bytes(document)):
        _reject()
    return document, preflight


def _audit(root: Path, expected_set: str, raw: bytes, expected_extraction: str) -> dict:
    extraction = _parse(raw, expected_extraction)
    _shape(
        extraction, {"schema_version", "id", "fixed_parameter", "boundary", "receipt_set_sha256", "target", "records"}
    )
    if (
        extraction["schema_version"] != EXTRACTION_SCHEMA
        or extraction["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(extraction["boundary"]) != BOUNDARY_CANONICAL
        or extraction["receipt_set_sha256"] != expected_set
    ):
        _reject()
    require_id(extraction["id"], "extraction id")
    target = _shape(extraction["target"], {"id", "dimensions", "estimate_kind", "source_requirements"})
    require_id(target["id"], "target id")
    _dimensions(target["dimensions"])
    if target["estimate_kind"] is not None and target["estimate_kind"] not in ESTIMATE_KINDS:
        _reject()
    requirements = {}
    for requirement in _list(target["source_requirements"], MAX_SOURCE_REQUIREMENTS, nonempty=True):
        _shape(requirement, {"receipt_id", "source_id", "study_version", "role"})
        key = tuple(require_id(requirement[name], "source requirement id") for name in ("receipt_id", "source_id"))
        _text(requirement["study_version"], nullable=True)
        if requirement["role"] not in ROLES or key in requirements:
            _reject()
        requirements[key] = requirement
    records = _list(extraction["records"], MAX_RECORDS)
    # These cardinality checks precede any receipt filesystem acquisition.
    document, preflight = _receipt_document(root, expected_set)
    receipt_map = {item["id"]: item for item in document["receipts"]}
    source_map = {
        (item["id"], source["id"]): source for item in document["receipts"] for source in item["source_records"]
    }
    if not set(requirements) <= set(source_map):
        _reject()
    rows, seen, represented = [], set(), set()
    for record in records:
        _shape(
            record,
            {
                "id",
                "receipt_id",
                "source_id",
                "raw_response_sha256",
                "source_locator",
                "source_field",
                "study_version",
                "role",
                "availability_date_field",
                "dimensions",
                "estimate",
                "aggregate_counts",
            },
        )
        identifier = require_id(record["id"], "record id")
        key = tuple(require_id(record[name], "record source id") for name in ("receipt_id", "source_id"))
        if identifier in seen or key not in requirements:
            _reject()
        seen.add(identifier)
        represented.add(key)
        receipt, source, requirement = receipt_map[key[0]], source_map[key], requirements[key]
        if (
            record["raw_response_sha256"] != receipt["raw_response"]["sha256"]
            or record["source_locator"] != source["locator"]
        ):
            _reject()
        _text(record["source_field"])
        _text(record["study_version"], nullable=True)
        if record["role"] is not None and record["role"] not in ROLES:
            _reject()
        field = record["availability_date_field"]
        if field is not None and field not in receipts.DATE_FIELDS:
            _reject()
        _dimensions(record["dimensions"])
        numeric_reasons = _estimate(record["estimate"])
        _counts(record["aggregate_counts"])
        dimensions = {name: _compare(target["dimensions"][name], record["dimensions"][name]) for name in DIMENSIONS}
        dimensions["study_version"] = _compare(requirement["study_version"], record["study_version"])
        dimensions["role"] = _compare(requirement["role"], record["role"])
        dimensions["estimate_kind"] = _compare(target["estimate_kind"], record["estimate"]["kind"])
        estimate, observed = record["estimate"], record["dimensions"]
        dimensions["estimate_unit"] = _compare(target["dimensions"]["unit"], estimate["unit"])
        dimensions["contrast_numerator"] = _compare(
            target["dimensions"]["intervention"], estimate["contrast"]["numerator"]
        )
        dimensions["contrast_denominator"] = _compare(
            target["dimensions"]["comparator"], estimate["contrast"]["denominator"]
        )
        consistency = {
            "estimate_unit": _compare(observed["unit"], estimate["unit"]),
            "contrast_numerator": _compare(observed["intervention"], estimate["contrast"]["numerator"]),
            "contrast_denominator": _compare(observed["comparator"], estimate["contrast"]["denominator"]),
        }
        counts = record["aggregate_counts"]
        for name in ("analysis_population", "counting_unit"):
            dimensions["aggregate_counts_" + name] = _compare(
                target["dimensions"][name], None if counts is None else counts[name]
            )
            consistency["aggregate_counts_" + name] = _compare(observed[name], None if counts is None else counts[name])
        availability = _availability(record, source, document["evidence_cutoff"], requirement["role"])
        if availability["input_date_constraint_applies"]:
            dimensions["declared_input_date"] = availability["input_date_fit"]
        issues = [
            name.upper() + "_DECLARED_MISMATCH" for name, state in dimensions.items() if state == "DECLARED_MISMATCH"
        ]
        issues += [
            "RECORD_" + name.upper() + "_INCONSISTENT"
            for name, state in consistency.items()
            if state == "DECLARED_MISMATCH"
        ]
        missing_numeric = {
            "ESTIMATE_VALUE_UNREPORTED",
            "CONFIDENCE_INTERVAL_UNREPORTED",
            "ESTIMATE_KIND_UNSUPPORTED_REPORTED_TEXT_RETAINED",
        }
        mismatch = bool(issues or set(numeric_reasons) - missing_numeric)
        issues += numeric_reasons
        complete = receipt["retrieval_state"] == "COMPLETE" and receipt["coverage"]["state"] == "COMPLETE"
        public_decision = (
            receipt["data_class"] == "PUBLIC_AGGREGATE" and receipt["semantic_state"] == "USABLE_FOR_DECLARED_SCOPE"
        )
        dimensions["acquisition_coverage"] = "DECLARED_MATCH" if complete else "UNKNOWN"
        dimensions["declared_public_decision_evidence"] = "DECLARED_MATCH" if public_decision else "UNKNOWN"
        if not complete:
            issues.append("ACQUISITION_OR_COVERAGE_INCOMPLETE_NOT_EVIDENCE_ABSENCE")
        if not public_decision:
            issues.append("SOURCE_NOT_DECLARED_PUBLIC_DECISION_EVIDENCE")
        incomplete = "UNKNOWN" in dimensions.values() or "UNKNOWN" in consistency.values() or bool(numeric_reasons)
        diagnostic = (
            "DECLARED_MISMATCH_PRESENT"
            if mismatch
            else "DECLARED_INFORMATION_INCOMPLETE"
            if incomplete
            else "DECLARED_LABELS_COMPARED_UNVERIFIED"
        )
        rows.append(
            {
                "record": deepcopy(record),
                "dimension_fit": dimensions,
                "record_consistency": consistency,
                "availability": availability,
                "receipt_dates": deepcopy(source["dates"]),
                "retrieval_state": receipt["retrieval_state"],
                "coverage": deepcopy(receipt["coverage"]),
                "semantic_state": receipt["semantic_state"],
                "temporal_attestation_state": receipt["temporal_attestation"]["state"],
                "diagnostic_status": diagnostic,
                "reason_codes": sorted(issues),
                "historical_eligible": False,
            }
        )
    rows.sort(key=lambda row: row["record"]["id"])
    target = deepcopy(target)
    target["source_requirements"].sort(key=lambda item: (item["receipt_id"], item["source_id"]))
    # Repeat existing byte-bound acquisition checks before returning a report.
    if canonical_bytes(receipts.preflight_receipts(root, expected_set)) != canonical_bytes(preflight):
        _reject()
    core = {
        "schema_version": REPORT_SCHEMA,
        "status": "DECLARED_EVIDENCE_FIT_AUDITED_NOT_ADMITTED",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "extraction_id": extraction["id"],
        "extraction_sha256": expected_extraction,
        "canonical_extraction_sha256": sha256_bytes(canonical_bytes(extraction)),
        "receipt_set_sha256": expected_set,
        "receipt_preflight_sha256": sha256_bytes(canonical_bytes(preflight)),
        "selection_origin": document["selection_origin"],
        "target": target,
        "records": rows,
        "records_n": len(rows),
        "source_requirements_n": len(requirements),
        "missing_source_requirements": [deepcopy(requirements[key]) for key in sorted(set(requirements) - represented)],
        "dimension_counts": {
            state: sum(list(row["dimension_fit"].values()).count(state) for row in rows)
            for state in ("DECLARED_MATCH", "DECLARED_MISMATCH", "UNKNOWN")
        },
        "historically_eligible_records_n": 0,
        "scientific_scoring": "DISABLED",
        "scientific_authority": False,
        "semantic_authentication": False,
        "nonclaims": list(NONCLAIMS),
    }
    result = {**core, "report_sha256": sha256_bytes(REPORT_DOMAIN + canonical_bytes(core))}
    _bounded(result, report=True)
    return result


def audit_evidence_fit(
    receipt_root: Path,
    expected_set_sha256: str,
    extraction: bytes,
    expected_extraction_sha256: str,
) -> dict:
    """Replay receipt acquisition and audit exact, caller-checkpointed extraction bytes."""
    try:
        return _audit(receipt_root, expected_set_sha256, extraction, expected_extraction_sha256)
    except CausalFrontierError as exc:
        if exc.reason_code.startswith("EVIDENCE_FIT_"):
            raise
        _reject()
    except (OSError, RecursionError, ValueError, TypeError, KeyError, OverflowError):
        _reject()


def verify_evidence_fit(
    receipt_root: Path,
    expected_set_sha256: str,
    extraction: bytes,
    expected_extraction_sha256: str,
    report: bytes,
    expected_report_sha256: str,
) -> dict:
    """Require full strict-canonical equality to a fresh source-bound audit, not just a report hash."""
    try:
        supplied = _parse(report, expected_report_sha256, report=True)
        rebuilt = audit_evidence_fit(receipt_root, expected_set_sha256, extraction, expected_extraction_sha256)
        if canonical_bytes(supplied) != canonical_bytes(rebuilt):
            _reject()
        return {
            "schema_version": "causalfrontier.evidence-fit-verification.v1",
            "status": "EXACT_EVIDENCE_FIT_REPLAY_VERIFIED_NOT_ADMITTED",
            "verified": True,
            "report_sha256": rebuilt["report_sha256"],
            "report_file_sha256": expected_report_sha256,
            "extraction_sha256": expected_extraction_sha256,
            "receipt_set_sha256": expected_set_sha256,
            "scientific_scoring": "DISABLED",
            "historically_eligible_records_n": 0,
            "scientific_authority": False,
            "boundary": fixed_boundary(),
        }
    except CausalFrontierError as exc:
        if exc.reason_code.startswith("EVIDENCE_FIT_"):
            raise
        _reject()
    except (OSError, RecursionError, ValueError, TypeError, KeyError, OverflowError):
        _reject()
