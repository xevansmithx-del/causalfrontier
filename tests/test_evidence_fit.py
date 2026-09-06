"""Synthetic-only checks of aggregate preservation and declared evidence fit."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from copy import deepcopy

import pytest
from test_receipts import _document

from causalfrontier import evidence_fit as fit
from causalfrontier import receipts
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path.resolve() / "receipts"
    (root / "raw").mkdir(parents=True)
    raw = b"Synthetic aggregate record: HR 0.80 (95% CI 0.60 to 1.20).\n"
    (root / "raw/response.txt").write_bytes(raw)
    document = _document(raw)
    receipt = document["receipts"][0]
    receipt["data_class"] = "PUBLIC_AGGREGATE"
    receipt["semantic_state"] = "USABLE_FOR_DECLARED_SCOPE"
    receipt["source_records"][0]["dates"]["publication_online"] = {
        "value": "2012-06-01",
        "precision": "DAY",
        "source_field": "synthetic online date",
    }
    metadata = canonical_bytes(document) + b"\n"
    (root / receipts.MANIFEST).write_bytes(metadata)
    dims = {key: "synthetic " + key for key in fit.DIMENSIONS}
    dims.update(intervention="candidate", comparator="comparator", unit="ratio")
    record = {
        "id": "record:one",
        "receipt_id": receipt["id"],
        "source_id": "source:synthetic-record",
        "raw_response_sha256": sha256_bytes(raw),
        "source_locator": "https://example.org/synthetic-record",
        "source_field": "synthetic table 1 row 1",
        "study_version": "synthetic original report",
        "role": "INPUT",
        "availability_date_field": "publication_online",
        "dimensions": deepcopy(dims),
        "estimate": {
            "kind": "HAZARD_RATIO",
            "value": "0.80",
            "ci": {"lower": "0.60", "upper": "1.20", "level": "0.95"},
            "unit": "ratio",
            "contrast": {"numerator": "candidate", "denominator": "comparator"},
            "reported_text": "Synthetic HR 0.80 (95% CI 0.60 to 1.20)",
        },
        "aggregate_counts": {
            "analysis_population": dims["analysis_population"],
            "counting_unit": dims["counting_unit"],
            "arms": [
                {
                    "label": "candidate",
                    "events": 8,
                    "denominator": 100,
                    "denominator_type": "PARTICIPANTS",
                    "denominator_unit": "participants",
                }
            ],
        },
    }
    extraction = {
        "schema_version": fit.EXTRACTION_SCHEMA,
        "id": "extraction:synthetic",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "receipt_set_sha256": sha256_bytes(metadata),
        "target": {
            "id": "target:synthetic",
            "dimensions": dims,
            "estimate_kind": "HAZARD_RATIO",
            "source_requirements": [{key: record[key] for key in ("receipt_id", "source_id", "study_version", "role")}],
        },
        "records": [record],
    }
    return root, document, extraction


def _run(bundle):
    root, document, extraction = bundle
    metadata = canonical_bytes(document) + b"\n"
    (root / receipts.MANIFEST).write_bytes(metadata)
    extraction["receipt_set_sha256"] = sha256_bytes(metadata)
    raw = canonical_bytes(extraction) + b"\n"
    return fit.audit_evidence_fit(root, sha256_bytes(metadata), raw, sha256_bytes(raw))


def _verify(bundle, report):
    root, _, extraction = bundle
    raw = canonical_bytes(extraction) + b"\n"
    encoded = canonical_bytes(report) + b"\n"
    return fit.verify_evidence_fit(
        root, extraction["receipt_set_sha256"], raw, sha256_bytes(raw), encoded, sha256_bytes(encoded)
    )


def test_preserves_every_quantity_and_all_authority_nonclaims(bundle):
    result = _run(bundle)
    row = result["records"][0]
    assert row["record"] == bundle[2]["records"][0]
    assert row["record"]["estimate"]["value"] == "0.80"
    assert set(row["dimension_fit"].values()) == {"DECLARED_MATCH"}
    assert row["diagnostic_status"] == "DECLARED_LABELS_COMPARED_UNVERIFIED"
    assert row["historical_eligible"] is False
    assert result["historically_eligible_records_n"] == 0
    assert result["scientific_scoring"] == "DISABLED"
    assert result["scientific_authority"] is False
    assert result["semantic_authentication"] is False
    assert result["boundary"] == fixed_boundary()
    assert result["selection_origin"] == "KNOWN_HINDSIGHT"
    assert _verify(bundle, result)["verified"] is True


@pytest.mark.parametrize("kind", sorted(fit.ESTIMATE_KINDS - {"UNSUPPORTED"}))
def test_registered_estimates_are_retained_not_pooled_or_classified(bundle, kind):
    record = bundle[2]["records"][0]
    record["estimate"]["kind"] = kind
    if kind == "MEAN_DIFFERENCE":
        record["estimate"].update(
            value="-4.20", unit="synthetic units", ci={"lower": "-6.00", "upper": "-1.20", "level": "0.95"}
        )
    result = _run(bundle)
    assert result["records"][0]["record"]["estimate"] == record["estimate"]
    assert result["records"][0]["dimension_fit"]["estimate_kind"] == (
        "DECLARED_MATCH" if kind == "HAZARD_RATIO" else "DECLARED_MISMATCH"
    )
    assert "branch_token" not in result["records"][0]


@pytest.mark.parametrize("dimension", fit.DIMENSIONS)
def test_each_dimension_mismatch_and_unknown_remains_distinct(bundle, dimension):
    record = bundle[2]["records"][0]
    record["dimensions"][dimension] = "different declared label"
    row = _run(bundle)["records"][0]
    assert row["dimension_fit"][dimension] == "DECLARED_MISMATCH"
    record["dimensions"][dimension] = None
    assert _run(bundle)["records"][0]["dimension_fit"][dimension] == "UNKNOWN"


def test_unknown_target_is_not_wildcard_and_labels_not_semantically_normalized(bundle):
    extraction = bundle[2]
    extraction["target"]["dimensions"]["population"] = None
    extraction["records"][0]["dimensions"]["endpoint"] = extraction["target"]["dimensions"]["endpoint"].upper()
    row = _run(bundle)["records"][0]
    assert row["dimension_fit"]["population"] == "UNKNOWN"
    assert row["dimension_fit"]["endpoint"] == "DECLARED_MISMATCH"


@pytest.mark.parametrize(
    ("value", "precision", "cutoff", "relation", "state"),
    [
        ("2011", "YEAR", "2012-12-31T23:59:59Z", "DECLARED_BY_CUTOFF", "DECLARED_MATCH"),
        ("2013", "YEAR", "2012-12-31T23:59:59Z", "DECLARED_AFTER_CUTOFF", "DECLARED_MISMATCH"),
        ("2012", "YEAR", "2012-06-01T12:00:00Z", "DECLARED_INTERVAL_SPANS_CUTOFF", "UNKNOWN"),
        ("2012-02", "MONTH", "2012-02-28T23:59:59Z", "DECLARED_INTERVAL_SPANS_CUTOFF", "UNKNOWN"),
        ("2012-02-29", "DAY", "2012-02-29T12:00:00Z", "DECLARED_INTERVAL_SPANS_CUTOFF", "UNKNOWN"),
        ("2012-02-29", "DAY", "2012-02-29T23:59:59Z", "DECLARED_BY_CUTOFF", "DECLARED_MATCH"),
        (None, "UNKNOWN", "2012-12-31T23:59:59Z", "UNKNOWN", "UNKNOWN"),
    ],
)
def test_date_precision_intervals_do_not_invent_available_instants(bundle, value, precision, cutoff, relation, state):
    document = bundle[1]
    document["evidence_cutoff"] = cutoff
    selected = document["receipts"][0]["source_records"][0]["dates"]["publication_online"]
    selected.update(value=value, precision=precision, source_field=None if value is None else "synthetic date")
    row = _run(bundle)["records"][0]
    assert row["availability"]["declared_date_relation"] == relation
    assert row["dimension_fit"]["declared_input_date"] == state
    assert row["availability"]["historical_eligible"] is False
    assert row["availability"]["selected_date"] == selected


def test_later_reveal_is_retained_not_rejected_or_promoted_to_input(bundle):
    document, extraction = bundle[1:]
    document["receipts"][0]["source_records"][0]["dates"]["publication_online"]["value"] = "2017-01-01"
    extraction["records"][0]["role"] = "REVEAL_ONLY"
    row = _run(bundle)["records"][0]
    assert row["availability"]["declared_date_relation"] == "DECLARED_AFTER_CUTOFF"
    assert row["dimension_fit"]["role"] == "DECLARED_MISMATCH"
    assert row["dimension_fit"]["declared_input_date"] == "DECLARED_MISMATCH"
    extraction["target"]["source_requirements"][0]["role"] = "REVEAL_ONLY"
    row = _run(bundle)["records"][0]
    assert row["dimension_fit"]["role"] == "DECLARED_MATCH"
    assert "declared_input_date" not in row["dimension_fit"]
    assert row["availability"]["input_date_constraint_applies"] is False
    assert row["historical_eligible"] is False


def test_source_scoped_roles_and_study_versions_do_not_bleed(bundle):
    document, extraction = bundle[1:]
    receipt = deepcopy(document["receipts"][0])
    receipt["id"] = "receipt:second"
    document["receipts"].append(receipt)
    record = deepcopy(extraction["records"][0])
    record.update(id="record:two", receipt_id=receipt["id"], role="REVEAL_ONLY", study_version="synthetic update")
    extraction["records"].append(record)
    extraction["target"]["source_requirements"].append(
        {
            "receipt_id": receipt["id"],
            "source_id": record["source_id"],
            "role": "REVEAL_ONLY",
            "study_version": "synthetic update",
        }
    )
    result = _run(bundle)
    assert all(row["dimension_fit"]["role"] == "DECLARED_MATCH" for row in result["records"])
    record["study_version"] = "synthetic original report"
    rows = _run(bundle)["records"]
    assert rows[0]["dimension_fit"]["study_version"] == "DECLARED_MATCH"
    assert rows[1]["dimension_fit"]["study_version"] == "DECLARED_MISMATCH"


def test_counts_missing_or_recurrent_are_not_zero_or_binomial_assumptions(bundle):
    record = bundle[2]["records"][0]
    record["aggregate_counts"]["arms"][0]["events"] = 150
    assert _run(bundle)["records"][0]["record"]["aggregate_counts"]["arms"][0]["events"] == 150
    record["aggregate_counts"] = None
    row = _run(bundle)["records"][0]
    assert row["record"]["aggregate_counts"] is None
    assert row["dimension_fit"]["aggregate_counts_counting_unit"] == "UNKNOWN"
    assert row["diagnostic_status"] == "DECLARED_INFORMATION_INCOMPLETE"


@pytest.mark.parametrize(
    ("kind", "denominator", "unit"),
    [
        ("PARTICIPANTS", 100, "participants"),
        ("OBSERVATIONS", 100, "visits"),
        ("PERSON_TIME", "125.50", "person years"),
        ("UNKNOWN", None, None),
    ],
)
def test_denominator_types_are_preserved(bundle, kind, denominator, unit):
    arm = bundle[2]["records"][0]["aggregate_counts"]["arms"][0]
    arm.update(denominator_type=kind, denominator=denominator, denominator_unit=unit)
    assert _run(bundle)["records"][0]["record"]["aggregate_counts"]["arms"][0] == arm


@pytest.mark.parametrize(
    ("kind", "denominator", "unit"),
    [
        ("PARTICIPANTS", True, "participants"),
        ("PARTICIPANTS", "100", "participants"),
        ("OBSERVATIONS", -1, "visits"),
        ("PERSON_TIME", 100, "person years"),
        ("PERSON_TIME", "1.5", None),
        ("PERSON_TIME", "-1", "person years"),
        ("UNKNOWN", 100, None),
        ("UNKNOWN_KIND", None, None),
    ],
)
def test_invalid_denominator_types_reject_without_coercion(bundle, kind, denominator, unit):
    arm = bundle[2]["records"][0]["aggregate_counts"]["arms"][0]
    arm.update(denominator_type=kind, denominator=denominator, denominator_unit=unit)
    with pytest.raises(CausalFrontierError):
        _run(bundle)


@pytest.mark.parametrize("number", ["NaN", "Infinity", "1e-2", ".8", "01.2", "+0.8", "8" * 65, 0.8, True])
def test_noncanonical_or_unbounded_decimal_values_reject(bundle, number):
    bundle[2]["records"][0]["estimate"]["value"] = number
    with pytest.raises(CausalFrontierError):
        _run(bundle)


def test_missing_estimate_and_unsupported_text_are_retained_as_incomplete(bundle):
    estimate = bundle[2]["records"][0]["estimate"]
    estimate.update(value=None, ci=None)
    row = _run(bundle)["records"][0]
    assert "ESTIMATE_VALUE_UNREPORTED" in row["reason_codes"]
    assert row["diagnostic_status"] == "DECLARED_INFORMATION_INCOMPLETE"
    estimate["kind"] = "UNSUPPORTED"
    row = _run(bundle)["records"][0]
    assert row["record"]["estimate"]["reported_text"] == estimate["reported_text"]
    assert "ESTIMATE_KIND_UNSUPPORTED_REPORTED_TEXT_RETAINED" in row["reason_codes"]


def test_arithmetic_inconsistency_retains_original_reported_values(bundle):
    estimate = bundle[2]["records"][0]["estimate"]
    estimate.update(value="-0.80", ci={"lower": "1.20", "upper": "-0.60", "level": "95"})
    row = _run(bundle)["records"][0]
    assert row["record"]["estimate"] == estimate
    assert "REPORTED_CI_BOUNDS_REVERSED" in row["reason_codes"]
    assert "REPORTED_CI_LEVEL_OUTSIDE_UNIT_INTERVAL" in row["reason_codes"]
    assert row["diagnostic_status"] == "DECLARED_MISMATCH_PRESENT"


def test_estimate_direction_and_unit_cannot_hide_behind_dimension_labels(bundle):
    estimate = bundle[2]["records"][0]["estimate"]
    estimate["contrast"] = {"numerator": "comparator", "denominator": "candidate"}
    estimate["unit"] = "percentage points"
    row = _run(bundle)["records"][0]
    assert row["dimension_fit"]["contrast_numerator"] == "DECLARED_MISMATCH"
    assert row["dimension_fit"]["contrast_denominator"] == "DECLARED_MISMATCH"
    assert row["record_consistency"]["estimate_unit"] == "DECLARED_MISMATCH"


def test_partial_metadata_only_receipt_does_not_become_decision_evidence(bundle):
    receipt = bundle[1]["receipts"][0]
    receipt.update(data_class="PUBLIC_METADATA", semantic_state="METADATA_ONLY", retrieval_state="FAILED")
    receipt["coverage"].update(state="PARTIAL", total_records=None)
    row = _run(bundle)["records"][0]
    assert row["dimension_fit"]["acquisition_coverage"] == "UNKNOWN"
    assert row["dimension_fit"]["declared_public_decision_evidence"] == "UNKNOWN"
    assert "ACQUISITION_OR_COVERAGE_INCOMPLETE_NOT_EVIDENCE_ABSENCE" in row["reason_codes"]
    assert row["historical_eligible"] is False


@pytest.mark.parametrize("field", ["source_id", "receipt_id", "source_locator", "raw_response_sha256"])
def test_source_binding_mismatch_rejects(bundle, field):
    bundle[2]["records"][0][field] = "substituted"
    with pytest.raises(CausalFrontierError):
        _run(bundle)


def test_empty_records_preserve_missing_source_requirement(bundle):
    bundle[2]["records"] = []
    result = _run(bundle)
    assert result["records_n"] == 0
    assert result["missing_source_requirements"] == bundle[2]["target"]["source_requirements"]
    assert set(result["dimension_counts"].values()) == {0}


@pytest.mark.parametrize("location", ["record", "requirement", "arm"])
def test_duplicate_ids_or_coordinates_reject(bundle, location):
    extraction = bundle[2]
    target = (
        extraction["records"]
        if location == "record"
        else extraction["target"]["source_requirements"]
        if location == "requirement"
        else extraction["records"][0]["aggregate_counts"]["arms"]
    )
    target.append(deepcopy(target[0]))
    with pytest.raises(CausalFrontierError):
        _run(bundle)


@pytest.mark.parametrize("location", ["record", "requirement"])
def test_work_bounds_reject_before_receipt_preflight(bundle, monkeypatch, location):
    monkeypatch.setattr(receipts, "preflight_receipts", lambda *args: pytest.fail("preflight reached"))
    extraction = bundle[2]
    target = extraction["records"] if location == "record" else extraction["target"]["source_requirements"]
    target.extend(deepcopy(target[0]) for _ in range(128))
    with pytest.raises(CausalFrontierError) as caught:
        _run(bundle)
    assert caught.value.reason_code == "EVIDENCE_FIT_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "payload",
    [b'{"secret":' + b"[" * 100 + b"0" + b"]" * 100 + b"}", b'{"duplicate":1,"duplicate":2}', b'{"secret":1.5}'],
)
def test_hostile_json_rejects_before_receipt_preflight_without_echo(bundle, monkeypatch, payload):
    monkeypatch.setattr(receipts, "preflight_receipts", lambda *args: pytest.fail("preflight reached"))
    with pytest.raises(CausalFrontierError) as caught:
        fit.audit_evidence_fit(bundle[0], bundle[2]["receipt_set_sha256"], payload, sha256_bytes(payload))
    assert "secret" not in str(caught.value)
    assert "duplicate" not in str(caught.value)


def test_private_decoded_escape_is_rejected_without_echo(bundle):
    raw = b'{"source_field":"/private/synthetic/a","patient_' + b'\\u0069d":"SECRET-SYNTHETIC"}'
    with pytest.raises(CausalFrontierError) as caught:
        fit.audit_evidence_fit(bundle[0], bundle[2]["receipt_set_sha256"], raw, sha256_bytes(raw))
    assert "SECRET" not in str(caught.value)
    assert "patient" not in str(caught.value)


@pytest.mark.parametrize("field", ["clinical_authority", "prospective_benchmark_cases_scored_n"])
def test_immutable_boundary_rejects_type_alias_and_authority_forgery(bundle, field):
    bundle[2]["boundary"][field] = 0 if field == "clinical_authority" else False
    with pytest.raises(CausalFrontierError):
        _run(bundle)


def test_full_replay_rejects_coherently_rehashed_report_forgery(bundle):
    result = _run(bundle)
    result["records"][0]["historical_eligible"] = True
    core = {key: value for key, value in result.items() if key != "report_sha256"}
    result["report_sha256"] = sha256_bytes(fit.REPORT_DOMAIN + canonical_bytes(core))
    with pytest.raises(CausalFrontierError):
        _verify(bundle, result)


def test_exact_byte_checkpoint_not_substituted_by_canonical_equivalence(bundle):
    result = _run(bundle)
    root, _, extraction = bundle
    raw = canonical_bytes(extraction) + b"\n"
    with pytest.raises(CausalFrontierError):
        fit.audit_evidence_fit(root, extraction["receipt_set_sha256"], raw + b" ", sha256_bytes(raw))
    report = canonical_bytes(result) + b"\n"
    with pytest.raises(CausalFrontierError):
        fit.verify_evidence_fit(
            root, extraction["receipt_set_sha256"], raw, sha256_bytes(raw), report + b" ", sha256_bytes(report)
        )


def test_source_bytes_changed_after_audit_reject_on_replay(bundle):
    result = _run(bundle)
    (bundle[0] / "raw/response.txt").write_bytes(b"different synthetic bytes\n")
    with pytest.raises(CausalFrontierError):
        _verify(bundle, result)


@pytest.mark.parametrize("value", [[], {}, ["HAZARD_RATIO"], {"HAZARD_RATIO": True}])
def test_unhashable_target_kind_is_sanitized(bundle, value):
    bundle[2]["target"]["estimate_kind"] = value
    with pytest.raises(CausalFrontierError) as caught:
        _run(bundle)
    assert caught.value.reason_code == "EVIDENCE_FIT_REJECTED"
    assert str(caught.value) == "evidence-fit input rejected"


def test_unverified_backdated_attestation_never_enables_historical_eligibility(bundle):
    receipt = bundle[1]["receipts"][0]
    receipt["temporal_attestation"] = {
        "state": "UNVERIFIED_CLAIM",
        "artifact": deepcopy(receipt["raw_response"]),
        "claimed_available_at": "2011-01-01T00:00:00Z",
        "locator": "https://example.org/synthetic-attestation",
    }
    result = _run(bundle)
    assert result["records"][0]["temporal_attestation_state"] == "UNVERIFIED_CLAIM"
    assert result["records"][0]["historical_eligible"] is False
    assert result["historically_eligible_records_n"] == 0


def test_deterministic_record_order_does_not_hide_changed_raw_checkpoint(bundle):
    extraction = bundle[2]
    second = deepcopy(extraction["records"][0])
    second["id"] = "record:two"
    extraction["records"].append(second)
    before = _run(bundle)
    extraction["records"].reverse()
    after = _run(bundle)
    assert after["records"] == before["records"]
    assert after["dimension_counts"] == before["dimension_counts"]
    assert after["extraction_sha256"] != before["extraction_sha256"]
    assert after["report_sha256"] != before["report_sha256"]


def test_report_output_bound_is_enforced_with_actual_expansion(bundle):
    document, extraction = bundle[1:]
    dates = document["receipts"][0]["source_records"][0]["dates"]
    for field in dates:
        dates[field] = {"value": "2011", "precision": "YEAR", "source_field": "s" * 8000}
    original = deepcopy(extraction["records"][0])
    extraction["records"] = [{**deepcopy(original), "id": "record:r%d" % index} for index in range(128)]
    assert len(canonical_bytes(document)) < receipts.MAX_FILE_BYTES
    assert len(canonical_bytes(extraction)) < receipts.MAX_FILE_BYTES
    with pytest.raises(CausalFrontierError) as caught:
        _run(bundle)
    assert caught.value.reason_code == "EVIDENCE_FIT_LIMIT_EXCEEDED"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "extra"])
def test_existing_no_follow_source_gates_remain_active(bundle, kind):
    path = bundle[0] / "raw/response.txt"
    if kind == "extra":
        (bundle[0] / "extra.txt").write_text("synthetic extra")
    else:
        outside = bundle[0].parent / "outside.txt"
        path.rename(outside)
        if kind == "symlink":
            path.symlink_to(outside)
        elif kind == "hardlink":
            os.link(outside, path)
        else:
            os.mkfifo(path)
    with pytest.raises(CausalFrontierError):
        _run(bundle)


def test_inputs_and_source_files_are_not_modified_by_api(bundle):
    _run(bundle)
    root, _, extraction = bundle
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    raw = canonical_bytes(extraction) + b"\n"
    saved = bytes(raw)
    fit.audit_evidence_fit(root, extraction["receipt_set_sha256"], raw, sha256_bytes(raw))
    assert raw == saved
    assert {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


def test_normal_and_optimized_python_produce_same_report_bytes(bundle):
    expected = canonical_bytes(_run(bundle))
    root, _, extraction = bundle
    raw = canonical_bytes(extraction) + b"\n"
    code = (
        "import base64,sys; from pathlib import Path; "
        "from causalfrontier.evidence_fit import audit_evidence_fit; "
        "from causalfrontier.canonical import canonical_bytes,sha256_bytes; "
        "raw=base64.b64decode(sys.argv[3]); "
        "sys.stdout.buffer.write(canonical_bytes(audit_evidence_fit(Path(sys.argv[1]),sys.argv[2],raw,sha256_bytes(raw))))"
    )
    args = ["-c", code, str(root), extraction["receipt_set_sha256"], base64.b64encode(raw).decode()]
    assert subprocess.check_output([sys.executable, *args], timeout=30) == expected
    assert subprocess.check_output([sys.executable, "-O", *args], timeout=30) == expected
