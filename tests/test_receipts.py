"""Offline receipt-gate tests; every payload and source record here is synthetic."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier import receipts
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import BOUNDARY, FIXED_PARAMETER, validate_case


def _document(raw: bytes) -> dict:
    unknown = {"value": None, "precision": "UNKNOWN", "source_field": None}
    return {
        "schema_version": receipts.SET_SCHEMA,
        "id": "set:synthetic",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": dict(BOUNDARY),
        "frozen_at": "2026-08-31T16:00:00Z",
        "evidence_cutoff": "2012-12-31T23:59:59Z",
        "selection_origin": "KNOWN_HINDSIGHT",
        "receipts": [
            {
                "schema_version": receipts.RECEIPT_SCHEMA,
                "id": "receipt:synthetic-metadata",
                # Synthetic fixture exercises the declared public-metadata branch.
                "data_class": "PUBLIC_METADATA",
                "authority": "PUBLIC_DATA",
                "raw_response": {"path": "raw/response.txt", "sha256": sha256_bytes(raw)},
                "response_layer": "TOOL_SERIALIZED_RESPONSE",
                "request": {
                    "tool_name": "Synthetic_metadata_fixture",
                    "tool_version": "test-only-1",
                    "submitted_arguments": {"record_id": "synthetic-record", "limit": 1},
                    "executed_query": "synthetic-record",
                    "query_rewrites": [],
                },
                "retrieved_at": "2026-08-31T15:00:00Z",
                "retrieval_state": "COMPLETE",
                "semantic_state": "METADATA_ONLY",
                "declared_scope": "Synthetic metadata fixture; not biomedical decision evidence",
                "coverage": {
                    "scope": "One explicitly named synthetic record, not a literature search",
                    "state": "COMPLETE",
                    "returned_records": 1,
                    "total_records": 1,
                    "pages_received": 1,
                    "next_cursor": None,
                    "truncated": False,
                },
                "source_records": [
                    {
                        "id": "source:synthetic-record",
                        "locator": "https://example.org/synthetic-record",
                        "dates": {field: dict(unknown) for field in receipts.DATE_FIELDS},
                    }
                ],
                "context": {
                    "entity_mappings": ["Synthetic fixture, no biological entity mapping"],
                    "population": None,
                    "comparator": None,
                    "endpoint": None,
                    "model": None,
                    "exposure": None,
                    "duration": None,
                },
                "funding_conflicts": {"state": "NOT_EXTRACTED", "detail": None},
                "license": {"state": "NOT_EXTRACTED", "detail": None},
                "temporal_attestation": {
                    "state": "ABSENT",
                    "artifact": None,
                    "claimed_available_at": None,
                    "locator": None,
                },
            }
        ],
    }


def _seal(root: Path, document: dict) -> str:
    raw = canonical_bytes(document) + b"\n"
    (root / receipts.MANIFEST).write_bytes(raw)
    return sha256_bytes(raw)


@pytest.fixture
def receipt_fixture(tmp_path: Path):
    root = tmp_path.resolve() / "receipts"
    (root / "raw").mkdir(parents=True)
    raw = b'{"fixture":"synthetic metadata only","numeric_response_value":1.5}\n'
    (root / "raw/response.txt").write_bytes(raw)
    document = _document(raw)
    digest = _seal(root, document)
    return root, document, digest


def _run(root: Path, document: dict) -> dict:
    return receipts.preflight_receipts(root, _seal(root, document))


def test_valid_receipts_bind_exact_bytes_but_preserve_hindsight_and_all_nonclaims(receipt_fixture):
    root, document, digest = receipt_fixture
    result = receipts.preflight_receipts(root, digest)
    item = result["receipt_results"][0]
    assert result["receipt_set_sha256"] == digest
    assert result["canonical_receipt_set_sha256"] == sha256_bytes(canonical_bytes(document))
    assert result["selection_origin"] == "KNOWN_HINDSIGHT"
    assert result["historical_scoring"] == "DISABLED"
    assert result["historically_eligible_receipts_n"] == 0
    assert canonical_bytes(result["boundary"]) == canonical_bytes(BOUNDARY)
    assert result["control_trio_status"] == "NOT_EVALUATED_NO_SCORING_PATH"
    assert result["privacy_status"] == "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"
    assert item["outcome_class"] == "NO_CALL"
    assert item["historical_eligible"] is False
    assert item["temporal_state"] == "DECLARED_TEMPORAL_METADATA_UNATTESTED"
    assert item["raw_response_sha256"] == document["receipts"][0]["raw_response"]["sha256"]
    assert item["submitted_arguments_sha256"] == sha256_bytes(
        canonical_bytes(document["receipts"][0]["request"]["submitted_arguments"])
    )


@pytest.mark.parametrize("mutation", ["extra-set-key", "missing-receipt-key", "extra-coverage-key"])
def test_receipt_schema_is_exact_at_each_level(receipt_fixture, mutation):
    root, document, _ = receipt_fixture
    if mutation == "extra-set-key":
        document["historical_scoring_enabled"] = True
    elif mutation == "missing-receipt-key":
        del document["receipts"][0]["funding_conflicts"]
    else:
        document["receipts"][0]["coverage"]["trust_me"] = True
    with pytest.raises(CausalFrontierError, match="schema mismatch"):
        _run(root, document)


@pytest.mark.parametrize("mutation", ["duplicate", "float", "nonfinite"])
def test_receipt_envelope_requires_strict_json(receipt_fixture, mutation):
    root, document, _ = receipt_fixture
    if mutation == "duplicate":
        raw = canonical_bytes(document).replace(b'"id":"set:synthetic"', b'"id":"set:synthetic","id":"set:synthetic"')
    else:
        document["receipts"][0]["request"]["submitted_arguments"]["limit"] = (
            1.5 if mutation == "float" else float("nan")
        )
        raw = json.dumps(document).encode("utf-8")
    (root / receipts.MANIFEST).write_bytes(raw)
    with pytest.raises(CausalFrontierError, match="strict JSON"):
        receipts.preflight_receipts(root, sha256_bytes(raw))


@pytest.mark.parametrize(
    ("field", "value"), [("clinical_authority", 0), ("prospective_benchmark_cases_scored_n", False)]
)
def test_receipt_boundary_rejects_bool_integer_aliases(receipt_fixture, field, value):
    root, document, _ = receipt_fixture
    document["boundary"][field] = value
    with pytest.raises(CausalFrontierError, match="boundary"):
        _run(root, document)


@pytest.mark.parametrize(
    ("field", "value"), [("clinical_authority", 0), ("prospective_benchmark_cases_scored_n", False)]
)
def test_existing_case_boundary_rejects_bool_integer_aliases(mutable_case, field, value):
    mutable_case["boundary"][field] = value
    with pytest.raises(CausalFrontierError, match="boundary"):
        validate_case(mutable_case)


def test_coverage_counts_do_not_accept_booleans(receipt_fixture):
    root, document, _ = receipt_fixture
    document["receipts"][0]["coverage"]["returned_records"] = True
    with pytest.raises(CausalFrontierError, match="integer"):
        _run(root, document)


def test_external_digest_rejects_coherent_substitution_and_rollback(receipt_fixture):
    root, document, original_digest = receipt_fixture
    original_bytes = (root / receipts.MANIFEST).read_bytes()
    original_raw = (root / "raw/response.txt").read_bytes()
    changed_raw = b"Another entirely synthetic metadata response.\n"
    (root / "raw/response.txt").write_bytes(changed_raw)
    document["selection_origin"] = "UNASSESSED"
    document["receipts"][0]["raw_response"]["sha256"] = sha256_bytes(changed_raw)
    successor_digest = _seal(root, document)
    with pytest.raises(CausalFrontierError, match="external receipt-set checkpoint mismatch"):
        receipts.preflight_receipts(root, original_digest)
    (root / receipts.MANIFEST).write_bytes(original_bytes)
    (root / "raw/response.txt").write_bytes(original_raw)
    with pytest.raises(CausalFrontierError, match="external receipt-set checkpoint mismatch"):
        receipts.preflight_receipts(root, successor_digest)


def test_dates_keep_precision_and_unknowns_without_creating_attestation(receipt_fixture):
    root, document, _ = receipt_fixture
    dates = document["receipts"][0]["source_records"][0]["dates"]
    dates["publication_online"] = {"value": "2012", "precision": "YEAR", "source_field": "year"}
    dates["publication_print"] = {"value": "2012-11", "precision": "MONTH", "source_field": "month"}
    dates["index_entry"] = {"value": "2012-11-15", "precision": "DAY", "source_field": "index_date"}
    before = deepcopy(document)
    result = _run(root, document)
    assert document == before
    assert result["receipt_results"][0]["outcome_class"] == "NO_CALL"
    assert "INDEPENDENT_TEMPORAL_ATTESTATION_MISSING" in result["receipt_results"][0]["reason_codes"]


@pytest.mark.parametrize("invalid_date", ["2012-02-30", "2012-13-01"])
def test_impossible_calendar_dates_are_rejected(receipt_fixture, invalid_date):
    root, document, _ = receipt_fixture
    document["receipts"][0]["source_records"][0]["dates"]["publication_online"] = {
        "value": invalid_date,
        "precision": "DAY",
        "source_field": "synthetic_date",
    }
    with pytest.raises(CausalFrontierError, match="real calendar date"):
        _run(root, document)


def test_unknown_date_cannot_contain_an_invented_year(receipt_fixture):
    root, document, _ = receipt_fixture
    document["receipts"][0]["source_records"][0]["dates"]["snapshot_created"]["value"] = "2012"
    with pytest.raises(CausalFrontierError, match="unknown date"):
        _run(root, document)


def test_date_precision_cannot_be_silently_invented(receipt_fixture):
    root, document, _ = receipt_fixture
    document["receipts"][0]["source_records"][0]["dates"]["publication_online"] = {
        "value": "2012",
        "precision": "DAY",
        "source_field": "synthetic_year_only",
    }
    with pytest.raises(CausalFrontierError, match="precision"):
        _run(root, document)


def test_hashed_self_declared_attestation_never_admits_a_receipt(receipt_fixture):
    root, document, _ = receipt_fixture
    raw = b"Synthetic self-declared archive claim; not an independent attestation.\n"
    (root / "raw/claim.txt").write_bytes(raw)
    document["receipts"][0]["temporal_attestation"] = {
        "state": "UNVERIFIED_CLAIM",
        "artifact": {"path": "raw/claim.txt", "sha256": sha256_bytes(raw)},
        "claimed_available_at": "2012-01-01T00:00:00Z",
        "locator": "https://example.org/synthetic-archive-claim",
    }
    item = _run(root, document)["receipt_results"][0]
    assert item["outcome_class"] == "NO_CALL"
    assert item["historical_eligible"] is False
    assert "TEMPORAL_ATTESTATION_VERIFIER_NOT_IMPLEMENTED" in item["reason_codes"]


@pytest.mark.parametrize(
    ("retrieval_state", "outcome_class"),
    [("FAILED", "FAILURE"), ("TIMEOUT", "FAILURE"), ("PARTIAL", "NO_CALL"), ("NOT_RUN", "NO_CALL")],
)
def test_acquisition_failure_and_semantic_no_call_remain_distinct(receipt_fixture, retrieval_state, outcome_class):
    root, document, _ = receipt_fixture
    item = document["receipts"][0]
    item["retrieval_state"] = retrieval_state
    item["semantic_state"] = "UNUSABLE"
    item["coverage"].update(state="UNKNOWN", returned_records=0, total_records=None, pages_received=0, next_cursor=None)
    result = _run(root, document)["receipt_results"][0]
    assert result["outcome_class"] == outcome_class
    assert result["historical_eligible"] is False
    assert ("ACQUISITION_FAILURE_NOT_EVIDENCE_ABSENCE" in result["reason_codes"]) == (outcome_class == "FAILURE")


def test_transport_success_with_missing_semantics_is_no_call(receipt_fixture):
    root, document, _ = receipt_fixture
    item = document["receipts"][0]
    item["semantic_state"] = "UNUSABLE"
    item["request"].update(executed_query=None, query_rewrites=None)
    result = _run(root, document)["receipt_results"][0]
    assert result["outcome_class"] == "NO_CALL"
    assert "NOT_PUBLIC_DECISION_EVIDENCE" in result["reason_codes"]
    assert "EXECUTED_QUERY_OR_REWRITES_UNREPORTED" in result["reason_codes"]


def test_complete_coverage_cannot_hide_pagination(receipt_fixture):
    root, document, _ = receipt_fixture
    document["receipts"][0]["coverage"]["next_cursor"] = "synthetic-next-page"
    with pytest.raises(CausalFrontierError, match="pagination"):
        _run(root, document)


@pytest.mark.parametrize("unsafe_path", ["../response.txt", "/response.txt", "raw//response.txt"])
def test_unsafe_payload_paths_are_rejected(receipt_fixture, unsafe_path):
    root, document, _ = receipt_fixture
    document["receipts"][0]["raw_response"]["path"] = unsafe_path
    with pytest.raises(CausalFrontierError):
        _run(root, document)


@pytest.mark.parametrize("unsafe_kind", ["leaf-symlink", "root-symlink", "ancestor-symlink", "hardlink", "fifo"])
def test_unsafe_filesystem_objects_are_rejected_without_following_or_blocking(receipt_fixture, unsafe_kind):
    root, _, digest = receipt_fixture
    payload = root / "raw/response.txt"
    target = root
    if unsafe_kind == "leaf-symlink":
        external = root.parent / "external-synthetic.txt"
        external.write_bytes(payload.read_bytes())
        payload.unlink()
        payload.symlink_to(external)
    elif unsafe_kind == "root-symlink":
        target = root.parent / "linked-root"
        target.symlink_to(root, target_is_directory=True)
    elif unsafe_kind == "ancestor-symlink":
        ancestor = root.parent / "linked-parent"
        ancestor.symlink_to(root.parent, target_is_directory=True)
        target = ancestor / root.name
    elif unsafe_kind == "hardlink":
        os.link(payload, root.parent / "external-synthetic-hardlink.txt")
    else:
        payload.unlink()
        os.mkfifo(payload)
    with pytest.raises(CausalFrontierError):
        receipts.preflight_receipts(target, digest)


def test_unmanifested_file_is_not_ignored(receipt_fixture):
    root, _, digest = receipt_fixture
    (root / "raw/unmanifested.txt").write_text("Synthetic surplus file.\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="inventory"):
        receipts.preflight_receipts(root, digest)


@pytest.mark.parametrize("payload_kind", ["patient-field", "credential"])
def test_prohibited_payload_is_rejected_without_echoing_its_value(receipt_fixture, payload_kind):
    root, document, _ = receipt_fixture
    marker = "synthetic-sensitive-marker-12345678"
    raw = (
        json.dumps({"patient_id": marker}).encode()
        if payload_kind == "patient-field"
        else ("ghp" + "_" + marker).encode()
    )
    (root / "raw/response.txt").write_bytes(raw)
    document["receipts"][0]["raw_response"]["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError) as error:
        _run(root, document)
    assert marker not in str(error.value)


def test_escaped_private_submitted_argument_is_rejected_after_json_decoding(receipt_fixture):
    root, document, _ = receipt_fixture
    marker = "synthetic-credential-marker-12345678"
    credential = "ghp" + "_" + marker
    document["receipts"][0]["request"]["submitted_arguments"]["query"] = credential
    raw = canonical_bytes(document).replace(credential.encode(), b"\\u0067" + credential[1:].encode())
    (root / receipts.MANIFEST).write_bytes(raw)
    with pytest.raises(CausalFrontierError) as error:
        receipts.preflight_receipts(root, sha256_bytes(raw))
    assert marker not in str(error.value)


def test_malformed_locator_has_a_redacted_api_and_cli_error(receipt_fixture, capsys):
    root, document, _ = receipt_fixture
    marker = "synthetic-sensitive-marker"
    document["receipts"][0]["source_records"][0]["locator"] = f"https://example.org:{marker}/record"
    digest = _seal(root, document)
    with pytest.raises(CausalFrontierError) as error:
        receipts.preflight_receipts(root, digest)
    assert marker not in str(error.value)
    assert main(["preflight-receipts", str(root), "--expected-set-sha256", digest]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert marker not in captured.err


def test_size_limits_fail_closed_for_payload_and_combined_inventory(receipt_fixture, monkeypatch):
    root, document, digest = receipt_fixture
    total = sum(item.stat().st_size for item in root.rglob("*") if item.is_file())
    monkeypatch.setattr(receipts, "MAX_TOTAL_BYTES", total - 1)
    with pytest.raises(CausalFrontierError, match="total byte limit"):
        receipts.preflight_receipts(root, digest)
    monkeypatch.setattr(receipts, "MAX_TOTAL_BYTES", 16 * 1024 * 1024)
    raw = b"x" * (receipts.MAX_FILE_BYTES + 1)
    (root / "raw/response.txt").write_bytes(raw)
    document["receipts"][0]["raw_response"]["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="bounded single-link regular file"):
        _run(root, document)


def test_raw_source_mutation_invalidates_the_frozen_digest(receipt_fixture):
    root, _, digest = receipt_fixture
    (root / "raw/response.txt").write_bytes(b"Mutated synthetic bytes.\n")
    with pytest.raises(CausalFrontierError, match="payload digest mismatch"):
        receipts.preflight_receipts(root, digest)


def test_payload_mutation_during_snapshot_is_rejected(receipt_fixture, monkeypatch):
    root, _, digest = receipt_fixture
    payload = root / "raw/response.txt"
    identity = payload.stat().st_ino
    real_read = os.read
    changed = False

    def mutate_after_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        raw = real_read(descriptor, count)
        if not changed and os.fstat(descriptor).st_ino == identity:
            changed = True
            payload.write_bytes(b"Mutated during synthetic snapshot.\n")
        return raw

    monkeypatch.setattr(receipts.os, "read", mutate_after_read)
    with pytest.raises(CausalFrontierError, match="changed while being read"):
        receipts.preflight_receipts(root, digest)
    assert changed


def test_preflight_performs_no_writes_network_or_source_execution(receipt_fixture, monkeypatch):
    root, _, digest = receipt_fixture
    before = {item.relative_to(root).as_posix(): item.read_bytes() for item in root.rglob("*") if item.is_file()}
    real_open = os.open

    def guarded_open(file, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return real_open(file, flags, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("receipt preflight attempted a write, network request, or execution")

    monkeypatch.setattr(os, "open", guarded_open)
    for name in ("write", "unlink", "rename", "mkdir", "system"):
        monkeypatch.setattr(os, name, forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    result = receipts.preflight_receipts(root, digest)
    after = {item.relative_to(root).as_posix(): item.read_bytes() for item in root.rglob("*") if item.is_file()}
    assert before == after
    assert result["historical_scoring"] == "DISABLED"


def test_cli_receipt_abstention_is_exit_three_and_invalid_checkpoint_is_exit_two(receipt_fixture, capsys):
    root, _, digest = receipt_fixture
    arguments = ["preflight-receipts", str(root), "--expected-set-sha256"]
    assert main([*arguments, digest]) == 3
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["historical_scoring"] == "DISABLED"
    assert main([*arguments, "0" * 64]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "external receipt-set checkpoint mismatch" in captured.err
