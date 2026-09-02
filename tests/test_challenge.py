"""Synthetic-only hostile tests for the scientific-decision challenge preflight."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier import challenge, model, receipts
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _write_artifact(root: Path, path: str, value: object) -> tuple[bytes, str]:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = (canonical_bytes(value) + b"\n") if not isinstance(value, bytes) else value
    target.write_bytes(raw)
    return raw, sha256_bytes(raw)


def _receipt_document(raw: bytes, raw_case: dict, origin: str, case_index: int) -> dict:
    unknown = {"value": None, "precision": "UNKNOWN", "source_field": None}
    return {
        "schema_version": receipts.SET_SCHEMA,
        "id": "set:synthetic-%d" % case_index,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "frozen_at": raw_case["frozen_at"],
        "evidence_cutoff": raw_case["evidence_cutoff"],
        "selection_origin": origin,
        "receipts": [
            {
                "schema_version": receipts.RECEIPT_SCHEMA,
                "id": "receipt:synthetic-%d" % case_index,
                "data_class": "SYNTHETIC",
                "authority": "SYNTHETIC_DATA",
                "raw_response": {"path": "raw/response.txt", "sha256": sha256_bytes(raw)},
                "response_layer": "SYNTHETIC_TEXT",
                "request": {
                    "tool_name": "Synthetic_challenge_fixture",
                    "tool_version": "test-only-1",
                    "submitted_arguments": {"case_index": case_index},
                    "executed_query": "synthetic-case-%d" % case_index,
                    "query_rewrites": [],
                },
                "retrieved_at": raw_case["provenance"][0]["retrieved_at"],
                "retrieval_state": "COMPLETE",
                "semantic_state": "SYNTHETIC_FIXTURE_ONLY",
                "declared_scope": "Synthetic challenge fixture with no biomedical meaning",
                "coverage": {
                    "scope": "One synthetic record",
                    "state": "COMPLETE",
                    "returned_records": 1,
                    "total_records": 1,
                    "pages_received": 1,
                    "next_cursor": None,
                    "truncated": False,
                },
                "source_records": [
                    {
                        "id": "source:synthetic-receipt-%d" % case_index,
                        "locator": "https://example.org/synthetic-case-%d" % case_index,
                        "dates": {field: dict(unknown) for field in receipts.DATE_FIELDS},
                    }
                ],
                "context": {
                    "entity_mappings": ["Synthetic fixture; no biological entity mapping"],
                    "population": None,
                    "comparator": None,
                    "endpoint": None,
                    "model": None,
                    "exposure": None,
                    "duration": None,
                },
                "funding_conflicts": {"state": "SYNTHETIC", "detail": "Synthetic fixture"},
                "license": {"state": "SYNTHETIC", "detail": "CC0 synthetic fixture"},
                "temporal_attestation": {
                    "state": "ABSENT",
                    "artifact": None,
                    "claimed_available_at": None,
                    "locator": None,
                },
            }
        ],
    }


def _add_receipt_bundle(
    root: Path,
    artifacts: list[dict],
    raw_case: dict,
    source_root: Path,
    origin: str,
    case_index: int,
) -> tuple[str, str]:
    prefix = "receipts/%d/bundle" % case_index
    # Receipt v1 binds the exact dossier source bytes. Derivations are deferred
    # until a separately specified transform contract exists.
    raw_response = (source_root / raw_case["provenance"][0]["path"]).read_bytes()
    _write_artifact(root, "%s/raw/response.txt" % prefix, raw_response)
    receipt_document = _receipt_document(raw_response, raw_case, origin, case_index)
    _, receipt_set_digest = _write_artifact(root, "%s/%s" % (prefix, receipts.MANIFEST), receipt_document)
    report = receipts.preflight_receipts(root / prefix, receipt_set_digest)
    report_path = "receipts/%d/preflight.json" % case_index
    _, report_digest = _write_artifact(root, report_path, report)
    report_id = "artifact:receipt-preflight-%d" % case_index
    artifacts.append(
        {
            "id": report_id,
            "path": report_path,
            "sha256": report_digest,
            "role": "RECEIPT_PREFLIGHT",
            "media_type": "application/json",
        }
    )
    for file_index, (relative, digest) in enumerate(sorted(report["files_sha256"].items())):
        artifacts.append(
            {
                "id": "artifact:receipt-file-%d-%d" % (case_index, file_index),
                "path": "%s/%s" % (prefix, relative),
                "sha256": digest,
                "role": "RECEIPT_SET_FILE",
                "media_type": "application/json" if relative.endswith(".json") else "text/plain",
            }
        )
    return report_id, prefix


def _baseline_spec(baseline_id: str, family: str) -> dict:
    return {
        "schema_version": challenge.BASELINE_SCHEMA_VERSION,
        "id": baseline_id,
        "family": family,
        "version": "synthetic-spec-1",
        "case_scope": "ALL_CHALLENGE_CASES",
        "input_contract": "FROZEN_CASE_AND_RECEIPT_BUNDLE",
        "output_contract": "DECISION_STATE_TRANSITION_AND_AUDITED_RESOURCE_LEDGER",
        "strategy_description": "Synthetic-only unexecuted baseline specification",
        "stopping_rule": "Stop only under the synthetic declared fixture rule",
        "budget_rule": "SAME_PREDECLARED_CASE_SPECIFIC_BUDGET_AS_ENTRANTS",
        "resource_accounting": "FULLY_LOADED_AUDIT_REQUIRED_BEFORE_EXECUTION",
        "execution_state": "SPECIFICATION_ONLY_NOT_EXECUTED",
        "implementation_sha256": None,
        "entrypoint": None,
    }


def _build(
    root: Path,
    raw_case: dict,
    source_root: Path,
    *,
    scope: str = "SYNTHETIC_PROTOCOL_TEST",
    balanced_six_case_cohort: bool = False,
) -> tuple[dict, str]:
    root.mkdir()
    artifacts: list[dict] = []
    cases = []
    encodings = []
    if balanced_six_case_cohort:
        # Balanced incomplete control-by-domain design. Every control occurs
        # twice, every domain occurs twice, and no domain/control cell repeats.
        controls = [
            "POSITIVE",
            "FAILED_TRANSLATION",
            "FAILED_TRANSLATION",
            "AMBIGUOUS",
            "AMBIGUOUS",
            "POSITIVE",
        ]
        domains = [
            "synthetic-domain-a",
            "synthetic-domain-a",
            "synthetic-domain-b",
            "synthetic-domain-b",
            "synthetic-domain-c",
            "synthetic-domain-c",
        ]
    else:
        controls = ["POSITIVE", "FAILED_TRANSLATION", "AMBIGUOUS"]
        domains = ["synthetic-genetics", "synthetic-perturbation", "synthetic-safety"]
    origins = ["SYNTHETIC_FIXTURE"] * len(controls)
    if scope == "HISTORICAL_REPLAY_DRAFT":
        origins = ["KNOWN_HINDSIGHT", "UNASSESSED", "UNASSESSED"]
    encoders = [
        {
            "id": "encoder:alpha",
            "organization_id": "organization:alpha",
            "independence_state": "SELF_DECLARED_UNVERIFIED",
        },
        {
            "id": "encoder:beta",
            "organization_id": "organization:beta",
            "independence_state": "SELF_DECLARED_UNVERIFIED",
        },
    ]
    for case_index, (control, domain, origin) in enumerate(zip(controls, domains, origins, strict=True)):
        suffix = "-%d" % case_index if balanced_six_case_cohort else ""
        case_id = "case:%s%s" % (control.lower().replace("_", "-"), suffix)
        report_id, bundle_path = _add_receipt_bundle(root, artifacts, raw_case, source_root, origin, case_index)
        cases.append(
            {
                "id": case_id,
                "control_class": control,
                "domain": domain,
                "evidence_cutoff": raw_case["evidence_cutoff"],
                "receipt_preflight_artifact_id": report_id,
                "receipt_bundle_path": bundle_path,
                "selection_origin": origin,
            }
        )
        for encoder_index, encoder in enumerate(encoders):
            document = deepcopy(raw_case)
            document["case_id"] = case_id
            document["title"] = "Synthetic challenge %d encoding %d" % (case_index, encoder_index)
            document["purpose"] = "Synthetic protocol exercise encoding %d" % encoder_index
            document["nonclaims"][0] = "Synthetic encoding %d has no scientific meaning" % encoder_index
            case_prefix = "cases/%d-%d" % (case_index, encoder_index)
            case_path = "%s/case.json" % case_prefix
            _, case_digest = _write_artifact(root, case_path, document)
            artifact_id = "artifact:case-%d-%d" % (case_index, encoder_index)
            artifacts.append(
                {
                    "id": artifact_id,
                    "path": case_path,
                    "sha256": case_digest,
                    "role": "FROZEN_CASE",
                    "media_type": "application/json",
                }
            )
            for source_index, source in enumerate(document["provenance"]):
                source_bytes = (source_root / source["path"]).read_bytes()
                if sha256_bytes(source_bytes) != source["sha256"]:
                    raise RuntimeError("synthetic fixture source digest changed")
                source_path = "%s/%s" % (case_prefix, source["path"])
                _, source_digest = _write_artifact(root, source_path, source_bytes)
                artifacts.append(
                    {
                        "id": "artifact:case-source-%d-%d-%d" % (case_index, encoder_index, source_index),
                        "path": source_path,
                        "sha256": source_digest,
                        "role": "FROZEN_CASE_SOURCE",
                        "media_type": "text/tab-separated-values",
                    }
                )
            encodings.append(
                {
                    "id": "encoding:%d-%d" % (case_index, encoder_index),
                    "case_id": case_id,
                    "encoder_id": encoder["id"],
                    "frozen_case_artifact_id": artifact_id,
                }
            )
    baselines = []
    for index, family in enumerate(sorted(challenge.BASELINE_FAMILIES)):
        baseline_id = "baseline:%d" % index
        path = "baselines/%d.json" % index
        _, digest = _write_artifact(root, path, _baseline_spec(baseline_id, family))
        artifact_id = "artifact:baseline-%d" % index
        artifacts.append(
            {
                "id": artifact_id,
                "path": path,
                "sha256": digest,
                "role": "BASELINE_SPECIFICATION",
                "media_type": "application/json",
            }
        )
        baselines.append({"id": baseline_id, "family": family, "artifact_id": artifact_id})
    reveal = canonical_bytes({"challenge_id": "challenge:synthetic", "outcome": "synthetic-hidden"})
    reveal_nonce = b"0" * 32
    if len(reveal_nonce) != 32:
        raise RuntimeError("synthetic reveal nonce size changed")
    document = {
        "schema_version": challenge.SCHEMA_VERSION,
        "id": "challenge:synthetic",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "sequence": 1,
        "predecessor_manifest_sha256": challenge.GENESIS,
        "frozen_at": raw_case["frozen_at"],
        "scope": scope,
        "metric_contract": challenge.fixed_metric_contract(),
        "reveal_commitment_sha256": sha256_bytes(b"causalfrontier.reveal.v1\0" + reveal + b"\0" + reveal_nonce),
        "reveal_commitment_scheme": challenge.REVEAL_COMMITMENT_SCHEME,
        "artifacts": artifacts,
        "cases": cases,
        "encoders": encoders,
        "encodings": encodings,
        "baselines": baselines,
    }
    raw = canonical_bytes(document) + b"\n"
    (root / challenge.MANIFEST).write_bytes(raw)
    return document, sha256_bytes(raw)


@pytest.fixture
def challenge_fixture(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "challenge"
    document, digest = _build(root, raw_case, case_root)
    return root, document, digest


def _reseal(root: Path, document: dict) -> str:
    raw = canonical_bytes(document) + b"\n"
    (root / challenge.MANIFEST).write_bytes(raw)
    return sha256_bytes(raw)


def _artifact(document: dict, artifact_id: str) -> dict:
    return next(item for item in document["artifacts"] if item["id"] == artifact_id)


def _rewrite_json_artifact(root: Path, artifact: dict, value: object) -> None:
    raw = canonical_bytes(value) + b"\n"
    (root / artifact["path"]).write_bytes(raw)
    artifact["sha256"] = sha256_bytes(raw)


def _remove_artifact(root: Path, document: dict, artifact_id: str) -> None:
    artifact = _artifact(document, artifact_id)
    (root / artifact["path"]).unlink()
    document["artifacts"].remove(artifact)


def _refresh_receipt_report(root: Path, document: dict, case_index: int) -> None:
    case = document["cases"][case_index]
    prefix = case["receipt_bundle_path"]
    set_path = "%s/%s" % (prefix, receipts.MANIFEST)
    set_artifact = next(item for item in document["artifacts"] if item["path"] == set_path)
    set_digest = sha256_bytes((root / set_path).read_bytes())
    set_artifact["sha256"] = set_digest
    report = receipts.preflight_receipts(root / prefix, set_digest)
    report_artifact = _artifact(document, case["receipt_preflight_artifact_id"])
    _rewrite_json_artifact(root, report_artifact, report)


def _run(root: Path, digest: str) -> dict:
    return challenge.preflight_challenge(root, digest, 1)


def test_valid_synthetic_challenge_replays_bytes_but_scoring_stays_disabled(challenge_fixture):
    root, _, digest = challenge_fixture
    result = _run(root, digest)
    gates = {gate["id"]: gate for gate in result["gates"]}
    assert result["status"] == "STRUCTURALLY_BOUND_AND_REPLAYED_SCIENTIFIC_SCORING_DISABLED"
    assert result["protocol_exercise_ready"] is True
    assert result["scientific_scoring_ready"] is False
    assert result["challenge_sequence"] == 1
    assert result["cases_n"] == 3
    assert result["encodings_n"] == 6
    assert result["control_classes"] == ["AMBIGUOUS", "FAILED_TRANSLATION", "POSITIVE"]
    assert len(result["domains"]) == 3
    assert len(result["required_baseline_families"]) == len(challenge.BASELINE_FAMILIES) == 15
    assert gates["domain_diversity"]["status"] == "NO_CALL"
    assert gates["temporal_leakage"]["status"] == "NO_CALL"
    assert gates["receipt_replay"]["status"] == "PASS"
    assert gates["rollback"]["status"] == "NO_CALL"
    assert gates["scientific_scoring"]["status"] == "NO_CALL"
    assert result["known_hindsight_cases_n"] == 0
    assert all(len(digests) == 2 for digests in result["case_encoding_sha256"].values())
    assert len(set(result["case_receipt_set_sha256"].values())) == 3
    assert len(result["nonclaims"]) >= 8


def test_historical_hindsight_is_retained_as_a_blocker(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "historical"
    _, digest = _build(root, raw_case, case_root, scope="HISTORICAL_REPLAY_DRAFT")
    result = _run(root, digest)
    gate = next(item for item in result["gates"] if item["id"] == "historical_blinding")
    assert result["known_hindsight_cases_n"] == 1
    assert gate == {"id": "historical_blinding", "status": "NO_CALL", "reason": "KNOWN_HINDSIGHT_CASES_PRESENT"}


def test_external_checkpoint_rejects_coherent_substitution(challenge_fixture):
    root, document, original_digest = challenge_fixture
    original = (root / challenge.MANIFEST).read_bytes()
    document["reveal_commitment_sha256"] = "9" * 64
    successor_digest = _reseal(root, document)
    with pytest.raises(CausalFrontierError, match="external challenge checkpoint mismatch"):
        _run(root, original_digest)
    (root / challenge.MANIFEST).write_bytes(original)
    with pytest.raises(CausalFrontierError, match="external challenge checkpoint mismatch"):
        _run(root, successor_digest)


def test_external_sequence_and_predecessor_are_structurally_checked(challenge_fixture):
    root, document, digest = challenge_fixture
    with pytest.raises(CausalFrontierError, match="external challenge sequence mismatch"):
        challenge.preflight_challenge(root, digest, 2)
    document["sequence"] = 2
    with pytest.raises(CausalFrontierError, match="predecessor lineage is discontinuous"):
        challenge.preflight_challenge(root, _reseal(root, document), 2)


def test_missing_control_trio_fails_closed(challenge_fixture):
    root, document, _ = challenge_fixture
    document["cases"][2]["control_class"] = "POSITIVE"
    with pytest.raises(CausalFrontierError, match="requires positive"):
        _run(root, _reseal(root, document))


def test_missing_required_baseline_fails_closed(challenge_fixture):
    root, document, _ = challenge_fixture
    removed = document["baselines"].pop()
    _remove_artifact(root, document, removed["artifact_id"])
    with pytest.raises(CausalFrontierError, match="baselines"):
        _run(root, _reseal(root, document))


def test_two_encoders_from_one_organization_fail_closed(challenge_fixture):
    root, document, _ = challenge_fixture
    document["encoders"][1]["organization_id"] = document["encoders"][0]["organization_id"]
    with pytest.raises(CausalFrontierError, match="two organizations"):
        _run(root, _reseal(root, document))


@pytest.mark.parametrize("mutation", ["float", "nan", "duplicate"])
def test_manifest_requires_strict_json(challenge_fixture, mutation):
    root, document, _ = challenge_fixture
    if mutation == "duplicate":
        raw = canonical_bytes(document).replace(b'{"artifacts":', b'{"id":"challenge:duplicate","artifacts":', 1)
    else:
        document["metric_contract"]["success_threshold_numerator"] = 1.5 if mutation == "float" else float("nan")
        raw = json.dumps(document).encode("utf-8")
    (root / challenge.MANIFEST).write_bytes(raw)
    with pytest.raises(CausalFrontierError):
        challenge.preflight_challenge(root, sha256_bytes(raw), 1)


@pytest.mark.parametrize(
    ("field", "value"), [("clinical_authority", 0), ("prospective_benchmark_cases_scored_n", False)]
)
def test_boundary_rejects_bool_integer_aliases(challenge_fixture, field, value):
    root, document, _ = challenge_fixture
    document["boundary"][field] = value
    with pytest.raises(CausalFrontierError, match="boundary"):
        _run(root, _reseal(root, document))


def test_mutated_artifact_is_detected(challenge_fixture):
    root, _, digest = challenge_fixture
    (root / "baselines/0.json").write_text('{"synthetic_fixture":false}\n', encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="digest mismatch"):
        _run(root, digest)


def test_unmanifested_file_is_rejected(challenge_fixture):
    root, _, digest = challenge_fixture
    (root / "surplus.txt").write_text("synthetic surplus\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="inventory"):
        _run(root, digest)


def test_private_or_patient_material_is_rejected_without_echo(challenge_fixture):
    root, document, _ = challenge_fixture
    marker = "synthetic-sensitive-marker-12345678"
    artifact = next(item for item in document["artifacts"] if item["role"] == "BASELINE_SPECIFICATION")
    raw = json.dumps({"patient_id": marker}).encode()
    (root / artifact["path"]).write_bytes(raw)
    artifact["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError) as error:
        _run(root, _reseal(root, document))
    assert marker not in str(error.value)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_artifacts_are_rejected_without_following_or_blocking(challenge_fixture, unsafe_kind):
    root, document, digest = challenge_fixture
    artifact = next(item for item in document["artifacts"] if item["role"] == "BASELINE_SPECIFICATION")
    target = root / artifact["path"]
    if unsafe_kind == "symlink":
        external = root.parent / "external.txt"
        external.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(external)
    elif unsafe_kind == "hardlink":
        os.link(target, root.parent / "external-hardlink.txt")
    else:
        target.unlink()
        os.mkfifo(target)
    with pytest.raises(CausalFrontierError):
        _run(root, digest)


def test_case_with_posthoc_outcome_leakage_is_rejected(challenge_fixture):
    root, document, _ = challenge_fixture
    artifact = _artifact(document, document["encodings"][0]["frozen_case_artifact_id"])
    case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    case["observed_outcome"] = "synthetic-posthoc-value"
    _rewrite_json_artifact(root, artifact, case)
    with pytest.raises(CausalFrontierError, match="observed_outcome"):
        _run(root, _reseal(root, document))


def test_synthetic_scope_cannot_smuggle_historical_origin(challenge_fixture):
    root, document, _ = challenge_fixture
    document["cases"][0]["selection_origin"] = "KNOWN_HINDSIGHT"
    with pytest.raises(CausalFrontierError, match="synthetic challenge"):
        _run(root, _reseal(root, document))


def test_unreferenced_artifact_is_rejected(challenge_fixture):
    root, document, _ = challenge_fixture
    raw, digest = _write_artifact(root, "extra.json", {"synthetic": True})
    if not raw:
        raise RuntimeError("synthetic artifact unexpectedly empty")
    document["artifacts"].append(
        {
            "id": "artifact:extra",
            "path": "extra.json",
            "sha256": digest,
            "role": "BASELINE_SPECIFICATION",
            "media_type": "application/json",
        }
    )
    with pytest.raises(CausalFrontierError, match="unreferenced"):
        _run(root, _reseal(root, document))


def test_single_domain_protocol_is_structural_only(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "single-domain"
    document, _ = _build(root, raw_case, case_root)
    for case in document["cases"]:
        case["domain"] = "synthetic-one-domain"
    result = _run(root, _reseal(root, document))
    gate = next(item for item in result["gates"] if item["id"] == "domain_diversity")
    assert gate["status"] == "NO_CALL"
    assert result["scientific_scoring_ready"] is False


def test_removing_last_frozen_source_rejects_empty_inventory_directory(challenge_fixture):
    root, document, _ = challenge_fixture
    source = next(item for item in document["artifacts"] if item["role"] == "FROZEN_CASE_SOURCE")
    _remove_artifact(root, document, source["id"])
    with pytest.raises(CausalFrontierError, match="empty directory"):
        _run(root, _reseal(root, document))


def test_forged_receipt_preflight_is_rejected_by_replay(challenge_fixture):
    root, document, _ = challenge_fixture
    artifact = next(item for item in document["artifacts"] if item["role"] == "RECEIPT_PREFLIGHT")
    report = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    report["canonical_receipt_set_sha256"] = "9" * 64
    _rewrite_json_artifact(root, artifact, report)
    with pytest.raises(CausalFrontierError, match="not reproducible"):
        _run(root, _reseal(root, document))


def test_untyped_receipt_reason_code_fails_closed_without_type_error(challenge_fixture, capsys):
    root, document, _ = challenge_fixture
    artifact = next(item for item in document["artifacts"] if item["role"] == "RECEIPT_PREFLIGHT")
    report = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    report["receipt_results"][0]["reason_codes"] = [{}]
    _rewrite_json_artifact(root, artifact, report)
    digest = _reseal(root, document)
    with pytest.raises(CausalFrontierError, match="receipt reason code"):
        _run(root, digest)
    assert (
        main(
            [
                "preflight-challenge",
                str(root),
                "--expected-manifest-sha256",
                digest,
                "--expected-sequence",
                "1",
            ]
        )
        == 2
    )
    assert "receipt reason code" in capsys.readouterr().err


def test_receipt_and_dossier_acquisition_semantics_cannot_conflict(challenge_fixture):
    root, document, _ = challenge_fixture
    case = document["cases"][0]
    receipt_set_path = "%s/%s" % (case["receipt_bundle_path"], receipts.MANIFEST)
    receipt_set_artifact = next(item for item in document["artifacts"] if item["path"] == receipt_set_path)
    receipt_set = json.loads((root / receipt_set_path).read_text(encoding="utf-8"))
    item = receipt_set["receipts"][0]
    item["retrieval_state"] = "FAILED"
    item["semantic_state"] = "UNUSABLE"
    item["coverage"].update(
        state="UNKNOWN",
        returned_records=0,
        total_records=None,
        pages_received=0,
        next_cursor=None,
        truncated=False,
    )
    _rewrite_json_artifact(root, receipt_set_artifact, receipt_set)
    _refresh_receipt_report(root, document, 0)
    with pytest.raises(CausalFrontierError, match="acquisition semantics differ"):
        _run(root, _reseal(root, document))


def test_unrelated_valid_receipt_and_case_capsules_are_rejected(challenge_fixture):
    root, document, _ = challenge_fixture
    case = document["cases"][0]
    prefix = case["receipt_bundle_path"]
    raw_path = "%s/raw/response.txt" % prefix
    raw_artifact = next(item for item in document["artifacts"] if item["path"] == raw_path)
    unrelated = b"valid synthetic receipt bytes unrelated to the frozen dossier\n"
    (root / raw_path).write_bytes(unrelated)
    raw_artifact["sha256"] = sha256_bytes(unrelated)
    set_path = "%s/%s" % (prefix, receipts.MANIFEST)
    receipt_set = json.loads((root / set_path).read_text(encoding="utf-8"))
    receipt_set["receipts"][0]["raw_response"]["sha256"] = sha256_bytes(unrelated)
    set_artifact = next(item for item in document["artifacts"] if item["path"] == set_path)
    _rewrite_json_artifact(root, set_artifact, receipt_set)
    _refresh_receipt_report(root, document, 0)
    with pytest.raises(CausalFrontierError, match="not directly bound to replayed receipt bytes"):
        _run(root, _reseal(root, document))


def test_receipt_bundle_frozen_after_challenge_lock_is_rejected(challenge_fixture):
    root, document, _ = challenge_fixture
    prefix = document["cases"][0]["receipt_bundle_path"]
    set_path = "%s/%s" % (prefix, receipts.MANIFEST)
    set_artifact = next(item for item in document["artifacts"] if item["path"] == set_path)
    receipt_set = json.loads((root / set_path).read_text(encoding="utf-8"))
    receipt_set["frozen_at"] = "2026-08-29T21:00:00Z"
    _rewrite_json_artifact(root, set_artifact, receipt_set)
    _refresh_receipt_report(root, document, 0)
    with pytest.raises(CausalFrontierError, match="frozen after the challenge lock"):
        _run(root, _reseal(root, document))


def test_public_provenance_cannot_be_relabelled_as_synthetic_scope(challenge_fixture):
    root, document, _ = challenge_fixture
    artifact = _artifact(document, document["encodings"][0]["frozen_case_artifact_id"])
    case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    case["provenance"][0]["data_class"] = "PUBLIC_AGGREGATE"
    case["provenance"][0]["authority"] = "PUBLIC_DATA"
    case["provenance"][0]["semantic_state"] = "USABLE_FOR_DECLARED_SCOPE"
    case["provenance"][0]["temporal_basis"] = "DATASET_SNAPSHOT_DATE"
    for gate in case["gates"]:
        if gate["authority"] == "SYNTHETIC_DATA":
            gate["authority"] = "PUBLIC_DATA"
    for experiment in case["experiments"]:
        experiment["required_authorities"] = [
            "PUBLIC_DATA" if authority == "SYNTHETIC_DATA" else authority
            for authority in experiment["required_authorities"]
        ]
    _rewrite_json_artifact(root, artifact, case)
    with pytest.raises(CausalFrontierError, match="frozen case is not synthetic-only"):
        _run(root, _reseal(root, document))


def test_encodings_must_share_one_decision_and_evidence_dossier(challenge_fixture):
    root, document, _ = challenge_fixture
    artifact = _artifact(document, document["encodings"][1]["frozen_case_artifact_id"])
    case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    case["decision"]["question"] = "A different synthetic scientific decision entirely?"
    _rewrite_json_artifact(root, artifact, case)
    with pytest.raises(CausalFrontierError, match="do not share one evidence and decision dossier"):
        _run(root, _reseal(root, document))


def test_action_contract_drift_disables_protocol_execution_without_claiming_agreement(challenge_fixture):
    root, document, _ = challenge_fixture
    encoding = document["encodings"][0]
    artifact = _artifact(document, encoding["frozen_case_artifact_id"])
    frozen_case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    frozen_case["experiments"][0]["resources"]["duration_minutes"] += 1
    _rewrite_json_artifact(root, artifact, frozen_case)
    result = _run(root, _reseal(root, document))
    gates = {gate["id"]: gate for gate in result["gates"]}
    assert result["protocol_exercise_ready"] is False
    assert gates["execution_alignment"] == {
        "id": "execution_alignment",
        "status": "NO_CALL",
        "reason": "ENCODER_ACTION_OR_MEASUREMENT_CONTRACTS_DIFFER",
    }
    assert gates["encoding_agreement"]["status"] == "NO_CALL"
    assert "case:positive" not in result["case_shared_action_input_sha256"]


def test_encoder_specific_prediction_relations_remain_separate_sensitivity_strata(challenge_fixture):
    root, document, _ = challenge_fixture
    encoding = document["encodings"][1]
    artifact = _artifact(document, encoding["frozen_case_artifact_id"])
    frozen_case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    experiment = frozen_case["experiments"][0]
    for prediction in experiment["predictions"]:
        if prediction["outcome_id"] == "outcome:global-context" and prediction["world_id"] != "world:residual":
            prediction["relation"] = "SURVIVES" if prediction["relation"] == "EXCLUDES" else "EXCLUDES"
    experiment["branch_plan_sha256"] = model.branch_plan_sha256(experiment)
    _rewrite_json_artifact(root, artifact, frozen_case)
    result = _run(root, _reseal(root, document))
    gates = {gate["id"]: gate for gate in result["gates"]}
    assert gates["execution_alignment"] == {
        "id": "execution_alignment",
        "status": "PASS",
        "reason": "EXACT_SHARED_DOSSIER_GATES_AND_ACTION_CONTRACT_ENCODER_WORLDS_REMAIN_SEPARATE",
    }
    assert gates["encoding_agreement"]["status"] == "NO_CALL"
    assert "case:positive" in result["case_shared_action_input_sha256"]


@pytest.mark.parametrize("mutation", ["arbitrary", "mislabelled"])
def test_baseline_content_is_schema_bound(challenge_fixture, mutation):
    root, document, _ = challenge_fixture
    baseline = document["baselines"][0]
    artifact = _artifact(document, baseline["artifact_id"])
    if mutation == "arbitrary":
        value = {"not": "a baseline specification"}
    else:
        value = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
        value["family"] = document["baselines"][1]["family"]
    _rewrite_json_artifact(root, artifact, value)
    with pytest.raises(CausalFrontierError, match="baseline specification"):
        _run(root, _reseal(root, document))


def test_role_media_type_mismatch_is_rejected(challenge_fixture):
    root, document, _ = challenge_fixture
    artifact = next(item for item in document["artifacts"] if item["role"] == "FROZEN_CASE")
    artifact["media_type"] = "text/plain"
    with pytest.raises(CausalFrontierError, match="media type"):
        _run(root, _reseal(root, document))


def test_oversized_source_cannot_bypass_standalone_case_limit(challenge_fixture):
    root, document, _ = challenge_fixture
    case_artifact = _artifact(document, document["encodings"][0]["frozen_case_artifact_id"])
    case_prefix = str(Path(case_artifact["path"]).parent).replace(os.sep, "/") + "/"
    source_artifact = next(
        item
        for item in document["artifacts"]
        if item["role"] == "FROZEN_CASE_SOURCE" and item["path"].startswith(case_prefix)
    )
    oversized = b"x" * (challenge.MAX_FROZEN_SOURCE_BYTES + 1)
    (root / source_artifact["path"]).write_bytes(oversized)
    source_artifact["sha256"] = sha256_bytes(oversized)
    case = json.loads((root / case_artifact["path"]).read_text(encoding="utf-8"))
    case["provenance"][0]["sha256"] = source_artifact["sha256"]
    _rewrite_json_artifact(root, case_artifact, case)
    with pytest.raises(CausalFrontierError, match="standalone case-loader limit"):
        _run(root, _reseal(root, document))


def test_public_policy_views_cannot_poison_validation(challenge_fixture):
    root, _, digest = challenge_fixture
    original_boundary = deepcopy(model.BOUNDARY)
    original_metric = deepcopy(challenge.METRIC_CONTRACT)
    try:
        model.BOUNDARY["clinical_authority"] = True
        challenge.METRIC_CONTRACT["resource_vector"].append("attacker_selected_metric")
        result = _run(root, digest)
        assert result["boundary"] == fixed_boundary()
        assert "attacker_selected_metric" not in result["metric_contract"]["resource_vector"]
    finally:
        model.BOUNDARY.clear()
        model.BOUNDARY.update(original_boundary)
        challenge.METRIC_CONTRACT.clear()
        challenge.METRIC_CONTRACT.update(original_metric)
    with pytest.raises(AttributeError):
        challenge.BASELINE_FAMILIES.clear()
    with pytest.raises(AttributeError):
        challenge.CONTROL_CLASSES.clear()
    with pytest.raises(AttributeError):
        model.GRANTED_AUTHORITIES.add("CLINICAL")
    with pytest.raises(AttributeError):
        model.OUTCOME_CLASSES.add("ATTACKER_SELECTED_CLASS")
    with pytest.raises(AttributeError):
        model.RELATIONS.add("ATTACKER_SELECTED_RELATION")


def test_mutating_returned_metric_does_not_poison_later_calls(challenge_fixture):
    root, _, digest = challenge_fixture
    first = _run(root, digest)
    first["metric_contract"]["resource_vector"].append("caller_mutation")
    second = _run(root, digest)
    assert "caller_mutation" not in second["metric_contract"]["resource_vector"]


def test_cli_emits_machine_readable_abstention(challenge_fixture, capsys):
    root, _, digest = challenge_fixture
    code = main(
        [
            "preflight-challenge",
            str(root),
            "--expected-manifest-sha256",
            digest,
            "--expected-sequence",
            "1",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 3
    assert output["status"] == "STRUCTURALLY_BOUND_AND_REPLAYED_SCIENTIFIC_SCORING_DISABLED"
