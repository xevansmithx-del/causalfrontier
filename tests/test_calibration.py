"""Hostile tests for the known-hindsight calibration tripwire."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import causalfrontier
from causalfrontier import calibration
from causalfrontier import cli as cli_module
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _execution_checkpoint(manifest: dict[str, Any]) -> str:
    input_inventory_sha256s = []
    output_raw_sha256s = []
    resource_ledger_raw_sha256s = []
    for control in manifest["controls"]:
        input_inventory_sha256s.append(
            sha256_bytes(calibration.INPUT_INVENTORY_DOMAIN_TAG + canonical_bytes(control["inputs"]))
        )
        output_raw_sha256s.extend(item["sha256"] for item in control["outputs"])
        resource_ledger_raw_sha256s.extend(item["sha256"] for item in control["resource_ledgers"])
    components = {
        "input_inventory_sha256s": input_inventory_sha256s,
        "output_raw_sha256s": output_raw_sha256s,
        "resource_ledger_raw_sha256s": resource_ledger_raw_sha256s,
    }
    return sha256_bytes(calibration.EXECUTION_CHECKPOINT_DOMAIN_TAG + canonical_bytes(components))


def _artifact_path(fixture: dict[str, Any], descriptor: dict[str, Any]) -> Path:
    return fixture["root"] / descriptor["path"]


def _refresh_bundle_bindings(fixture: dict[str, Any]) -> None:
    for control in fixture["manifest"]["controls"]:
        for descriptor in (*control["inputs"], *control["outputs"], *control["resource_ledgers"]):
            descriptor["sha256"] = sha256_bytes(_artifact_path(fixture, descriptor).read_bytes())
    fixture["manifest_sha256"] = _write_json(fixture["manifest_path"], fixture["manifest"])
    fixture["execution_checkpoint"] = _execution_checkpoint(fixture["manifest"])


def _write_fresh_lock(fixture: dict[str, Any]) -> dict[str, Any]:
    lock = calibration.lock_calibration_tripwire(
        fixture["root"], fixture["manifest_sha256"], fixture["execution_checkpoint"]
    )
    fixture["lock"] = lock
    fixture["lock_sha256"] = _write_json(fixture["lock_path"], lock)
    return lock


def _lock(fixture: dict[str, Any]) -> dict[str, Any]:
    return calibration.lock_calibration_tripwire(
        fixture["root"], fixture["manifest_sha256"], fixture["execution_checkpoint"]
    )


def _evaluate(fixture: dict[str, Any]) -> dict[str, Any]:
    return calibration.evaluate_calibration_tripwire(
        fixture["root"],
        fixture["manifest_sha256"],
        fixture["execution_checkpoint"],
        fixture["lock_path"],
        fixture["lock_sha256"],
        fixture["opening_path"],
        fixture["opening_sha256"],
    )


def build_calibration_fixture(
    base: Path,
    *,
    candidate_actions: dict[str, str] | None = None,
    simple_rule_actions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a real three-role by two-policy closed bundle in temporary paths."""

    root = base / "calibration-root"
    external = base / "external-checkpoints"
    root.mkdir(parents=True)
    external.mkdir(parents=True)
    candidate_actions = candidate_actions or dict(calibration.REQUIRED_BEHAVIOR)
    simple_rule_actions = simple_rule_actions or dict.fromkeys(calibration.CONTROL_ROLES, "NEXT_FALSIFICATION")
    cutoffs = {
        "POSITIVE": "2012-12-31T23:59:59Z",
        "FAILED_TRANSLATION": "2016-11-03T23:59:59Z",
        "AMBIGUOUS": "2020-02-20T23:59:59Z",
    }
    available = {
        "POSITIVE": "2012-03-14T00:00:00Z",
        "FAILED_TRANSLATION": "2016-11-03T00:00:00Z",
        "AMBIGUOUS": "2020-02-13T00:00:00Z",
    }
    reveal_available = {
        "POSITIVE": "2017-03-17T00:00:00Z",
        "FAILED_TRANSLATION": "2018-05-03T00:00:00Z",
        "AMBIGUOUS": "2020-05-22T00:00:00Z",
    }
    opaque_ids = {
        role: "entrant:control:" + sha256_bytes(("opaque:" + role).encode("utf-8"))
        for role in calibration.CONTROL_ROLES
    }
    opening_payload = {
        "schema_version": calibration.OPENING_PAYLOAD_SCHEMA_VERSION,
        "tripwire_id": "calibration.tripwire.test.v1",
        "entries": [
            {
                "role": role,
                "opaque_id": opaque_ids[role],
                "oracle_state": role,
                "reveal_source_sha256": sha256_bytes(("public-reveal:" + role).encode("utf-8")),
                "reveal_available_at": reveal_available[role],
            }
            for role in calibration.CONTROL_ROLES
        ],
    }
    nonce_hex = "ab" * 32
    reveal_commitment = sha256_bytes(
        calibration.REVEAL_DOMAIN_TAG + canonical_bytes(opening_payload) + b"\0" + bytes.fromhex(nonce_hex)
    )
    controls = []
    artifact_coordinates: dict[tuple[str, str, str], dict[str, Any]] = {}
    for role in calibration.CONTROL_ROLES:
        slug = role.lower()
        input_path = f"inputs/{slug}.json"
        input_digest = _write_json(
            root / input_path,
            {
                "schema_version": "test.public-evidence.v1",
                "opaque_id": opaque_ids[role],
                "source_kind": "PUBLIC_METADATA",
            },
        )
        inputs = [
            {
                "path": input_path,
                "sha256": input_digest,
                "available_at": available[role],
                "data_class": "PUBLIC_METADATA",
                "authority": "PUBLIC_DATA",
            }
        ]
        outputs = []
        ledgers = []
        for policy_id in calibration.POLICIES:
            policy_slug = policy_id.lower()
            output_path = f"outputs/{slug}-{policy_slug}.json"
            action = candidate_actions[role] if policy_id == "CAUSALFRONTIER" else simple_rule_actions[role]
            output_digest = _write_json(
                root / output_path,
                {
                    "schema_version": calibration.OUTPUT_SCHEMA_VERSION,
                    "opaque_id": opaque_ids[role],
                    "policy_id": policy_id,
                    "action": action,
                },
            )
            output_descriptor = {"policy_id": policy_id, "path": output_path, "sha256": output_digest}
            outputs.append(output_descriptor)
            artifact_coordinates[(role, policy_id, "output")] = output_descriptor

            ledger_path = f"ledgers/{slug}-{policy_slug}.json"
            stages = dict.fromkeys(calibration.LEDGER_STAGES, 0)
            stages["preprocessing"] = 1
            stages["retrieval"] = 2
            ledger_digest = _write_json(
                root / ledger_path,
                {
                    "schema_version": calibration.LEDGER_SCHEMA_VERSION,
                    "opaque_id": opaque_ids[role],
                    "policy_id": policy_id,
                    "stages": stages,
                    "complete": True,
                    "reveal_accessed": False,
                },
            )
            ledger_descriptor = {"policy_id": policy_id, "path": ledger_path, "sha256": ledger_digest}
            ledgers.append(ledger_descriptor)
            artifact_coordinates[(role, policy_id, "ledger")] = ledger_descriptor
        control = {
            "role": role,
            "opaque_id": opaque_ids[role],
            "knowledge_cutoff": cutoffs[role],
            "required_behavior": calibration.REQUIRED_BEHAVIOR[role],
            "inputs": inputs,
            "outputs": outputs,
            "resource_ledgers": ledgers,
        }
        controls.append(control)
        artifact_coordinates[(role, "INPUT", "input")] = inputs[0]
    manifest = {
        "schema_version": calibration.MANIFEST_SCHEMA_VERSION,
        "id": opening_payload["tripwire_id"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "scientific_scoring_ready": False,
        "reveal_commitment_scheme": calibration.REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": reveal_commitment,
        "policies": list(calibration.POLICIES),
        "controls": controls,
    }
    manifest_path = root / calibration.MANIFEST
    fixture = {
        "root": root,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_sha256": _write_json(manifest_path, manifest),
        "execution_checkpoint": _execution_checkpoint(manifest),
        "opening": {
            "schema_version": calibration.OPENING_SCHEMA_VERSION,
            "nonce_hex": nonce_hex,
            "payload": opening_payload,
        },
        "opening_path": external / "opening.json",
        "lock_path": external / "lock.json",
        "artifacts": artifact_coordinates,
    }
    fixture["opening_sha256"] = _write_json(fixture["opening_path"], fixture["opening"])
    _write_fresh_lock(fixture)
    return fixture


@pytest.fixture
def calibration_fixture(tmp_path: Path) -> dict[str, Any]:
    return build_calibration_fixture(tmp_path)


def test_complete_three_by_two_tripwire_locks_and_passes_without_promotion(
    calibration_fixture: dict[str, Any],
) -> None:
    lock = _lock(calibration_fixture)
    assert lock == calibration_fixture["lock"]
    assert lock["status"] == calibration.LOCK_STATUS
    assert lock["controls_n"] == 3
    assert lock["outputs_n"] == 6
    assert lock["resource_ledgers_n"] == 6
    assert lock["opening_read"] is False
    assert lock["primary_scoring_ready"] is False
    assert lock["scientific_scoring_ready"] is False
    assert lock["winner"] is None
    assert lock["ranking"] == []

    report = _evaluate(calibration_fixture)
    assert report["status"] == calibration.REPORT_PASS_STATUS
    assert report["controls_passed_n"] == 3
    assert report["all_required_roles_pass"] is True
    assert [item["control_status"] for item in report["role_results"]] == ["PASS", "PASS", "PASS"]
    assert all(item["policies"][1]["diagnostic_only"] is True for item in report["role_results"])
    assert report["primary_scoring_blocked"] is True
    assert report["primary_scoring_block_reasons"] == [
        "KNOWN_HINDSIGHT_CALIBRATION_ONLY",
        "MODEL_CONTAMINATION_UNRESOLVED",
    ]
    assert report["comparison_performed"] is False
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None
    assert report["primary_scoring_ready"] is False
    assert report["scientific_scoring_ready"] is False
    assert report["scientific_claim_ready"] is False


def test_calibration_workflow_is_exported_from_package_root() -> None:
    assert causalfrontier.lock_calibration_tripwire is calibration.lock_calibration_tripwire
    assert causalfrontier.evaluate_calibration_tripwire is calibration.evaluate_calibration_tripwire
    assert "lock_calibration_tripwire" in causalfrontier.__all__
    assert "evaluate_calibration_tripwire" in causalfrontier.__all__


def test_calibration_cli_dispatches_every_checkpoint_and_exits_three(monkeypatch, capsys) -> None:
    calls: list[tuple[str, tuple[Any, ...]]] = []

    def fake_lock(*args: Any) -> dict[str, Any]:
        calls.append(("lock", args))
        return {"status": "LOCK_TEST", "scientific_scoring_ready": False}

    def fake_evaluate(*args: Any) -> dict[str, Any]:
        calls.append(("evaluate", args))
        return {"status": "REPORT_TEST", "scientific_scoring_ready": False}

    monkeypatch.setattr(cli_module, "lock_calibration_tripwire", fake_lock)
    monkeypatch.setattr(cli_module, "evaluate_calibration_tripwire", fake_evaluate)
    digests = [character * 64 for character in "abcdef"]

    assert (
        cli_module.main(
            [
                "lock-calibration-tripwire",
                "root",
                "--expected-manifest-sha256",
                digests[0],
                "--expected-execution-checkpoint-sha256",
                digests[1],
            ]
        )
        == 3
    )
    assert json.loads(capsys.readouterr().out) == {"scientific_scoring_ready": False, "status": "LOCK_TEST"}
    assert calls.pop(0) == ("lock", (Path("root"), digests[0], digests[1]))

    assert (
        cli_module.main(
            [
                "evaluate-calibration-tripwire",
                "root",
                "lock.json",
                "opening.json",
                "--expected-manifest-sha256",
                digests[0],
                "--expected-execution-checkpoint-sha256",
                digests[1],
                "--expected-lock-sha256",
                digests[2],
                "--expected-opening-sha256",
                digests[3],
            ]
        )
        == 3
    )
    assert json.loads(capsys.readouterr().out) == {"scientific_scoring_ready": False, "status": "REPORT_TEST"}
    assert calls.pop(0) == (
        "evaluate",
        (Path("root"), digests[0], digests[1], Path("lock.json"), digests[2], Path("opening.json"), digests[3]),
    )


@pytest.mark.parametrize(
    ("role", "action", "status"),
    [
        ("POSITIVE", "NO_CALL", "NO_CALL"),
        ("POSITIVE", "REJECT_TRANSLATION", "FAIL"),
        ("FAILED_TRANSLATION", "NO_CALL", "NO_CALL"),
        ("FAILED_TRANSLATION", "NEXT_FALSIFICATION", "FAIL"),
        ("AMBIGUOUS", "NO_CALL", "PASS"),
        ("AMBIGUOUS", "NEXT_FALSIFICATION", "FAIL"),
    ],
)
def test_candidate_terminal_semantics_are_role_specific(tmp_path: Path, role: str, action: str, status: str) -> None:
    actions = dict(calibration.REQUIRED_BEHAVIOR)
    actions[role] = action
    fixture = build_calibration_fixture(tmp_path, candidate_actions=actions)
    report = _evaluate(fixture)
    result = next(item for item in report["role_results"] if item["role"] == role)
    assert result["control_status"] == status
    expected_passes = 3 if status == "PASS" else 2
    assert report["controls_passed_n"] == expected_passes
    assert report["primary_scoring_blocked"] is True
    assert report["scientific_scoring_ready"] is False
    if status != "PASS":
        assert "ONE_OR_MORE_REQUIRED_CAUSALFRONTIER_CONTROL_RESULTS_NOT_PASS" in report["primary_scoring_block_reasons"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda manifest: manifest["controls"].reverse(), "canonical role order"),
        (lambda manifest: manifest["controls"].pop(), "exactly three controls"),
        (
            lambda manifest: manifest["controls"][1].__setitem__("role", "POSITIVE"),
            "canonical role order",
        ),
        (
            lambda manifest: manifest["controls"][1].__setitem__("opaque_id", manifest["controls"][0]["opaque_id"]),
            "identifiers must be unique",
        ),
        (
            lambda manifest: manifest["controls"][0]["outputs"].reverse(),
            "fixed policy order",
        ),
        (
            lambda manifest: manifest["controls"][0]["outputs"].pop(),
            "exactly two outputs",
        ),
    ],
)
def test_role_policy_order_missing_and_duplicate_coordinates_fail_closed(
    calibration_fixture: dict[str, Any], mutation: Any, message: str
) -> None:
    mutation(calibration_fixture["manifest"])
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match=message):
        _lock(calibration_fixture)


def test_input_declared_after_knowledge_cutoff_fails(calibration_fixture: dict[str, Any]) -> None:
    control = calibration_fixture["manifest"]["controls"][0]
    control["inputs"][0]["available_at"] = "2013-01-01T00:00:00Z"
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match="available after its knowledge cutoff"):
        _lock(calibration_fixture)


def test_artifact_digest_substitution_fails(calibration_fixture: dict[str, Any]) -> None:
    descriptor = calibration_fixture["artifacts"][("POSITIVE", "INPUT", "input")]
    _artifact_path(calibration_fixture, descriptor).write_text("substituted public metadata\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="artifact digest mismatch"):
        _lock(calibration_fixture)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"patient\\u005fid":"encoded-private-field"}\n',
        b'{"source":"\\u002fUsers\\u002falice\\u002frecord.json"}\n',
    ],
)
def test_escaped_private_material_in_input_fails_after_json_decode(
    calibration_fixture: dict[str, Any], raw: bytes
) -> None:
    descriptor = calibration_fixture["artifacts"][("POSITIVE", "INPUT", "input")]
    _artifact_path(calibration_fixture, descriptor).write_bytes(raw)
    _refresh_bundle_bindings(calibration_fixture)
    with pytest.raises(CausalFrontierError, match=r"prohibited material|private path or credential material"):
        _lock(calibration_fixture)


def test_reveal_substitution_fails_even_with_a_fresh_file_checkpoint(calibration_fixture: dict[str, Any]) -> None:
    calibration_fixture["opening"]["payload"]["entries"][0]["reveal_source_sha256"] = sha256_bytes(
        b"substituted reveal"
    )
    calibration_fixture["opening_sha256"] = _write_json(
        calibration_fixture["opening_path"], calibration_fixture["opening"]
    )
    with pytest.raises(CausalFrontierError, match="does not match the reveal commitment"):
        _evaluate(calibration_fixture)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda ledger: ledger.__setitem__("complete", False), "incomplete, opened, or misbound"),
        (lambda ledger: ledger.__setitem__("reveal_accessed", True), "incomplete, opened, or misbound"),
        (
            lambda ledger: ledger.__setitem__("stages", dict.fromkeys(calibration.LEDGER_STAGES, 0)),
            "all-zero placeholder",
        ),
        (lambda ledger: ledger["stages"].__setitem__("preprocessing", True), "bounded nonnegative integer"),
    ],
)
def test_incomplete_zero_boolean_or_reveal_opened_resource_ledger_fails(
    calibration_fixture: dict[str, Any], mutation: Any, message: str
) -> None:
    descriptor = calibration_fixture["artifacts"][("POSITIVE", "CAUSALFRONTIER", "ledger")]
    path = _artifact_path(calibration_fixture, descriptor)
    ledger = json.loads(path.read_text(encoding="utf-8"))
    mutation(ledger)
    _write_json(path, ledger)
    _refresh_bundle_bindings(calibration_fixture)
    with pytest.raises(CausalFrontierError, match=message):
        _lock(calibration_fixture)


def test_all_zero_artifact_digest_placeholder_fails(calibration_fixture: dict[str, Any]) -> None:
    calibration_fixture["manifest"]["controls"][0]["outputs"][0]["sha256"] = "0" * 64
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match="all-zero placeholder"):
        _lock(calibration_fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("known_hindsight", False),
        ("prospective", True),
        ("model_contamination_unresolved", False),
        ("calibration_only", False),
        ("primary_performance_eligible", True),
        ("scientific_scoring_ready", True),
    ],
)
def test_manifest_promotion_flags_are_fixed_false_or_conservative(
    calibration_fixture: dict[str, Any], field: str, value: bool
) -> None:
    calibration_fixture["manifest"][field] = value
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match="overclaims its boundary"):
        _lock(calibration_fixture)


def test_orphan_file_fails_exact_inventory(calibration_fixture: dict[str, Any]) -> None:
    (calibration_fixture["root"] / "orphan.txt").write_text("orphan\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="root file inventory differs"):
        _lock(calibration_fixture)


def test_orphan_empty_directory_fails_exact_inventory(calibration_fixture: dict[str, Any]) -> None:
    (calibration_fixture["root"] / "surplus-empty-dir").mkdir()
    with pytest.raises(CausalFrontierError, match="empty directory"):
        _lock(calibration_fixture)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_filesystem_objects_fail_closed(
    calibration_fixture: dict[str, Any], tmp_path: Path, unsafe_kind: str
) -> None:
    descriptor = calibration_fixture["artifacts"][("POSITIVE", "INPUT", "input")]
    target = _artifact_path(calibration_fixture, descriptor)
    preserved = tmp_path / "preserved-input.json"
    preserved.write_bytes(target.read_bytes())
    target.unlink()
    if unsafe_kind == "symlink":
        target.symlink_to(preserved)
    elif unsafe_kind == "hardlink":
        os.link(preserved, target)
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation is unavailable")
        os.mkfifo(target)
    with pytest.raises(CausalFrontierError, match=r"unsafe filesystem object|single-link regular file"):
        _lock(calibration_fixture)


def test_casefold_collision_fails_before_artifact_resolution(calibration_fixture: dict[str, Any]) -> None:
    first = calibration_fixture["manifest"]["controls"][0]["inputs"][0]["path"]
    calibration_fixture["manifest"]["controls"][1]["inputs"][0]["path"] = first.upper()
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match="casefold collision"):
        _lock(calibration_fixture)


def test_artifact_path_reuse_fails(calibration_fixture: dict[str, Any]) -> None:
    control = calibration_fixture["manifest"]["controls"][0]
    control["outputs"][0]["path"] = control["inputs"][0]["path"]
    calibration_fixture["manifest_sha256"] = _write_json(
        calibration_fixture["manifest_path"], calibration_fixture["manifest"]
    )
    with pytest.raises(CausalFrontierError, match="artifact path is reused"):
        _lock(calibration_fixture)


def test_identical_complete_input_digest_multisets_across_controls_fail(
    calibration_fixture: dict[str, Any],
) -> None:
    first = calibration_fixture["manifest"]["controls"][0]["inputs"][0]
    second = calibration_fixture["manifest"]["controls"][1]["inputs"][0]
    _artifact_path(calibration_fixture, second).write_bytes(_artifact_path(calibration_fixture, first).read_bytes())
    _refresh_bundle_bindings(calibration_fixture)
    with pytest.raises(CausalFrontierError, match="identical complete input digest multisets"):
        _lock(calibration_fixture)


def test_duplicate_json_keys_fail_for_manifest_and_bound_output(
    calibration_fixture: dict[str, Any], tmp_path: Path
) -> None:
    raw_manifest = calibration_fixture["manifest_path"].read_bytes()
    duplicated_manifest = raw_manifest.replace(b'{"boundary":', b'{"boundary":{},"boundary":', 1)
    calibration_fixture["manifest_path"].write_bytes(duplicated_manifest)
    calibration_fixture["manifest_sha256"] = sha256_bytes(duplicated_manifest)
    with pytest.raises(CausalFrontierError, match="duplicate JSON key"):
        _lock(calibration_fixture)

    second = build_calibration_fixture(tmp_path / "output-duplicate")
    descriptor = second["artifacts"][("POSITIVE", "CAUSALFRONTIER", "output")]
    path = _artifact_path(second, descriptor)
    raw_output = path.read_bytes()
    duplicated_output = raw_output.replace(b'{"action":', b'{"action":"NO_CALL","action":', 1)
    path.write_bytes(duplicated_output)
    descriptor["sha256"] = sha256_bytes(duplicated_output)
    second["manifest_sha256"] = _write_json(second["manifest_path"], second["manifest"])
    second["execution_checkpoint"] = _execution_checkpoint(second["manifest"])
    with pytest.raises(CausalFrontierError, match="duplicate JSON key"):
        _lock(second)


def test_manifest_and_execution_external_checkpoint_forgery_fails(calibration_fixture: dict[str, Any]) -> None:
    with pytest.raises(CausalFrontierError, match="manifest checkpoint mismatch"):
        calibration.lock_calibration_tripwire(
            calibration_fixture["root"], "f" * 64, calibration_fixture["execution_checkpoint"]
        )
    with pytest.raises(CausalFrontierError, match="execution checkpoint mismatch"):
        calibration.lock_calibration_tripwire(
            calibration_fixture["root"], calibration_fixture["manifest_sha256"], "e" * 64
        )


def test_saved_lock_checkpoint_and_semantic_forgery_fail(calibration_fixture: dict[str, Any]) -> None:
    with pytest.raises(CausalFrontierError, match="lock external checkpoint mismatch"):
        calibration.evaluate_calibration_tripwire(
            calibration_fixture["root"],
            calibration_fixture["manifest_sha256"],
            calibration_fixture["execution_checkpoint"],
            calibration_fixture["lock_path"],
            "d" * 64,
            calibration_fixture["opening_path"],
            calibration_fixture["opening_sha256"],
        )

    forged = deepcopy(calibration_fixture["lock"])
    forged["scientific_scoring_ready"] = True
    core = {key: value for key, value in forged.items() if key != "lock_sha256"}
    forged["lock_sha256"] = sha256_bytes(calibration.LOCK_DOMAIN_TAG + canonical_bytes(core))
    calibration_fixture["lock_sha256"] = _write_json(calibration_fixture["lock_path"], forged)
    with pytest.raises(CausalFrontierError, match="does not replay from the exact closed bundle"):
        _evaluate(calibration_fixture)


def test_opening_checkpoint_forgery_fails(calibration_fixture: dict[str, Any]) -> None:
    with pytest.raises(CausalFrontierError, match="opening external checkpoint mismatch"):
        calibration.evaluate_calibration_tripwire(
            calibration_fixture["root"],
            calibration_fixture["manifest_sha256"],
            calibration_fixture["execution_checkpoint"],
            calibration_fixture["lock_path"],
            calibration_fixture["lock_sha256"],
            calibration_fixture["opening_path"],
            "c" * 64,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda opening: opening["payload"]["entries"].reverse(), "canonical locked control identities"),
        (
            lambda opening: opening["payload"]["entries"][0].__setitem__("oracle_state", "AMBIGUOUS"),
            "oracle state",
        ),
        (
            lambda opening: opening["payload"]["entries"][0].__setitem__("reveal_source_sha256", "0" * 64),
            "all-zero placeholder",
        ),
        (
            lambda opening: opening["payload"]["entries"][0].__setitem__("reveal_available_at", "2012-12-31T23:59:59Z"),
            "after the knowledge cutoff",
        ),
    ],
)
def test_opening_role_order_oracle_digest_and_temporal_gates_fail_before_commitment(
    calibration_fixture: dict[str, Any], mutation: Any, message: str
) -> None:
    mutation(calibration_fixture["opening"])
    calibration_fixture["opening_sha256"] = _write_json(
        calibration_fixture["opening_path"], calibration_fixture["opening"]
    )
    with pytest.raises(CausalFrontierError, match=message):
        _evaluate(calibration_fixture)


def _content_snapshot(paths: list[Path]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for root in paths:
        if root.is_file():
            snapshot[str(root)] = sha256_bytes(root.read_bytes())
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            snapshot[str(path)] = sha256_bytes(path.read_bytes())
    return snapshot


def test_lock_and_evaluation_are_offline_and_read_only(
    calibration_fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    watched = [calibration_fixture["root"], calibration_fixture["lock_path"], calibration_fixture["opening_path"]]
    before = _content_snapshot(watched)
    files = [path for path in calibration_fixture["root"].rglob("*") if path.is_file()]
    files.extend([calibration_fixture["lock_path"], calibration_fixture["opening_path"]])
    directories = [path for path in calibration_fixture["root"].rglob("*") if path.is_dir()]
    directories.append(calibration_fixture["root"])
    for path in files:
        path.chmod(0o444)
    for path in directories:
        path.chmod(0o555)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("offline/read-only calibration attempted an external side effect")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    try:
        lock = _lock(calibration_fixture)
        report = _evaluate(calibration_fixture)
        assert lock["opening_read"] is False
        assert report["scientific_scoring_ready"] is False
        assert _content_snapshot(watched) == before
    finally:
        for path in directories:
            path.chmod(0o755)
        for path in files:
            path.chmod(0o644)


def test_assertion_independent_probe_is_optimized_and_hash_seed_stable() -> None:
    repository = Path(__file__).resolve().parents[1]
    probe = repository / "tests" / "calibration_optimized_probe.py"
    source = probe.read_text(encoding="utf-8")
    assert "assert " not in source
    outputs: list[bytes] = []
    for optimized in (False, True):
        for seed in ("1", "77"):
            command = [sys.executable]
            if optimized:
                command.append("-O")
            command.append(str(probe))
            completed = subprocess.run(
                command,
                cwd=repository,
                env={**os.environ, "PYTHONHASHSEED": seed, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
            assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
            outputs.append(completed.stdout)
    assert len(set(outputs)) == 1
    result = json.loads(outputs[0])
    assert result["lock_status"] == calibration.LOCK_STATUS
    assert result["report_status"] == calibration.REPORT_PASS_STATUS
    assert result["controls_passed_n"] == 3
    assert result["scientific_scoring_ready"] is False


def test_checked_in_biomedical_tripwire_replays_exact_blocked_result() -> None:
    repository = Path(__file__).resolve().parents[1]
    example = repository / "examples" / "calibration-tripwire-v1"
    root = example / "root"
    checkpoint = json.loads((example / "checkpoints" / "local-checkpoint.json").read_text(encoding="utf-8"))

    lock = calibration.lock_calibration_tripwire(
        root,
        checkpoint["manifest_raw_sha256"],
        checkpoint["execution_checkpoint_sha256"],
    )
    generated_lock = canonical_bytes(lock) + b"\n"
    assert generated_lock == (example / "lock.json").read_bytes()
    assert sha256_bytes(generated_lock) == checkpoint["lock_raw_sha256"]
    assert lock["lock_sha256"] == checkpoint["lock_semantic_sha256"]

    report = calibration.evaluate_calibration_tripwire(
        root,
        checkpoint["manifest_raw_sha256"],
        checkpoint["execution_checkpoint_sha256"],
        example / "lock.json",
        checkpoint["lock_raw_sha256"],
        example / "opening.json",
        checkpoint["opening_raw_sha256"],
    )
    generated_report = canonical_bytes(report) + b"\n"
    assert generated_report == (example / "report.json").read_bytes()
    assert sha256_bytes(generated_report) == checkpoint["report_raw_sha256"]
    assert report["report_sha256"] == checkpoint["report_semantic_sha256"]
    assert report["status"] == calibration.REPORT_BLOCKED_STATUS
    assert report["controls_passed_n"] == 1
    assert report["action_role_matches_n"] == 1
    assert report["candidate_always_abstain_equivalent"] is True
    assert [item["control_status"] for item in report["role_results"]] == ["NO_CALL", "NO_CALL", "PASS"]
    assert [item["policies"][1]["status"] for item in report["role_results"]] == ["PASS", "FAIL", "FAIL"]
    assert report["comparison_performed"] is False
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None
    for field in (
        "temporal_admissibility_verified",
        "temporal_attestation_verified",
        "content_outcome_isolation_verified",
        "independent_output_generation_verified",
        "policy_generation_independence_verified",
        "real_resource_measurement_verified",
        "blinding_verified",
        "privacy_certified",
        "independent_custody_verified",
        "rollback_resistance_verified",
        "branch_totality_verified",
        "control_semantic_validity_verified",
        "action_semantics_verified",
        "calibrated_abstention_verified",
        "primary_scoring_ready",
        "scientific_scoring_ready",
        "scientific_claim_ready",
    ):
        assert report[field] is False
