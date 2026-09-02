"""Hostile tests for the phase-bound sentinel successor composition."""

from __future__ import annotations

import inspect
import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import pytest
from sentinel_fixture import build_sentinel_fixture, reseal_goal_plan
from test_sentinel_witness import _build_fixture as build_dual_witness_fixture
from test_sentinel_witness import _preflight as preflight_dual_witness

import causalfrontier
import causalfrontier.cli as cli
import causalfrontier.sentinel as sentinel
import causalfrontier.sentinel_phase as phase
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _different_digest(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def _seal_composition(fixture: dict[str, Any]) -> None:
    manifest = fixture["manifest"]
    core = {key: value for key, value in manifest.items() if key != "composition_sha256"}
    manifest["composition_sha256"] = sha256_bytes(phase.COMPOSITION_DOMAIN_TAG + canonical_bytes(core))
    fixture["manifest_sha256"] = _write_json(fixture["manifest_path"], manifest)


def _build_composition(base: Path, *, seed_outer_registry_digest_collision: bool = False) -> dict[str, Any]:
    dual = build_dual_witness_fixture(
        base / "phase-1",
        seed_outer_registry_digest_collision=seed_outer_registry_digest_collision,
    )
    phase1 = preflight_dual_witness(dual)
    context = phase._fresh_phase_context(phase1)
    successor = build_sentinel_fixture(
        base / "successor",
        generation_phase_context=context,
        seed_outer_registry_digest_collision=seed_outer_registry_digest_collision,
    )
    if successor["generation_plan_sha256"] != dual["generation_plan_sha256"]:
        raise RuntimeError("deterministic successor fixture changed the phase-1 generation plan")
    if successor["generation_plan_path"].read_bytes() != dual["generation_plan_path"].read_bytes():
        raise RuntimeError("successor generation-plan bytes differ from the witnessed plan")

    root = base / "composition"
    root.mkdir()
    generation_plan_path = root / "generation-plan.json"
    goal_plan_path = root / "goal-claim-plan.json"
    lock_root = root / "dual-witness-lock"
    sentinel_root = root / "sentinel"
    shutil.copy2(dual["generation_plan_path"], generation_plan_path)
    shutil.copy2(successor["goal_plan_path"], goal_plan_path)
    shutil.copytree(dual["root"], lock_root)
    shutil.copytree(successor["root"], sentinel_root)
    manifest = {
        "schema_version": phase.COMPOSITION_SCHEMA_VERSION,
        "status": phase.COMPOSITION_STATUS,
        "composition_id": "composition:sentinel-phase-bound:1",
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "generation_phase_context": context,
        "generation_plan": {
            "path": generation_plan_path.name,
            "sha256": sha256_bytes(generation_plan_path.read_bytes()),
            "media_type": phase.MEDIA_TYPE,
        },
        "goal_claim_plan": {
            "path": goal_plan_path.name,
            "sha256": sha256_bytes(goal_plan_path.read_bytes()),
            "media_type": phase.MEDIA_TYPE,
        },
        "dual_witness_lock_root": lock_root.name,
        "dual_witness_lock_manifest_checkpoint_sha256": dual["manifest_sha256"],
        "sentinel_root": sentinel_root.name,
        "sentinel_manifest_checkpoint_sha256": successor["manifest_sha256"],
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    fixture = {
        "root": root,
        "manifest_path": root / phase.COMPOSITION_MANIFEST,
        "manifest": manifest,
        "context": context,
        "phase1": phase1,
        "openssl": dual["openssl"],
        "openssl_sha256": dual["openssl_sha256"],
    }
    _seal_composition(fixture)
    return fixture


@pytest.fixture(scope="module")
def phase_fixture(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _build_composition(tmp_path_factory.mktemp("phase-bound-sentinel"))


def _copy_composition(fixture: dict[str, Any], base: Path) -> dict[str, Any]:
    root = base / "composition"
    shutil.copytree(fixture["root"], root)
    return {
        **fixture,
        "root": root,
        "manifest_path": root / phase.COMPOSITION_MANIFEST,
        "manifest": _json(root / phase.COMPOSITION_MANIFEST),
    }


def _preflight(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    values = {
        "root": fixture["root"],
        "expected_composition_manifest_sha256": fixture["manifest_sha256"],
        "expected_sequence": 1,
        "openssl_paths": [fixture["openssl"], fixture["openssl"]],
        "expected_openssl_sha256s": [fixture["openssl_sha256"], fixture["openssl_sha256"]],
    }
    values.update(overrides)
    return phase.preflight_sentinel_phase_bound_admission(**values)


def _sentinel_manifest_path(fixture: dict[str, Any]) -> Path:
    return fixture["root"] / fixture["manifest"]["sentinel_root"] / sentinel.MANIFEST


def _sentinel_manifest(fixture: dict[str, Any]) -> dict[str, Any]:
    return _json(_sentinel_manifest_path(fixture))


def _case_artifacts_by_role(fixture: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for domain in _sentinel_manifest(fixture)["domains"]:
        for case in domain["cases"]:
            result.setdefault(
                case["case_role"],
                {
                    "case_payload_artifact_id": case["case_payload_artifact_id"],
                    "provenance_artifact_id": case["provenance_artifact_id"],
                },
            )
    if set(result) != set(sentinel.CASE_ROLES):
        raise RuntimeError("phase fixture does not cover every case role")
    return result


def _finish_successor_rewrite(
    fixture: dict[str, Any],
    sentinel_manifest: dict[str, Any],
) -> None:
    sentinel_sha256 = _write_json(_sentinel_manifest_path(fixture), sentinel_manifest)
    goal_path = fixture["root"] / fixture["manifest"]["goal_claim_plan"]["path"]
    goal_plan = _json(goal_path)
    goal_plan["cohort_checkpoint_sha256"] = sentinel_sha256
    reseal_goal_plan(goal_plan)
    goal_sha256 = _write_json(goal_path, goal_plan)
    fixture["manifest"]["sentinel_manifest_checkpoint_sha256"] = sentinel_sha256
    fixture["manifest"]["goal_claim_plan"]["sha256"] = goal_sha256
    _seal_composition(fixture)


def _rewrite_artifacts(
    fixture: dict[str, Any],
    editors: dict[str, Callable[[dict[str, Any]], None]],
    manifest_editor: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    manifest = _sentinel_manifest(fixture)
    descriptors = {item["artifact_id"]: item for item in manifest["artifacts"]}
    sentinel_root = _sentinel_manifest_path(fixture).parent
    for artifact_id, editor in editors.items():
        descriptor = descriptors[artifact_id]
        path = sentinel_root / descriptor["path"]
        document = _json(path)
        editor(document)
        descriptor["sha256"] = _write_json(path, document)
    if manifest_editor is not None:
        manifest_editor(manifest)
    _finish_successor_rewrite(fixture, manifest)


def _verify_saved(report: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    return phase.verify_sentinel_phase_bound_admission_preflight(
        report,
        fixture["root"],
        fixture["manifest_sha256"],
        1,
        [fixture["openssl"], fixture["openssl"]],
        [fixture["openssl_sha256"], fixture["openssl_sha256"]],
    )


def test_clean_composition_replays_exact_39_by_39_without_admission(phase_fixture: dict[str, Any]) -> None:
    report = _preflight(phase_fixture)
    assert report["status"] == phase.PREFLIGHT_STATUS
    assert report["generation_phase_context"] == phase_fixture["context"]
    assert report["case_payload_epoch_bindings_n"] == 39
    assert report["case_provenance_epoch_bindings_n"] == 39
    assert report["primary_payload_epoch_bindings_n"] == 30
    assert report["positive_payload_epoch_bindings_n"] == 3
    assert report["failed_translation_payload_epoch_bindings_n"] == 3
    assert report["ambiguous_payload_epoch_bindings_n"] == 3
    assert report["all_payload_and_provenance_epoch_bindings_replayed"] is True
    assert report["generator_seed_or_case_oracle_outer_snapshot_digest_alias_absent_verified"] is True
    assert report["outer_snapshot_preimage_digests_n"] > 0
    assert report["underlying_sentinel_admission_state"] == "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"
    assert all(report[field] is False for field in phase.FIXED_FALSE_FIELDS)
    assert report["admission_disabled"] is True
    assert report["scoring_disabled"] is True
    assert _verify_saved(report, phase_fixture) == report


def test_seed_commitment_cannot_alias_raw_outer_lock_preimage(tmp_path: Path) -> None:
    fixture = _build_composition(tmp_path, seed_outer_registry_digest_collision=True)
    with pytest.raises(CausalFrontierError, match="supplied input preimage"):
        _preflight(fixture)


def test_empty_outer_directory_is_rejected(phase_fixture: dict[str, Any], tmp_path: Path) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    (fixture["root"] / "empty-unmanifested-directory").mkdir()
    with pytest.raises(CausalFrontierError, match="empty directory"):
        _preflight(fixture)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "extra-file"])
def test_unsafe_or_orphaned_outer_filesystem_entries_are_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
    kind: str,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    manifest_path = fixture["root"] / phase.COMPOSITION_MANIFEST
    rogue = fixture["root"] / ("rogue-" + kind)
    if kind == "symlink":
        rogue.symlink_to(manifest_path.name)
    elif kind == "hardlink":
        os.link(manifest_path, rogue)
    else:
        rogue.write_bytes(b"orphaned outer bytes\n")
    with pytest.raises(
        CausalFrontierError,
        match=r"unsafe filesystem object|orphaned or incomplete|bounded single-link regular file",
    ):
        _preflight(fixture)


def test_symlinked_outer_root_is_rejected(phase_fixture: dict[str, Any], tmp_path: Path) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path / "copy")
    alias = tmp_path / "composition-link"
    alias.symlink_to(fixture["root"], target_is_directory=True)
    with pytest.raises(CausalFrontierError):
        _preflight({**fixture, "root": alias})


def test_casefolded_outer_root_identity_collision_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    fixture["manifest"]["dual_witness_lock_root"] = fixture["manifest"]["sentinel_root"].upper()
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="paths overlap"):
        _preflight(fixture)


def test_private_staging_refuses_existing_destination(tmp_path: Path) -> None:
    stage = tmp_path / "private-stage"
    stage.mkdir()
    phase._write_private_snapshot(stage, "snapshot.bin", b"first\n")
    with pytest.raises(FileExistsError):
        phase._write_private_snapshot(stage, "snapshot.bin", b"second\n")


@pytest.mark.parametrize("role", ["PRIMARY", *sentinel.CONTROL_ROLES])
@pytest.mark.parametrize(
    "artifact_field",
    ["case_payload_artifact_id", "provenance_artifact_id"],
)
@pytest.mark.parametrize("mutation", ["missing", "wrong", "mixed"])
def test_every_role_packet_fails_closed_on_missing_wrong_or_mixed_context(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
    role: str,
    artifact_field: str,
    mutation: str,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    artifact_id = _case_artifacts_by_role(fixture)[role][artifact_field]

    def edit(document: dict[str, Any]) -> None:
        if mutation == "missing":
            document.pop("generation_phase_context")
        elif mutation == "wrong":
            document["generation_phase_context"] = None
        else:
            mixed = deepcopy(document["generation_phase_context"])
            mixed["generation_epoch_sha256"] = _different_digest(mixed["generation_epoch_sha256"])
            document["generation_phase_context"] = mixed

    _rewrite_artifacts(fixture, {artifact_id: edit})
    with pytest.raises(CausalFrontierError):
        _preflight(fixture)


@pytest.mark.parametrize("target", ["manifest", "payload", "provenance"])
def test_v1_downgrade_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
    target: str,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    if target == "manifest":

        def downgrade_manifest(manifest: dict[str, Any]) -> None:
            manifest["schema_version"] = sentinel.MANIFEST_SCHEMA_VERSION
            manifest.pop("generation_phase_context")

        _rewrite_artifacts(fixture, {}, downgrade_manifest)
    else:
        key = "case_payload_artifact_id" if target == "payload" else "provenance_artifact_id"
        artifact_id = _case_artifacts_by_role(fixture)["PRIMARY"][key]

        def downgrade(document: dict[str, Any]) -> None:
            document["schema_version"] = (
                "causalfrontier.sentinel-case-payload.v1"
                if target == "payload"
                else "causalfrontier.case-provenance.v1"
            )
            document.pop("generation_phase_context")

        _rewrite_artifacts(fixture, {artifact_id: downgrade})
    with pytest.raises(CausalFrontierError):
        _preflight(fixture)


def test_coherently_rehashed_whole_bundle_epoch_forgery_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    forged = deepcopy(fixture["context"])
    forged["generation_epoch_sha256"] = _different_digest(forged["generation_epoch_sha256"])
    sentinel_manifest = _sentinel_manifest(fixture)
    phase_ids = {
        item["artifact_id"]
        for item in sentinel_manifest["artifacts"]
        if item["role"] in {"CASE_PAYLOAD", "CASE_PROVENANCE"}
    }

    def replace_context(document: dict[str, Any]) -> None:
        document["generation_phase_context"] = forged

    def replace_manifest_context(manifest: dict[str, Any]) -> None:
        manifest["generation_phase_context"] = forged

    _rewrite_artifacts(
        fixture,
        dict.fromkeys(phase_ids, replace_context),
        replace_manifest_context,
    )
    fixture["manifest"]["generation_phase_context"] = forged
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="fresh phase-1 replay"):
        _preflight(fixture)


@pytest.mark.parametrize(
    "field",
    [
        "generation_lock_preflight_sha256",
        "generation_epoch_sha256",
        "generation_plan_checkpoint_sha256",
        "generation_plan_sha256",
    ],
)
def test_outer_context_wrong_preflight_epoch_or_plan_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
    field: str,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    context = fixture["manifest"]["generation_phase_context"]
    context[field] = _different_digest(context[field])
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError):
        _preflight(fixture)


def test_null_phase1_predecessor_is_never_a_successor_default(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    fixture["manifest"]["generation_phase_context"]["generation_lock_preflight_sha256"] = None
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="lowercase SHA-256"):
        _preflight(fixture)


def test_malformed_phase_context_error_is_hash_seed_stable() -> None:
    script = """
from causalfrontier.canonical import CausalFrontierError
from causalfrontier.sentinel import GENERATION_PHASE_CONTEXT_SCHEMA_VERSION, _validate_generation_phase_context

value = {
    "schema_version": GENERATION_PHASE_CONTEXT_SCHEMA_VERSION,
    "lock_id": "lock:phase-context:error-order",
    "sequence": 1,
    "generation_plan_checkpoint_sha256": None,
    "generation_plan_sha256": None,
    "generation_lock_preflight_sha256": None,
    "generation_epoch_sha256": None,
}
try:
    _validate_generation_phase_context(value)
except CausalFrontierError as exc:
    print(str(exc))
"""
    outputs = []
    for seed in ("1", "77"):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "PYTHONHASHSEED": seed},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
        outputs.append(completed.stdout)
    assert len(set(outputs)) == 1
    assert b"generation_epoch_sha256" in outputs[0]


def test_coherently_resealed_cross_sequence_replay_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    fixture["manifest"]["sequence"] = 2
    fixture["manifest"]["generation_phase_context"]["sequence"] = 2
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="sequence"):
        _preflight(fixture, expected_sequence=2)


def test_coherently_resealed_cross_plan_replay_is_rejected(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    fixture = _copy_composition(phase_fixture, tmp_path)
    plan_path = fixture["root"] / fixture["manifest"]["generation_plan"]["path"]
    plan = _json(plan_path)
    plan["plan_id"] = "plan:sentinel-generation:substituted"
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = sha256_bytes(sentinel.GENERATION_PLAN_DOMAIN_TAG + canonical_bytes(core))
    raw_checkpoint = _write_json(plan_path, plan)
    fixture["manifest"]["generation_plan"]["sha256"] = raw_checkpoint
    fixture["manifest"]["generation_phase_context"]["generation_plan_checkpoint_sha256"] = raw_checkpoint
    fixture["manifest"]["generation_phase_context"]["generation_plan_sha256"] = plan["plan_sha256"]
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="different generation plan"):
        _preflight(fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("actual_artifact_creation_time_verified", True),
        ("case_payload_epoch_bindings_n", 38),
        ("generation_phase_context", None),
    ],
)
def test_coherently_rehashed_saved_report_forgery_requires_full_replay(
    phase_fixture: dict[str, Any],
    field: str,
    value: object,
) -> None:
    report = deepcopy(_preflight(phase_fixture))
    report[field] = value
    core = {key: item for key, item in report.items() if key != "preflight_sha256"}
    report["preflight_sha256"] = sha256_bytes(phase.PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    with pytest.raises(CausalFrontierError, match="exact deterministic replay"):
        _verify_saved(report, phase_fixture)


def test_stale_saved_report_fails_after_coherent_successor_change(
    phase_fixture: dict[str, Any],
    tmp_path: Path,
) -> None:
    report = _preflight(phase_fixture)
    fixture = _copy_composition(phase_fixture, tmp_path)
    fixture["manifest"]["composition_id"] = "composition:sentinel-phase-bound:successor-2"
    _seal_composition(fixture)
    with pytest.raises(CausalFrontierError, match="exact deterministic replay"):
        _verify_saved(report, fixture)


def test_composition_drift_during_replay_is_rejected(
    phase_fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = phase.receipt_io._snapshot
    calls = {"manifest": 0}

    def drifting_snapshot(descriptor: int, relative: str) -> bytes:
        raw = original(descriptor, relative)
        if relative == phase.COMPOSITION_MANIFEST:
            calls["manifest"] += 1
            if calls["manifest"] == 2:
                return raw + b" "
        return raw

    monkeypatch.setattr(phase.receipt_io, "_snapshot", drifting_snapshot)
    with pytest.raises(CausalFrontierError, match="bytes changed during replay"):
        _preflight(phase_fixture)


def test_public_api_and_cli_have_no_outcome_channel_and_exit_three(
    phase_fixture: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert causalfrontier.preflight_sentinel_phase_bound_admission is phase.preflight_sentinel_phase_bound_admission
    assert (
        causalfrontier.verify_sentinel_phase_bound_admission_preflight
        is phase.verify_sentinel_phase_bound_admission_preflight
    )
    parameters = set(inspect.signature(phase.preflight_sentinel_phase_bound_admission).parameters)
    assert parameters == {
        "root",
        "expected_composition_manifest_sha256",
        "expected_sequence",
        "openssl_paths",
        "expected_openssl_sha256s",
    }
    assert not parameters & {
        "artifact",
        "payload",
        "outcome",
        "opening",
        "oracle",
        "result",
        "winner",
        "score",
        "patient",
        "material",
    }
    code = main(
        [
            "preflight-sentinel-phase-bound-admission",
            str(phase_fixture["root"]),
            "--expected-composition-manifest-sha256",
            phase_fixture["manifest_sha256"],
            "--expected-sequence",
            "1",
            "--openssl",
            str(phase_fixture["openssl"]),
            "--openssl",
            str(phase_fixture["openssl"]),
            "--expected-openssl-sha256",
            phase_fixture["openssl_sha256"],
            "--expected-openssl-sha256",
            phase_fixture["openssl_sha256"],
        ]
    )
    assert code == 3
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == phase.PREFLIGHT_STATUS
    assert output["cohort_admitted"] is False
    assert output["scientific_scoring_ready"] is False


def test_cli_replay_rejects_coherently_rehashed_forged_projection(
    phase_fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    forged = deepcopy(_preflight(phase_fixture))
    forged["case_payload_epoch_bindings_n"] = 38
    core = {key: value for key, value in forged.items() if key != "preflight_sha256"}
    forged["preflight_sha256"] = sha256_bytes(phase.PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    monkeypatch.setattr(cli, "preflight_sentinel_phase_bound_admission", lambda *_args: forged)

    code = cli.main(
        [
            "preflight-sentinel-phase-bound-admission",
            str(phase_fixture["root"]),
            "--expected-composition-manifest-sha256",
            phase_fixture["manifest_sha256"],
            "--expected-sequence",
            "1",
            "--openssl",
            str(phase_fixture["openssl"]),
            "--openssl",
            str(phase_fixture["openssl"]),
            "--expected-openssl-sha256",
            phase_fixture["openssl_sha256"],
            "--expected-openssl-sha256",
            phase_fixture["openssl_sha256"],
        ]
    )

    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "exact deterministic replay" in captured.err


def test_assertion_independent_probe_is_optimized_and_hash_seed_stable() -> None:
    repository = Path(__file__).resolve().parents[1]
    probe = repository / "tests" / "phase_optimized_probe.py"
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
    report = json.loads(outputs[0])
    assert report["status"] == phase.PREFLIGHT_STATUS
    assert report["case_payload_epoch_bindings_n"] == 39
    assert report["case_provenance_epoch_bindings_n"] == 39
    assert report["scientific_scoring_ready"] is False
