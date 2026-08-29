"""No-clobber capsule build, exact replay verification, and rehearsal recording."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    read_json,
    require_id,
    require_sha256,
    sha256_bytes,
    sha256_file,
    write_canonical,
)
from .classifier import execute_classifiers
from .frontier import compile_case, simulate_branch
from .ledger import append_event, create_ledger, verify_ledger
from .model import load_case

CAPSULE_FILES = {"analysis.json", "case", "classifier-results.json", "ledger.sqlite", "manifest.json"}


def _regular_single_link(path: Path, field: str) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise CausalFrontierError("%s must be a single-link regular file" % field)


def _remove_created_capsule(destination: Path, created_inode: Optional[int]) -> None:
    if created_inode is None:
        return
    try:
        information = destination.lstat()
    except OSError:
        return
    if destination.is_dir() and not destination.is_symlink() and information.st_ino == created_inode:
        shutil.rmtree(destination)


def build_capsule(case_root: Path, destination: Path) -> Dict[str, Any]:
    """Compile a verified case into a new self-contained capsule."""

    if destination.exists() or destination.is_symlink():
        raise CausalFrontierError("refusing to overwrite capsule destination")
    if case_root.is_symlink():
        raise CausalFrontierError("case root must not be a symlink")
    case_root = case_root.resolve(strict=True)
    try:
        destination.resolve(strict=False).relative_to(case_root)
    except ValueError:
        pass
    else:
        raise CausalFrontierError("capsule destination must not be inside the frozen case root")
    case = load_case(case_root)
    analysis = compile_case(case)
    classifier_results = execute_classifiers(case, case_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    created_inode: Optional[int] = None
    try:
        destination.mkdir(mode=0o700)
        created_inode = destination.stat().st_ino
        case_destination = destination / "case"
        case_destination.mkdir()
        write_canonical(case_destination / "case.json", case)
        for source in case["provenance"]:
            target = case_destination / source["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(case_root / source["path"], target)
        write_canonical(destination / "analysis.json", analysis)
        write_canonical(destination / "classifier-results.json", classifier_results)
        ledger_result = create_ledger(
            destination / "ledger.sqlite",
            case["case_id"],
            case["frozen_at"],
            analysis["case_sha256"],
            analysis["analysis_sha256"],
            analysis["run_id"],
        )
        if ledger_result["state"] != "VERIFIED":
            raise CausalFrontierError("new ledger did not verify")
        immutable_files = {}
        for path in sorted(
            (item for item in destination.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(destination).as_posix(),
        ):
            relative = path.relative_to(destination).as_posix()
            if relative == "ledger.sqlite":
                continue
            immutable_files[relative] = sha256_file(path)
        manifest_core = {
            "schema_version": "causalfrontier.capsule-manifest.v1",
            "case_id": case["case_id"],
            "case_sha256": analysis["case_sha256"],
            "analysis_sha256": analysis["analysis_sha256"],
            "run_id": analysis["run_id"],
            "immutable_files": immutable_files,
            "ledger_genesis_head": ledger_result["head_digest"],
            "ledger_genesis_logical_state_sha256": ledger_result["logical_state_sha256"],
            "ledger_policy": "APPEND_ONLY_EVENTS_NOT_PART_OF_IMMUTABLE_FILE_MANIFEST",
        }
        manifest = dict(
            manifest_core,
            manifest_sha256=sha256_bytes(canonical_bytes(manifest_core)),
        )
        write_canonical(destination / "manifest.json", manifest)
        parent_fd = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        _remove_created_capsule(destination, created_inode)
        raise
    verification = verify_capsule(destination)
    if verification["status"] != "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE":
        _remove_created_capsule(destination, created_inode)
        raise CausalFrontierError("new capsule failed exact replay: %s" % verification.get("error", "unknown"))
    return verification


def verify_capsule(
    capsule: Path,
    expected_ledger_head: Optional[str] = None,
) -> Dict[str, Any]:
    """Replay immutable inputs and verify the append-only ledger without mutation."""

    result: Dict[str, Any] = {
        "schema_version": "causalfrontier.capsule-verification.v1",
        "status": "INVALID",
    }
    try:
        if capsule.is_symlink():
            raise CausalFrontierError("capsule must be a non-symlink directory")
        capsule = capsule.resolve(strict=True)
        if not capsule.is_dir():
            raise CausalFrontierError("capsule must be a non-symlink directory")
        if expected_ledger_head is not None:
            expected_ledger_head = require_sha256(
                expected_ledger_head,
                "expected_ledger_head",
            )
        top_level = {item.name for item in capsule.iterdir()}
        if top_level != CAPSULE_FILES:
            raise CausalFrontierError(
                "capsule top-level inventory mismatch; unexpected=%s missing=%s"
                % (sorted(top_level - CAPSULE_FILES), sorted(CAPSULE_FILES - top_level))
            )
        _regular_single_link(capsule / "manifest.json", "manifest")
        _regular_single_link(capsule / "analysis.json", "analysis")
        _regular_single_link(capsule / "classifier-results.json", "classifier results")
        _regular_single_link(capsule / "ledger.sqlite", "ledger")
        manifest = read_json(capsule / "manifest.json")
        required_manifest = {
            "schema_version",
            "case_id",
            "case_sha256",
            "analysis_sha256",
            "run_id",
            "immutable_files",
            "ledger_genesis_head",
            "ledger_genesis_logical_state_sha256",
            "ledger_policy",
            "manifest_sha256",
        }
        if not isinstance(manifest, dict) or set(manifest) != required_manifest:
            raise CausalFrontierError("manifest schema mismatch")
        manifest_core = {key: manifest[key] for key in manifest if key != "manifest_sha256"}
        if sha256_bytes(canonical_bytes(manifest_core)) != manifest["manifest_sha256"]:
            raise CausalFrontierError("manifest self-digest mismatch")
        if manifest["schema_version"] != "causalfrontier.capsule-manifest.v1":
            raise CausalFrontierError("manifest version mismatch")
        if manifest["ledger_policy"] != "APPEND_ONLY_EVENTS_NOT_PART_OF_IMMUTABLE_FILE_MANIFEST":
            raise CausalFrontierError("manifest ledger policy mismatch")
        require_id(manifest["case_id"], "manifest case_id")
        for field in (
            "case_sha256",
            "analysis_sha256",
            "run_id",
            "ledger_genesis_head",
            "ledger_genesis_logical_state_sha256",
            "manifest_sha256",
        ):
            require_sha256(manifest[field], "manifest %s" % field)
        immutable_files = manifest["immutable_files"]
        if not isinstance(immutable_files, dict) or not immutable_files:
            raise CausalFrontierError("manifest immutable file inventory is empty")
        actual_immutable = set()
        for path in capsule.rglob("*"):
            if path.is_symlink():
                raise CausalFrontierError("capsule contains a symlink")
            relative = path.relative_to(capsule).as_posix()
            if path.is_file() and relative not in {"manifest.json", "ledger.sqlite"}:
                actual_immutable.add(relative)
                _regular_single_link(path, "capsule file %s" % relative)
        if actual_immutable != set(immutable_files):
            raise CausalFrontierError("immutable file inventory differs from manifest")
        for relative, expected in sorted(immutable_files.items()):
            if sha256_file(capsule / relative) != expected:
                raise CausalFrontierError("immutable file digest mismatch: %s" % relative)
        case = load_case(capsule / "case")
        analysis = read_json(capsule / "analysis.json")
        replayed = compile_case(case)
        classifier_results = read_json(capsule / "classifier-results.json")
        replayed_classifier_results = execute_classifiers(case, capsule / "case")
        if canonical_bytes(analysis) != canonical_bytes(replayed):
            raise CausalFrontierError("analysis does not exactly replay from the frozen case")
        if canonical_bytes(classifier_results) != canonical_bytes(replayed_classifier_results):
            raise CausalFrontierError("classifier results do not exactly replay from the frozen case")
        for field in ("case_sha256", "analysis_sha256", "run_id"):
            if manifest[field] != replayed[field]:
                raise CausalFrontierError("manifest %s differs from replay" % field)
        if manifest["case_id"] != case["case_id"]:
            raise CausalFrontierError("manifest case_id differs from replay")
        ledger = verify_ledger(capsule / "ledger.sqlite")
        if ledger["state"] != "VERIFIED":
            raise CausalFrontierError("ledger is invalid: %s" % ledger.get("error", "unknown"))
        if ledger["genesis_head_digest"] != manifest["ledger_genesis_head"]:
            raise CausalFrontierError("ledger genesis head differs from manifest")
        if ledger["genesis_logical_state_sha256"] != manifest["ledger_genesis_logical_state_sha256"]:
            raise CausalFrontierError("ledger genesis logical state differs from manifest")
        if expected_ledger_head is not None and ledger["head_digest"] != expected_ledger_head:
            raise CausalFrontierError("ledger head differs from the external checkpoint")
        initial = ledger["replay"]["initial_compile"]
        if initial != {
            "case_sha256": replayed["case_sha256"],
            "analysis_sha256": replayed["analysis_sha256"],
            "run_id": replayed["run_id"],
        }:
            raise CausalFrontierError("ledger compile event differs from replay")
        if ledger["metadata"]["case_id"] != case["case_id"]:
            raise CausalFrontierError("ledger case id differs from case")
        for payload in ledger["replay"]["verifications"]:
            if payload != {
                "run_id": replayed["run_id"],
                "manifest_sha256": manifest["manifest_sha256"],
            }:
                raise CausalFrontierError("ledger verification event differs from capsule replay")
        predecessor_active_world_ids = replayed["active_world_ids"]
        predecessor_case_state = replayed["case_state"]
        for payload in ledger["replay"]["rehearsals"]:
            rehearsal = simulate_branch(
                case,
                payload["experiment_id"],
                payload["outcome_id"],
                branch_plan_sha256=payload["branch_plan_sha256"],
                active_world_ids=predecessor_active_world_ids,
                case_state=predecessor_case_state,
            )
            expected_payload = {
                "predecessor_run_id": rehearsal["predecessor_run_id"],
                "predecessor_active_world_ids": rehearsal["predecessor_active_world_ids"],
                "predecessor_case_state": rehearsal["predecessor_case_state"],
                "experiment_id": payload["experiment_id"],
                "outcome_id": payload["outcome_id"],
                "branch_plan_sha256": rehearsal["branch_plan_sha256"],
                "successor_run_id": rehearsal["successor_analysis"]["run_id"],
                "successor_active_world_ids": rehearsal["successor_active_world_ids"],
                "successor_case_state": rehearsal["successor_case_state"],
                "status": rehearsal["status"],
            }
            if payload != expected_payload:
                raise CausalFrontierError("ledger rehearsal does not semantically replay")
            predecessor_active_world_ids = rehearsal["successor_active_world_ids"]
            predecessor_case_state = rehearsal["successor_case_state"]
        result.update(
            {
                "status": "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE",
                "case_id": case["case_id"],
                "run_id": replayed["run_id"],
                "case_sha256": replayed["case_sha256"],
                "analysis_sha256": replayed["analysis_sha256"],
                "manifest_sha256": manifest["manifest_sha256"],
                "frontiers": replayed["frontiers"],
                "minimax": replayed["minimax"],
                "ledger": ledger,
                "boundary": replayed["boundary"],
                "verification_scope": replayed["verification_scope"],
                "provenance_binding_status": "EXACT_CAPSULE_FILE_DIGESTS_VERIFIED",
                "classifier_results": replayed_classifier_results,
            }
        )
    except (CausalFrontierError, OSError, ValueError) as exc:
        result["error"] = str(exc)
    return result


def record_rehearsal(
    capsule: Path,
    expected_ledger_head: str,
    timestamp: str,
    experiment_id: str,
    outcome_id: str,
    branch_plan_sha256: str,
) -> Dict[str, Any]:
    """Append a counterfactual rehearsal event bound to a frozen branch plan."""

    expected_ledger_head = require_sha256(expected_ledger_head, "expected_ledger_head")
    verification = verify_capsule(capsule, expected_ledger_head=expected_ledger_head)
    if verification["status"] != "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE":
        raise CausalFrontierError("cannot rehearse against an invalid capsule")
    case = load_case(capsule / "case")
    rehearsals = verification["ledger"]["replay"]["rehearsals"]
    if rehearsals:
        predecessor_active_world_ids = rehearsals[-1]["successor_active_world_ids"]
        predecessor_case_state = rehearsals[-1]["successor_case_state"]
    else:
        predecessor_active_world_ids = sorted(world["id"] for world in case["worlds"])
        predecessor_case_state = "DECLARED_PARTITION_ACTIVE"
    rehearsal = simulate_branch(
        case,
        experiment_id,
        outcome_id,
        branch_plan_sha256=branch_plan_sha256,
        active_world_ids=predecessor_active_world_ids,
        case_state=predecessor_case_state,
    )
    payload = {
        "predecessor_run_id": rehearsal["predecessor_run_id"],
        "predecessor_active_world_ids": rehearsal["predecessor_active_world_ids"],
        "predecessor_case_state": rehearsal["predecessor_case_state"],
        "experiment_id": experiment_id,
        "outcome_id": outcome_id,
        "branch_plan_sha256": branch_plan_sha256,
        "successor_run_id": rehearsal["successor_analysis"]["run_id"],
        "successor_active_world_ids": rehearsal["successor_active_world_ids"],
        "successor_case_state": rehearsal["successor_case_state"],
        "status": rehearsal["status"],
    }
    appended = append_event(
        capsule / "ledger.sqlite",
        timestamp,
        "COUNTERFACTUAL_REHEARSAL",
        case["case_id"],
        payload,
        expected_head=expected_ledger_head,
    )
    post_append = verify_capsule(
        capsule,
        expected_ledger_head=appended["head_digest"],
    )
    if post_append["status"] != "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE":
        raise CausalFrontierError("appended rehearsal failed semantic capsule replay")
    return {"rehearsal": rehearsal, "ledger": post_append["ledger"]}
