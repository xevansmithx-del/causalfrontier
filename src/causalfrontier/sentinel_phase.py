"""Phase-bind every sentinel payload and provenance packet after witness replay.

The successor composition snapshots one closed outer root, reconstructs the
phase-1 dual-witness preflight from raw RFC 3161 evidence, derives the only
accepted generation phase context, and then applies the full sentinel structural
preflight to successor schemas that physically embed that context in every case
payload and provenance packet.

This proves byte-level phase binding only.  Content may have been conceived or
prepared before the witnesses ran, and the module cannot establish independent
custody, currentness, provenance truth, cohort admission, or scientific value.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Sequence as SequenceABC
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Sequence

from . import receipts as receipt_io
from . import sentinel, sentinel_witness
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    require_exact_keys,
    require_id,
    require_sha256,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

COMPOSITION_MANIFEST = "sentinel-phase-bound.json"
COMPOSITION_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-composition.v1"
COMPOSITION_STATUS = "PHASE_BOUND_SENTINEL_COMPOSITION_CLOSED_ADMISSION_AND_SCORING_DISABLED"
COMPOSITION_DOMAIN_TAG = b"causalfrontier.sentinel-phase-bound-composition.v1\x00"
PREFLIGHT_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-preflight.v1"
PREFLIGHT_STATUS = "ALL_SENTINEL_PAYLOAD_AND_PROVENANCE_EPOCH_BINDINGS_REPLAYED_NOT_ADMITTED"
PREFLIGHT_DOMAIN_TAG = b"causalfrontier.sentinel-phase-bound-preflight.v1\x00"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_PHASE_BOUND_SENTINEL_PREFLIGHT"
MEDIA_TYPE = "application/json"
MAX_FILES = 640
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
EXACT_CASES = sentinel.EXACT_DOMAINS * (sentinel.PRIMARY_CASES_PER_DOMAIN + len(sentinel.CONTROL_ROLES))

FIXED_FALSE_FIELDS = frozenset(
    {
        "actual_artifact_creation_time_verified",
        "content_conception_after_epoch_verified",
        "prospective_order_verified",
        "successor_uniqueness_verified",
        "witness_signer_identity_verified",
        "witness_independence_verified",
        "controller_independence_verified",
        "store_independence_verified",
        "certificate_revocation_checked",
        "canonical_der_verified",
        "openssl_runtime_hermeticity_verified",
        "certificate_validity_over_signed_accuracy_interval_verified",
        "long_term_validity_verified",
        "rollback_currentness_verified",
        "public_registration_verified",
        "provenance_truth_verified",
        "privacy_certified",
        "content_outcome_isolation_verified",
        "cohort_admitted",
        "prospective_primary_eligible",
        "scientific_scoring_ready",
        "scientific_claim_ready",
        "publication_claim_authorized",
    }
)

NONCLAIMS = (
    "Embedding the replayed epoch proves an exact byte dependency, not when scientific content was conceived.",
    "A generator can prepare content before the ceremony and wrap it in a phase-bound packet afterward.",
    "A caller-pinned successor checkpoint selects one bundle locally but does not prevent same-predecessor "
    "equivocation.",
    "Replayed distinct witnesses, roots, keys, tokens, organizations, and stores do not prove real independence.",
    "Offline RFC 3161 verification without revocation, signer-identity proof, or long-term validation remains "
    "qualified.",
    "Exact provenance graph structure does not establish provenance truth, source availability, authorship, or "
    "semantics.",
    "Public or synthetic declarations and pattern screening do not certify privacy or patient-data absence.",
    "Known-hindsight controls remain calibration only and cannot count as prospective primary performance.",
    "No outcome, oracle opening, comparator result, winner, resource effect, or scientific score is accepted.",
    "Digest non-alias checks do not prove seed or oracle secrecy, entropy, or commitment hiding.",
    "No patient, clinical, biological, wet-lab, material, release, scoring, or publication authority is granted.",
)


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _digest(value: Any, field: str) -> str:
    result = require_sha256(value, field)
    if result == "0" * 64:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return result


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or not 1 <= value <= 1_000_000_000:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    receipt_io._screen(canonical_bytes(value))
    if raw != canonical_bytes(value) + b"\n":
        raise CausalFrontierError("%s must use its single canonical JSON encoding plus LF" % label)
    return value


def _file(value: Any, field: str) -> tuple[str, str]:
    descriptor = _shape(value, {"path", "sha256", "media_type"}, field)
    path = receipt_io._relative(descriptor["path"])
    digest = _digest(descriptor["sha256"], "%s digest" % field)
    if descriptor["media_type"] != MEDIA_TYPE:
        raise CausalFrontierError("%s must be canonical JSON" % field)
    return path, digest


def _root(value: Any, field: str) -> str:
    result = receipt_io._relative(value)
    if "/" in result:
        raise CausalFrontierError("%s must be one canonical directory component" % field)
    return result


def _under(path: str, prefix: str) -> bool:
    return path.startswith(prefix + "/")


def _validate_manifest(
    value: Any,
    expected_manifest_sha256: str,
    expected_sequence: int,
) -> tuple[dict[str, Any], str, str, str, str, str, str]:
    manifest = _shape(
        value,
        {
            "schema_version",
            "status",
            "composition_id",
            "sequence",
            "fixed_parameter",
            "boundary",
            "generation_phase_context",
            "generation_plan",
            "goal_claim_plan",
            "dual_witness_lock_root",
            "dual_witness_lock_manifest_checkpoint_sha256",
            "sentinel_root",
            "sentinel_manifest_checkpoint_sha256",
            "designated_outcome_input_absent",
            "oracle_opening_input_absent",
            "admission_disabled",
            "scoring_disabled",
            "composition_sha256",
        },
        "phase-bound sentinel composition manifest",
    )
    if not (
        manifest["schema_version"] == COMPOSITION_SCHEMA_VERSION
        and manifest["status"] == COMPOSITION_STATUS
        and manifest["fixed_parameter"] == FIXED_PARAMETER
        and canonical_bytes(manifest["boundary"]) == BOUNDARY_CANONICAL
    ):
        raise CausalFrontierError("phase-bound composition changes a fixed contract")
    require_id(manifest["composition_id"], "phase-bound composition id")
    sequence = _positive_integer(manifest["sequence"], "phase-bound composition sequence")
    if sequence != expected_sequence:
        raise CausalFrontierError("phase-bound composition sequence differs from caller checkpoint")
    context = sentinel._validate_generation_phase_context(manifest["generation_phase_context"])
    if context["sequence"] != sequence:
        raise CausalFrontierError("phase-bound composition and generation context sequences differ")
    generation_plan_path, generation_plan_sha256 = _file(manifest["generation_plan"], "phase-bound generation plan")
    goal_plan_path, _goal_plan_sha256 = _file(manifest["goal_claim_plan"], "phase-bound goal claim plan")
    lock_root = _root(manifest["dual_witness_lock_root"], "phase-bound dual-witness root")
    sentinel_root = _root(manifest["sentinel_root"], "phase-bound sentinel root")
    lock_manifest_sha256 = _digest(
        manifest["dual_witness_lock_manifest_checkpoint_sha256"],
        "phase-bound dual-witness lock manifest checkpoint",
    )
    sentinel_manifest_sha256 = _digest(
        manifest["sentinel_manifest_checkpoint_sha256"],
        "phase-bound sentinel manifest checkpoint",
    )
    path_identities = {
        COMPOSITION_MANIFEST,
        generation_plan_path,
        goal_plan_path,
        lock_root,
        sentinel_root,
    }
    if (
        len({COMPOSITION_MANIFEST, generation_plan_path, goal_plan_path}) != 3
        or len({item.casefold() for item in path_identities}) != len(path_identities)
        or lock_root == sentinel_root
        or any(
            _under(path, root) or path == root
            for path in {COMPOSITION_MANIFEST, generation_plan_path, goal_plan_path}
            for root in {lock_root, sentinel_root}
        )
    ):
        raise CausalFrontierError("phase-bound composition paths overlap")
    if context["generation_plan_checkpoint_sha256"] != generation_plan_sha256:
        raise CausalFrontierError("phase-bound context names a different raw generation plan")
    if not (
        manifest["designated_outcome_input_absent"] is True
        and manifest["oracle_opening_input_absent"] is True
        and manifest["admission_disabled"] is True
        and manifest["scoring_disabled"] is True
    ):
        raise CausalFrontierError("phase-bound composition opens an outcome, admission, or scoring path")
    core = {key: manifest[key] for key in manifest if key != "composition_sha256"}
    if manifest["composition_sha256"] != sha256_bytes(COMPOSITION_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("phase-bound composition semantic digest differs")
    _digest(expected_manifest_sha256, "phase-bound composition external checkpoint")
    return (
        manifest,
        generation_plan_path,
        goal_plan_path,
        lock_root,
        sentinel_root,
        lock_manifest_sha256,
        sentinel_manifest_sha256,
    )


def _inventory(
    root_fd: int,
    prefix: str = "",
    entries: set[str] | None = None,
    visited: list[int] | None = None,
) -> set[str]:
    entries = set() if entries is None else entries
    visited = [0] if visited is None else visited
    names: list[str] = []
    with os.scandir(root_fd) as directory:
        for entry in directory:
            visited[0] += 1
            if visited[0] > MAX_FILES:
                raise CausalFrontierError("phase-bound composition exceeds its fixed file limit")
            names.append(entry.name)
    for name in sorted(names):
        relative = receipt_io._relative(prefix + name)
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            before = len(entries)
            with ExitStack() as stack:
                child = receipt_io._open_directory(stack, name, root_fd)
                _inventory(child, relative + "/", entries, visited)
            if len(entries) == before:
                raise CausalFrontierError(
                    "phase-bound composition contains an empty directory",
                    reason_code="INVENTORY_MISMATCH",
                    operation="sentinel_phase._inventory",
                )
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entries.add(relative)
        else:
            raise CausalFrontierError(
                "phase-bound composition contains an unsafe filesystem object",
                reason_code="SAFE_FILE_REJECTED",
                operation="sentinel_phase._inventory",
            )
    return entries


def _snapshot_composition(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
) -> tuple[dict[str, Any], dict[str, bytes], set[str], tuple[str, str, str, str, str, str]]:
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, COMPOSITION_MANIFEST)
            if sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("phase-bound composition external checkpoint mismatch")
            value = _canonical_json(raw_manifest, "phase-bound sentinel composition manifest")
            (
                manifest,
                generation_plan_path,
                goal_plan_path,
                lock_root,
                sentinel_root,
                lock_manifest_sha256,
                sentinel_manifest_sha256,
            ) = _validate_manifest(value, expected_manifest_sha256, expected_sequence)
            inventory = _inventory(descriptor)
            direct = {COMPOSITION_MANIFEST, generation_plan_path, goal_plan_path}
            lock_files = {path for path in inventory if _under(path, lock_root)}
            sentinel_files = {path for path in inventory if _under(path, sentinel_root)}
            if not lock_files or not sentinel_files or inventory != direct | lock_files | sentinel_files:
                raise CausalFrontierError(
                    "phase-bound composition inventory is orphaned or incomplete",
                    reason_code="INVENTORY_MISMATCH",
                    operation="sentinel_phase._snapshot_composition",
                )
            expected_lock_manifest = "%s/%s" % (lock_root, sentinel_witness.LOCK_MANIFEST)
            expected_sentinel_manifest = "%s/%s" % (sentinel_root, sentinel.MANIFEST)
            if expected_lock_manifest not in lock_files or expected_sentinel_manifest not in sentinel_files:
                raise CausalFrontierError("phase-bound composition omits a required inner manifest")
            snapshots: dict[str, bytes] = {}
            total = 0
            for relative in sorted(inventory):
                raw = raw_manifest if relative == COMPOSITION_MANIFEST else receipt_io._snapshot(descriptor, relative)
                total += len(raw)
                if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("phase-bound composition exceeds its fixed byte limits")
                snapshots[relative] = raw
            if sha256_bytes(snapshots[generation_plan_path]) != manifest["generation_plan"]["sha256"]:
                raise CausalFrontierError("phase-bound generation plan bytes differ")
            if sha256_bytes(snapshots[goal_plan_path]) != manifest["goal_claim_plan"]["sha256"]:
                raise CausalFrontierError("phase-bound goal plan bytes differ")
            if sha256_bytes(snapshots[expected_lock_manifest]) != lock_manifest_sha256:
                raise CausalFrontierError("phase-bound lock manifest bytes differ")
            if sha256_bytes(snapshots[expected_sentinel_manifest]) != sentinel_manifest_sha256:
                raise CausalFrontierError("phase-bound sentinel manifest bytes differ")
            if _inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "phase-bound composition inventory changed while being read",
                    reason_code="INPUT_CHANGED",
                    operation="sentinel_phase._snapshot_composition",
                )
    except OSError as exc:
        raise io_error(
            exc, "phase-bound composition cannot be read safely", operation="sentinel_phase._snapshot_composition"
        ) from None
    paths = (
        generation_plan_path,
        goal_plan_path,
        lock_root,
        sentinel_root,
        lock_manifest_sha256,
        sentinel_manifest_sha256,
    )
    return manifest, snapshots, inventory, paths


def _write_private_snapshot(root: Path, relative: str, raw: bytes) -> None:
    destination = root.joinpath(*relative.split("/"))
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise CausalFrontierError("private phase-bound snapshot write did not progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fresh_phase_context(report: dict[str, Any]) -> dict[str, Any]:
    return sentinel._validate_generation_phase_context(
        {
            "schema_version": sentinel.GENERATION_PHASE_CONTEXT_SCHEMA_VERSION,
            "lock_id": report["lock_id"],
            "sequence": report["sequence"],
            "generation_plan_checkpoint_sha256": report["generation_plan_checkpoint_sha256"],
            "generation_plan_sha256": report["generation_plan_sha256"],
            "generation_lock_preflight_sha256": report["preflight_sha256"],
            "generation_epoch_sha256": report["generation_epoch_sha256"],
        }
    )


def _runtime_inputs(
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
) -> tuple[list[Path], list[str]]:
    if (
        not isinstance(openssl_paths, SequenceABC)
        or not isinstance(expected_openssl_sha256s, SequenceABC)
        or isinstance(openssl_paths, (str, bytes))
        or isinstance(expected_openssl_sha256s, (str, bytes))
        or len(openssl_paths) != sentinel_witness.EXACT_WITNESSES
        or len(expected_openssl_sha256s) != sentinel_witness.EXACT_WITNESSES
    ):
        raise CausalFrontierError("phase-bound replay requires exactly two aligned OpenSSL runtimes")
    paths: list[Path] = []
    digests: list[str] = []
    for path, digest in zip(openssl_paths, expected_openssl_sha256s, strict=True):
        if not isinstance(path, Path):
            raise CausalFrontierError("phase-bound OpenSSL runtime path must be a Path")
        paths.append(path)
        digests.append(_digest(digest, "phase-bound OpenSSL runtime checkpoint"))
    return paths, digests


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def preflight_sentinel_phase_bound_admission(
    root: Path,
    expected_composition_manifest_sha256: str,
    expected_sequence: int,
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Replay phase 1 and all successor packet bindings without admission."""

    _digest(expected_composition_manifest_sha256, "phase-bound composition external checkpoint")
    expected_sequence = _positive_integer(expected_sequence, "phase-bound caller sequence")
    runtime_paths, runtime_digests = _runtime_inputs(openssl_paths, expected_openssl_sha256s)
    manifest, snapshots, inventory, paths = _snapshot_composition(
        root,
        expected_composition_manifest_sha256,
        expected_sequence,
    )
    generation_plan_path, goal_plan_path, lock_root, sentinel_root, lock_manifest_sha256, sentinel_manifest_sha256 = (
        paths
    )
    outer_supplied_preimage_digests = frozenset(sha256_bytes(raw) for raw in snapshots.values())

    with tempfile.TemporaryDirectory(prefix="causalfrontier-phase-bound-") as temporary:
        staged_root = Path(temporary).resolve(strict=True)
        for relative, raw in sorted(snapshots.items()):
            _write_private_snapshot(staged_root, relative, raw)
        staged_generation_plan = staged_root / generation_plan_path
        staged_goal_plan = staged_root / goal_plan_path
        staged_lock_root = staged_root / lock_root
        staged_sentinel_root = staged_root / sentinel_root
        phase1 = sentinel_witness.preflight_sentinel_dual_witness_lock(
            staged_lock_root,
            lock_manifest_sha256,
            staged_generation_plan,
            manifest["generation_plan"]["sha256"],
            expected_sequence,
            runtime_paths,
            runtime_digests,
        )
        context = _fresh_phase_context(phase1)
        sentinel._validate_generation_phase_context(manifest["generation_phase_context"], context)
        if phase1.get("generated_artifact_phase_bound") is not False:
            raise CausalFrontierError("phase-1 report must retain its historical unbound-artifact boundary")
        sentinel_report = sentinel._preflight_sentinel_phase_bound_admission(
            staged_sentinel_root,
            sentinel_manifest_sha256,
            expected_sequence,
            staged_generation_plan,
            manifest["generation_plan"]["sha256"],
            staged_goal_plan,
            manifest["goal_claim_plan"]["sha256"],
            context,
            outer_supplied_preimage_digests,
        )
        repeated_phase1 = sentinel_witness.preflight_sentinel_dual_witness_lock(
            staged_lock_root,
            lock_manifest_sha256,
            staged_generation_plan,
            manifest["generation_plan"]["sha256"],
            expected_sequence,
            runtime_paths,
            runtime_digests,
        )
        if canonical_bytes(phase1) != canonical_bytes(repeated_phase1):
            raise CausalFrontierError(
                "phase-1 witness replay changed during successor composition",
                reason_code="INPUT_CHANGED",
                operation="sentinel_phase.preflight_sentinel_phase_bound_admission",
            )

    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            if _inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "phase-bound composition inventory changed during replay",
                    reason_code="INPUT_CHANGED",
                    operation="sentinel_phase.preflight_sentinel_phase_bound_admission",
                )
            for relative, raw in snapshots.items():
                if receipt_io._snapshot(descriptor, relative) != raw:
                    raise CausalFrontierError(
                        "phase-bound composition bytes changed during replay",
                        reason_code="INPUT_CHANGED",
                        operation="sentinel_phase.preflight_sentinel_phase_bound_admission",
                    )
    except OSError as exc:
        raise io_error(
            exc,
            "phase-bound composition cannot be reread safely",
            operation="sentinel_phase.preflight_sentinel_phase_bound_admission",
        ) from None

    gates = sorted(
        [
            _gate("closed_composition", "PASS", "ONE_CALLER_CHECKPOINTED_OUTER_SNAPSHOT_REPLAYED"),
            _gate("raw_phase1_replay", "PASS", "DUAL_RFC3161_LOCK_REBUILT_TWICE_FROM_RAW_EVIDENCE"),
            _gate("generation_phase_context", "PASS", "MANIFEST_CONTEXT_EQUALS_FRESH_PHASE1_PROJECTION"),
            _gate("payload_epoch_binding", "PASS", "EXACT_30_PRIMARY_AND_3_PER_CONTROL_ROLE_PAYLOADS_BOUND"),
            _gate("provenance_epoch_binding", "PASS", "EXACT_39_PROVENANCE_PACKETS_BOUND"),
            _gate("goal_plan_successor_closure", "PASS", "GOAL_PLAN_BINDS_RAW_PHASE_BOUND_SENTINEL_MANIFEST"),
            _gate(
                "seed_oracle_outer_preimage_alias",
                "PASS",
                "COMMITMENTS_DISJOINT_FROM_ENUMERATED_OUTER_SNAPSHOT_DIGESTS",
            ),
            _gate("artifact_creation_time", "NO_CALL", "BYTE_DEPENDENCY_CANNOT_DATE_CONTENT_CONCEPTION"),
            _gate("prospective_order", "NO_CALL", "NO_INDEPENDENTLY_OBSERVED_GENERATOR_EXECUTION"),
            _gate("successor_uniqueness", "NO_CALL", "NO_EXTERNAL_APPEND_ONLY_SUCCESSOR_REGISTER"),
            _gate("witness_independence", "NO_CALL", "DISTINCT_REPLAYED_IDENTITIES_AND_KEYS_ARE_NOT_INDEPENDENCE"),
            _gate("recursive_der_canonicality", "NO_CALL", "PHASE1_RETAINS_QUALIFIED_DER_BOUNDARY"),
            _gate("runtime_hermeticity", "NO_CALL", "PINNED_EXECUTABLE_BYTES_DO_NOT_PROVE_HERMETIC_EXECUTION"),
            _gate(
                "signed_accuracy_interval_certificate_validity",
                "NO_CALL",
                "PHASE1_DOES_NOT_VERIFY_CERTIFICATE_VALIDITY_OVER_THE_FULL_SIGNED_INTERVAL",
            ),
            _gate("rollback_currentness", "NO_CALL", "CALLER_CHECKPOINT_IS_NOT_MONOTONIC_CURRENTNESS"),
            _gate("privacy", "NO_CALL", "PATTERN_SCREENING_IS_NOT_PRIVACY_CERTIFICATION"),
            _gate("provenance_truth", "NO_CALL", "GRAPH_CLOSURE_IS_NOT_EXTERNAL_PROVENANCE_TRUTH"),
            _gate("cohort_admission", "NO_CALL", "PHASE_BINDING_DOES_NOT_ADMIT_A_COHORT"),
            _gate("scientific_scoring", "NO_CALL", "NO_OUTCOME_COMPARATOR_RESOURCE_OR_SCORE_CHANNEL"),
            _gate("authority", "PASS", "READ_ONLY_REPLAY_GRANTS_NO_CLINICAL_BIOLOGICAL_OR_MATERIAL_AUTHORITY"),
        ],
        key=lambda item: item["id"],
    )
    core: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "status": PREFLIGHT_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "composition_id": manifest["composition_id"],
        "sequence": expected_sequence,
        "composition_manifest_checkpoint_sha256": expected_composition_manifest_sha256,
        "composition_sha256": manifest["composition_sha256"],
        "generation_phase_context": context,
        "dual_witness_lock_manifest_checkpoint_sha256": lock_manifest_sha256,
        "phase1_dual_witness_preflight_sha256": phase1["preflight_sha256"],
        "sentinel_manifest_checkpoint_sha256": sentinel_manifest_sha256,
        "sentinel_structural_preflight_sha256": sentinel_report["preflight_sha256"],
        "goal_claim_plan_checkpoint_sha256": manifest["goal_claim_plan"]["sha256"],
        "goal_claim_plan_sha256": sentinel_report["goal_claim_plan_sha256"],
        "generation_plan_checkpoint_sha256": manifest["generation_plan"]["sha256"],
        "generation_plan_sha256": sentinel_report["generation_plan_sha256"],
        "underlying_sentinel_admission_state": sentinel_report["admission_state"],
        "underlying_sentinel_rejection_reasons": sentinel_report["rejection_reasons"],
        "primary_payload_epoch_bindings_n": sentinel.EXACT_DOMAINS * sentinel.PRIMARY_CASES_PER_DOMAIN,
        "positive_payload_epoch_bindings_n": sentinel.EXACT_DOMAINS,
        "failed_translation_payload_epoch_bindings_n": sentinel.EXACT_DOMAINS,
        "ambiguous_payload_epoch_bindings_n": sentinel.EXACT_DOMAINS,
        "case_payload_epoch_bindings_n": EXACT_CASES,
        "case_provenance_epoch_bindings_n": EXACT_CASES,
        "closed_outer_snapshot_replayed": True,
        "fresh_phase1_raw_evidence_replayed": True,
        "phase1_replay_stable_across_composition": True,
        "manifest_phase_context_matches_fresh_phase1_replay": True,
        "all_payload_and_provenance_epoch_bindings_replayed": True,
        "exact_role_and_case_binding_geometry_replayed": True,
        "goal_plan_binds_phase_bound_manifest_checkpoint": True,
        "outer_snapshot_preimage_digests_n": len(outer_supplied_preimage_digests),
        "generator_seed_or_case_oracle_outer_snapshot_digest_alias_absent_verified": True,
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
        **dict.fromkeys(FIXED_FALSE_FIELDS, False),
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "preflight_sha256": sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))}


def verify_sentinel_phase_bound_admission_preflight(
    value: Any,
    root: Path,
    expected_composition_manifest_sha256: str,
    expected_sequence: int,
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Full-replay a saved successor report and reject coherent projection forgery."""

    if not isinstance(value, dict):
        raise CausalFrontierError("phase-bound sentinel preflight report must be an object")
    expected = preflight_sentinel_phase_bound_admission(
        root,
        expected_composition_manifest_sha256,
        expected_sequence,
        openssl_paths,
        expected_openssl_sha256s,
    )
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("phase-bound sentinel report differs from exact deterministic replay")
    return value
