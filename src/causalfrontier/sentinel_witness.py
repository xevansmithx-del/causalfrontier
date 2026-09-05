"""Dual-witness pre-generation lock replay with a post-token generation epoch.

The lock target is created before either RFC 3161 response and binds the exact
sentinel generation plan, organization registry, deadline, and declared witness
pair.  Two raw attestation and trust-policy bundles are replayed from a private
snapshot; saved verification reports are never trusted.  The two token digests
then derive an epoch for a later sentinel payload schema.

This module proves only byte-level composition under caller-pinned policies.
Different identifiers, roots, keys, tokens, and stores do not prove legal or
operational independence.  Until a successor sentinel schema binds the derived
epoch into every generated payload, plan-before-generation also remains unproved.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence as SequenceABC
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Sequence

from . import attestation, claim, sentinel
from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    require_exact_keys,
    require_id,
    require_sha256,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

TARGET_SCHEMA_VERSION = "causalfrontier.sentinel-generation-lock-target.v1"
TARGET_STATUS = "SENTINEL_PREGENERATION_WITNESS_TARGET_SCORING_DISABLED"
TARGET_DOMAIN_TAG = b"causalfrontier.sentinel-generation-lock-target.v1\x00"
LOCK_SCHEMA_VERSION = "causalfrontier.sentinel-dual-witness-lock-manifest.v1"
LOCK_STATUS = "DUAL_WITNESS_EVIDENCE_BUNDLE_CLOSED_SCORING_DISABLED"
LOCK_DOMAIN_TAG = b"causalfrontier.sentinel-dual-witness-lock-manifest.v1\x00"
PREFLIGHT_SCHEMA_VERSION = "causalfrontier.sentinel-dual-witness-lock-preflight.v1"
PREFLIGHT_STATUS = "DUAL_WITNESS_PLAN_LOCK_REPLAYED_GENERATION_EPOCH_DERIVED_NOT_ADMITTED"
PREFLIGHT_DOMAIN_TAG = b"causalfrontier.sentinel-dual-witness-lock-preflight.v1\x00"
GENERATION_EPOCH_DOMAIN_TAG = b"causalfrontier.sentinel-generation-epoch.v1\x00"
LOCK_MANIFEST = "dual-witness-lock.json"
TARGET_MEDIA_TYPE = "application/json"
INDEPENDENCE_STATE = "DECLARED_DISJOINT_NOT_INDEPENDENTLY_AUDITED"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_DUAL_WITNESS_LOCK_PREFLIGHT"
EXACT_WITNESSES = 2
MAX_BUNDLE_BYTES = 32 * 1024 * 1024

FIXED_FALSE_FIELDS = frozenset(
    {
        "generated_artifact_phase_bound",
        "actual_artifact_creation_time_verified",
        "prospective_order_verified",
        "witness_signer_identity_verified",
        "witness_independence_verified",
        "controller_independence_verified",
        "store_independence_verified",
        "certificate_revocation_checked",
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
    "Two caller-declared organizations, governance groups, trust roots, keys, tokens, and paths do not prove "
    "legal, beneficial-owner, infrastructure, or operational independence.",
    "Offline RFC 3161 replay without revocation does not establish an unqualified cryptographic timestamp.",
    "The witness organization and trust policy labels are caller supplied; signer identity is not verified.",
    "The lock does not prove that either witness or store was public, append-only, honest, or externally controlled.",
    "A derived generation epoch does not prove when scientific content was conceived or created.",
    "Generated artifacts are not phase-bound until a later closed sentinel schema requires this exact epoch in "
    "every primary, positive, failed-translation, and ambiguous payload and provenance packet.",
    "The API has no designated artifact, outcome, opening, result, or score input, but arbitrary identifiers, "
    "certificates, nonces, tokens, and post-target manifests may encode or be selected using such content.",
    "The predecessor digest is bound but predecessor existence, chain currentness, and rollback resistance are "
    "not verified.",
    "Recursive DER canonicality, OpenSSL runtime hermeticity, and certificate validity over both endpoints of "
    "the complete signed-accuracy interval remain unverified.",
    "Exact organization-registry bytes and alias checks do not establish governance independence.",
    "No source availability, provenance truth, privacy, domain validity, cohort admission, comparator execution, "
    "acceleration, scientific, clinical, biological, health-impact, or publication claim is established.",
    "No patient, human-decision, clinical, biological, wet-lab, material, release, scoring, or publication "
    "authority is granted.",
)


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or not 1 <= value <= 1_000_000_000:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _digest(value: Any, field: str) -> str:
    result = require_sha256(value, field)
    if result == "0" * 64:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return result


def _canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    receipt_io._screen(canonical_bytes(value))
    if raw != canonical_bytes(value) + b"\n":
        raise CausalFrontierError("%s must use its single canonical JSON encoding plus LF" % label)
    return value


def _artifact(value: Any, field: str) -> tuple[str, str]:
    item = _shape(value, {"path", "sha256", "media_type"}, field)
    path = receipt_io._relative(item["path"])
    digest = _digest(item["sha256"], "%s digest" % field)
    if item["media_type"] != TARGET_MEDIA_TYPE:
        raise CausalFrontierError("%s must be canonical JSON" % field)
    return path, digest


def _under(path: str, prefix: str) -> bool:
    return path.startswith(prefix + "/")


def _prefixes_overlap(left: str, right: str) -> bool:
    return left == right or _under(left, right) or _under(right, left)


def _validate_witness_descriptor(value: Any, index: int) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "witness_id",
            "witness_organization_id",
            "controller_group_id",
            "store_group_id",
            "attestation_id",
            "trust_policy_id",
            "trust_policy_checkpoint_sha256",
            "trust_anchor_sha256",
            "trust_anchor_spki_sha256",
            "tsa_signer_spki_sha256",
            "openssl_binary_sha256",
            "independence_state",
        },
        "dual-witness target witness[%d]" % index,
    )
    for key in {
        "witness_id",
        "witness_organization_id",
        "controller_group_id",
        "store_group_id",
        "attestation_id",
        "trust_policy_id",
    }:
        require_id(item[key], "dual-witness %s" % key)
    for key in {
        "trust_policy_checkpoint_sha256",
        "trust_anchor_sha256",
        "trust_anchor_spki_sha256",
        "tsa_signer_spki_sha256",
        "openssl_binary_sha256",
    }:
        _digest(item[key], "dual-witness %s" % key)
    if item["independence_state"] != INDEPENDENCE_STATE:
        raise CausalFrontierError("dual-witness target invents an independence conclusion")
    own_identities = {
        item[key].casefold()
        for key in {
            "witness_id",
            "witness_organization_id",
            "controller_group_id",
            "store_group_id",
            "attestation_id",
            "trust_policy_id",
        }
    }
    if len(own_identities) != 6:
        raise CausalFrontierError("dual-witness descriptor launders one identity across roles")
    return item


def _validate_target(
    value: Any,
    raw_checkpoint_sha256: str,
    generation_plan: dict[str, Any],
    expected_generation_plan_sha256: str,
    expected_sequence: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    target = _shape(
        value,
        {
            "schema_version",
            "status",
            "lock_id",
            "sequence",
            "predecessor_lock_preflight_sha256",
            "fixed_parameter",
            "boundary",
            "goal_claim_contract_sha256",
            "generation_plan_id",
            "generation_plan_checkpoint_sha256",
            "generation_plan_sha256",
            "organization_registry_checkpoint_sha256",
            "organization_registry_sha256",
            "witness_completion_not_after",
            "witnesses",
            "generated_artifact_input_absent",
            "outcome_input_absent",
            "oracle_opening_input_absent",
            "scoring_disabled",
            "target_sha256",
        },
        "dual-witness lock target",
    )
    if (
        target["schema_version"] != TARGET_SCHEMA_VERSION
        or target["status"] != TARGET_STATUS
        or target["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(target["boundary"]) != BOUNDARY_CANONICAL
        or target["goal_claim_contract_sha256"] != claim.goal_claim_contract_sha256()
    ):
        raise CausalFrontierError("dual-witness target changes the fixed goal or authority boundary")
    require_id(target["lock_id"], "dual-witness lock id")
    if _positive_integer(target["sequence"], "dual-witness target sequence") != expected_sequence:
        raise CausalFrontierError("dual-witness target sequence differs from caller checkpoint")
    predecessor = target["predecessor_lock_preflight_sha256"]
    if expected_sequence == 1:
        if predecessor is not None:
            raise CausalFrontierError("first dual-witness lock must declare a null predecessor")
    else:
        _digest(predecessor, "dual-witness predecessor preflight")
    if (
        target["generation_plan_id"] != generation_plan["plan_id"]
        or target["generation_plan_checkpoint_sha256"] != expected_generation_plan_sha256
        or target["generation_plan_sha256"] != generation_plan["plan_sha256"]
        or generation_plan["sequence"] != expected_sequence
    ):
        raise CausalFrontierError("dual-witness target binds a different generation plan")
    _digest(target["organization_registry_checkpoint_sha256"], "organization registry external checkpoint")
    if target["organization_registry_sha256"] != generation_plan["organization_registry_sha256"]:
        raise CausalFrontierError("dual-witness target binds a different organization registry")
    require_utc_timestamp(target["witness_completion_not_after"], "dual-witness completion deadline")
    if not (
        target["generated_artifact_input_absent"] is True
        and target["outcome_input_absent"] is True
        and target["oracle_opening_input_absent"] is True
        and target["scoring_disabled"] is True
    ):
        raise CausalFrontierError("dual-witness target opens a generated-artifact, outcome, or scoring channel")

    raw_witnesses = target["witnesses"]
    if not isinstance(raw_witnesses, list) or len(raw_witnesses) != EXACT_WITNESSES:
        raise CausalFrontierError("dual-witness target must predeclare exactly two witnesses")
    witnesses = [_validate_witness_descriptor(item, index) for index, item in enumerate(raw_witnesses)]
    witness_ids = [item["witness_id"] for item in witnesses]
    if witness_ids != sorted(witness_ids) or len({item.casefold() for item in witness_ids}) != EXACT_WITNESSES:
        raise CausalFrontierError("dual-witness descriptors must use canonical distinct witness order")
    left_identities = {
        witnesses[0][key].casefold()
        for key in {
            "witness_id",
            "witness_organization_id",
            "controller_group_id",
            "store_group_id",
            "attestation_id",
            "trust_policy_id",
        }
    }
    right_identities = {
        witnesses[1][key].casefold()
        for key in {
            "witness_id",
            "witness_organization_id",
            "controller_group_id",
            "store_group_id",
            "attestation_id",
            "trust_policy_id",
        }
    }
    if left_identities & right_identities:
        raise CausalFrontierError("dual-witness declarations share a witness or governance identity")
    for field in {
        "trust_policy_checkpoint_sha256",
        "trust_anchor_sha256",
        "trust_anchor_spki_sha256",
        "tsa_signer_spki_sha256",
    }:
        if witnesses[0][field] == witnesses[1][field]:
            raise CausalFrontierError("dual-witness declarations share %s" % field)

    core = {key: target[key] for key in target if key != "target_sha256"}
    if target["target_sha256"] != sha256_bytes(TARGET_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("dual-witness target semantic digest differs")
    _digest(raw_checkpoint_sha256, "dual-witness target raw checkpoint")
    return target, witnesses


def _validate_manifest(
    value: Any,
    expected_manifest_sha256: str,
    expected_sequence: int,
) -> tuple[dict[str, Any], str, str, list[dict[str, Any]]]:
    manifest = _shape(
        value,
        {
            "schema_version",
            "status",
            "lock_id",
            "sequence",
            "fixed_parameter",
            "boundary",
            "target",
            "target_sha256",
            "organization_registry",
            "organization_registry_sha256",
            "generation_plan_checkpoint_sha256",
            "generation_plan_sha256",
            "witnesses",
            "generated_artifact_input_absent",
            "outcome_input_absent",
            "oracle_opening_input_absent",
            "scoring_disabled",
            "lock_sha256",
        },
        "dual-witness lock manifest",
    )
    if (
        manifest["schema_version"] != LOCK_SCHEMA_VERSION
        or manifest["status"] != LOCK_STATUS
        or manifest["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(manifest["boundary"]) != BOUNDARY_CANONICAL
    ):
        raise CausalFrontierError("dual-witness lock changes a fixed contract")
    require_id(manifest["lock_id"], "dual-witness lock id")
    if _positive_integer(manifest["sequence"], "dual-witness lock sequence") != expected_sequence:
        raise CausalFrontierError("dual-witness lock sequence differs from caller checkpoint")
    target_path, _target_checkpoint = _artifact(manifest["target"], "dual-witness target artifact")
    registry_path, _registry_checkpoint = _artifact(
        manifest["organization_registry"], "dual-witness organization registry artifact"
    )
    if target_path in (registry_path, LOCK_MANIFEST) or registry_path == LOCK_MANIFEST:
        raise CausalFrontierError("dual-witness root artifacts must use distinct registered paths")
    for field in {
        "target_sha256",
        "organization_registry_sha256",
        "generation_plan_checkpoint_sha256",
        "generation_plan_sha256",
    }:
        _digest(manifest[field], "dual-witness lock %s" % field)
    raw_witnesses = manifest["witnesses"]
    if not isinstance(raw_witnesses, list) or len(raw_witnesses) != EXACT_WITNESSES:
        raise CausalFrontierError("dual-witness lock must close exactly two witnesses")
    witnesses: list[dict[str, Any]] = []
    prefixes: list[str] = []
    for index, raw_item in enumerate(raw_witnesses):
        item = _shape(
            raw_item,
            {
                "witness_id",
                "attestation_root",
                "attestation_checkpoint_sha256",
                "trust_policy_root",
                "trust_policy_checkpoint_sha256",
            },
            "dual-witness lock witness[%d]" % index,
        )
        require_id(item["witness_id"], "dual-witness lock witness id")
        item["attestation_root"] = receipt_io._relative(item["attestation_root"])
        item["trust_policy_root"] = receipt_io._relative(item["trust_policy_root"])
        _digest(item["attestation_checkpoint_sha256"], "dual-witness attestation checkpoint")
        _digest(item["trust_policy_checkpoint_sha256"], "dual-witness trust-policy checkpoint")
        if item["attestation_root"] in {target_path, registry_path, LOCK_MANIFEST} or item["trust_policy_root"] in {
            target_path,
            registry_path,
            LOCK_MANIFEST,
        }:
            raise CausalFrontierError("dual-witness subtree aliases a root artifact")
        prefixes.extend([item["attestation_root"], item["trust_policy_root"]])
        witnesses.append(item)
    witness_ids = [item["witness_id"] for item in witnesses]
    if witness_ids != sorted(witness_ids) or len({item.casefold() for item in witness_ids}) != EXACT_WITNESSES:
        raise CausalFrontierError("dual-witness lock witness order differs")
    if any(_prefixes_overlap(left, right) for index, left in enumerate(prefixes) for right in prefixes[index + 1 :]):
        raise CausalFrontierError("dual-witness evidence subtrees overlap")
    if not (
        manifest["generated_artifact_input_absent"] is True
        and manifest["outcome_input_absent"] is True
        and manifest["oracle_opening_input_absent"] is True
        and manifest["scoring_disabled"] is True
    ):
        raise CausalFrontierError("dual-witness lock opens a generated-artifact, outcome, or scoring channel")
    core = {key: manifest[key] for key in manifest if key != "lock_sha256"}
    if manifest["lock_sha256"] != sha256_bytes(LOCK_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("dual-witness lock semantic digest differs")
    if sha256_bytes(canonical_bytes(manifest) + b"\n") != expected_manifest_sha256:
        raise CausalFrontierError("dual-witness lock raw checkpoint differs")
    return manifest, target_path, registry_path, witnesses


def _validate_registry(
    raw: bytes,
    expected_raw_sha256: str,
    expected_semantic_sha256: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if sha256_bytes(raw) != expected_raw_sha256:
        raise CausalFrontierError("dual-witness organization registry checkpoint mismatch")
    receipt_io._screen(raw)
    value = read_json_bytes(raw, "dual-witness organization registry")
    if raw != canonical_bytes(value) + b"\n":
        raise CausalFrontierError("dual-witness organization registry must be canonical JSON plus LF")
    organizations, by_id = sentinel._validate_organizations(value)
    if sha256_bytes(canonical_bytes(organizations)) != expected_semantic_sha256:
        raise CausalFrontierError("dual-witness organization registry semantic digest differs")
    return organizations, by_id


def _reject_witness_registry_aliases(
    witnesses: list[dict[str, Any]],
    organizations: list[dict[str, Any]],
) -> None:
    participant_identities = {
        item[key].casefold()
        for item in organizations
        for key in {"organization_id", "controller_group_id", "store_group_id"}
    }
    for witness in witnesses:
        witness_identities = {
            witness[key].casefold()
            for key in {
                "witness_id",
                "witness_organization_id",
                "controller_group_id",
                "store_group_id",
                "attestation_id",
                "trust_policy_id",
            }
        }
        if witness_identities & participant_identities:
            raise CausalFrontierError("dual-witness identity aliases a sentinel participant or governance group")


def _snapshot_bundle(
    descriptor: int,
    expected_manifest_sha256: str,
) -> tuple[bytes, dict[str, Any], dict[str, bytes], set[str]]:
    raw_manifest = receipt_io._snapshot(descriptor, LOCK_MANIFEST)
    if sha256_bytes(raw_manifest) != expected_manifest_sha256:
        raise CausalFrontierError("dual-witness lock external checkpoint mismatch")
    manifest_value = _canonical_json(raw_manifest, "dual-witness lock manifest")
    inventory = receipt_io._inventory(descriptor)
    snapshots: dict[str, bytes] = {}
    total = 0
    for relative in sorted(inventory):
        raw = raw_manifest if relative == LOCK_MANIFEST else receipt_io._snapshot(descriptor, relative)
        total += len(raw)
        if total > MAX_BUNDLE_BYTES:
            raise CausalFrontierError("dual-witness bundle exceeds its total byte limit")
        snapshots[relative] = raw
    if LOCK_MANIFEST not in snapshots:
        raise CausalFrontierError("dual-witness lock manifest is absent from its inventory")
    return raw_manifest, manifest_value, snapshots, inventory


def _validate_inventory(
    inventory: set[str],
    target_path: str,
    registry_path: str,
    witnesses: list[dict[str, Any]],
) -> None:
    roots = {LOCK_MANIFEST, target_path, registry_path}
    prefixes = [item[field] for item in witnesses for field in {"attestation_root", "trust_policy_root"}]
    if not roots <= inventory:
        raise CausalFrontierError("dual-witness bundle omits a declared root artifact")
    counts = dict.fromkeys(prefixes, 0)
    for relative in inventory - roots:
        matches = [prefix for prefix in prefixes if _under(relative, prefix)]
        if len(matches) != 1:
            raise CausalFrontierError(
                "dual-witness inventory contains an orphan or ambiguous artifact",
                reason_code="INVENTORY_MISMATCH",
                operation="sentinel_witness._validate_inventory",
            )
        counts[matches[0]] += 1
    if any(count == 0 for count in counts.values()):
        raise CausalFrontierError("dual-witness evidence subtree is empty")


def _write_private_snapshot(root: Path, relative: str, raw: bytes) -> None:
    destination = root.joinpath(*relative.split("/"))
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    try:
        written = 0
        while written < len(raw):
            written_now = os.write(descriptor, raw[written:])
            if written_now <= 0:
                raise CausalFrontierError("private dual-witness snapshot write did not progress")
            written += written_now
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def _runtime_inputs(
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
    witnesses: list[dict[str, Any]],
) -> list[tuple[Path, str]]:
    if (
        not isinstance(openssl_paths, SequenceABC)
        or not isinstance(expected_openssl_sha256s, SequenceABC)
        or isinstance(openssl_paths, (str, bytes))
        or isinstance(expected_openssl_sha256s, (str, bytes))
        or len(openssl_paths) != EXACT_WITNESSES
        or len(expected_openssl_sha256s) != EXACT_WITNESSES
    ):
        raise CausalFrontierError("dual-witness replay requires exactly two aligned OpenSSL runtimes")
    result: list[tuple[Path, str]] = []
    for index, (path, digest) in enumerate(zip(openssl_paths, expected_openssl_sha256s, strict=True)):
        if not isinstance(path, Path):
            raise CausalFrontierError("dual-witness OpenSSL runtime path must be a Path")
        digest = _digest(digest, "dual-witness OpenSSL runtime checkpoint")
        if digest != witnesses[index]["openssl_binary_sha256"]:
            raise CausalFrontierError("dual-witness OpenSSL runtime differs from the pre-token target")
        result.append((path, digest))
    return result


def preflight_sentinel_dual_witness_lock(
    root: Path,
    expected_lock_manifest_sha256: str,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    expected_sequence: int,
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Replay a dual-witness lock and derive an unusable-until-successor epoch."""

    _digest(expected_lock_manifest_sha256, "dual-witness lock external checkpoint")
    _digest(expected_generation_plan_sha256, "sentinel generation plan external checkpoint")
    expected_sequence = _positive_integer(expected_sequence, "dual-witness caller sequence")
    generation_plan = sentinel.preflight_sentinel_generation_plan(generation_plan_path, expected_generation_plan_sha256)
    if generation_plan["sequence"] != expected_sequence:
        raise CausalFrontierError("sentinel generation plan sequence differs from caller checkpoint")

    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            _raw_manifest, manifest_value, snapshots, inventory = _snapshot_bundle(
                descriptor, expected_lock_manifest_sha256
            )
            manifest, target_path, registry_path, lock_witnesses = _validate_manifest(
                manifest_value, expected_lock_manifest_sha256, expected_sequence
            )
            _validate_inventory(inventory, target_path, registry_path, lock_witnesses)
            target_raw = snapshots[target_path]
            registry_raw = snapshots[registry_path]
            if sha256_bytes(target_raw) != manifest["target"]["sha256"]:
                raise CausalFrontierError("dual-witness target artifact digest mismatch")
            target_value = _canonical_json(target_raw, "dual-witness lock target")
            target, target_witnesses = _validate_target(
                target_value,
                manifest["target"]["sha256"],
                generation_plan,
                expected_generation_plan_sha256,
                expected_sequence,
            )
            if (
                manifest["lock_id"] != target["lock_id"]
                or manifest["target_sha256"] != target["target_sha256"]
                or manifest["generation_plan_checkpoint_sha256"] != target["generation_plan_checkpoint_sha256"]
                or manifest["generation_plan_sha256"] != target["generation_plan_sha256"]
                or manifest["organization_registry"]["sha256"] != target["organization_registry_checkpoint_sha256"]
                or manifest["organization_registry_sha256"] != target["organization_registry_sha256"]
            ):
                raise CausalFrontierError("dual-witness lock and pre-token target bindings differ")
            organizations, _organizations_by_id = _validate_registry(
                registry_raw,
                target["organization_registry_checkpoint_sha256"],
                target["organization_registry_sha256"],
            )
            _reject_witness_registry_aliases(target_witnesses, organizations)
            if [item["witness_id"] for item in lock_witnesses] != [item["witness_id"] for item in target_witnesses]:
                raise CausalFrontierError("dual-witness lock closes a different witness pair")
            for lock_item, target_item in zip(lock_witnesses, target_witnesses, strict=True):
                if lock_item["trust_policy_checkpoint_sha256"] != target_item["trust_policy_checkpoint_sha256"]:
                    raise CausalFrontierError("dual-witness trust policy differs from the pre-token target")
            runtimes = _runtime_inputs(openssl_paths, expected_openssl_sha256s, target_witnesses)

            with tempfile.TemporaryDirectory(prefix="causalfrontier-dual-witness-") as temporary:
                # macOS exposes /var as a symlink to /private/var.  Resolve the
                # process-owned temporary root before the no-follow verifier
                # walks it, while keeping every staged child descriptor-safe.
                staged_root = Path(temporary).resolve(strict=True)
                for relative, raw in sorted(snapshots.items()):
                    _write_private_snapshot(staged_root, relative, raw)
                reports: list[dict[str, Any]] = []
                for index, (lock_item, target_item, runtime) in enumerate(
                    zip(lock_witnesses, target_witnesses, runtimes, strict=True)
                ):
                    report = attestation.verify_rfc3161_attestation(
                        staged_root / target_path,
                        manifest["target"]["sha256"],
                        staged_root / lock_item["attestation_root"],
                        lock_item["attestation_checkpoint_sha256"],
                        staged_root / lock_item["trust_policy_root"],
                        lock_item["trust_policy_checkpoint_sha256"],
                        runtime[0],
                        runtime[1],
                        target["witness_completion_not_after"],
                    )
                    expected_pairs = {
                        "attestation_id": target_item["attestation_id"],
                        "attestation_checkpoint_sha256": lock_item["attestation_checkpoint_sha256"],
                        "trust_policy_id": target_item["trust_policy_id"],
                        "trust_policy_checkpoint_sha256": target_item["trust_policy_checkpoint_sha256"],
                        "trust_anchor_sha256": target_item["trust_anchor_sha256"],
                        "trust_anchor_spki_sha256": target_item["trust_anchor_spki_sha256"],
                        "tsa_signer_spki_sha256": target_item["tsa_signer_spki_sha256"],
                        "tsa_organization_id": target_item["witness_organization_id"],
                        "target_checkpoint_sha256": manifest["target"]["sha256"],
                        "openssl_binary_sha256": target_item["openssl_binary_sha256"],
                        "caller_checkpointed_not_after": target["witness_completion_not_after"],
                    }
                    if any(report.get(key) != value for key, value in expected_pairs.items()):
                        raise CausalFrontierError("dual-witness RFC 3161 replay differs from witness %d target" % index)
                    if any(
                        report.get(field) is not False
                        for field in {
                            "canonical_der_verified",
                            "openssl_runtime_hermeticity_verified",
                            "certificate_validity_over_signed_accuracy_interval_verified",
                        }
                    ):
                        raise CausalFrontierError("dual-witness RFC 3161 replay loses a mandatory qualification")
                    if (
                        report[
                            "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"
                        ]
                        is not True
                    ):
                        raise CausalFrontierError("dual-witness signed time bound follows its predeclared deadline")
                    reports.append(report)

            distinct_fields = (
                "attestation_checkpoint_sha256",
                "trust_policy_checkpoint_sha256",
                "trust_anchor_sha256",
                "trust_anchor_spki_sha256",
                "trust_anchor_key_material_sha256",
                "tsa_signer_spki_sha256",
                "tsa_signer_key_material_sha256",
                "request_sha256",
                "response_sha256",
                "timestamp_token_sha256",
            )
            for field in distinct_fields:
                if reports[0][field] == reports[1][field]:
                    raise CausalFrontierError("dual-witness replay reuses %s" % field)

            if receipt_io._inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "dual-witness bundle inventory changed during replay",
                    reason_code="INPUT_CHANGED",
                    operation="sentinel_witness.preflight_sentinel_dual_witness_lock",
                )
            for relative, raw in snapshots.items():
                if receipt_io._snapshot(descriptor, relative) != raw:
                    raise CausalFrontierError(
                        "dual-witness bundle changed during replay",
                        reason_code="INPUT_CHANGED",
                        operation="sentinel_witness.preflight_sentinel_dual_witness_lock",
                    )
    except OSError as exc:
        raise io_error(
            exc,
            "dual-witness bundle cannot be read safely",
            operation="sentinel_witness.preflight_sentinel_dual_witness_lock",
        ) from None

    second_plan = sentinel.preflight_sentinel_generation_plan(generation_plan_path, expected_generation_plan_sha256)
    if canonical_bytes(second_plan) != canonical_bytes(generation_plan):
        raise CausalFrontierError(
            "sentinel generation plan changed during dual-witness replay",
            reason_code="INPUT_CHANGED",
            operation="sentinel_witness.preflight_sentinel_dual_witness_lock",
        )

    witness_projections = []
    epoch_witnesses = []
    for target_item, report in zip(target_witnesses, reports, strict=True):
        projection = {
            "witness_id": target_item["witness_id"],
            "witness_organization_id": target_item["witness_organization_id"],
            "controller_group_id": target_item["controller_group_id"],
            "store_group_id": target_item["store_group_id"],
            "attestation_id": report["attestation_id"],
            "attestation_checkpoint_sha256": report["attestation_checkpoint_sha256"],
            "trust_policy_id": report["trust_policy_id"],
            "trust_policy_checkpoint_sha256": report["trust_policy_checkpoint_sha256"],
            "trust_anchor_sha256": report["trust_anchor_sha256"],
            "trust_anchor_spki_sha256": report["trust_anchor_spki_sha256"],
            "trust_anchor_key_algorithm": report["trust_anchor_key_algorithm"],
            "trust_anchor_key_material_sha256": report["trust_anchor_key_material_sha256"],
            "tsa_signer_spki_sha256": report["tsa_signer_spki_sha256"],
            "tsa_signer_key_algorithm": report["tsa_signer_key_algorithm"],
            "tsa_signer_key_material_sha256": report["tsa_signer_key_material_sha256"],
            "request_sha256": report["request_sha256"],
            "response_sha256": report["response_sha256"],
            "timestamp_token_sha256": report["timestamp_token_sha256"],
            "signed_time_text": report["signed_time_text"],
            "policy_checked_time_upper_bound": report["policy_checked_time_upper_bound"],
            "caller_checkpointed_not_after": report["caller_checkpointed_not_after"],
            "openssl_binary_sha256": report["openssl_binary_sha256"],
            "rfc3161_report_sha256": report["report_sha256"],
            "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity": True,
            "witness_signer_identity_verified": False,
            "witness_independence_verified": False,
            "certificate_revocation_checked": False,
            "canonical_der_verified": False,
            "openssl_runtime_hermeticity_verified": False,
            "certificate_validity_over_signed_accuracy_interval_verified": False,
        }
        witness_projections.append(projection)
        epoch_witnesses.append(
            {
                key: projection[key]
                for key in {
                    "witness_id",
                    "attestation_checkpoint_sha256",
                    "request_sha256",
                    "response_sha256",
                    "timestamp_token_sha256",
                }
            }
        )
    epoch_core = {
        "target_checkpoint_sha256": manifest["target"]["sha256"],
        "lock_manifest_checkpoint_sha256": expected_lock_manifest_sha256,
        "sequence": expected_sequence,
        "witnesses": epoch_witnesses,
    }
    generation_epoch_sha256 = sha256_bytes(GENERATION_EPOCH_DOMAIN_TAG + canonical_bytes(epoch_core))
    gates = sorted(
        [
            _gate("artifact_closure", "PASS", "EXACT_ROOT_AND_TWO_ATTESTATION_AND_TRUST_SUBTREES_REPLAYED"),
            _gate("generation_plan_binding", "PASS", "RAW_AND_SEMANTIC_GENERATION_PLAN_DIGESTS_REPLAYED"),
            _gate("organization_registry_binding", "PASS", "RAW_AND_SEMANTIC_REGISTRY_DIGESTS_REPLAYED"),
            _gate("canonical_pre_token_target", "PASS", "ONE_CANONICAL_TARGET_BOUND_WITNESS_PAIR_BEFORE_TOKENS"),
            _gate("dual_rfc3161_target_binding", "PASS", "TWO_RAW_REQUEST_RESPONSE_POLICY_BUNDLES_BIND_ONE_TARGET"),
            _gate("signed_time_bounds", "PASS", "BOTH_POLICY_UPPER_BOUNDS_NO_LATER_THAN_PREDECLARED_LIMIT"),
            _gate("declared_alias_absence", "PASS", "OBVIOUS_WITNESS_REGISTRY_ROOT_KEY_AND_TOKEN_ALIASES_REJECTED"),
            _gate("generation_epoch_derivation", "PASS", "EPOCH_BINDS_BOTH_TOKEN_PROJECTIONS_AND_LOCK_BYTES"),
            _gate(
                "generated_artifact_phase_binding",
                "NO_CALL",
                "SENTINEL_V1_PAYLOADS_DO_NOT_YET_REQUIRE_THE_DERIVED_EPOCH",
            ),
            _gate("actual_artifact_creation_time", "NO_CALL", "EPOCH_BINDING_CANNOT_DATE_CONTENT_CONCEPTION"),
            _gate("witness_signer_identity", "NO_CALL", "SIGNER_IDENTITY_IS_NOT VERIFIED"),
            _gate("witness_independence", "NO_CALL", "DISTINCT_DECLARATIONS_AND_KEYS_ARE_NOT_INDEPENDENCE"),
            _gate("store_continuity", "NO_CALL", "NO_APPEND_ONLY_STORE_CONTINUITY_ADAPTER_EXECUTED"),
            _gate("certificate_revocation", "NO_CALL", "OFFLINE_REVOCATION_NOT_CHECKED"),
            _gate("rollback_currentness", "NO_CALL", "PREDECESSOR_AND_CALLER_CHECKPOINTS_ARE_NOT_CURRENTNESS"),
            _gate("privacy", "NO_CALL", "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"),
            _gate("cohort_admission", "NO_CALL", "WITNESS LOCK_DOES_NOT_ADMIT_A_SENTINEL_COHORT"),
            _gate(
                "scientific_scoring",
                "NO_CALL",
                "NO_DESIGNATED_OUTCOME_COMPARATOR_OR_SCORE_API_CHANNEL_ACCEPTED_CONTENT_ISOLATION_UNVERIFIED",
            ),
            _gate("authority", "PASS", "READ_ONLY_COMPUTATION_GRANTS_NO_CLINICAL_BIOLOGICAL_OR_MATERIAL_AUTHORITY"),
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
        "lock_id": manifest["lock_id"],
        "sequence": expected_sequence,
        "predecessor_lock_preflight_sha256": target["predecessor_lock_preflight_sha256"],
        "lock_manifest_checkpoint_sha256": expected_lock_manifest_sha256,
        "lock_sha256": manifest["lock_sha256"],
        "target_checkpoint_sha256": manifest["target"]["sha256"],
        "target_sha256": target["target_sha256"],
        "generation_plan_id": generation_plan["plan_id"],
        "generation_plan_checkpoint_sha256": expected_generation_plan_sha256,
        "generation_plan_sha256": generation_plan["plan_sha256"],
        "organization_registry_checkpoint_sha256": manifest["organization_registry"]["sha256"],
        "organization_registry_sha256": generation_plan["organization_registry_sha256"],
        "witness_completion_not_after": target["witness_completion_not_after"],
        "witnesses": witness_projections,
        "generation_epoch_sha256": generation_epoch_sha256,
        "exact_generation_plan_replayed": True,
        "exact_organization_registry_replayed": True,
        "canonical_pre_token_target_replayed": True,
        "closed_dual_witness_bundle_replayed": True,
        "both_raw_rfc3161_bundles_replayed_against_same_target": True,
        "both_signed_target_imprint_time_bounds_replayed_without_revocation_or_signer_identity": True,
        "declared_witness_registry_alias_absent": True,
        "distinct_trust_anchor_bytes_verified": True,
        "distinct_trust_anchor_spkis_verified": True,
        "distinct_trust_anchor_key_material_verified": True,
        "distinct_tsa_signer_spkis_verified": True,
        "distinct_tsa_signer_key_material_verified": True,
        "distinct_request_response_and_token_bytes_verified": True,
        "generation_epoch_derived": True,
        **dict.fromkeys(FIXED_FALSE_FIELDS, False),
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "preflight_sha256": sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))}


def verify_sentinel_dual_witness_lock_preflight(
    value: Any,
    root: Path,
    expected_lock_manifest_sha256: str,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    expected_sequence: int,
    openssl_paths: Sequence[Path],
    expected_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Rebuild a lock report from raw evidence and reject coherent report forgery."""

    if not isinstance(value, dict):
        raise CausalFrontierError("dual-witness preflight report must be an object")
    expected = preflight_sentinel_dual_witness_lock(
        root,
        expected_lock_manifest_sha256,
        generation_plan_path,
        expected_generation_plan_sha256,
        expected_sequence,
        openssl_paths,
        expected_openssl_sha256s,
    )
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("dual-witness preflight report differs from exact deterministic replay")
    return value
