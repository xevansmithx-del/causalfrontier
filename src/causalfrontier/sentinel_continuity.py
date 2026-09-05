"""Replay a pre-token custody target and a fixed two-log continuity ceremony.

This module closes a narrow gap left deliberately open by the phase-bound
sentinel verifier.  Before either custody witness token is issued, one target
must freeze the generation-plan digests, two declared log identities and
verification keys, their caller-preserved prior checkpoints, and a dedicated
two-slot sequence rule.  After the phase-bound composition exists, the verifier
derives one transition statement, requires it at the reserved position in both
supplied log views, derives a seal over both intermediate checkpoints, and
requires that same seal at the next reserved position in both final views.

The result is continuity only relative to the supplied, signed checkpoints.  It
does not prove global successor uniqueness, absence of hidden split views,
currentness, actual store operation, organizational independence, or scientific
admissibility.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import tempfile
from collections.abc import Sequence as SequenceABC
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Sequence

from . import _transparency, attestation, sentinel_phase
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

COMPOSITION_MANIFEST = "sentinel-continuity.json"
COMPOSITION_SCHEMA_VERSION = "causalfrontier.sentinel-dual-declared-log-continuity-composition.v1"
COMPOSITION_STATUS = "DUAL_DECLARED_LOG_CONTINUITY_COMPOSITION_CLOSED_ADMISSION_AND_SCORING_DISABLED"
COMPOSITION_DOMAIN_TAG = b"causalfrontier.sentinel-dual-declared-log-continuity-composition.v1\x00"
TARGET_SCHEMA_VERSION = "causalfrontier.sentinel-continuity-custody-target.v1"
TARGET_STATUS = "PRE_TOKEN_DUAL_LOG_CUSTODY_TARGET_SCORING_DISABLED"
TARGET_DOMAIN_TAG = b"causalfrontier.sentinel-continuity-custody-target.v1\x00"
TRANSITION_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-transition.v1"
TRANSITION_STATUS = "PHASE_BOUND_TRANSITION_DERIVED_ADMISSION_AND_SCORING_DISABLED"
TRANSITION_DOMAIN_TAG = b"causalfrontier.sentinel-phase-bound-transition.v1\x00"
SEAL_SCHEMA_VERSION = "causalfrontier.sentinel-dual-log-seal.v1"
SEAL_STATUS = "DUAL_DECLARED_LOG_INTERMEDIATE_CHECKPOINTS_CROSS_SEALED_NOT_ADMITTED"
SEAL_DOMAIN_TAG = b"causalfrontier.sentinel-dual-log-seal.v1\x00"
PROOF_SCHEMA_VERSION = "causalfrontier.rfc6962-sha256-proof.v1"
PREFLIGHT_SCHEMA_VERSION = "causalfrontier.sentinel-dual-declared-log-continuity-preflight.v1"
PREFLIGHT_STATUS = "DUAL_DECLARED_LOG_EDGE_AND_CROSS_SEAL_REPLAYED_RELATIVE_TO_CALLER_CHECKPOINTS_NOT_ADMITTED"
PREFLIGHT_DOMAIN_TAG = b"causalfrontier.sentinel-dual-declared-log-continuity-preflight.v1\x00"
STATE_DOMAIN_TAG = b"causalfrontier.sentinel-dual-declared-log-continuity-state.v1\x00"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_DUAL_DECLARED_LOG_CONTINUITY_PREFLIGHT"

MEDIA_JSON = "application/json"
MEDIA_CHECKPOINT = "text/vnd.c2sp.tlog-checkpoint"
CHECKPOINT_PROFILE = "c2sp.org/tlog-checkpoint@v1.0.0-ed25519-pinned-key"
PROOF_PROFILE = "RFC6962_SHA256_PREORDERED_TWO_SLOT_V1"
STATEMENT_PROFILE = "CAUSALFRONTIER_PHASE_BOUND_TRANSITION_CANONICAL_JSON_V1"
CROSS_LOG_RULE = "IDENTICAL_TRANSITION_THEN_IDENTICAL_INTERMEDIATE_CHECKPOINT_CROSS_SEAL"
INDEPENDENCE_STATE = "DECLARED_DISJOINT_NOT_INDEPENDENTLY_AUDITED"
EXACT_STORES = 2
EXACT_CUSTODY_WITNESSES = 2
MAX_FILES = 896
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SEQUENCE = 100_000_000
MAX_PROOF_HASHES = 63
MAX_CHECKPOINT_BYTES = 128 * 1024
MAX_CHECKPOINT_SIGNATURES = 16
MAX_SIGNATURE_BLOB_BYTES = 8 * 1024
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
VKEY_PATTERN = re.compile(r"([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})")
ORIGIN_PATTERN = re.compile(r"[^+\s\x00-\x1f\x7f]+")
DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]{0,19}")

FIXED_FALSE_FIELDS = frozenset(
    {
        "actual_external_store_operation_verified",
        "store_operator_identity_verified",
        "store_independence_verified",
        "controller_independence_verified",
        "global_successor_uniqueness_verified",
        "unseen_equivocation_absent_verified",
        "future_fork_absence_verified",
        "rollback_currentness_verified",
        "public_registration_verified",
        "content_conception_after_epoch_verified",
        "prospective_order_verified",
        "witness_signer_identity_verified",
        "witness_independence_verified",
        "certificate_revocation_checked",
        "openssl_runtime_hermeticity_verified",
        "long_term_validity_verified",
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
    "The two reserved positions are enforced only inside each supplied authenticated log view.",
    "Valid inclusion and consistency proofs do not exclude a hidden split view, an unseen successor, or a future fork.",
    "Caller-supplied final checkpoints are not proof that either view is globally latest or publicly registered.",
    "Distinct declared store, operator, controller, namespace, key, witness, and trust-root identifiers do not "
    "prove independence.",
    "A dual-timestamped custody target binds bytes under qualified offline RFC 3161 policy; it does not date "
    "content conception.",
    "Pinned OpenSSL executable bytes do not prove a hermetic runtime, host integrity, or non-malicious "
    "executable behavior.",
    "OpenSSL paths are executable inputs and must refer to application-controlled trusted binaries; digest pinning "
    "does not sandbox their host effects.",
    "The verifier accepts no outcome, oracle opening, comparator result, winner, resource effect, or scientific score.",
    "Structural continuity does not establish provenance truth, privacy, biological validity, clinical utility, "
    "or acceleration.",
    "No patient, clinical, biological, wet-lab, material, release, scoring, or publication authority is granted.",
)


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _digest(value: Any, field: str) -> str:
    result = require_sha256(value, field)
    if result == "0" * 64:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return result


def _sequence(value: Any, field: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SEQUENCE:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _bounded_nonnegative(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 2 * MAX_SEQUENCE:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def _canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise CausalFrontierError("%s must be one canonical JSON object plus LF" % label)
    return value


def _file(value: Any, field: str, media_type: str) -> tuple[str, str]:
    descriptor = _shape(value, {"path", "sha256", "media_type"}, field)
    path = receipt_io._relative(descriptor["path"])
    digest = _digest(descriptor["sha256"], "%s digest" % field)
    if descriptor["media_type"] != media_type:
        raise CausalFrontierError("%s uses a different media type" % field)
    return path, digest


def _root(value: Any, field: str) -> str:
    result = receipt_io._relative(value)
    if "/" in result:
        raise CausalFrontierError("%s must be one canonical directory component" % field)
    return result


def _under(path: str, prefix: str) -> bool:
    return path.startswith(prefix + "/")


def _overlap(left: str, right: str) -> bool:
    return left == right or _under(left, right) or _under(right, left)


def _canonical_base64(value: Any, field: str, expected_length: int = 32) -> bytes:
    if not isinstance(value, str) or len(value) > 256:
        raise CausalFrontierError("%s must be bounded canonical base64" % field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise CausalFrontierError("%s is not valid base64" % field) from None
    if len(raw) != expected_length or base64.b64encode(raw).decode("ascii") != value:
        raise CausalFrontierError("%s is not canonical fixed-width base64" % field)
    return raw


def _parse_vkey(value: Any, field: str) -> tuple[str, bytes, bytes]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        raise CausalFrontierError("%s must be a bounded verifier key" % field)
    match = VKEY_PATTERN.fullmatch(value)
    if match is None:
        raise CausalFrontierError("%s is not a canonical C2SP verifier key" % field)
    name, key_id_hex, encoded = match.groups()
    try:
        material = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise CausalFrontierError("%s has invalid key material" % field) from None
    if len(material) != 33 or material[0] != 1 or base64.b64encode(material).decode("ascii") != encoded:
        raise CausalFrontierError("%s must contain one Ed25519 public key" % field)
    public_key = material[1:]
    key_id = bytes.fromhex(key_id_hex)
    expected = bytes.fromhex(sha256_bytes(name.encode("utf-8") + b"\n\x01" + public_key))[:4]
    if key_id != expected:
        raise CausalFrontierError("%s key id differs from its name and public key" % field)
    return name, key_id, public_key


def _slot_rule(sequence: int) -> dict[str, int]:
    prior = 2 * (sequence - 1)
    return {
        "prior_tree_size": prior,
        "transition_leaf_index": prior,
        "intermediate_tree_size": prior + 1,
        "seal_leaf_index": prior + 1,
        "final_tree_size": prior + 2,
    }


def _validate_witness(value: Any, index: int) -> dict[str, Any]:
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
        "continuity custody witness[%d]" % index,
    )
    identity_fields = {
        "witness_id",
        "witness_organization_id",
        "controller_group_id",
        "store_group_id",
        "attestation_id",
        "trust_policy_id",
    }
    for key in identity_fields:
        require_id(item[key], "continuity witness %s" % key)
    if len({item[key].casefold() for key in identity_fields}) != len(identity_fields):
        raise CausalFrontierError("continuity witness aliases identities across roles")
    for key in {
        "trust_policy_checkpoint_sha256",
        "trust_anchor_sha256",
        "trust_anchor_spki_sha256",
        "tsa_signer_spki_sha256",
        "openssl_binary_sha256",
    }:
        _digest(item[key], "continuity witness %s" % key)
    if item["independence_state"] != INDEPENDENCE_STATE:
        raise CausalFrontierError("continuity witness invents independence")
    return item


def _validate_store(value: Any, index: int, rule: dict[str, int]) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "store_id",
            "operator_organization_id",
            "controller_group_id",
            "store_group_id",
            "namespace_id",
            "checkpoint_origin",
            "checkpoint_verifier_key",
            "checkpoint_verifier_key_sha256",
            "openssl_binary_sha256",
            "prior_checkpoint_sha256",
            "prior_tree_size",
            "prior_root_sha256",
            "independence_state",
        },
        "continuity store[%d]" % index,
    )
    identity_fields = {
        "store_id",
        "operator_organization_id",
        "controller_group_id",
        "store_group_id",
        "namespace_id",
    }
    for key in identity_fields:
        require_id(item[key], "continuity store %s" % key)
    if len({item[key].casefold() for key in identity_fields}) != len(identity_fields):
        raise CausalFrontierError("continuity store aliases identities across roles")
    origin = item["checkpoint_origin"]
    if not isinstance(origin, str) or ORIGIN_PATTERN.fullmatch(origin) is None:
        raise CausalFrontierError("continuity checkpoint origin is not canonical")
    key_name, _key_id, _public_key = _parse_vkey(item["checkpoint_verifier_key"], "continuity store vkey")
    if key_name != origin:
        raise CausalFrontierError("continuity store vkey name differs from checkpoint origin")
    if item["checkpoint_verifier_key_sha256"] != sha256_bytes(item["checkpoint_verifier_key"].encode("utf-8")):
        raise CausalFrontierError("continuity store vkey digest differs")
    _digest(item["openssl_binary_sha256"], "continuity store OpenSSL checkpoint")
    _digest(item["prior_checkpoint_sha256"], "continuity prior checkpoint")
    if _bounded_nonnegative(item["prior_tree_size"], "continuity prior tree size") != rule["prior_tree_size"]:
        raise CausalFrontierError("continuity prior tree size violates the reserved-slot rule")
    _digest(item["prior_root_sha256"], "continuity prior root hash")
    if item["independence_state"] != INDEPENDENCE_STATE:
        raise CausalFrontierError("continuity store invents independence")
    return item


def _validate_target(
    value: Any, expected_sequence: int
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    target = _shape(
        value,
        {
            "schema_version",
            "status",
            "continuity_id",
            "sequence",
            "predecessor_continuity_state_sha256",
            "fixed_parameter",
            "boundary",
            "generation_plan_checkpoint_sha256",
            "generation_plan_sha256",
            "witness_completion_not_after",
            "statement_profile",
            "checkpoint_profile",
            "proof_profile",
            "slot_rule",
            "cross_log_rule",
            "custody_witnesses",
            "stores",
            "generated_artifact_input_absent",
            "outcome_input_absent",
            "oracle_opening_input_absent",
            "admission_disabled",
            "scoring_disabled",
            "target_sha256",
        },
        "continuity custody target",
    )
    if not (
        target["schema_version"] == TARGET_SCHEMA_VERSION
        and target["status"] == TARGET_STATUS
        and target["fixed_parameter"] == FIXED_PARAMETER
        and canonical_bytes(target["boundary"]) == BOUNDARY_CANONICAL
    ):
        raise CausalFrontierError("continuity custody target changes a fixed contract")
    require_id(target["continuity_id"], "continuity id")
    sequence = _sequence(target["sequence"], "continuity target sequence")
    if sequence != expected_sequence:
        raise CausalFrontierError("continuity target sequence differs from caller checkpoint")
    predecessor = target["predecessor_continuity_state_sha256"]
    if sequence == 1:
        if predecessor is not None:
            raise CausalFrontierError("first continuity target must declare a null predecessor")
    else:
        _digest(predecessor, "continuity predecessor state")
    _digest(target["generation_plan_checkpoint_sha256"], "continuity generation plan checkpoint")
    _digest(target["generation_plan_sha256"], "continuity generation plan semantic digest")
    require_utc_timestamp(target["witness_completion_not_after"], "continuity custody witness deadline")
    if not (
        target["statement_profile"] == STATEMENT_PROFILE
        and target["checkpoint_profile"] == CHECKPOINT_PROFILE
        and target["proof_profile"] == PROOF_PROFILE
        and target["slot_rule"] == _slot_rule(sequence)
        and target["cross_log_rule"] == CROSS_LOG_RULE
    ):
        raise CausalFrontierError("continuity custody target changes the fixed log protocol")
    raw_witnesses = target["custody_witnesses"]
    if not isinstance(raw_witnesses, list) or len(raw_witnesses) != EXACT_CUSTODY_WITNESSES:
        raise CausalFrontierError("continuity target requires exactly two custody witnesses")
    witnesses = [_validate_witness(item, index) for index, item in enumerate(raw_witnesses)]
    witness_ids = [item["witness_id"] for item in witnesses]
    if witness_ids != sorted(witness_ids) or len({item.casefold() for item in witness_ids}) != 2:
        raise CausalFrontierError("continuity witness descriptors are not canonically distinct")
    for key in {"trust_anchor_sha256", "trust_anchor_spki_sha256", "tsa_signer_spki_sha256"}:
        if witnesses[0][key] == witnesses[1][key]:
            raise CausalFrontierError("continuity custody witnesses share %s" % key)
    raw_stores = target["stores"]
    if not isinstance(raw_stores, list) or len(raw_stores) != EXACT_STORES:
        raise CausalFrontierError("continuity target requires exactly two declared stores")
    stores = [_validate_store(item, index, target["slot_rule"]) for index, item in enumerate(raw_stores)]
    store_ids = [item["store_id"] for item in stores]
    if store_ids != sorted(store_ids) or len({item.casefold() for item in store_ids}) != 2:
        raise CausalFrontierError("continuity store descriptors are not canonically distinct")
    witness_identities = {
        item[key].casefold()
        for item in witnesses
        for key in {
            "witness_id",
            "witness_organization_id",
            "controller_group_id",
            "store_group_id",
            "attestation_id",
            "trust_policy_id",
        }
    }
    store_identities = {
        item[key].casefold()
        for item in stores
        for key in {"store_id", "operator_organization_id", "controller_group_id", "store_group_id", "namespace_id"}
    }
    if len(witness_identities) != 12 or len(store_identities) != 10 or witness_identities & store_identities:
        raise CausalFrontierError("continuity custody roles alias across witnesses or stores")
    if len({item["checkpoint_origin"].casefold() for item in stores}) != 2:
        raise CausalFrontierError("continuity stores share a checkpoint origin")
    parsed_keys = [_parse_vkey(item["checkpoint_verifier_key"], "continuity store vkey")[2] for item in stores]
    if parsed_keys[0] == parsed_keys[1]:
        raise CausalFrontierError("continuity stores share Ed25519 key material")
    if not (
        target["generated_artifact_input_absent"] is True
        and target["outcome_input_absent"] is True
        and target["oracle_opening_input_absent"] is True
        and target["admission_disabled"] is True
        and target["scoring_disabled"] is True
    ):
        raise CausalFrontierError("continuity custody target opens an artifact, outcome, admission, or scoring path")
    core = {key: target[key] for key in target if key != "target_sha256"}
    if target["target_sha256"] != sha256_bytes(TARGET_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("continuity custody target semantic digest differs")
    return target, witnesses, stores


def _validate_manifest(
    value: Any, expected_sequence: int
) -> tuple[dict[str, Any], dict[str, str], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest = _shape(
        value,
        {
            "schema_version",
            "status",
            "continuity_id",
            "sequence",
            "fixed_parameter",
            "boundary",
            "custody_target",
            "custody_target_sha256",
            "custody_witnesses",
            "phase_bound_root",
            "phase_bound_manifest_checkpoint_sha256",
            "transition",
            "seal",
            "stores",
            "designated_outcome_input_absent",
            "oracle_opening_input_absent",
            "admission_disabled",
            "scoring_disabled",
            "composition_sha256",
        },
        "continuity composition manifest",
    )
    if not (
        manifest["schema_version"] == COMPOSITION_SCHEMA_VERSION
        and manifest["status"] == COMPOSITION_STATUS
        and manifest["fixed_parameter"] == FIXED_PARAMETER
        and canonical_bytes(manifest["boundary"]) == BOUNDARY_CANONICAL
    ):
        raise CausalFrontierError("continuity composition changes a fixed contract")
    require_id(manifest["continuity_id"], "continuity composition id")
    if _sequence(manifest["sequence"], "continuity composition sequence") != expected_sequence:
        raise CausalFrontierError("continuity composition sequence differs from caller checkpoint")
    target_path, target_checkpoint = _file(manifest["custody_target"], "continuity custody target", MEDIA_JSON)
    transition_path, transition_checkpoint = _file(manifest["transition"], "continuity transition", MEDIA_JSON)
    seal_path, seal_checkpoint = _file(manifest["seal"], "continuity seal", MEDIA_JSON)
    phase_root = _root(manifest["phase_bound_root"], "continuity phase-bound root")
    _digest(manifest["custody_target_sha256"], "continuity target semantic digest")
    _digest(manifest["phase_bound_manifest_checkpoint_sha256"], "continuity phase-bound checkpoint")
    raw_witnesses = manifest["custody_witnesses"]
    if not isinstance(raw_witnesses, list) or len(raw_witnesses) != 2:
        raise CausalFrontierError("continuity composition must close exactly two custody witnesses")
    witnesses: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_witnesses):
        item = _shape(
            raw,
            {
                "witness_id",
                "attestation_root",
                "attestation_checkpoint_sha256",
                "trust_policy_root",
                "trust_policy_checkpoint_sha256",
            },
            "continuity manifest witness[%d]" % index,
        )
        require_id(item["witness_id"], "continuity manifest witness id")
        item["attestation_root"] = _root(item["attestation_root"], "continuity witness attestation root")
        item["trust_policy_root"] = _root(item["trust_policy_root"], "continuity witness trust root")
        _digest(item["attestation_checkpoint_sha256"], "continuity attestation checkpoint")
        _digest(item["trust_policy_checkpoint_sha256"], "continuity trust-policy checkpoint")
        witnesses.append(item)
    if [item["witness_id"] for item in witnesses] != sorted(item["witness_id"] for item in witnesses):
        raise CausalFrontierError("continuity manifest witness order differs")
    raw_stores = manifest["stores"]
    if not isinstance(raw_stores, list) or len(raw_stores) != 2:
        raise CausalFrontierError("continuity composition must close exactly two stores")
    stores: list[dict[str, Any]] = []
    file_fields = {
        "prior_checkpoint": MEDIA_CHECKPOINT,
        "prior_to_intermediate_consistency": MEDIA_JSON,
        "intermediate_checkpoint": MEDIA_CHECKPOINT,
        "transition_inclusion": MEDIA_JSON,
        "intermediate_to_final_consistency": MEDIA_JSON,
        "final_checkpoint": MEDIA_CHECKPOINT,
        "seal_inclusion": MEDIA_JSON,
    }
    for index, raw in enumerate(raw_stores):
        item = dict(_shape(raw, {"store_id", *file_fields}, "continuity manifest store[%d]" % index))
        require_id(item["store_id"], "continuity manifest store id")
        item["_files"] = {
            key: _file(item[key], "continuity %s" % key.replace("_", " "), media) for key, media in file_fields.items()
        }
        stores.append(item)
    if [item["store_id"] for item in stores] != sorted(item["store_id"] for item in stores):
        raise CausalFrontierError("continuity manifest store order differs")
    direct_list = [
        COMPOSITION_MANIFEST,
        target_path,
        transition_path,
        seal_path,
        *(path for item in stores for path, _digest_value in item["_files"].values()),
    ]
    prefix_list = [
        phase_root,
        *(item["attestation_root"] for item in witnesses),
        *(item["trust_policy_root"] for item in witnesses),
    ]
    all_paths = direct_list + prefix_list
    if len({item.casefold() for item in all_paths}) != len(all_paths) or any(
        _overlap(left, right) for index, left in enumerate(all_paths) for right in all_paths[index + 1 :]
    ):
        raise CausalFrontierError("continuity composition paths overlap")
    if not (
        manifest["designated_outcome_input_absent"] is True
        and manifest["oracle_opening_input_absent"] is True
        and manifest["admission_disabled"] is True
        and manifest["scoring_disabled"] is True
    ):
        raise CausalFrontierError("continuity composition opens an outcome, admission, or scoring path")
    core = {key: manifest[key] for key in manifest if key != "composition_sha256"}
    if manifest["composition_sha256"] != sha256_bytes(COMPOSITION_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("continuity composition semantic digest differs")
    paths = {
        "target": target_path,
        "target_checkpoint": target_checkpoint,
        "transition": transition_path,
        "transition_checkpoint": transition_checkpoint,
        "seal": seal_path,
        "seal_checkpoint": seal_checkpoint,
        "phase_root": phase_root,
    }
    return manifest, paths, witnesses, stores


def _inventory(
    root_fd: int, prefix: str = "", entries: set[str] | None = None, visited: list[int] | None = None
) -> set[str]:
    entries = set() if entries is None else entries
    visited = [0] if visited is None else visited
    names: list[str] = []
    with os.scandir(root_fd) as directory:
        for entry in directory:
            visited[0] += 1
            if visited[0] > MAX_FILES:
                raise CausalFrontierError("continuity composition exceeds its fixed file limit")
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
                    "continuity composition contains an empty directory",
                    reason_code="INVENTORY_MISMATCH",
                    operation="sentinel_continuity._inventory",
                )
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entries.add(relative)
        else:
            raise CausalFrontierError(
                "continuity composition contains an unsafe filesystem object",
                reason_code="SAFE_FILE_REJECTED",
                operation="sentinel_continuity._inventory",
            )
    return entries


def _snapshot_bundle(
    root: Path, expected_manifest_sha256: str, expected_sequence: int
) -> tuple[dict[str, Any], dict[str, bytes], set[str], dict[str, str], list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, COMPOSITION_MANIFEST)
            if sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("continuity composition external checkpoint mismatch")
            manifest_value = _canonical_json(raw_manifest, "continuity composition manifest")
            manifest, paths, witnesses, stores = _validate_manifest(manifest_value, expected_sequence)
            inventory = _inventory(descriptor)
            direct = {
                COMPOSITION_MANIFEST,
                paths["target"],
                paths["transition"],
                paths["seal"],
                *(path for item in stores for path, _value in item["_files"].values()),
            }
            prefixes = {
                paths["phase_root"],
                *(item["attestation_root"] for item in witnesses),
                *(item["trust_policy_root"] for item in witnesses),
            }
            covered = direct | {path for path in inventory if any(_under(path, prefix) for prefix in prefixes)}
            if inventory != covered or any(not any(_under(path, prefix) for path in inventory) for prefix in prefixes):
                raise CausalFrontierError(
                    "continuity composition inventory is orphaned or incomplete",
                    reason_code="INVENTORY_MISMATCH",
                    operation="sentinel_continuity._snapshot_bundle",
                )
            snapshots: dict[str, bytes] = {}
            total = 0
            for relative in sorted(inventory):
                raw = raw_manifest if relative == COMPOSITION_MANIFEST else receipt_io._snapshot(descriptor, relative)
                total += len(raw)
                if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("continuity composition exceeds its fixed byte limits")
                snapshots[relative] = raw
            declared = {
                paths["target"]: paths["target_checkpoint"],
                paths["transition"]: paths["transition_checkpoint"],
                paths["seal"]: paths["seal_checkpoint"],
                **{path: digest for item in stores for path, digest in item["_files"].values()},
            }
            if any(sha256_bytes(snapshots[path]) != digest for path, digest in declared.items()):
                raise CausalFrontierError("continuity declared artifact bytes differ")
            if _inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "continuity inventory changed while being read",
                    reason_code="INPUT_CHANGED",
                    operation="sentinel_continuity._snapshot_bundle",
                )
    except OSError as exc:
        raise io_error(
            exc, "continuity composition cannot be read safely", operation="sentinel_continuity._snapshot_bundle"
        ) from None
    return manifest, snapshots, inventory, paths, witnesses, stores


def _write_private_snapshot(root: Path, relative: str, raw: bytes) -> None:
    destination = root.joinpath(*relative.split("/"))
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise CausalFrontierError("private continuity snapshot write did not progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _runtime_inputs(
    paths: Sequence[Path], digests: Sequence[str], expected: list[str], label: str
) -> list[tuple[Path, str]]:
    if (
        not isinstance(paths, SequenceABC)
        or not isinstance(digests, SequenceABC)
        or isinstance(paths, (str, bytes))
        or isinstance(digests, (str, bytes))
        or len(paths) != 2
        or len(digests) != 2
    ):
        raise CausalFrontierError("%s requires exactly two aligned OpenSSL runtimes" % label)
    result: list[tuple[Path, str]] = []
    for index, (path, digest) in enumerate(zip(paths, digests, strict=True)):
        if not isinstance(path, Path):
            raise CausalFrontierError("%s OpenSSL runtime path must be a Path" % label)
        digest = _digest(digest, "%s OpenSSL checkpoint" % label)
        if digest != expected[index]:
            raise CausalFrontierError("%s OpenSSL runtime differs from the pre-token target" % label)
        result.append((path, digest))
    return result


def _checkpoint_components(
    raw: bytes, store: dict[str, Any], label: str
) -> tuple[bytes, int, bytes, list[bytes], bytes]:
    if not 1 <= len(raw) <= MAX_CHECKPOINT_BYTES or b"\r" in raw or not raw.endswith(b"\n"):
        raise CausalFrontierError("%s is not a bounded LF-terminated C2SP note" % label)
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise CausalFrontierError("%s is not UTF-8" % label) from None
    if any(ord(char) < 0x20 and char != "\n" for char in text) or "\x7f" in text:
        raise CausalFrontierError("%s contains a forbidden control character" % label)
    separator = raw.rfind(b"\n\n")
    if separator < 0:
        raise CausalFrontierError("%s has no signed-note separator" % label)
    note = raw[: separator + 1]
    signature_section = raw[separator + 2 :]
    note_lines = note[:-1].split(b"\n")
    if len(note_lines) != 3 or any(not line for line in note_lines):
        raise CausalFrontierError("%s must use an extension-free three-line checkpoint body" % label)
    try:
        origin = note_lines[0].decode("utf-8")
        size_text = note_lines[1].decode("ascii")
        root_text = note_lines[2].decode("ascii")
    except UnicodeError:
        raise CausalFrontierError("%s checkpoint body encoding differs" % label) from None
    if origin != store["checkpoint_origin"] or DECIMAL_PATTERN.fullmatch(size_text) is None:
        raise CausalFrontierError("%s origin or tree-size encoding differs" % label)
    size = int(size_text)
    if size > 2 * MAX_SEQUENCE:
        raise CausalFrontierError("%s tree size exceeds the fixed limit" % label)
    root_hash = _canonical_base64(root_text, "%s root" % label)
    signature_lines = signature_section.splitlines(keepends=True)
    if not 1 <= len(signature_lines) <= MAX_CHECKPOINT_SIGNATURES or any(
        not line.endswith(b"\n") for line in signature_lines
    ):
        raise CausalFrontierError("%s signature count or framing is outside the C2SP profile" % label)
    key_name, key_id, public_key = _parse_vkey(store["checkpoint_verifier_key"], "%s vkey" % label)
    known_signatures: list[bytes] = []
    for index, line in enumerate(signature_lines):
        try:
            signature_text = line.decode("utf-8")
        except UnicodeError:
            raise CausalFrontierError("%s signature[%d] is not UTF-8" % (label, index)) from None
        if not signature_text.startswith("— ") or not signature_text.endswith("\n"):
            raise CausalFrontierError("%s signature[%d] framing differs" % (label, index))
        fields = signature_text[2:-1].split(" ")
        if len(fields) != 2 or ORIGIN_PATTERN.fullmatch(fields[0]) is None:
            raise CausalFrontierError("%s signature[%d] name differs" % (label, index))
        signer_name, encoded = fields
        try:
            signature_blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise CausalFrontierError("%s signature[%d] is not valid base64" % (label, index)) from None
        if not 5 <= len(signature_blob) <= MAX_SIGNATURE_BLOB_BYTES or (
            base64.b64encode(signature_blob).decode("ascii") != encoded
        ):
            raise CausalFrontierError("%s signature[%d] encoding differs" % (label, index))
        if signer_name == key_name and signature_blob[:4] == key_id:
            if len(signature_blob) != 68:
                raise CausalFrontierError("%s pinned Ed25519 signature[%d] has the wrong width" % (label, index))
            known_signatures.append(signature_blob[4:])
    if not known_signatures:
        raise CausalFrontierError("%s has no signature from its pinned checkpoint key" % label)
    return note, size, root_hash, known_signatures, public_key


def _verify_checkpoint_set(
    raws: list[bytes], store: dict[str, Any], openssl_path: Path, openssl_sha256: str
) -> list[tuple[int, bytes]]:
    parsed = [_checkpoint_components(raw, store, "continuity checkpoint[%d]" % index) for index, raw in enumerate(raws)]
    openssl_bytes, _digest_value = attestation._read_openssl_binary(openssl_path, openssl_sha256)
    with tempfile.TemporaryDirectory(prefix="causalfrontier-c2sp-checkpoint-") as temporary:
        root = Path(temporary).resolve(strict=True)
        binary = root / "openssl-verifier"
        config = root / "openssl.cnf"
        empty = root / "empty-cert-directory"
        empty.mkdir(mode=0o700)
        attestation._write_private(binary, openssl_bytes)
        attestation._write_private(config, attestation.OPENSSL_CONFIG)
        binary.chmod(0o500)
        version = attestation._run_openssl(binary, ["version"], "C2SP version inspection", root, config).strip()
        if attestation.OPENSSL_VERSION.fullmatch(version) is None:
            raise CausalFrontierError("continuity checkpoint verifier requires an exact OpenSSL 3 identity")
        for index, (note, _size, _root_hash, signatures, public_key) in enumerate(parsed):
            note_path = root / ("note-%d.txt" % index)
            public_path = root / ("public-%d.der" % index)
            attestation._write_private(note_path, note)
            attestation._write_private(public_path, ED25519_SPKI_PREFIX + public_key)
            for signature_index, signature in enumerate(signatures):
                signature_path = root / ("signature-%d-%d.bin" % (index, signature_index))
                attestation._write_private(signature_path, signature)
                attestation._run_openssl(
                    binary,
                    [
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        str(public_path),
                        "-keyform",
                        "DER",
                        "-rawin",
                        "-in",
                        str(note_path),
                        "-sigfile",
                        str(signature_path),
                    ],
                    "C2SP Ed25519 checkpoint signature",
                    root,
                    config,
                )
        if sha256_bytes(binary.read_bytes()) != openssl_sha256:
            raise CausalFrontierError("private checkpoint OpenSSL snapshot changed")
    return [(size, root_hash) for _note, size, root_hash, _signatures, _key in parsed]


def _proof(raw: bytes, proof_type: str, left_size: int, right_size: int, label: str) -> list[bytes]:
    value = _shape(
        _canonical_json(raw, label),
        {"schema_version", "proof_profile", "proof_type", "left_size", "right_size", "hashes"},
        label,
    )
    if not (
        value["schema_version"] == PROOF_SCHEMA_VERSION
        and value["proof_profile"] == PROOF_PROFILE
        and value["proof_type"] == proof_type
        and _bounded_nonnegative(value["left_size"], "%s left size" % label) == left_size
        and _bounded_nonnegative(value["right_size"], "%s right size" % label) == right_size
    ):
        raise CausalFrontierError("%s changes the fixed proof contract" % label)
    hashes = value["hashes"]
    if not isinstance(hashes, list) or len(hashes) > MAX_PROOF_HASHES:
        raise CausalFrontierError("%s hash path exceeds its fixed limit" % label)
    return [_canonical_base64(item, "%s hash[%d]" % (label, index)) for index, item in enumerate(hashes)]


def _transition(
    target: dict[str, Any],
    phase: dict[str, Any],
    custody_reports: list[dict[str, Any]],
    target_checkpoint: str,
    phase_checkpoint: str,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema_version": TRANSITION_SCHEMA_VERSION,
        "status": TRANSITION_STATUS,
        "record_type": "CAUSALFRONTIER_SENTINEL_PHASE_BOUND_TRANSITION",
        "continuity_id": target["continuity_id"],
        "sequence": target["sequence"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "predecessor_continuity_state_sha256": target["predecessor_continuity_state_sha256"],
        "custody_target_checkpoint_sha256": target_checkpoint,
        "custody_target_sha256": target["target_sha256"],
        "custody_witness_report_sha256s": [report["report_sha256"] for report in custody_reports],
        "generation_phase_context": phase["generation_phase_context"],
        "phase1_dual_witness_preflight_sha256": phase["phase1_dual_witness_preflight_sha256"],
        "phase_bound_composition_manifest_checkpoint_sha256": phase_checkpoint,
        "phase_bound_composition_sha256": phase["composition_sha256"],
        "phase_bound_preflight_sha256": phase["preflight_sha256"],
        "sentinel_manifest_checkpoint_sha256": phase["sentinel_manifest_checkpoint_sha256"],
        "sentinel_structural_preflight_sha256": phase["sentinel_structural_preflight_sha256"],
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    return {**core, "transition_sha256": sha256_bytes(TRANSITION_DOMAIN_TAG + canonical_bytes(core))}


def _seal(
    target: dict[str, Any], transition: dict[str, Any], intermediate: list[dict[str, Any]], transition_checkpoint: str
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema_version": SEAL_SCHEMA_VERSION,
        "status": SEAL_STATUS,
        "record_type": "CAUSALFRONTIER_SENTINEL_DUAL_DECLARED_LOG_SEAL",
        "continuity_id": target["continuity_id"],
        "sequence": target["sequence"],
        "transition_statement_checkpoint_sha256": transition_checkpoint,
        "transition_statement_sha256": transition["transition_sha256"],
        "stores": intermediate,
        "partial_commit_accepted": False,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    return {**core, "seal_sha256": sha256_bytes(SEAL_DOMAIN_TAG + canonical_bytes(core))}


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def _read_predecessor_state(
    path: Path,
    expected_state_sha256: str,
    target: dict[str, Any],
    stores: list[dict[str, Any]],
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(path, Path):
        raise CausalFrontierError("continuity predecessor state path must be a Path")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError as exc:
        raise io_error(
            exc,
            "continuity predecessor state cannot be read safely",
            operation="sentinel_continuity._read_predecessor_state",
        ) from None
    value = _shape(
        _canonical_json(raw, "continuity predecessor state"),
        {
            "schema_version",
            "continuity_id",
            "sequence",
            "fixed_parameter",
            "transition_sha256",
            "seal_sha256",
            "stores",
            "state_sha256",
        },
        "continuity predecessor state",
    )
    predecessor_sequence = _sequence(value["sequence"], "continuity predecessor sequence")
    if not (
        value["schema_version"] == "causalfrontier.sentinel-dual-declared-log-continuity-state.v1"
        and value["continuity_id"] == target["continuity_id"]
        and predecessor_sequence == target["sequence"] - 1
        and value["fixed_parameter"] == FIXED_PARAMETER
    ):
        raise CausalFrontierError("continuity predecessor state belongs to a different chain or sequence")
    _digest(value["transition_sha256"], "continuity predecessor transition")
    _digest(value["seal_sha256"], "continuity predecessor seal")
    core = {key: value[key] for key in value if key != "state_sha256"}
    if value["state_sha256"] != sha256_bytes(STATE_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("continuity predecessor state semantic digest differs")
    if value["state_sha256"] != expected_state_sha256:
        raise CausalFrontierError("continuity predecessor state differs from caller and pre-token checkpoints")
    raw_stores = value["stores"]
    if not isinstance(raw_stores, list) or len(raw_stores) != EXACT_STORES:
        raise CausalFrontierError("continuity predecessor state must close exactly two stores")
    previous: list[dict[str, Any]] = []
    for index, raw_store in enumerate(raw_stores):
        item = _shape(
            raw_store,
            {
                "store_id",
                "operator_organization_id",
                "controller_group_id",
                "store_group_id",
                "namespace_id",
                "checkpoint_origin",
                "checkpoint_verifier_key_sha256",
                "openssl_binary_sha256",
                "independence_state",
                "final_checkpoint_sha256",
                "final_tree_size",
                "final_root_sha256",
            },
            "continuity predecessor store[%d]" % index,
        )
        for key in {
            "store_id",
            "operator_organization_id",
            "controller_group_id",
            "store_group_id",
            "namespace_id",
        }:
            require_id(item[key], "continuity predecessor %s" % key)
        if (
            not isinstance(item["checkpoint_origin"], str)
            or ORIGIN_PATTERN.fullmatch(item["checkpoint_origin"]) is None
        ):
            raise CausalFrontierError("continuity predecessor checkpoint origin is not canonical")
        for key in {
            "checkpoint_verifier_key_sha256",
            "openssl_binary_sha256",
            "final_checkpoint_sha256",
            "final_root_sha256",
        }:
            _digest(item[key], "continuity predecessor %s" % key)
        if item["independence_state"] != INDEPENDENCE_STATE:
            raise CausalFrontierError("continuity predecessor state invents independence")
        _bounded_nonnegative(item["final_tree_size"], "continuity predecessor final tree size")
        previous.append(item)
    if [item["store_id"] for item in previous] != sorted(item["store_id"] for item in previous):
        raise CausalFrontierError("continuity predecessor store order differs")
    for previous_store, current_store in zip(previous, stores, strict=True):
        if not (
            previous_store["store_id"] == current_store["store_id"]
            and previous_store["operator_organization_id"] == current_store["operator_organization_id"]
            and previous_store["controller_group_id"] == current_store["controller_group_id"]
            and previous_store["store_group_id"] == current_store["store_group_id"]
            and previous_store["namespace_id"] == current_store["namespace_id"]
            and previous_store["checkpoint_origin"] == current_store["checkpoint_origin"]
            and previous_store["checkpoint_verifier_key_sha256"] == current_store["checkpoint_verifier_key_sha256"]
            and previous_store["openssl_binary_sha256"] == current_store["openssl_binary_sha256"]
            and previous_store["independence_state"] == current_store["independence_state"]
            and previous_store["final_checkpoint_sha256"] == current_store["prior_checkpoint_sha256"]
            and previous_store["final_tree_size"] == current_store["prior_tree_size"]
            and previous_store["final_root_sha256"] == current_store["prior_root_sha256"]
        ):
            raise CausalFrontierError("continuity predecessor state does not equal this step's prior store state")
    return raw, value


def preflight_sentinel_dual_log_continuity(
    root: Path,
    expected_composition_manifest_sha256: str,
    expected_sequence: int,
    expected_predecessor_continuity_state_sha256: str | None,
    predecessor_continuity_state_path: Path | None,
    expected_prior_store_checkpoint_sha256s: Sequence[str],
    expected_final_store_checkpoint_sha256s: Sequence[str],
    phase_openssl_paths: Sequence[Path],
    expected_phase_openssl_sha256s: Sequence[str],
    custody_openssl_paths: Sequence[Path],
    expected_custody_openssl_sha256s: Sequence[str],
    store_openssl_paths: Sequence[Path],
    expected_store_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Replay one dual-timestamped, two-log continuity step without admission."""

    _digest(expected_composition_manifest_sha256, "continuity composition external checkpoint")
    expected_sequence = _sequence(expected_sequence, "continuity caller sequence")
    if expected_sequence == 1:
        if expected_predecessor_continuity_state_sha256 is not None or predecessor_continuity_state_path is not None:
            raise CausalFrontierError("first continuity replay requires a null predecessor and no predecessor file")
    else:
        _digest(expected_predecessor_continuity_state_sha256, "continuity caller predecessor state")
        if not isinstance(predecessor_continuity_state_path, Path):
            raise CausalFrontierError("later continuity replay requires a caller-supplied predecessor state file")
    manifest, snapshots, inventory, paths, manifest_witnesses, manifest_stores = _snapshot_bundle(
        root, expected_composition_manifest_sha256, expected_sequence
    )
    target = _canonical_json(snapshots[paths["target"]], "continuity custody target")
    target, target_witnesses, target_stores = _validate_target(target, expected_sequence)
    if not (
        target["continuity_id"] == manifest["continuity_id"]
        and target["target_sha256"] == manifest["custody_target_sha256"]
        and target["predecessor_continuity_state_sha256"] == expected_predecessor_continuity_state_sha256
    ):
        raise CausalFrontierError("continuity manifest, target, or caller predecessor differs")
    if [item["witness_id"] for item in manifest_witnesses] != [item["witness_id"] for item in target_witnesses]:
        raise CausalFrontierError("continuity composition closes a different custody witness pair")
    if [item["store_id"] for item in manifest_stores] != [item["store_id"] for item in target_stores]:
        raise CausalFrontierError("continuity composition closes a different store pair")
    for manifest_item, target_item in zip(manifest_witnesses, target_witnesses, strict=True):
        if manifest_item["trust_policy_checkpoint_sha256"] != target_item["trust_policy_checkpoint_sha256"]:
            raise CausalFrontierError("continuity trust policy differs from the pre-token target")
    if (
        not isinstance(expected_prior_store_checkpoint_sha256s, SequenceABC)
        or not isinstance(expected_final_store_checkpoint_sha256s, SequenceABC)
        or isinstance(expected_prior_store_checkpoint_sha256s, (str, bytes))
        or isinstance(expected_final_store_checkpoint_sha256s, (str, bytes))
        or len(expected_prior_store_checkpoint_sha256s) != 2
        or len(expected_final_store_checkpoint_sha256s) != 2
    ):
        raise CausalFrontierError("continuity replay requires exactly two prior and two final caller checkpoints")
    prior_pins = [
        _digest(item, "continuity caller prior checkpoint") for item in expected_prior_store_checkpoint_sha256s
    ]
    final_pins = [
        _digest(item, "continuity caller final checkpoint") for item in expected_final_store_checkpoint_sha256s
    ]
    if prior_pins != [item["prior_checkpoint_sha256"] for item in target_stores]:
        raise CausalFrontierError("continuity caller prior checkpoints differ from the pre-token target")
    if final_pins != [item["_files"]["final_checkpoint"][1] for item in manifest_stores]:
        raise CausalFrontierError("continuity caller final checkpoints differ from the closed composition")
    predecessor_raw: bytes | None = None
    if predecessor_continuity_state_path is not None:
        predecessor_raw, _predecessor_state = _read_predecessor_state(
            predecessor_continuity_state_path,
            expected_predecessor_continuity_state_sha256,
            target,
            target_stores,
        )

    phase_runtimes = _runtime_inputs(
        phase_openssl_paths,
        expected_phase_openssl_sha256s,
        list(expected_phase_openssl_sha256s),
        "continuity phase replay",
    )
    custody_runtimes = _runtime_inputs(
        custody_openssl_paths,
        expected_custody_openssl_sha256s,
        [item["openssl_binary_sha256"] for item in target_witnesses],
        "continuity custody replay",
    )
    store_runtimes = _runtime_inputs(
        store_openssl_paths,
        expected_store_openssl_sha256s,
        [item["openssl_binary_sha256"] for item in target_stores],
        "continuity store replay",
    )

    with tempfile.TemporaryDirectory(prefix="causalfrontier-continuity-") as temporary:
        staged_root = Path(temporary).resolve(strict=True)
        for relative, raw in sorted(snapshots.items()):
            _write_private_snapshot(staged_root, relative, raw)
        custody_reports: list[dict[str, Any]] = []
        for manifest_item, target_item, runtime in zip(
            manifest_witnesses, target_witnesses, custody_runtimes, strict=True
        ):
            report = attestation.verify_rfc3161_attestation(
                staged_root / paths["target"],
                paths["target_checkpoint"],
                staged_root / manifest_item["attestation_root"],
                manifest_item["attestation_checkpoint_sha256"],
                staged_root / manifest_item["trust_policy_root"],
                manifest_item["trust_policy_checkpoint_sha256"],
                runtime[0],
                runtime[1],
                target["witness_completion_not_after"],
            )
            if not (
                report["attestation_id"] == target_item["attestation_id"]
                and report["trust_policy_id"] == target_item["trust_policy_id"]
                and report["trust_anchor_sha256"] == target_item["trust_anchor_sha256"]
                and report["trust_anchor_spki_sha256"] == target_item["trust_anchor_spki_sha256"]
                and report["tsa_signer_spki_sha256"] == target_item["tsa_signer_spki_sha256"]
                and report["openssl_binary_sha256"] == target_item["openssl_binary_sha256"]
                and report["target_checkpoint_sha256"] == paths["target_checkpoint"]
                and report[
                    "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"
                ]
                is True
            ):
                raise CausalFrontierError("continuity custody witness report differs from the pre-token target")
            custody_reports.append(report)
        if len({report["timestamp_token_sha256"] for report in custody_reports}) != 2:
            raise CausalFrontierError("continuity custody witnesses reuse one timestamp token")

        phase_report = sentinel_phase.preflight_sentinel_phase_bound_admission(
            staged_root / paths["phase_root"],
            manifest["phase_bound_manifest_checkpoint_sha256"],
            expected_sequence,
            [item[0] for item in phase_runtimes],
            [item[1] for item in phase_runtimes],
        )
        if not (
            target["generation_plan_checkpoint_sha256"] == phase_report["generation_plan_checkpoint_sha256"]
            and target["generation_plan_sha256"] == phase_report["generation_plan_sha256"]
        ):
            raise CausalFrontierError("continuity pre-token target binds a different generation plan")
        transition = _transition(
            target,
            phase_report,
            custody_reports,
            paths["target_checkpoint"],
            manifest["phase_bound_manifest_checkpoint_sha256"],
        )
        if snapshots[paths["transition"]] != canonical_bytes(transition) + b"\n":
            raise CausalFrontierError("continuity transition differs from fresh Phase 2 replay")

        rule = target["slot_rule"]
        checkpoint_values: list[list[tuple[int, bytes]]] = []
        intermediate_records: list[dict[str, Any]] = []
        for manifest_store, target_store, runtime in zip(manifest_stores, target_stores, store_runtimes, strict=True):
            raw_checkpoints = [
                snapshots[manifest_store["_files"][name][0]]
                for name in ("prior_checkpoint", "intermediate_checkpoint", "final_checkpoint")
            ]
            values = _verify_checkpoint_set(raw_checkpoints, target_store, runtime[0], runtime[1])
            expected_sizes = [rule["prior_tree_size"], rule["intermediate_tree_size"], rule["final_tree_size"]]
            if [size for size, _root_hash in values] != expected_sizes:
                raise CausalFrontierError("continuity signed checkpoint sizes violate the reserved-slot rule")
            if values[0][1].hex() != target_store["prior_root_sha256"]:
                raise CausalFrontierError("continuity prior signed root differs from the pre-token target")
            if sha256_bytes(raw_checkpoints[0]) != target_store["prior_checkpoint_sha256"]:
                raise CausalFrontierError("continuity prior signed checkpoint differs from the pre-token target")
            prior_consistency = _proof(
                snapshots[manifest_store["_files"]["prior_to_intermediate_consistency"][0]],
                "CONSISTENCY",
                rule["prior_tree_size"],
                rule["intermediate_tree_size"],
                "continuity prior-to-intermediate consistency proof",
            )
            if not _transparency.verify_consistency_proof(
                rule["prior_tree_size"],
                rule["intermediate_tree_size"],
                values[0][1],
                values[1][1],
                prior_consistency,
            ):
                raise CausalFrontierError("continuity prior-to-intermediate consistency proof is invalid")
            transition_inclusion = _proof(
                snapshots[manifest_store["_files"]["transition_inclusion"][0]],
                "INCLUSION",
                rule["transition_leaf_index"],
                rule["intermediate_tree_size"],
                "continuity transition inclusion proof",
            )
            if not _transparency.verify_inclusion_proof(
                _transparency.leaf_hash(snapshots[paths["transition"]]),
                rule["transition_leaf_index"],
                rule["intermediate_tree_size"],
                transition_inclusion,
                values[1][1],
            ):
                raise CausalFrontierError("continuity transition inclusion proof is invalid")
            intermediate_records.append(
                {
                    "store_id": target_store["store_id"],
                    "intermediate_checkpoint_sha256": sha256_bytes(raw_checkpoints[1]),
                    "intermediate_root_sha256": values[1][1].hex(),
                    "intermediate_tree_size": values[1][0],
                }
            )
            checkpoint_values.append(values)
        seal = _seal(target, transition, intermediate_records, paths["transition_checkpoint"])
        if snapshots[paths["seal"]] != canonical_bytes(seal) + b"\n":
            raise CausalFrontierError("continuity seal differs from both exact intermediate checkpoints")
        for manifest_store, values in zip(manifest_stores, checkpoint_values, strict=True):
            final_consistency = _proof(
                snapshots[manifest_store["_files"]["intermediate_to_final_consistency"][0]],
                "CONSISTENCY",
                rule["intermediate_tree_size"],
                rule["final_tree_size"],
                "continuity intermediate-to-final consistency proof",
            )
            if not _transparency.verify_consistency_proof(
                rule["intermediate_tree_size"],
                rule["final_tree_size"],
                values[1][1],
                values[2][1],
                final_consistency,
            ):
                raise CausalFrontierError("continuity intermediate-to-final consistency proof is invalid")
            seal_inclusion = _proof(
                snapshots[manifest_store["_files"]["seal_inclusion"][0]],
                "INCLUSION",
                rule["seal_leaf_index"],
                rule["final_tree_size"],
                "continuity seal inclusion proof",
            )
            if not _transparency.verify_inclusion_proof(
                _transparency.leaf_hash(snapshots[paths["seal"]]),
                rule["seal_leaf_index"],
                rule["final_tree_size"],
                seal_inclusion,
                values[2][1],
            ):
                raise CausalFrontierError("continuity seal inclusion proof is invalid")

    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            if _inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "continuity inventory changed during replay",
                    reason_code="INPUT_CHANGED",
                    operation="sentinel_continuity.preflight_sentinel_dual_log_continuity",
                )
            for relative, raw in snapshots.items():
                if receipt_io._snapshot(descriptor, relative) != raw:
                    raise CausalFrontierError(
                        "continuity bytes changed during replay",
                        reason_code="INPUT_CHANGED",
                        operation="sentinel_continuity.preflight_sentinel_dual_log_continuity",
                    )
    except OSError as exc:
        raise io_error(
            exc,
            "continuity composition cannot be reread safely",
            operation="sentinel_continuity.preflight_sentinel_dual_log_continuity",
        ) from None
    if predecessor_continuity_state_path is not None and predecessor_raw is not None:
        repeated_predecessor_raw, _repeated_predecessor_state = _read_predecessor_state(
            predecessor_continuity_state_path,
            expected_predecessor_continuity_state_sha256,
            target,
            target_stores,
        )
        if repeated_predecessor_raw != predecessor_raw:
            raise CausalFrontierError(
                "continuity predecessor state changed during replay",
                reason_code="INPUT_CHANGED",
                operation="sentinel_continuity.preflight_sentinel_dual_log_continuity",
            )

    gates = sorted(
        [
            _gate("closed_composition", "PASS", "ONE_CALLER_CHECKPOINTED_OUTER_SNAPSHOT_REPLAYED"),
            _gate("pre_token_custody", "PASS", "DUAL_RFC3161_CUSTODY_TARGET_REPLAYED_FROM_RAW_EVIDENCE"),
            _gate("phase_bound_transition", "PASS", "TRANSITION_DERIVED_FROM_FRESH_PHASE1_AND_PHASE2_REPLAY"),
            _gate("prior_head_binding", "PASS", "BOTH_PRIOR_SIGNED_HEADS_EQUAL_PRE_TOKEN_AND_CALLER_CHECKPOINTS"),
            _gate("reserved_transition_slots", "PASS", "IDENTICAL_TRANSITION_INCLUDED_AT_BOTH_PRESCRIBED_POSITIONS"),
            _gate("cross_log_seal", "PASS", "IDENTICAL_SEAL_COMMITS_BOTH_INTERMEDIATE_SIGNED_CHECKPOINTS"),
            _gate("reserved_seal_slots", "PASS", "IDENTICAL_SEAL_INCLUDED_AT_BOTH_NEXT_PRESCRIBED_POSITIONS"),
            _gate("supplied_view_continuity", "PASS", "BOTH_TWO_STEP_CONSISTENCY_CHAINS_REPLAYED"),
            _gate("global_uniqueness", "NO_CALL", "SUPPLIED_LOG_VIEWS_CANNOT_EXCLUDE_HIDDEN_OR_FUTURE_FORKS"),
            _gate("rollback_currentness", "NO_CALL", "CALLER_FINAL_HEADS_ARE_NOT_GLOBAL_LATESTNESS"),
            _gate("store_independence", "NO_CALL", "DISTINCT_KEYS_AND_IDENTIFIERS_DO_NOT_PROVE_INDEPENDENCE"),
            _gate("prospective_order", "NO_CALL", "NO_INDEPENDENTLY_OBSERVED_GENERATOR_EXECUTION"),
            _gate("privacy", "NO_CALL", "STRUCTURAL_REPLAY_IS_NOT_PRIVACY_CERTIFICATION"),
            _gate("scientific_scoring", "NO_CALL", "NO_OUTCOME_COMPARATOR_RESOURCE_OR_SCORE_CHANNEL"),
            _gate("authority", "PASS", "NO_CLINICAL_BIOLOGICAL_OR_MATERIAL_AUTHORITY_GRANTED"),
        ],
        key=lambda item: item["id"],
    )
    current_state_core = {
        "schema_version": "causalfrontier.sentinel-dual-declared-log-continuity-state.v1",
        "continuity_id": target["continuity_id"],
        "sequence": expected_sequence,
        "fixed_parameter": FIXED_PARAMETER,
        "transition_sha256": transition["transition_sha256"],
        "seal_sha256": seal["seal_sha256"],
        "stores": [
            {
                "store_id": target_store["store_id"],
                "operator_organization_id": target_store["operator_organization_id"],
                "controller_group_id": target_store["controller_group_id"],
                "store_group_id": target_store["store_group_id"],
                "namespace_id": target_store["namespace_id"],
                "checkpoint_origin": target_store["checkpoint_origin"],
                "checkpoint_verifier_key_sha256": target_store["checkpoint_verifier_key_sha256"],
                "openssl_binary_sha256": target_store["openssl_binary_sha256"],
                "independence_state": target_store["independence_state"],
                "final_checkpoint_sha256": manifest_store["_files"]["final_checkpoint"][1],
                "final_tree_size": values[2][0],
                "final_root_sha256": values[2][1].hex(),
            }
            for target_store, manifest_store, values in zip(
                target_stores, manifest_stores, checkpoint_values, strict=True
            )
        ],
    }
    current_state = {
        **current_state_core,
        "state_sha256": sha256_bytes(STATE_DOMAIN_TAG + canonical_bytes(current_state_core)),
    }
    core: dict[str, Any] = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "status": PREFLIGHT_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "continuity_id": target["continuity_id"],
        "sequence": expected_sequence,
        "composition_manifest_checkpoint_sha256": expected_composition_manifest_sha256,
        "composition_sha256": manifest["composition_sha256"],
        "predecessor_continuity_state_sha256": expected_predecessor_continuity_state_sha256,
        "custody_target_checkpoint_sha256": paths["target_checkpoint"],
        "custody_target_sha256": target["target_sha256"],
        "custody_witness_report_sha256s": [report["report_sha256"] for report in custody_reports],
        "phase_bound_composition_manifest_checkpoint_sha256": manifest["phase_bound_manifest_checkpoint_sha256"],
        "phase_bound_preflight_sha256": phase_report["preflight_sha256"],
        "generation_phase_context": phase_report["generation_phase_context"],
        "transition_statement_checkpoint_sha256": paths["transition_checkpoint"],
        "transition_statement_sha256": transition["transition_sha256"],
        "seal_checkpoint_sha256": paths["seal_checkpoint"],
        "seal_sha256": seal["seal_sha256"],
        "slot_rule": rule,
        "checkpoint_profile": CHECKPOINT_PROFILE,
        "proof_profile": PROOF_PROFILE,
        "pre_token_custody_target_dual_witness_replayed": True,
        "continuity_relative_to_supplied_checkpoints_verified": True,
        "one_reserved_transition_slot_per_supplied_view_verified": True,
        "checkpoint_signatures_under_precommitted_keys_verified": True,
        "same_transition_bytes_in_both_supplied_views_verified": True,
        "dual_store_intermediate_views_cross_logged_verified": True,
        "complete_two_store_seal_relative_to_supplied_final_heads_verified": True,
        "no_extra_leaf_between_supplied_prior_and_final_heads_verified": True,
        "closed_outer_snapshot_replayed": True,
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
        **dict.fromkeys(FIXED_FALSE_FIELDS, False),
        "current_state": current_state,
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "preflight_sha256": sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))}


def verify_sentinel_dual_log_continuity_preflight(
    value: Any,
    root: Path,
    expected_composition_manifest_sha256: str,
    expected_sequence: int,
    expected_predecessor_continuity_state_sha256: str | None,
    predecessor_continuity_state_path: Path | None,
    expected_prior_store_checkpoint_sha256s: Sequence[str],
    expected_final_store_checkpoint_sha256s: Sequence[str],
    phase_openssl_paths: Sequence[Path],
    expected_phase_openssl_sha256s: Sequence[str],
    custody_openssl_paths: Sequence[Path],
    expected_custody_openssl_sha256s: Sequence[str],
    store_openssl_paths: Sequence[Path],
    expected_store_openssl_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Full-replay a saved continuity report and reject projection forgery."""

    if not isinstance(value, dict):
        raise CausalFrontierError("continuity preflight report must be an object")
    expected = preflight_sentinel_dual_log_continuity(
        root,
        expected_composition_manifest_sha256,
        expected_sequence,
        expected_predecessor_continuity_state_sha256,
        predecessor_continuity_state_path,
        expected_prior_store_checkpoint_sha256s,
        expected_final_store_checkpoint_sha256s,
        phase_openssl_paths,
        expected_phase_openssl_sha256s,
        custody_openssl_paths,
        expected_custody_openssl_sha256s,
        store_openssl_paths,
        expected_store_openssl_sha256s,
    )
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("continuity report differs from exact deterministic replay")
    return value
