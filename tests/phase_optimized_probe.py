"""Assertion-independent deterministic phase-bound sentinel probe."""

# ruff: noqa: E402 -- direct execution needs the src-layout path before imports.

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from sentinel_fixture import build_sentinel_fixture
from witness_optimized_probe import _digest, _seal, _write_json

from causalfrontier import sentinel_phase as phase
from causalfrontier import sentinel_witness as witness
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _build_lock(base: Path, seed_fixture: dict) -> tuple[Path, str, list[dict]]:
    root = base / "lock"
    root.mkdir()
    registry_checkpoint = _write_json(
        root / "organization-registry.json",
        seed_fixture["manifest"]["organizations"],
    )
    descriptors = []
    for label in ("a", "b"):
        attestation_root = root / ("witness-" + label) / "attestation"
        trust_root = root / ("witness-" + label) / "trust-policy"
        attestation_root.mkdir(parents=True)
        trust_root.mkdir(parents=True)
        (attestation_root / "opaque-evidence.bin").write_bytes(("attestation-" + label).encode("ascii"))
        (trust_root / "opaque-policy.pem").write_bytes(("trust-" + label).encode("ascii"))
        descriptors.append(
            {
                "label": label,
                "witness_id": "witness:" + label,
                "witness_organization_id": "organization:external-witness-" + label,
                "controller_group_id": "controller:external-witness-" + label,
                "store_group_id": "store:external-witness-" + label,
                "attestation_id": "attestation:external-witness-" + label,
                "attestation_checkpoint_sha256": _digest("attestation-checkpoint-" + label),
                "trust_policy_id": "trust-policy:external-witness-" + label,
                "trust_policy_checkpoint_sha256": _digest("trust-policy-checkpoint-" + label),
                "trust_anchor_sha256": _digest("trust-anchor-" + label),
                "trust_anchor_spki_sha256": _digest("trust-anchor-spki-" + label),
                "tsa_signer_spki_sha256": _digest("tsa-signer-spki-" + label),
                "openssl_binary_sha256": _digest("openssl-" + label),
            }
        )
    target = {
        "schema_version": witness.TARGET_SCHEMA_VERSION,
        "status": witness.TARGET_STATUS,
        "lock_id": "lock:phase-optimized-probe:1",
        "sequence": 1,
        "predecessor_lock_preflight_sha256": None,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "goal_claim_contract_sha256": seed_fixture["generation_plan"]["goal_claim_contract_sha256"],
        "generation_plan_id": seed_fixture["generation_plan"]["plan_id"],
        "generation_plan_checkpoint_sha256": seed_fixture["generation_plan_sha256"],
        "generation_plan_sha256": seed_fixture["generation_plan"]["plan_sha256"],
        "organization_registry_checkpoint_sha256": registry_checkpoint,
        "organization_registry_sha256": seed_fixture["generation_plan"]["organization_registry_sha256"],
        "witness_completion_not_after": "2026-02-01T00:00:00Z",
        "witnesses": [
            {
                key: descriptor[key]
                for key in {
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
                }
            }
            | {"independence_state": witness.INDEPENDENCE_STATE}
            for descriptor in descriptors
        ],
        "generated_artifact_input_absent": True,
        "outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "scoring_disabled": True,
    }
    _seal(target, "target_sha256", witness.TARGET_DOMAIN_TAG)
    target_checkpoint = _write_json(root / "lock-target.json", target)
    manifest = {
        "schema_version": witness.LOCK_SCHEMA_VERSION,
        "status": witness.LOCK_STATUS,
        "lock_id": target["lock_id"],
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "target": {
            "path": "lock-target.json",
            "sha256": target_checkpoint,
            "media_type": "application/json",
        },
        "target_sha256": target["target_sha256"],
        "organization_registry": {
            "path": "organization-registry.json",
            "sha256": registry_checkpoint,
            "media_type": "application/json",
        },
        "organization_registry_sha256": target["organization_registry_sha256"],
        "generation_plan_checkpoint_sha256": target["generation_plan_checkpoint_sha256"],
        "generation_plan_sha256": target["generation_plan_sha256"],
        "witnesses": [
            {
                "witness_id": descriptor["witness_id"],
                "attestation_root": "witness-%s/attestation" % descriptor["label"],
                "attestation_checkpoint_sha256": descriptor["attestation_checkpoint_sha256"],
                "trust_policy_root": "witness-%s/trust-policy" % descriptor["label"],
                "trust_policy_checkpoint_sha256": descriptor["trust_policy_checkpoint_sha256"],
            }
            for descriptor in descriptors
        ],
        "generated_artifact_input_absent": True,
        "outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "scoring_disabled": True,
    }
    _seal(manifest, "lock_sha256", witness.LOCK_DOMAIN_TAG)
    checkpoint = _write_json(root / witness.LOCK_MANIFEST, manifest)
    return root, checkpoint, descriptors


def _deterministic_attestation(descriptors: list[dict]):
    calls = {"n": 0}
    signed_bound_field = (
        "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"
    )

    def replay(
        target_path: Path,
        expected_target_sha256: str,
        attestation_root: Path,
        expected_attestation_checkpoint_sha256: str,
        trust_policy_root: Path,
        expected_trust_policy_checkpoint_sha256: str,
        openssl_path: Path,
        expected_openssl_sha256: str,
        expected_not_after: str,
    ) -> dict:
        del target_path, attestation_root, trust_policy_root, openssl_path
        descriptor = descriptors[calls["n"] % len(descriptors)]
        calls["n"] += 1
        label = descriptor["label"]
        return {
            "attestation_id": descriptor["attestation_id"],
            "attestation_checkpoint_sha256": expected_attestation_checkpoint_sha256,
            "trust_policy_id": descriptor["trust_policy_id"],
            "trust_policy_checkpoint_sha256": expected_trust_policy_checkpoint_sha256,
            "trust_anchor_sha256": descriptor["trust_anchor_sha256"],
            "trust_anchor_spki_sha256": descriptor["trust_anchor_spki_sha256"],
            "trust_anchor_key_algorithm": "rsaEncryption",
            "trust_anchor_key_material_sha256": _digest("trust-anchor-key-material-" + label),
            "tsa_signer_spki_sha256": descriptor["tsa_signer_spki_sha256"],
            "tsa_signer_key_algorithm": "rsaEncryption",
            "tsa_signer_key_material_sha256": _digest("tsa-signer-key-material-" + label),
            "tsa_organization_id": descriptor["witness_organization_id"],
            "target_checkpoint_sha256": expected_target_sha256,
            "openssl_binary_sha256": expected_openssl_sha256,
            "caller_checkpointed_not_after": expected_not_after,
            "request_sha256": _digest("request-" + label),
            "response_sha256": _digest("response-" + label),
            "timestamp_token_sha256": _digest("token-" + label),
            "signed_time_text": "Feb  1 00:00:00 2026 GMT",
            "policy_checked_time_upper_bound": "2026-02-01T00:00:00Z",
            "report_sha256": _digest("rfc3161-report-" + label),
            signed_bound_field: True,
            "canonical_der_verified": False,
            "openssl_runtime_hermeticity_verified": False,
            "certificate_validity_over_signed_accuracy_interval_verified": False,
        }

    return replay


def _build_composition(
    base: Path,
    seed_fixture: dict,
    lock_root: Path,
    lock_checkpoint: str,
    context: dict,
) -> tuple[Path, str]:
    successor = build_sentinel_fixture(base / "successor", generation_phase_context=context)
    if successor["generation_plan_path"].read_bytes() != seed_fixture["generation_plan_path"].read_bytes():
        raise RuntimeError("phase probe successor changed witnessed generation-plan bytes")
    root = base / "composition"
    root.mkdir()
    generation_plan_path = root / "generation-plan.json"
    goal_plan_path = root / "goal-claim-plan.json"
    copied_lock = root / "dual-witness-lock"
    copied_sentinel = root / "sentinel"
    shutil.copy2(seed_fixture["generation_plan_path"], generation_plan_path)
    shutil.copy2(successor["goal_plan_path"], goal_plan_path)
    shutil.copytree(lock_root, copied_lock)
    shutil.copytree(successor["root"], copied_sentinel)
    manifest = {
        "schema_version": phase.COMPOSITION_SCHEMA_VERSION,
        "status": phase.COMPOSITION_STATUS,
        "composition_id": "composition:phase-optimized-probe:1",
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
        "dual_witness_lock_root": copied_lock.name,
        "dual_witness_lock_manifest_checkpoint_sha256": lock_checkpoint,
        "sentinel_root": copied_sentinel.name,
        "sentinel_manifest_checkpoint_sha256": successor["manifest_sha256"],
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    _seal(manifest, "composition_sha256", phase.COMPOSITION_DOMAIN_TAG)
    checkpoint = _write_json(root / phase.COMPOSITION_MANIFEST, manifest)
    return root, checkpoint


def main() -> None:
    with TemporaryDirectory() as directory:
        base = Path(directory).resolve()
        seed_fixture = build_sentinel_fixture(base / "seed")
        lock_root, lock_checkpoint, descriptors = _build_lock(base, seed_fixture)
        runtime_paths = [Path("/synthetic/openssl-a"), Path("/synthetic/openssl-b")]
        runtime_digests = [descriptor["openssl_binary_sha256"] for descriptor in descriptors]
        original = witness.attestation.verify_rfc3161_attestation
        witness.attestation.verify_rfc3161_attestation = _deterministic_attestation(descriptors)
        try:
            phase1 = witness.preflight_sentinel_dual_witness_lock(
                lock_root,
                lock_checkpoint,
                seed_fixture["generation_plan_path"],
                seed_fixture["generation_plan_sha256"],
                1,
                runtime_paths,
                runtime_digests,
            )
            context = phase._fresh_phase_context(phase1)
            composition_root, composition_checkpoint = _build_composition(
                base,
                seed_fixture,
                lock_root,
                lock_checkpoint,
                context,
            )
            report = phase.preflight_sentinel_phase_bound_admission(
                composition_root,
                composition_checkpoint,
                1,
                runtime_paths,
                runtime_digests,
            )
        finally:
            witness.attestation.verify_rfc3161_attestation = original
    print(canonical_bytes(report).decode("utf-8"))


if __name__ == "__main__":
    main()
