"""Assertion-independent deterministic dual-witness composition probe."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel_fixture import build_sentinel_fixture

from causalfrontier import sentinel_witness as witness
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _seal(value: dict, field: str, tag: bytes) -> None:
    core = {key: item for key, item in value.items() if key != field}
    value[field] = sha256_bytes(tag + canonical_bytes(core))


def main() -> None:
    with TemporaryDirectory() as directory:
        base = Path(directory).resolve()
        sentinel_fixture = build_sentinel_fixture(base / "sentinel")
        root = base / "lock"
        root.mkdir()
        registry_checkpoint = _write_json(
            root / "organization-registry.json", sentinel_fixture["manifest"]["organizations"]
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
            "lock_id": "lock:optimized-probe:1",
            "sequence": 1,
            "predecessor_lock_preflight_sha256": None,
            "fixed_parameter": FIXED_PARAMETER,
            "boundary": fixed_boundary(),
            "goal_claim_contract_sha256": sentinel_fixture["generation_plan"]["goal_claim_contract_sha256"],
            "generation_plan_id": sentinel_fixture["generation_plan"]["plan_id"],
            "generation_plan_checkpoint_sha256": sentinel_fixture["generation_plan_sha256"],
            "generation_plan_sha256": sentinel_fixture["generation_plan"]["plan_sha256"],
            "organization_registry_checkpoint_sha256": registry_checkpoint,
            "organization_registry_sha256": sentinel_fixture["generation_plan"]["organization_registry_sha256"],
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
        manifest_checkpoint = _write_json(root / witness.LOCK_MANIFEST, manifest)
        calls = {"n": 0}
        signed_bound_field = "signed_target_imprint_time_bound_under_caller_policy_verified_" + (
            "without_revocation_or_signer_identity"
        )

        def deterministic_rfc3161_projection(
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
            index = calls["n"]
            calls["n"] += 1
            descriptor = descriptors[index]
            return {
                "attestation_id": descriptor["attestation_id"],
                "attestation_checkpoint_sha256": expected_attestation_checkpoint_sha256,
                "trust_policy_id": descriptor["trust_policy_id"],
                "trust_policy_checkpoint_sha256": expected_trust_policy_checkpoint_sha256,
                "trust_anchor_sha256": descriptor["trust_anchor_sha256"],
                "trust_anchor_spki_sha256": descriptor["trust_anchor_spki_sha256"],
                "trust_anchor_key_algorithm": "rsaEncryption",
                "trust_anchor_key_material_sha256": _digest("trust-anchor-key-material-" + descriptor["label"]),
                "tsa_signer_spki_sha256": descriptor["tsa_signer_spki_sha256"],
                "tsa_signer_key_algorithm": "rsaEncryption",
                "tsa_signer_key_material_sha256": _digest("tsa-signer-key-material-" + descriptor["label"]),
                "tsa_organization_id": descriptor["witness_organization_id"],
                "target_checkpoint_sha256": expected_target_sha256,
                "openssl_binary_sha256": expected_openssl_sha256,
                "caller_checkpointed_not_after": expected_not_after,
                "request_sha256": _digest("request-" + descriptor["label"]),
                "response_sha256": _digest("response-" + descriptor["label"]),
                "timestamp_token_sha256": _digest("token-" + descriptor["label"]),
                "signed_time_text": "Feb  1 00:00:00 2026 GMT",
                "policy_checked_time_upper_bound": "2026-02-01T00:00:00Z",
                "report_sha256": _digest("rfc3161-report-" + descriptor["label"]),
                signed_bound_field: True,
                "canonical_der_verified": False,
                "openssl_runtime_hermeticity_verified": False,
                "certificate_validity_over_signed_accuracy_interval_verified": False,
            }

        original = witness.attestation.verify_rfc3161_attestation
        witness.attestation.verify_rfc3161_attestation = deterministic_rfc3161_projection
        try:
            report = witness.preflight_sentinel_dual_witness_lock(
                root,
                manifest_checkpoint,
                sentinel_fixture["generation_plan_path"],
                sentinel_fixture["generation_plan_sha256"],
                1,
                [Path("/synthetic/openssl-a"), Path("/synthetic/openssl-b")],
                [descriptor["openssl_binary_sha256"] for descriptor in descriptors],
            )
        finally:
            witness.attestation.verify_rfc3161_attestation = original
    print(canonical_bytes(report).decode("utf-8"))


if __name__ == "__main__":
    main()
