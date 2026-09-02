"""Assertion-independent deterministic dual-log continuity probe."""

# ruff: noqa: E402 -- direct execution needs the src-layout path before imports.

from __future__ import annotations

import base64
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from causalfrontier import _transparency
from causalfrontier import sentinel_continuity as continuity
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("ascii"))


def _write(path: Path, raw: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _write_json(path: Path, value: object) -> str:
    return _write(path, canonical_bytes(value) + b"\n")


def _file(path: str, digest: str, media_type: str) -> dict[str, str]:
    return {"path": path, "sha256": digest, "media_type": media_type}


def _vkey(origin: str, public_key: bytes) -> str:
    key_id = bytes.fromhex(sha256_bytes(origin.encode("ascii") + b"\n\x01" + public_key))[:4]
    return "%s+%s+%s" % (
        origin,
        key_id.hex(),
        base64.b64encode(b"\x01" + public_key).decode("ascii"),
    )


def _proof(proof_type: str, left: int, right: int, hashes: list[bytes]) -> dict[str, object]:
    return {
        "schema_version": continuity.PROOF_SCHEMA_VERSION,
        "proof_profile": continuity.PROOF_PROFILE,
        "proof_type": proof_type,
        "left_size": left,
        "right_size": right,
        "hashes": [base64.b64encode(item).decode("ascii") for item in hashes],
    }


def _phase_report() -> dict[str, object]:
    context = {
        "schema_version": "causalfrontier.sentinel-generation-phase-context.v1",
        "lock_id": "lock:continuity-probe:1",
        "sequence": 1,
        "generation_plan_checkpoint_sha256": _digest("generation-plan-checkpoint"),
        "generation_plan_sha256": _digest("generation-plan-semantic"),
        "generation_lock_preflight_sha256": _digest("phase1-preflight"),
        "generation_epoch_sha256": _digest("generation-epoch"),
    }
    return {
        "composition_id": "composition:continuity-probe:1",
        "composition_sha256": _digest("phase-composition-semantic"),
        "preflight_sha256": _digest("phase2-preflight"),
        "phase1_dual_witness_preflight_sha256": _digest("phase1-preflight"),
        "sentinel_manifest_checkpoint_sha256": _digest("sentinel-manifest"),
        "sentinel_structural_preflight_sha256": _digest("sentinel-preflight"),
        "generation_plan_checkpoint_sha256": _digest("generation-plan-checkpoint"),
        "generation_plan_sha256": _digest("generation-plan-semantic"),
        "generation_phase_context": context,
    }


def _custody_reports(witnesses: list[dict[str, object]], target_checkpoint: str) -> list[dict[str, object]]:
    reports: list[dict[str, object]] = []
    bound = "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"
    for index, witness in enumerate(witnesses):
        reports.append(
            {
                "attestation_id": witness["attestation_id"],
                "trust_policy_id": witness["trust_policy_id"],
                "trust_anchor_sha256": witness["trust_anchor_sha256"],
                "trust_anchor_spki_sha256": witness["trust_anchor_spki_sha256"],
                "tsa_signer_spki_sha256": witness["tsa_signer_spki_sha256"],
                "openssl_binary_sha256": witness["openssl_binary_sha256"],
                "target_checkpoint_sha256": target_checkpoint,
                "timestamp_token_sha256": _digest("custody-token-%d" % index),
                "report_sha256": _digest("custody-report-%d" % index),
                bound: True,
            }
        )
    return reports


def _build(root: Path) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]], list[bytes]]:
    phase_report = _phase_report()
    phase_root = root / "phase-bound"
    _write(phase_root / "opaque-phase-evidence.txt", b"phase-bound-evidence\n")
    runtime = _digest("application-owned-openssl")
    witnesses: list[dict[str, object]] = []
    manifest_witnesses: list[dict[str, object]] = []
    for suffix in ("a", "b"):
        attestation_root = "custody-%s-attestation" % suffix
        trust_root = "custody-%s-trust" % suffix
        _write(root / attestation_root / "opaque-attestation.txt", ("attestation-%s\n" % suffix).encode("ascii"))
        _write(root / trust_root / "opaque-trust.txt", ("trust-%s\n" % suffix).encode("ascii"))
        witness = {
            "witness_id": "witness:continuity-probe-%s" % suffix,
            "witness_organization_id": "organization:continuity-probe-witness-%s" % suffix,
            "controller_group_id": "controller:continuity-probe-witness-%s" % suffix,
            "store_group_id": "store:continuity-probe-witness-%s" % suffix,
            "attestation_id": "attestation:continuity-probe-%s" % suffix,
            "trust_policy_id": "trust-policy:continuity-probe-%s" % suffix,
            "trust_policy_checkpoint_sha256": _digest("trust-policy-%s" % suffix),
            "trust_anchor_sha256": _digest("trust-anchor-%s" % suffix),
            "trust_anchor_spki_sha256": _digest("trust-anchor-spki-%s" % suffix),
            "tsa_signer_spki_sha256": _digest("tsa-signer-spki-%s" % suffix),
            "openssl_binary_sha256": runtime,
            "independence_state": continuity.INDEPENDENCE_STATE,
        }
        witnesses.append(witness)
        manifest_witnesses.append(
            {
                "witness_id": witness["witness_id"],
                "attestation_root": attestation_root,
                "attestation_checkpoint_sha256": _digest("attestation-checkpoint-%s" % suffix),
                "trust_policy_root": trust_root,
                "trust_policy_checkpoint_sha256": witness["trust_policy_checkpoint_sha256"],
            }
        )

    checkpoint_raw: list[list[bytes]] = []
    stores: list[dict[str, object]] = []
    for suffix in ("a", "b"):
        prior_raw = ("prior-checkpoint-%s\n" % suffix).encode("ascii")
        checkpoint_raw.append([prior_raw])
        public_key = bytes.fromhex(_digest("public-key-%s" % suffix))
        origin = "causalfrontier.example/log-%s" % suffix
        vkey = _vkey(origin, public_key)
        stores.append(
            {
                "store_id": "store:continuity-probe-%s" % suffix,
                "operator_organization_id": "organization:continuity-probe-operator-%s" % suffix,
                "controller_group_id": "controller:continuity-probe-log-%s" % suffix,
                "store_group_id": "store-group:continuity-probe-log-%s" % suffix,
                "namespace_id": "namespace:continuity-probe-%s" % suffix,
                "checkpoint_origin": origin,
                "checkpoint_verifier_key": vkey,
                "checkpoint_verifier_key_sha256": sha256_bytes(vkey.encode("utf-8")),
                "openssl_binary_sha256": runtime,
                "prior_checkpoint_sha256": sha256_bytes(prior_raw),
                "prior_tree_size": 0,
                "prior_root_sha256": _transparency.empty_hash().hex(),
                "independence_state": continuity.INDEPENDENCE_STATE,
            }
        )

    target: dict[str, object] = {
        "schema_version": continuity.TARGET_SCHEMA_VERSION,
        "status": continuity.TARGET_STATUS,
        "continuity_id": "continuity:optimized-probe:1",
        "sequence": 1,
        "predecessor_continuity_state_sha256": None,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "generation_plan_checkpoint_sha256": phase_report["generation_plan_checkpoint_sha256"],
        "generation_plan_sha256": phase_report["generation_plan_sha256"],
        "witness_completion_not_after": "2099-01-01T00:00:00Z",
        "statement_profile": continuity.STATEMENT_PROFILE,
        "checkpoint_profile": continuity.CHECKPOINT_PROFILE,
        "proof_profile": continuity.PROOF_PROFILE,
        "slot_rule": continuity._slot_rule(1),
        "cross_log_rule": continuity.CROSS_LOG_RULE,
        "custody_witnesses": witnesses,
        "stores": stores,
        "generated_artifact_input_absent": True,
        "outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    target_core = dict(target)
    target["target_sha256"] = sha256_bytes(continuity.TARGET_DOMAIN_TAG + canonical_bytes(target_core))
    target_checkpoint = _write_json(root / "custody-target.json", target)
    custody_reports = _custody_reports(witnesses, target_checkpoint)
    transition = continuity._transition(
        target,
        phase_report,
        custody_reports,
        target_checkpoint,
        _digest("phase-manifest-checkpoint"),
    )
    transition_checkpoint = _write_json(root / "transition.json", transition)
    transition_raw = (root / "transition.json").read_bytes()
    transition_root = _transparency.leaf_hash(transition_raw)
    intermediate_records: list[dict[str, object]] = []
    for index, store in enumerate(stores):
        intermediate_raw = ("intermediate-checkpoint-%d\n" % index).encode("ascii")
        checkpoint_raw[index].append(intermediate_raw)
        intermediate_records.append(
            {
                "store_id": store["store_id"],
                "intermediate_checkpoint_sha256": sha256_bytes(intermediate_raw),
                "intermediate_root_sha256": transition_root.hex(),
                "intermediate_tree_size": 1,
            }
        )
    seal = continuity._seal(target, transition, intermediate_records, transition_checkpoint)
    seal_checkpoint = _write_json(root / "seal.json", seal)
    seal_raw = (root / "seal.json").read_bytes()
    seal_root = _transparency.leaf_hash(seal_raw)
    final_root = _transparency.node_hash(transition_root, seal_root)

    manifest_stores: list[dict[str, object]] = []
    for index, store in enumerate(stores):
        suffix = ("a", "b")[index]
        final_raw = ("final-checkpoint-%d\n" % index).encode("ascii")
        checkpoint_raw[index].append(final_raw)
        raw_artifacts = {
            "prior_checkpoint": (checkpoint_raw[index][0], continuity.MEDIA_CHECKPOINT),
            "prior_to_intermediate_consistency": (
                canonical_bytes(_proof("CONSISTENCY", 0, 1, [])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "intermediate_checkpoint": (checkpoint_raw[index][1], continuity.MEDIA_CHECKPOINT),
            "transition_inclusion": (
                canonical_bytes(_proof("INCLUSION", 0, 1, [])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "intermediate_to_final_consistency": (
                canonical_bytes(_proof("CONSISTENCY", 1, 2, [seal_root])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "final_checkpoint": (checkpoint_raw[index][2], continuity.MEDIA_CHECKPOINT),
            "seal_inclusion": (
                canonical_bytes(_proof("INCLUSION", 1, 2, [transition_root])) + b"\n",
                continuity.MEDIA_JSON,
            ),
        }
        manifest_store: dict[str, object] = {"store_id": store["store_id"]}
        for field, (raw, media_type) in raw_artifacts.items():
            path = "store-%s-%s%s" % (
                suffix,
                field.replace("_", "-"),
                ".checkpoint" if media_type == continuity.MEDIA_CHECKPOINT else ".json",
            )
            manifest_store[field] = _file(path, _write(root / path, raw), media_type)
        manifest_stores.append(manifest_store)

    manifest: dict[str, object] = {
        "schema_version": continuity.COMPOSITION_SCHEMA_VERSION,
        "status": continuity.COMPOSITION_STATUS,
        "continuity_id": target["continuity_id"],
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "custody_target": _file("custody-target.json", target_checkpoint, continuity.MEDIA_JSON),
        "custody_target_sha256": target["target_sha256"],
        "custody_witnesses": manifest_witnesses,
        "phase_bound_root": "phase-bound",
        "phase_bound_manifest_checkpoint_sha256": _digest("phase-manifest-checkpoint"),
        "transition": _file("transition.json", transition_checkpoint, continuity.MEDIA_JSON),
        "seal": _file("seal.json", seal_checkpoint, continuity.MEDIA_JSON),
        "stores": manifest_stores,
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    manifest_core = dict(manifest)
    manifest["composition_sha256"] = sha256_bytes(continuity.COMPOSITION_DOMAIN_TAG + canonical_bytes(manifest_core))
    manifest_checkpoint = _write_json(root / continuity.COMPOSITION_MANIFEST, manifest)
    values = [
        (0, _transparency.empty_hash()),
        (1, transition_root),
        (2, final_root),
    ]
    return (
        {
            "manifest_checkpoint": manifest_checkpoint,
            "runtime": runtime,
            "prior_pins": [store["prior_checkpoint_sha256"] for store in stores],
            "final_pins": [item["final_checkpoint"]["sha256"] for item in manifest_stores],
        },
        phase_report,
        custody_reports,
        values,
    )


def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        inputs, phase_report, custody_reports, checkpoint_values = _build(root)
        original_phase = continuity.sentinel_phase.preflight_sentinel_phase_bound_admission
        original_custody = continuity.attestation.verify_rfc3161_attestation
        original_checkpoints = continuity._verify_checkpoint_set
        calls = {"custody": 0}

        def custody_replay(*_args: object, **_kwargs: object) -> dict[str, object]:
            report = custody_reports[calls["custody"]]
            calls["custody"] += 1
            return report

        continuity.sentinel_phase.preflight_sentinel_phase_bound_admission = lambda *_args, **_kwargs: phase_report
        continuity.attestation.verify_rfc3161_attestation = custody_replay
        continuity._verify_checkpoint_set = lambda *_args, **_kwargs: checkpoint_values
        try:
            runtime_paths = [Path("/application/openssl-a"), Path("/application/openssl-b")]
            runtime_digests = [inputs["runtime"], inputs["runtime"]]
            report = continuity.preflight_sentinel_dual_log_continuity(
                root,
                inputs["manifest_checkpoint"],
                1,
                None,
                None,
                inputs["prior_pins"],
                inputs["final_pins"],
                runtime_paths,
                runtime_digests,
                runtime_paths,
                runtime_digests,
                runtime_paths,
                runtime_digests,
            )
        finally:
            continuity.sentinel_phase.preflight_sentinel_phase_bound_admission = original_phase
            continuity.attestation.verify_rfc3161_attestation = original_custody
            continuity._verify_checkpoint_set = original_checkpoints
    print(canonical_bytes(report).decode("utf-8"))


if __name__ == "__main__":
    main()
