"""Hostile tests for the dual-declared-log sentinel continuity step."""

from __future__ import annotations

import base64
import inspect
import json
import os
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import pytest
from test_sentinel_phase import _build_composition as build_phase_composition
from test_sentinel_phase import _preflight as preflight_phase
from test_sentinel_witness import _build_tsa, _run, _timestamp

import causalfrontier
import causalfrontier.sentinel_continuity as continuity
from causalfrontier import _transparency, attestation
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _different_digest(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


def _seal_target(target: dict[str, Any]) -> None:
    core = {key: value for key, value in target.items() if key != "target_sha256"}
    target["target_sha256"] = sha256_bytes(continuity.TARGET_DOMAIN_TAG + canonical_bytes(core))


def _seal_manifest(fixture: dict[str, Any]) -> None:
    manifest = fixture["manifest"]
    core = {key: value for key, value in manifest.items() if key != "composition_sha256"}
    manifest["composition_sha256"] = sha256_bytes(continuity.COMPOSITION_DOMAIN_TAG + canonical_bytes(core))
    fixture["manifest_sha256"] = _write_json(fixture["manifest_path"], manifest)


def _file(path: str, digest: str, media_type: str) -> dict[str, str]:
    return {"path": path, "sha256": digest, "media_type": media_type}


def _proof(proof_type: str, left_size: int, right_size: int, hashes: list[bytes]) -> dict[str, Any]:
    return {
        "schema_version": continuity.PROOF_SCHEMA_VERSION,
        "proof_profile": continuity.PROOF_PROFILE,
        "proof_type": proof_type,
        "left_size": left_size,
        "right_size": right_size,
        "hashes": [base64.b64encode(value).decode("ascii") for value in hashes],
    }


def _merkle_split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _transparency.empty_hash()
    if len(leaves) == 1:
        return _transparency.leaf_hash(leaves[0])
    split = _merkle_split(len(leaves))
    return _transparency.node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def _inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    split = _merkle_split(len(leaves))
    if index < split:
        return [*_inclusion_proof(leaves[:split], index), _merkle_root(leaves[split:])]
    return [*_inclusion_proof(leaves[split:], index - split), _merkle_root(leaves[:split])]


def _consistency_subproof(leaves: list[bytes], old_size: int, complete: bool) -> list[bytes]:
    if old_size == len(leaves):
        return [] if complete else [_merkle_root(leaves)]
    split = _merkle_split(len(leaves))
    if old_size <= split:
        return [
            *_consistency_subproof(leaves[:split], old_size, complete),
            _merkle_root(leaves[split:]),
        ]
    return [
        *_consistency_subproof(leaves[split:], old_size - split, False),
        _merkle_root(leaves[:split]),
    ]


def _consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    if old_size == 0 or old_size == len(leaves):
        return []
    return _consistency_subproof(leaves, old_size, True)


def _seal_state(state: dict[str, Any]) -> None:
    core = {key: value for key, value in state.items() if key != "state_sha256"}
    state["state_sha256"] = sha256_bytes(continuity.STATE_DOMAIN_TAG + canonical_bytes(core))


def _sequence_two_target(fixture: dict[str, Any], sequence_one_report: dict[str, Any]) -> dict[str, Any]:
    target = deepcopy(fixture["target"])
    state = sequence_one_report["current_state"]
    target["sequence"] = 2
    target["predecessor_continuity_state_sha256"] = state["state_sha256"]
    target["slot_rule"] = continuity._slot_rule(2)
    for target_store, previous_store in zip(target["stores"], state["stores"], strict=True):
        target_store["prior_checkpoint_sha256"] = previous_store["final_checkpoint_sha256"]
        target_store["prior_tree_size"] = previous_store["final_tree_size"]
        target_store["prior_root_sha256"] = previous_store["final_root_sha256"]
    _seal_target(target)
    return target


def _generate_log_key(openssl: Path, root: Path, origin: str) -> dict[str, Any]:
    root.mkdir(parents=True)
    private_key = root / "private.pem"
    public_der = root / "public.der"
    _run([str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    _run(
        [
            str(openssl),
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_der),
        ]
    )
    encoded = public_der.read_bytes()
    if not encoded.startswith(continuity.ED25519_SPKI_PREFIX) or len(encoded) != 44:
        raise RuntimeError("synthetic Ed25519 SubjectPublicKeyInfo encoding changed")
    public_key = encoded[len(continuity.ED25519_SPKI_PREFIX) :]
    key_id = bytes.fromhex(sha256_bytes(origin.encode("utf-8") + b"\n\x01" + public_key))[:4]
    vkey = "%s+%s+%s" % (
        origin,
        key_id.hex(),
        base64.b64encode(b"\x01" + public_key).decode("ascii"),
    )
    return {
        "origin": origin,
        "private_key": private_key,
        "public_key": public_key,
        "key_id": key_id,
        "vkey": vkey,
    }


def _signed_checkpoint(
    openssl: Path,
    key: dict[str, Any],
    tree_size: int,
    root_hash: bytes,
    work: Path,
    label: str,
) -> bytes:
    note = (
        key["origin"].encode("utf-8")
        + b"\n"
        + str(tree_size).encode("ascii")
        + b"\n"
        + base64.b64encode(root_hash)
        + b"\n"
    )
    note_path = work / (label + ".note")
    signature_path = work / (label + ".signature")
    note_path.write_bytes(note)
    _run(
        [
            str(openssl),
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key["private_key"]),
            "-rawin",
            "-in",
            str(note_path),
            "-out",
            str(signature_path),
        ]
    )
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise RuntimeError("synthetic Ed25519 signature length changed")
    signature_line = (
        "— %s %s\n"
        % (
            key["origin"],
            base64.b64encode(key["key_id"] + signature).decode("ascii"),
        )
    ).encode("utf-8")
    return note + b"\n" + signature_line


def _store_descriptor(
    index: int,
    key: dict[str, Any],
    openssl_sha256: str,
    prior_checkpoint_sha256: str,
) -> dict[str, Any]:
    suffix = chr(ord("a") + index)
    return {
        "store_id": "store:continuity-log-%s" % suffix,
        "operator_organization_id": "organization:continuity-log-operator-%s" % suffix,
        "controller_group_id": "group:continuity-log-controller-%s" % suffix,
        "store_group_id": "group:continuity-log-store-%s" % suffix,
        "namespace_id": "namespace:continuity-log-%s" % suffix,
        "checkpoint_origin": key["origin"],
        "checkpoint_verifier_key": key["vkey"],
        "checkpoint_verifier_key_sha256": sha256_bytes(key["vkey"].encode("utf-8")),
        "openssl_binary_sha256": openssl_sha256,
        "prior_checkpoint_sha256": prior_checkpoint_sha256,
        "prior_tree_size": 0,
        "prior_root_sha256": _transparency.empty_hash().hex(),
        "independence_state": continuity.INDEPENDENCE_STATE,
    }


def _witness_descriptor(tsa: dict[str, Any], openssl_sha256: str) -> dict[str, Any]:
    suffix = tsa["label"][-1]
    return {
        "witness_id": "witness:continuity-custody-%s" % suffix,
        "witness_organization_id": tsa["organization_id"],
        "controller_group_id": "group:continuity-custody-controller-%s" % suffix,
        "store_group_id": "group:continuity-custody-store-%s" % suffix,
        "attestation_id": tsa["attestation_id"],
        "trust_policy_id": tsa["trust_policy"]["id"],
        "trust_policy_checkpoint_sha256": tsa["trust_checkpoint"],
        "trust_anchor_sha256": tsa["anchor_sha256"],
        "trust_anchor_spki_sha256": tsa["anchor_spki_sha256"],
        "tsa_signer_spki_sha256": tsa["signer_spki_sha256"],
        "openssl_binary_sha256": openssl_sha256,
        "independence_state": continuity.INDEPENDENCE_STATE,
    }


def _build_continuity_fixture(base: Path) -> dict[str, Any]:
    phase_fixture = build_phase_composition(base / "phase-source")
    phase_report = preflight_phase(phase_fixture)
    openssl = phase_fixture["openssl"]
    openssl_sha256 = phase_fixture["openssl_sha256"]

    root = base / "continuity"
    root.mkdir()
    phase_root = root / "phase-bound"
    shutil.copytree(phase_fixture["root"], phase_root)

    key_work = base / "log-key-work"
    keys = [
        _generate_log_key(openssl, key_work / "a", "causalfrontier-log-a"),
        _generate_log_key(openssl, key_work / "b", "causalfrontier-log-b"),
    ]
    signed_prior = [
        _signed_checkpoint(
            openssl,
            key,
            0,
            _transparency.empty_hash(),
            key_work,
            "prior-%d" % index,
        )
        for index, key in enumerate(keys)
    ]
    stores = [
        _store_descriptor(index, key, openssl_sha256, sha256_bytes(signed_prior[index]))
        for index, key in enumerate(keys)
    ]

    tsa_work = base / "custody-work"
    tsa_bundle_source = base / "custody-bundle-source"
    tsa_bundle_source.mkdir()
    tsas = [
        _build_tsa(
            openssl,
            tsa_work,
            tsa_bundle_source,
            "continuity-a",
            "organization:continuity-custody-a",
            "1.2.3.4.201",
        ),
        _build_tsa(
            openssl,
            tsa_work,
            tsa_bundle_source,
            "continuity-b",
            "organization:continuity-custody-b",
            "1.2.3.4.202",
        ),
    ]
    witnesses = [_witness_descriptor(tsa, openssl_sha256) for tsa in tsas]
    deadline = "2099-01-01T00:00:00Z"
    target = {
        "schema_version": continuity.TARGET_SCHEMA_VERSION,
        "status": continuity.TARGET_STATUS,
        "continuity_id": "continuity:sentinel-phase-bound:1",
        "sequence": 1,
        "predecessor_continuity_state_sha256": None,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "generation_plan_checkpoint_sha256": phase_report["generation_plan_checkpoint_sha256"],
        "generation_plan_sha256": phase_report["generation_plan_sha256"],
        "witness_completion_not_after": deadline,
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
    _seal_target(target)
    target_path = root / "custody-target.json"
    target_checkpoint = _write_json(target_path, target)

    custody_checkpoints = [_timestamp(openssl, tsa, target_path, deadline) for tsa in tsas]
    for suffix, tsa in zip(("a", "b"), tsas, strict=True):
        trust = root / ("custody-%s-trust" % suffix)
        bundle = root / ("custody-%s-attestation" % suffix)
        shutil.copytree(tsa["trust"], trust)
        shutil.copytree(tsa["bundle"], bundle)
        tsa["trust"] = trust
        tsa["bundle"] = bundle
    custody_reports = [
        attestation.verify_rfc3161_attestation(
            target_path,
            target_checkpoint,
            tsa["bundle"],
            attestation_checkpoint,
            tsa["trust"],
            tsa["trust_checkpoint"],
            openssl,
            openssl_sha256,
            deadline,
        )
        for tsa, attestation_checkpoint in zip(tsas, custody_checkpoints, strict=True)
    ]
    transition = continuity._transition(
        target,
        phase_report,
        custody_reports,
        target_checkpoint,
        phase_fixture["manifest_sha256"],
    )
    transition_path = root / "transition.json"
    transition_checkpoint = _write_json(transition_path, transition)
    transition_raw = transition_path.read_bytes()
    transition_root = _transparency.leaf_hash(transition_raw)

    signed_intermediate = [
        _signed_checkpoint(openssl, key, 1, transition_root, key_work, "intermediate-%d" % index)
        for index, key in enumerate(keys)
    ]
    intermediate_records = [
        {
            "store_id": store["store_id"],
            "intermediate_checkpoint_sha256": sha256_bytes(signed_intermediate[index]),
            "intermediate_root_sha256": transition_root.hex(),
            "intermediate_tree_size": 1,
        }
        for index, store in enumerate(stores)
    ]
    seal = continuity._seal(target, transition, intermediate_records, transition_checkpoint)
    seal_path = root / "seal.json"
    seal_checkpoint = _write_json(seal_path, seal)
    seal_raw = seal_path.read_bytes()
    seal_root = _transparency.leaf_hash(seal_raw)
    final_root = _transparency.node_hash(transition_root, seal_root)
    signed_final = [
        _signed_checkpoint(openssl, key, 2, final_root, key_work, "final-%d" % index) for index, key in enumerate(keys)
    ]

    manifest_stores: list[dict[str, Any]] = []
    for index, store in enumerate(stores):
        suffix = chr(ord("a") + index)
        artifacts: dict[str, tuple[bytes, str]] = {
            "prior_checkpoint": (signed_prior[index], continuity.MEDIA_CHECKPOINT),
            "prior_to_intermediate_consistency": (
                canonical_bytes(_proof("CONSISTENCY", 0, 1, [])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "intermediate_checkpoint": (signed_intermediate[index], continuity.MEDIA_CHECKPOINT),
            "transition_inclusion": (
                canonical_bytes(_proof("INCLUSION", 0, 1, [])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "intermediate_to_final_consistency": (
                canonical_bytes(_proof("CONSISTENCY", 1, 2, [seal_root])) + b"\n",
                continuity.MEDIA_JSON,
            ),
            "final_checkpoint": (signed_final[index], continuity.MEDIA_CHECKPOINT),
            "seal_inclusion": (
                canonical_bytes(_proof("INCLUSION", 1, 2, [transition_root])) + b"\n",
                continuity.MEDIA_JSON,
            ),
        }
        item: dict[str, Any] = {"store_id": store["store_id"]}
        for field, (raw, media_type) in artifacts.items():
            relative = "store-%s-%s%s" % (
                suffix,
                field.replace("_", "-"),
                ".checkpoint" if media_type == continuity.MEDIA_CHECKPOINT else ".json",
            )
            (root / relative).write_bytes(raw)
            item[field] = _file(relative, sha256_bytes(raw), media_type)
        manifest_stores.append(item)

    manifest = {
        "schema_version": continuity.COMPOSITION_SCHEMA_VERSION,
        "status": continuity.COMPOSITION_STATUS,
        "continuity_id": target["continuity_id"],
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "custody_target": _file("custody-target.json", target_checkpoint, continuity.MEDIA_JSON),
        "custody_target_sha256": target["target_sha256"],
        "custody_witnesses": [
            {
                "witness_id": witness["witness_id"],
                "attestation_root": tsa["bundle"].relative_to(root).as_posix(),
                "attestation_checkpoint_sha256": checkpoint,
                "trust_policy_root": tsa["trust"].relative_to(root).as_posix(),
                "trust_policy_checkpoint_sha256": tsa["trust_checkpoint"],
            }
            for witness, tsa, checkpoint in zip(witnesses, tsas, custody_checkpoints, strict=True)
        ],
        "phase_bound_root": phase_root.name,
        "phase_bound_manifest_checkpoint_sha256": phase_fixture["manifest_sha256"],
        "transition": _file("transition.json", transition_checkpoint, continuity.MEDIA_JSON),
        "seal": _file("seal.json", seal_checkpoint, continuity.MEDIA_JSON),
        "stores": manifest_stores,
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "admission_disabled": True,
        "scoring_disabled": True,
    }
    fixture = {
        "root": root,
        "manifest": manifest,
        "manifest_path": root / continuity.COMPOSITION_MANIFEST,
        "target": target,
        "target_path": target_path,
        "phase_root": phase_root,
        "phase_fixture": phase_fixture,
        "phase_report": phase_report,
        "openssl": openssl,
        "openssl_sha256": openssl_sha256,
        "tsas": tsas,
        "custody_reports": custody_reports,
        "log_keys": keys,
    }
    _seal_manifest(fixture)
    return fixture


@pytest.fixture(scope="module")
def continuity_fixture(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return _build_continuity_fixture(tmp_path_factory.mktemp("sentinel-continuity"))


def _copy_fixture(fixture: dict[str, Any], base: Path) -> dict[str, Any]:
    root = base / "continuity"
    shutil.copytree(fixture["root"], root)
    result = {
        **fixture,
        "root": root,
        "manifest_path": root / continuity.COMPOSITION_MANIFEST,
        "target_path": root / "custody-target.json",
        "phase_root": root / "phase-bound",
        "manifest": _json(root / continuity.COMPOSITION_MANIFEST),
        "target": _json(root / "custody-target.json"),
    }
    return result


def _build_sequence_two_fixture(
    fixture: dict[str, Any], sequence_one_report: dict[str, Any], base: Path
) -> dict[str, Any]:
    result = _copy_fixture(fixture, base)
    root = result["root"]
    manifest = result["manifest"]
    state = deepcopy(sequence_one_report["current_state"])
    predecessor_path = base / "sequence-one-continuity-state.json"
    _write_json(predecessor_path, state)

    old_transition_raw = (root / manifest["transition"]["path"]).read_bytes()
    old_seal_raw = (root / manifest["seal"]["path"]).read_bytes()
    old_final_raws = [(root / item["final_checkpoint"]["path"]).read_bytes() for item in manifest["stores"]]

    target = _sequence_two_target(fixture, sequence_one_report)
    result["target"] = target
    target_checkpoint = _write_json(result["target_path"], target)
    manifest["sequence"] = 2
    manifest["custody_target"]["sha256"] = target_checkpoint
    manifest["custody_target_sha256"] = target["target_sha256"]

    phase_report = deepcopy(fixture["phase_report"])
    custody_reports = deepcopy(fixture["custody_reports"])
    for index, report in enumerate(custody_reports):
        report["target_checkpoint_sha256"] = target_checkpoint
        report["report_sha256"] = sha256_bytes(
            b"sequence-two-mocked-custody-report\x00" + bytes([index]) + canonical_bytes(report)
        )
    transition = continuity._transition(
        target,
        phase_report,
        custody_reports,
        target_checkpoint,
        manifest["phase_bound_manifest_checkpoint_sha256"],
    )
    transition_path = root / manifest["transition"]["path"]
    transition_checkpoint = _write_json(transition_path, transition)
    manifest["transition"]["sha256"] = transition_checkpoint
    transition_raw = transition_path.read_bytes()
    first_three_leaves = [old_transition_raw, old_seal_raw, transition_raw]
    intermediate_root = _merkle_root(first_three_leaves)

    signed_intermediate: list[bytes] = []
    for index, key in enumerate(fixture["log_keys"]):
        signed_intermediate.append(
            _signed_checkpoint(
                fixture["openssl"],
                key,
                3,
                intermediate_root,
                base,
                "sequence-two-intermediate-%d" % index,
            )
        )
        prior_descriptor = manifest["stores"][index]["prior_checkpoint"]
        (root / prior_descriptor["path"]).write_bytes(old_final_raws[index])
        prior_descriptor["sha256"] = sha256_bytes(old_final_raws[index])
        intermediate_descriptor = manifest["stores"][index]["intermediate_checkpoint"]
        (root / intermediate_descriptor["path"]).write_bytes(signed_intermediate[index])
        intermediate_descriptor["sha256"] = sha256_bytes(signed_intermediate[index])

    intermediate_records = [
        {
            "store_id": target_store["store_id"],
            "intermediate_checkpoint_sha256": sha256_bytes(signed_intermediate[index]),
            "intermediate_root_sha256": intermediate_root.hex(),
            "intermediate_tree_size": 3,
        }
        for index, target_store in enumerate(target["stores"])
    ]
    seal = continuity._seal(target, transition, intermediate_records, transition_checkpoint)
    seal_path = root / manifest["seal"]["path"]
    seal_checkpoint = _write_json(seal_path, seal)
    manifest["seal"]["sha256"] = seal_checkpoint
    seal_raw = seal_path.read_bytes()
    four_leaves = [*first_three_leaves, seal_raw]
    final_root = _merkle_root(four_leaves)

    for index, key in enumerate(fixture["log_keys"]):
        signed_final = _signed_checkpoint(
            fixture["openssl"],
            key,
            4,
            final_root,
            base,
            "sequence-two-final-%d" % index,
        )
        final_descriptor = manifest["stores"][index]["final_checkpoint"]
        (root / final_descriptor["path"]).write_bytes(signed_final)
        final_descriptor["sha256"] = sha256_bytes(signed_final)
        proof_values = {
            "prior_to_intermediate_consistency": _proof("CONSISTENCY", 2, 3, _consistency_proof(first_three_leaves, 2)),
            "transition_inclusion": _proof("INCLUSION", 2, 3, _inclusion_proof(first_three_leaves, 2)),
            "intermediate_to_final_consistency": _proof("CONSISTENCY", 3, 4, _consistency_proof(four_leaves, 3)),
            "seal_inclusion": _proof("INCLUSION", 3, 4, _inclusion_proof(four_leaves, 3)),
        }
        for field, proof_value in proof_values.items():
            descriptor = manifest["stores"][index][field]
            descriptor["sha256"] = _write_json(root / descriptor["path"], proof_value)

    result["mock_phase_report"] = phase_report
    result["mock_custody_reports"] = custody_reports
    result["predecessor_state"] = state
    result["predecessor_state_path"] = predecessor_path
    _seal_manifest(result)
    return result


def _caller_prior_pins(fixture: dict[str, Any]) -> list[str]:
    return [item["prior_checkpoint_sha256"] for item in fixture["target"]["stores"]]


def _caller_final_pins(fixture: dict[str, Any]) -> list[str]:
    return [item["final_checkpoint"]["sha256"] for item in fixture["manifest"]["stores"]]


def _preflight(fixture: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    values = {
        "root": fixture["root"],
        "expected_composition_manifest_sha256": fixture["manifest_sha256"],
        "expected_sequence": 1,
        "expected_predecessor_continuity_state_sha256": None,
        "predecessor_continuity_state_path": None,
        "expected_prior_store_checkpoint_sha256s": _caller_prior_pins(fixture),
        "expected_final_store_checkpoint_sha256s": _caller_final_pins(fixture),
        "phase_openssl_paths": [fixture["openssl"], fixture["openssl"]],
        "expected_phase_openssl_sha256s": [fixture["openssl_sha256"], fixture["openssl_sha256"]],
        "custody_openssl_paths": [fixture["openssl"], fixture["openssl"]],
        "expected_custody_openssl_sha256s": [fixture["openssl_sha256"], fixture["openssl_sha256"]],
        "store_openssl_paths": [fixture["openssl"], fixture["openssl"]],
        "expected_store_openssl_sha256s": [fixture["openssl_sha256"], fixture["openssl_sha256"]],
    }
    values.update(overrides)
    return continuity.preflight_sentinel_dual_log_continuity(**values)


def _verify_saved(report: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    return continuity.verify_sentinel_dual_log_continuity_preflight(
        report,
        fixture["root"],
        fixture["manifest_sha256"],
        1,
        None,
        None,
        _caller_prior_pins(fixture),
        _caller_final_pins(fixture),
        [fixture["openssl"], fixture["openssl"]],
        [fixture["openssl_sha256"], fixture["openssl_sha256"]],
        [fixture["openssl"], fixture["openssl"]],
        [fixture["openssl_sha256"], fixture["openssl_sha256"]],
        [fixture["openssl"], fixture["openssl"]],
        [fixture["openssl_sha256"], fixture["openssl_sha256"]],
    )


def _rewrite_target(fixture: dict[str, Any], editor: Callable[[dict[str, Any]], None]) -> None:
    target = fixture["target"]
    editor(target)
    _seal_target(target)
    checkpoint = _write_json(fixture["target_path"], target)
    fixture["manifest"]["custody_target"]["sha256"] = checkpoint
    fixture["manifest"]["custody_target_sha256"] = target["target_sha256"]
    _seal_manifest(fixture)


def _rewrite_direct_json(
    fixture: dict[str, Any], manifest_field: str, editor: Callable[[dict[str, Any]], None]
) -> None:
    descriptor = fixture["manifest"][manifest_field]
    path = fixture["root"] / descriptor["path"]
    value = _json(path)
    editor(value)
    descriptor["sha256"] = _write_json(path, value)
    _seal_manifest(fixture)


def _rewrite_store_json(
    fixture: dict[str, Any], store_index: int, field: str, editor: Callable[[dict[str, Any]], None]
) -> None:
    descriptor = fixture["manifest"]["stores"][store_index][field]
    path = fixture["root"] / descriptor["path"]
    value = _json(path)
    editor(value)
    descriptor["sha256"] = _write_json(path, value)
    _seal_manifest(fixture)


@pytest.fixture(scope="module")
def continuity_report(continuity_fixture: dict[str, Any]) -> dict[str, Any]:
    return _preflight(continuity_fixture)


def test_clean_sequence_one_and_saved_report_replay(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any]
) -> None:
    report = continuity_report
    assert report["status"] == continuity.PREFLIGHT_STATUS
    assert report["sequence"] == 1
    assert report["slot_rule"] == {
        "prior_tree_size": 0,
        "transition_leaf_index": 0,
        "intermediate_tree_size": 1,
        "seal_leaf_index": 1,
        "final_tree_size": 2,
    }
    assert report["continuity_relative_to_supplied_checkpoints_verified"] is True
    assert report["same_transition_bytes_in_both_supplied_views_verified"] is True
    assert report["dual_store_intermediate_views_cross_logged_verified"] is True
    assert report["no_extra_leaf_between_supplied_prior_and_final_heads_verified"] is True
    assert report["checkpoint_signatures_under_precommitted_keys_verified"] is True
    assert [item["checkpoint_origin"] for item in report["current_state"]["stores"]] == [
        "causalfrontier-log-a",
        "causalfrontier-log-b",
    ]
    assert [item["checkpoint_verifier_key_sha256"] for item in report["current_state"]["stores"]] == [
        item["checkpoint_verifier_key_sha256"] for item in continuity_fixture["target"]["stores"]
    ]
    assert all(report[field] is False for field in continuity.FIXED_FALSE_FIELDS)
    assert report["designated_outcome_input_absent"] is True
    assert report["oracle_opening_input_absent"] is True
    assert report["admission_disabled"] is True
    assert report["scoring_disabled"] is True
    assert _verify_saved(report, continuity_fixture) == report


def test_sequence_one_state_is_accepted_as_the_exact_sequence_two_predecessor(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any], tmp_path: Path
) -> None:
    state = deepcopy(continuity_report["current_state"])
    state_path = tmp_path / "predecessor-state.json"
    _write_json(state_path, state)
    target = _sequence_two_target(continuity_fixture, continuity_report)
    raw, replayed = continuity._read_predecessor_state(
        state_path,
        state["state_sha256"],
        target,
        target["stores"],
    )
    assert raw == canonical_bytes(state) + b"\n"
    assert replayed == state
    assert [item["prior_checkpoint_sha256"] for item in target["stores"]] == [
        item["final_checkpoint_sha256"] for item in state["stores"]
    ]
    assert [item["prior_tree_size"] for item in target["stores"]] == [2, 2]


def test_sequence_two_public_api_requires_the_predecessor_state_file(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any]
) -> None:
    with pytest.raises(CausalFrontierError, match="caller-supplied predecessor state file"):
        _preflight(
            continuity_fixture,
            expected_sequence=2,
            expected_predecessor_continuity_state_sha256=continuity_report["current_state"]["state_sha256"],
            predecessor_continuity_state_path=None,
        )


@pytest.mark.parametrize("case", ["boolean-sequence", "sequence-gap"])
def test_predecessor_sequence_is_an_exact_non_boolean_immediate_predecessor(
    continuity_fixture: dict[str, Any],
    continuity_report: dict[str, Any],
    tmp_path: Path,
    case: str,
) -> None:
    state = deepcopy(continuity_report["current_state"])
    target = _sequence_two_target(continuity_fixture, continuity_report)
    if case == "boolean-sequence":
        state["sequence"] = True
    else:
        target["sequence"] = 3
    state_path = tmp_path / (case + ".json")
    _write_json(state_path, state)
    with pytest.raises(CausalFrontierError, match=r"bounded positive integer|different chain or sequence"):
        continuity._read_predecessor_state(
            state_path,
            continuity_report["current_state"]["state_sha256"],
            target,
            target["stores"],
        )


def test_predecessor_state_cannot_cross_continuity_ids(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any], tmp_path: Path
) -> None:
    state = deepcopy(continuity_report["current_state"])
    state["continuity_id"] = "continuity:different-chain:1"
    _seal_state(state)
    state_path = tmp_path / "wrong-chain.json"
    _write_json(state_path, state)
    target = _sequence_two_target(continuity_fixture, continuity_report)
    with pytest.raises(CausalFrontierError, match="different chain or sequence"):
        continuity._read_predecessor_state(
            state_path,
            state["state_sha256"],
            target,
            target["stores"],
        )


@pytest.mark.parametrize(
    "case",
    ["reorder", "store-id", "operator", "namespace", "origin", "vkey-digest"],
)
def test_predecessor_store_identity_and_key_continuity_cannot_be_spliced(
    continuity_fixture: dict[str, Any],
    continuity_report: dict[str, Any],
    tmp_path: Path,
    case: str,
) -> None:
    state = deepcopy(continuity_report["current_state"])
    if case == "reorder":
        state["stores"].reverse()
    elif case == "store-id":
        state["stores"][1]["store_id"] = "store:continuity-log-c"
    elif case == "operator":
        state["stores"][0]["operator_organization_id"] = "organization:continuity-log-operator-c"
    elif case == "namespace":
        state["stores"][0]["namespace_id"] = "namespace:continuity-log-c"
    elif case == "origin":
        state["stores"][0]["checkpoint_origin"] = "causalfrontier-log-c"
    else:
        value = state["stores"][0]["checkpoint_verifier_key_sha256"]
        state["stores"][0]["checkpoint_verifier_key_sha256"] = _different_digest(value)
    _seal_state(state)
    state_path = tmp_path / (case + ".json")
    _write_json(state_path, state)
    target = _sequence_two_target(continuity_fixture, continuity_report)
    with pytest.raises(CausalFrontierError, match=r"store order differs|does not equal this step"):
        continuity._read_predecessor_state(
            state_path,
            state["state_sha256"],
            target,
            target["stores"],
        )


@pytest.mark.parametrize("field", ["prior_checkpoint_sha256", "prior_root_sha256", "prior_tree_size"])
def test_sequence_two_target_prior_checkpoint_root_and_size_must_equal_the_predecessor_finals(
    continuity_fixture: dict[str, Any],
    continuity_report: dict[str, Any],
    tmp_path: Path,
    field: str,
) -> None:
    state = deepcopy(continuity_report["current_state"])
    state_path = tmp_path / (field + ".json")
    _write_json(state_path, state)
    target = _sequence_two_target(continuity_fixture, continuity_report)
    if field == "prior_tree_size":
        target["stores"][0][field] = 3
    else:
        target["stores"][0][field] = _different_digest(target["stores"][0][field])
    with pytest.raises(CausalFrontierError, match="does not equal this step's prior store state"):
        continuity._read_predecessor_state(
            state_path,
            state["state_sha256"],
            target,
            target["stores"],
        )


def test_predecessor_state_semantic_hash_mismatch_is_rejected(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any], tmp_path: Path
) -> None:
    state = deepcopy(continuity_report["current_state"])
    state["transition_sha256"] = _different_digest(state["transition_sha256"])
    state_path = tmp_path / "semantic-mismatch.json"
    _write_json(state_path, state)
    target = _sequence_two_target(continuity_fixture, continuity_report)
    with pytest.raises(CausalFrontierError, match="semantic digest differs"):
        continuity._read_predecessor_state(
            state_path,
            continuity_report["current_state"]["state_sha256"],
            target,
            target["stores"],
        )


def test_sequence_two_replays_real_four_leaf_log_evidence_with_only_phase_and_custody_layers_mocked(
    continuity_fixture: dict[str, Any],
    continuity_report: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _build_sequence_two_fixture(continuity_fixture, continuity_report, tmp_path)
    phase_report = deepcopy(fixture["mock_phase_report"])
    custody_reports = iter(deepcopy(fixture["mock_custody_reports"]))
    monkeypatch.setattr(
        continuity.sentinel_phase,
        "preflight_sentinel_phase_bound_admission",
        lambda *_arguments, **_keywords: deepcopy(phase_report),
    )
    monkeypatch.setattr(
        continuity.attestation,
        "verify_rfc3161_attestation",
        lambda *_arguments, **_keywords: next(custody_reports),
    )
    report = _preflight(
        fixture,
        expected_sequence=2,
        expected_predecessor_continuity_state_sha256=fixture["predecessor_state"]["state_sha256"],
        predecessor_continuity_state_path=fixture["predecessor_state_path"],
    )
    assert report["sequence"] == 2
    assert report["predecessor_continuity_state_sha256"] == continuity_report["current_state"]["state_sha256"]
    assert report["slot_rule"] == {
        "prior_tree_size": 2,
        "transition_leaf_index": 2,
        "intermediate_tree_size": 3,
        "seal_leaf_index": 3,
        "final_tree_size": 4,
    }
    assert [item["final_tree_size"] for item in report["current_state"]["stores"]] == [4, 4]
    assert report["continuity_relative_to_supplied_checkpoints_verified"] is True
    assert report["checkpoint_signatures_under_precommitted_keys_verified"] is True
    assert report["no_extra_leaf_between_supplied_prior_and_final_heads_verified"] is True


def test_replay_is_exactly_deterministic(continuity_fixture: dict[str, Any]) -> None:
    assert canonical_bytes(_preflight(continuity_fixture)) == canonical_bytes(_preflight(continuity_fixture))


@pytest.mark.parametrize("kind", ["manifest", "prior", "final"])
def test_caller_checkpoints_are_required_exactly(continuity_fixture: dict[str, Any], kind: str) -> None:
    overrides: dict[str, Any] = {}
    if kind == "manifest":
        overrides["expected_composition_manifest_sha256"] = _different_digest(continuity_fixture["manifest_sha256"])
    elif kind == "prior":
        pins = _caller_prior_pins(continuity_fixture)
        pins[0] = _different_digest(pins[0])
        overrides["expected_prior_store_checkpoint_sha256s"] = pins
    else:
        pins = _caller_final_pins(continuity_fixture)
        pins[1] = _different_digest(pins[1])
        overrides["expected_final_store_checkpoint_sha256s"] = pins
    with pytest.raises(CausalFrontierError, match=r"checkpoint|checkpoints"):
        _preflight(continuity_fixture, **overrides)


def test_sequence_one_rejects_any_predecessor_state_path(continuity_fixture: dict[str, Any], tmp_path: Path) -> None:
    with pytest.raises(CausalFrontierError, match="first continuity replay requires a null predecessor"):
        _preflight(continuity_fixture, predecessor_continuity_state_path=tmp_path / "unexpected-state.json")


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("statement_profile", "UNREGISTERED_STATEMENT_PROFILE", "fixed log protocol"),
        ("checkpoint_profile", "UNREGISTERED_CHECKPOINT_PROFILE", "fixed log protocol"),
        ("proof_profile", "GENERIC_INCLUSION_ONLY", "fixed log protocol"),
        ("cross_log_rule", "INCLUSION_WITHOUT_CROSS_SEAL", "fixed log protocol"),
        ("slot_rule", {**continuity._slot_rule(1), "seal_leaf_index": 2}, "fixed log protocol"),
        ("generated_artifact_input_absent", False, "artifact, outcome, admission, or scoring path"),
        ("outcome_input_absent", False, "artifact, outcome, admission, or scoring path"),
        ("oracle_opening_input_absent", False, "artifact, outcome, admission, or scoring path"),
        ("admission_disabled", False, "artifact, outcome, admission, or scoring path"),
        ("scoring_disabled", False, "artifact, outcome, admission, or scoring path"),
    ],
)
def test_pre_token_target_cannot_weaken_protocol_or_authority_boundaries(
    continuity_fixture: dict[str, Any],
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    _rewrite_target(fixture, lambda value: value.__setitem__(field, replacement))
    with pytest.raises(CausalFrontierError, match=message):
        _preflight(fixture)


def test_coherently_resealed_target_substitution_fails_its_prior_custody_tokens(
    continuity_fixture: dict[str, Any], tmp_path: Path
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    _rewrite_target(
        fixture,
        lambda value: value.__setitem__("generation_plan_sha256", _different_digest(value["generation_plan_sha256"])),
    )
    with pytest.raises(CausalFrontierError, match=r"timestamp|imprint|attestation|OpenSSL"):
        _preflight(fixture)


def test_nested_generation_plan_post_token_substitution_is_rejected(
    continuity_fixture: dict[str, Any], tmp_path: Path
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    path = fixture["phase_root"] / "generation-plan.json"
    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 1
    path.write_bytes(bytes(raw))
    with pytest.raises(CausalFrontierError, match=r"declared artifact|checkpoint|digest|JSON|generation"):
        _preflight(fixture)


@pytest.mark.parametrize("field", ["transition", "seal"])
def test_post_token_transition_or_seal_substitution_is_rejected(
    continuity_fixture: dict[str, Any], tmp_path: Path, field: str
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    semantic_field = "transition_sha256" if field == "transition" else "seal_sha256"
    _rewrite_direct_json(
        fixture,
        field,
        lambda value: value.__setitem__(semantic_field, _different_digest(value[semantic_field])),
    )
    with pytest.raises(CausalFrontierError, match=r"transition differs|seal differs"):
        _preflight(fixture)


@pytest.mark.parametrize(
    ("field", "edit", "message"),
    [
        (
            "transition_inclusion",
            lambda value: value["hashes"].append(base64.b64encode(b"x" * 32).decode("ascii")),
            "transition inclusion proof is invalid",
        ),
        (
            "prior_to_intermediate_consistency",
            lambda value: value["hashes"].append(base64.b64encode(b"y" * 32).decode("ascii")),
            "prior-to-intermediate consistency proof is invalid",
        ),
        (
            "intermediate_to_final_consistency",
            lambda value: value["hashes"].__setitem__(0, base64.b64encode(b"z" * 32).decode("ascii")),
            "intermediate-to-final consistency proof is invalid",
        ),
        (
            "seal_inclusion",
            lambda value: value["hashes"].__setitem__(0, base64.b64encode(b"q" * 32).decode("ascii")),
            "seal inclusion proof is invalid",
        ),
    ],
)
def test_corrupt_inclusion_and_consistency_proofs_fail_closed(
    continuity_fixture: dict[str, Any],
    tmp_path: Path,
    field: str,
    edit: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    _rewrite_store_json(fixture, 0, field, edit)
    with pytest.raises(CausalFrontierError, match=message):
        _preflight(fixture)


@pytest.mark.parametrize(
    ("field", "key", "replacement"),
    [
        ("transition_inclusion", "left_size", 1),
        ("transition_inclusion", "right_size", 2),
        ("seal_inclusion", "left_size", 0),
        ("seal_inclusion", "right_size", 1),
        ("prior_to_intermediate_consistency", "right_size", 2),
        ("intermediate_to_final_consistency", "left_size", 0),
    ],
)
def test_proof_indices_and_sizes_are_fixed_by_the_reserved_slot_rule(
    continuity_fixture: dict[str, Any],
    tmp_path: Path,
    field: str,
    key: str,
    replacement: int,
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    _rewrite_store_json(fixture, 1, field, lambda value: value.__setitem__(key, replacement))
    with pytest.raises(CausalFrontierError, match="changes the fixed proof contract"):
        _preflight(fixture)


def test_corrupt_c2sp_checkpoint_signature_is_rejected(continuity_fixture: dict[str, Any], tmp_path: Path) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    descriptor = fixture["manifest"]["stores"][1]["final_checkpoint"]
    path = fixture["root"] / descriptor["path"]
    raw = path.read_bytes()
    prefix, encoded = raw.rsplit(b" ", 1)
    blob = bytearray(base64.b64decode(encoded.strip(), validate=True))
    blob[-1] ^= 1
    corrupted = prefix + b" " + base64.b64encode(bytes(blob)) + b"\n"
    path.write_bytes(corrupted)
    descriptor["sha256"] = sha256_bytes(corrupted)
    _seal_manifest(fixture)
    with pytest.raises(CausalFrontierError, match=r"checkpoint signature|OpenSSL"):
        _preflight(fixture)


@pytest.mark.parametrize(
    ("field", "tree_size"),
    [("intermediate_checkpoint", 2), ("final_checkpoint", 3)],
)
def test_validly_signed_checkpoint_sizes_cannot_escape_the_reserved_slot_rule(
    continuity_fixture: dict[str, Any], tmp_path: Path, field: str, tree_size: int
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    store_index = 0
    transition_raw = (fixture["root"] / fixture["manifest"]["transition"]["path"]).read_bytes()
    root_hash = _transparency.leaf_hash(transition_raw)
    if field == "final_checkpoint":
        seal_raw = (fixture["root"] / fixture["manifest"]["seal"]["path"]).read_bytes()
        root_hash = _transparency.node_hash(root_hash, _transparency.leaf_hash(seal_raw))
    raw = _signed_checkpoint(
        fixture["openssl"],
        fixture["log_keys"][store_index],
        tree_size,
        root_hash,
        tmp_path,
        "wrong-size-%s" % field,
    )
    descriptor = fixture["manifest"]["stores"][store_index][field]
    (fixture["root"] / descriptor["path"]).write_bytes(raw)
    descriptor["sha256"] = sha256_bytes(raw)
    _seal_manifest(fixture)
    with pytest.raises(CausalFrontierError, match="signed checkpoint sizes violate the reserved-slot rule"):
        _preflight(fixture)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda target: target["stores"][1].__setitem__("store_id", target["stores"][0]["store_id"]),
        lambda target: target["stores"][1].__setitem__("checkpoint_origin", target["stores"][0]["checkpoint_origin"]),
        lambda target: target["stores"][1].__setitem__(
            "checkpoint_verifier_key", target["stores"][0]["checkpoint_verifier_key"]
        ),
        lambda target: target["custody_witnesses"][1].__setitem__(
            "witness_id", target["custody_witnesses"][0]["witness_id"]
        ),
        lambda target: target["stores"][0].__setitem__(
            "controller_group_id", target["custody_witnesses"][0]["controller_group_id"]
        ),
    ],
    ids=["duplicate-store-id", "duplicate-origin", "duplicate-key", "duplicate-witness-id", "role-alias"],
)
def test_duplicate_store_key_witness_and_role_identities_are_rejected_before_replay(
    continuity_fixture: dict[str, Any],
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    _rewrite_target(fixture, mutation)
    with pytest.raises(CausalFrontierError, match=r"distinct|share|differs|alias"):
        _preflight(fixture)


@pytest.mark.parametrize("field", sorted(continuity.FIXED_FALSE_FIELDS))
def test_saved_report_cannot_invent_any_fixed_false_claim(
    continuity_fixture: dict[str, Any], continuity_report: dict[str, Any], field: str
) -> None:
    forged = deepcopy(continuity_report)
    forged[field] = True
    with pytest.raises(CausalFrontierError, match="deterministic replay"):
        _verify_saved(forged, continuity_fixture)


def test_public_replay_apis_have_no_outcome_or_oracle_parameters() -> None:
    forbidden = {"outcome", "result", "winner", "oracle", "comparator", "effect", "score"}
    for function in (
        continuity.preflight_sentinel_dual_log_continuity,
        continuity.verify_sentinel_dual_log_continuity_preflight,
    ):
        names = set(inspect.signature(function).parameters)
        assert not any(token in name for name in names for token in forbidden)


def _checkpoint_raws(fixture: dict[str, Any], store_index: int) -> list[bytes]:
    store = fixture["manifest"]["stores"][store_index]
    return [
        (fixture["root"] / store[field]["path"]).read_bytes()
        for field in ("prior_checkpoint", "intermediate_checkpoint", "final_checkpoint")
    ]


def _unknown_signature_line(name: str, key_id: bytes = b"UNKN") -> bytes:
    encoded = base64.b64encode(key_id + b"u" * 64).decode("ascii")
    return ("— %s %s\n" % (name, encoded)).encode("utf-8")


def _add_signature_lines(raw: bytes, lines: list[bytes]) -> bytes:
    note, signatures = raw.rsplit(b"\n\n", 1)
    return note + b"\n\n" + b"".join(lines) + signatures


def test_c2sp_checkpoint_accepts_sixteen_lines_and_ignores_unknown_keys(
    continuity_fixture: dict[str, Any],
) -> None:
    store = continuity_fixture["target"]["stores"][0]
    raws = _checkpoint_raws(continuity_fixture, 0)
    unknown = [_unknown_signature_line("unknown-%02d.example" % index) for index in range(14)]
    unknown.append(_unknown_signature_line(store["checkpoint_origin"], b"DIFF"))
    raws[0] = _add_signature_lines(raws[0], unknown)
    values = continuity._verify_checkpoint_set(
        raws,
        store,
        continuity_fixture["openssl"],
        continuity_fixture["openssl_sha256"],
    )
    assert [size for size, _root in values] == [0, 1, 2]


def test_c2sp_checkpoint_rejects_more_than_sixteen_signature_lines(
    continuity_fixture: dict[str, Any],
) -> None:
    store = continuity_fixture["target"]["stores"][0]
    raw = _checkpoint_raws(continuity_fixture, 0)[0]
    excessive = [_unknown_signature_line("unknown-%02d.example" % index) for index in range(16)]
    with pytest.raises(CausalFrontierError, match="signature count or framing"):
        continuity._checkpoint_components(_add_signature_lines(raw, excessive), store, "checkpoint")


def test_c2sp_checkpoint_requires_one_signature_from_the_pinned_key(
    continuity_fixture: dict[str, Any],
) -> None:
    store = continuity_fixture["target"]["stores"][0]
    raw = _checkpoint_raws(continuity_fixture, 0)[0]
    note, _signature = raw.rsplit(b"\n\n", 1)
    unknown_only = note + b"\n\n" + _unknown_signature_line("unknown.example")
    with pytest.raises(CausalFrontierError, match="no signature from its pinned checkpoint key"):
        continuity._checkpoint_components(unknown_only, store, "checkpoint")


def test_one_invalid_matching_signature_rejects_the_entire_c2sp_note(
    continuity_fixture: dict[str, Any],
) -> None:
    store = continuity_fixture["target"]["stores"][0]
    raws = _checkpoint_raws(continuity_fixture, 0)
    signature_line = raws[0].rsplit(b"\n\n", 1)[1]
    prefix, encoded = signature_line.rsplit(b" ", 1)
    blob = bytearray(base64.b64decode(encoded.strip(), validate=True))
    blob[-1] ^= 1
    corrupted = prefix + b" " + base64.b64encode(bytes(blob)) + b"\n"
    raws[0] = _add_signature_lines(raws[0], [corrupted])
    with pytest.raises(CausalFrontierError, match=r"checkpoint signature|OpenSSL"):
        continuity._verify_checkpoint_set(
            raws,
            store,
            continuity_fixture["openssl"],
            continuity_fixture["openssl_sha256"],
        )


def test_two_store_evidence_descriptors_cannot_alias_one_exact_path(
    continuity_fixture: dict[str, Any], tmp_path: Path
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    fixture["manifest"]["stores"][1]["prior_to_intermediate_consistency"] = deepcopy(
        fixture["manifest"]["stores"][0]["prior_to_intermediate_consistency"]
    )
    _seal_manifest(fixture)
    with pytest.raises(CausalFrontierError, match="paths overlap"):
        _preflight(fixture)


@pytest.mark.parametrize("mutation", ["orphan", "empty-directory", "symlink", "hardlink"])
def test_outer_inventory_rejects_orphans_and_unsafe_filesystem_objects(
    continuity_fixture: dict[str, Any], tmp_path: Path, mutation: str
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    if mutation == "orphan":
        (fixture["root"] / "orphan.txt").write_text("orphan\n", encoding="utf-8")
    elif mutation == "empty-directory":
        (fixture["root"] / "empty").mkdir()
    elif mutation == "symlink":
        (fixture["root"] / "unsafe-link").symlink_to(fixture["manifest_path"])
    else:
        source = fixture["root"] / fixture["manifest"]["stores"][0]["transition_inclusion"]["path"]
        os.link(source, fixture["root"] / "unsafe-hardlink")
    with pytest.raises(CausalFrontierError, match=r"inventory|unsafe|empty|orphan"):
        _preflight(fixture)


def test_noncanonical_proof_json_is_rejected_even_when_recheckpointed(
    continuity_fixture: dict[str, Any], tmp_path: Path
) -> None:
    fixture = _copy_fixture(continuity_fixture, tmp_path)
    descriptor = fixture["manifest"]["stores"][0]["transition_inclusion"]
    path = fixture["root"] / descriptor["path"]
    raw = (json.dumps(_json(path), indent=2, sort_keys=False) + "\n").encode("utf-8")
    path.write_bytes(raw)
    descriptor["sha256"] = sha256_bytes(raw)
    _seal_manifest(fixture)
    with pytest.raises(CausalFrontierError, match="canonical JSON"):
        _preflight(fixture)


def test_public_api_exports_and_cli_structural_abstention(
    continuity_fixture: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert causalfrontier.preflight_sentinel_dual_log_continuity is continuity.preflight_sentinel_dual_log_continuity
    assert (
        causalfrontier.verify_sentinel_dual_log_continuity_preflight
        is continuity.verify_sentinel_dual_log_continuity_preflight
    )
    arguments = [
        "preflight-sentinel-dual-log-continuity",
        str(continuity_fixture["root"]),
        "--expected-composition-manifest-sha256",
        continuity_fixture["manifest_sha256"],
        "--expected-sequence",
        "1",
    ]
    for digest in _caller_prior_pins(continuity_fixture):
        arguments.extend(["--expected-prior-store-checkpoint-sha256", digest])
    for digest in _caller_final_pins(continuity_fixture):
        arguments.extend(["--expected-final-store-checkpoint-sha256", digest])
    for prefix in ("phase", "custody", "store"):
        for _index in range(2):
            arguments.extend(["--%s-openssl" % prefix, str(continuity_fixture["openssl"])])
            arguments.extend(["--expected-%s-openssl-sha256" % prefix, continuity_fixture["openssl_sha256"]])
    assert main(arguments) == 3
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == continuity.PREFLIGHT_STATUS
    assert output["scientific_scoring_ready"] is False
