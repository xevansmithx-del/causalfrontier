"""Hostile synthetic-only tests for pre-reveal selections and reveal opening."""

from __future__ import annotations

import inspect
import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from test_challenge import _artifact, _build, _reseal, _rewrite_json_artifact

from causalfrontier import challenge, comparators, reveal
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main

NONCE_HEX = "42" * 32


def _payload(root: Path, document: dict, required_replicates: int = 2) -> dict:
    cases = []
    for case in document["cases"]:
        encoding = next(item for item in document["encodings"] if item["case_id"] == case["id"])
        artifact = _artifact(document, encoding["frozen_case_artifact_id"])
        frozen_case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
        actions = []
        for experiment in frozen_case["experiments"]:
            outcome_id = experiment["outcomes"][0]["id"]
            actions.append(
                {
                    "experiment_id": experiment["id"],
                    "replicate_outcome_ids": [outcome_id] * required_replicates,
                }
            )
        cases.append({"case_id": case["id"], "action_outcomes": actions})
    return {
        "schema_version": reveal.PAYLOAD_SCHEMA_VERSION,
        "challenge_id": document["id"],
        "challenge_sequence": document["sequence"],
        "challenge_registration_sha256": challenge.challenge_registration_sha256(document),
        "predecessor_manifest_sha256": document["predecessor_manifest_sha256"],
        "scope": document["scope"],
        "required_replicates": required_replicates,
        "cases": cases,
    }


def _write_opening(path: Path, payload: dict, nonce_hex: str = NONCE_HEX) -> str:
    raw = (
        canonical_bytes({"schema_version": reveal.OPENING_SCHEMA_VERSION, "nonce_hex": nonce_hex, "payload": payload})
        + b"\n"
    )
    path.write_bytes(raw)
    return sha256_bytes(raw)


@pytest.fixture
def protocol_fixture(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "challenge"
    document, _digest = _build(root, raw_case, case_root)
    payload = _payload(root, document)
    document["reveal_commitment_sha256"] = reveal.reveal_commitment(payload, NONCE_HEX)
    digest = _reseal(root, document)
    opening = tmp_path / "opening.json"
    opening_digest = _write_opening(opening, payload)
    return root, document, digest, opening, opening_digest, payload


def test_pre_reveal_reference_lock_has_no_reveal_interface_and_preserves_all_nonclaims(protocol_fixture):
    root, _, digest, _, _, _ = protocol_fixture
    assert "reveal" not in inspect.signature(comparators.lock_reference_selections).parameters
    result = comparators.lock_reference_selections(root, digest, 1)
    assert result["status"] == "PRE_REVEAL_REFERENCE_SELECTIONS_LOCKED_SCIENTIFIC_SCORING_DISABLED"
    assert result["reveal_input_accepted"] is False
    assert result["scientific_scoring_ready"] is False
    assert result["combined_encoder_case_selection_ready"] is False
    assert result["scientific_baseline_families_executed"] == []
    assert set(result["required_scientific_baseline_families_unexecuted"]) == challenge.BASELINE_FAMILIES
    assert len(result["reference_lanes"]) == 6
    assert len(result["nonclaims"]) >= 6
    gates = {item["id"]: item for item in result["gates"]}
    assert gates["pre_reveal_interface"]["status"] == "PASS"
    assert gates["entrant_blinding"]["status"] == "NO_CALL"
    assert gates["encoder_decision_model_agreement"]["status"] == "NO_CALL"
    assert gates["scientific_scoring"]["status"] == "NO_CALL"


def test_causalfrontier_tie_is_no_call_and_uniform_policy_enumerates_exactly(protocol_fixture):
    root, _, digest, _, _, _ = protocol_fixture
    result = comparators.lock_reference_selections(root, digest, 1)
    for lane in result["reference_lanes"]:
        policies = {item["policy_id"]: item for item in lane["reference_policy_traces"]}
        candidate = policies["CAUSALFRONTIER_UNIQUE_MINIMAX_V1"]
        assert candidate["status"] == "NO_CALL"
        assert candidate["selections"][0]["action"] == "NO_CALL"
        uniform = policies["UNIFORM_ACTION_ENUMERATION_REFERENCE_V1"]
        assert uniform["status"] == "ENUMERATED"
        assert [item["experiment_id"] for item in uniform["selections"]] == uniform["eligible_action_ids"]
        assert {item["enumeration_numerator"] for item in uniform["selections"]} == {1}
        assert {item["enumeration_denominator"] for item in uniform["selections"]} == {
            len(uniform["eligible_action_ids"])
        }


def test_reference_lock_is_byte_deterministic_and_order_invariant(protocol_fixture):
    root, document, digest, _, _, _ = protocol_fixture
    first = comparators.lock_reference_selections(root, digest, 1)
    document["encodings"].reverse()
    document["cases"].reverse()
    digest = _reseal(root, document)
    second = comparators.lock_reference_selections(root, digest, 1)
    assert first["reference_lanes"] == second["reference_lanes"]
    assert first["policy_contract_sha256"] == second["policy_contract_sha256"]


def test_registration_digest_excludes_only_commitment_value(protocol_fixture):
    _, document, _, _, _, _ = protocol_fixture
    registration = challenge.challenge_registration_sha256(document)
    changed = deepcopy(document)
    changed["reveal_commitment_sha256"] = "0" * 64
    assert changed["reveal_commitment_sha256"] != document["reveal_commitment_sha256"]
    assert challenge.challenge_registration_sha256(changed) == registration

    for field, value in document.items():
        if field == "reveal_commitment_sha256":
            continue
        changed = deepcopy(document)
        if isinstance(value, list):
            changed[field] = [*value, {"tampered": field}]
        elif isinstance(value, dict):
            changed[field] = {**value, "tampered": field}
        elif type(value) is int:
            changed[field] = value + 1
        else:
            changed[field] = f"{value}:tampered"
        assert challenge.challenge_registration_sha256(changed) != registration, field


def test_valid_synthetic_reveal_opens_but_outcome_derivation_and_scoring_stay_disabled(protocol_fixture):
    root, _, digest, opening, opening_digest, _ = protocol_fixture
    result = reveal.open_synthetic_reveal(root, digest, 1, opening, opening_digest)
    assert result["status"] == "SYNTHETIC_REVEAL_OPENED_OUTCOME_DERIVATION_AND_SCIENTIFIC_SCORING_DISABLED"
    assert result["cases_n"] == 3
    assert result["actions_n"] == 9
    assert result["required_replicates"] == 2
    assert result["outcome_derivation_ready"] is False
    assert result["scientific_scoring_ready"] is False
    gates = {item["id"]: item for item in result["gates"]}
    assert gates["reveal_commitment"]["status"] == "PASS"
    assert gates["outcome_derivation"]["status"] == "NO_CALL"
    assert gates["scientific_scoring"]["status"] == "NO_CALL"


@pytest.mark.parametrize("mutation", ["nonce", "payload", "sequence", "predecessor"])
def test_wrong_opening_never_matches_commitment(protocol_fixture, mutation):
    root, _, digest, opening, _, payload = protocol_fixture
    changed = deepcopy(payload)
    nonce = NONCE_HEX
    if mutation == "nonce":
        nonce = "43" * 32
    elif mutation == "payload":
        changed["required_replicates"] = 3
        for case in changed["cases"]:
            for action in case["action_outcomes"]:
                action["replicate_outcome_ids"].append(action["replicate_outcome_ids"][0])
    elif mutation == "sequence":
        changed["challenge_sequence"] = 2
    else:
        changed["predecessor_manifest_sha256"] = "9" * 64
    opening_digest = _write_opening(opening, changed, nonce)
    with pytest.raises(CausalFrontierError):
        reveal.open_synthetic_reveal(root, digest, 1, opening, opening_digest)


@pytest.mark.parametrize("mutation", ["missing-case", "missing-action", "extra-action", "short-replicates"])
def test_reveal_inventory_and_replication_are_total(protocol_fixture, mutation):
    root, document, _, opening, _, payload = protocol_fixture
    changed = deepcopy(payload)
    if mutation == "missing-case":
        changed["cases"].pop()
    elif mutation == "missing-action":
        changed["cases"][0]["action_outcomes"].pop()
    elif mutation == "extra-action":
        duplicate = deepcopy(changed["cases"][0]["action_outcomes"][0])
        duplicate["experiment_id"] = "experiment:posthoc"
        changed["cases"][0]["action_outcomes"].append(duplicate)
    else:
        changed["cases"][0]["action_outcomes"][0]["replicate_outcome_ids"].pop()
    document["reveal_commitment_sha256"] = reveal.reveal_commitment(changed, NONCE_HEX)
    digest = _reseal(root, document)
    opening_digest = _write_opening(opening, changed)
    with pytest.raises(CausalFrontierError):
        reveal.open_synthetic_reveal(root, digest, 1, opening, opening_digest)


@pytest.mark.parametrize("nonce", ["42" * 31, "42" * 33, "GG" * 32, "AB" * 32])
def test_nonce_is_exact_lowercase_32_bytes(nonce):
    with pytest.raises(CausalFrontierError, match="32 lowercase hexadecimal bytes"):
        reveal.reveal_commitment({"synthetic": "payload"}, nonce)


def test_opening_checkpoint_rejects_coherent_file_substitution(protocol_fixture):
    root, _, digest, opening, opening_digest, payload = protocol_fixture
    _write_opening(opening, payload, "43" * 32)
    with pytest.raises(CausalFrontierError, match="checkpoint mismatch"):
        reveal.open_synthetic_reveal(root, digest, 1, opening, opening_digest)


@pytest.mark.parametrize("mutation", ["duplicate-key", "float", "wrong-type"])
def test_malformed_opening_json_and_types_fail_closed(protocol_fixture, mutation):
    root, _, digest, opening, _, _ = protocol_fixture
    raw = opening.read_bytes()
    if mutation == "duplicate-key":
        raw = raw.replace(
            b'{"nonce_hex":',
            b'{"nonce_hex":"' + (b"00" * 32) + b'","nonce_hex":',
            1,
        )
    elif mutation == "float":
        raw = raw.replace(b'"required_replicates":2', b'"required_replicates":2.0', 1)
    else:
        value = json.loads(raw)
        value["payload"]["cases"] = {}
        raw = canonical_bytes(value) + b"\n"
    target = opening.parent / f"malformed-{mutation}.json"
    target.write_bytes(raw)
    with pytest.raises(CausalFrontierError):
        reveal.open_synthetic_reveal(root, digest, 1, target, sha256_bytes(raw))


def test_valid_opening_cannot_be_transplanted_to_a_different_challenge_registration(protocol_fixture):
    root, document, _, opening, opening_digest, _ = protocol_fixture
    baseline = document["baselines"][0]
    artifact = _artifact(document, baseline["artifact_id"])
    specification = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    specification["strategy_description"] = "Different synthetic-only unexecuted baseline specification"
    _rewrite_json_artifact(root, artifact, specification)
    digest = _reseal(root, document)
    with pytest.raises(CausalFrontierError, match="another challenge or scope"):
        reveal.open_synthetic_reveal(root, digest, 1, opening, opening_digest)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "fifo", "directory", "ancestor-symlink"])
def test_opening_filesystem_objects_fail_closed(protocol_fixture, unsafe_kind):
    root, _, digest, opening, opening_digest, _ = protocol_fixture
    target = opening.parent / "unsafe-opening.json"
    if unsafe_kind == "symlink":
        target.symlink_to(opening)
    elif unsafe_kind == "hardlink":
        os.link(opening, target)
    elif unsafe_kind == "fifo":
        os.mkfifo(target)
    elif unsafe_kind == "directory":
        target.mkdir()
    else:
        linked_parent = opening.parent / "unsafe-parent"
        linked_parent.symlink_to(opening.parent, target_is_directory=True)
        target = linked_parent / opening.name
    with pytest.raises(CausalFrontierError):
        reveal.open_synthetic_reveal(root, digest, 1, target, opening_digest)


def test_historical_scope_cannot_use_synthetic_reference_kernel(tmp_path, raw_case, case_root):
    root = tmp_path / "historical"
    _, digest = _build(root, raw_case, case_root, scope="HISTORICAL_REPLAY_DRAFT")
    with pytest.raises(CausalFrontierError, match="restricted to synthetic"):
        comparators.lock_reference_selections(root, digest, 1)


def test_action_contract_drift_blocks_reference_selection(protocol_fixture):
    root, document, _, _, _, _ = protocol_fixture
    encoding = document["encodings"][0]
    artifact = _artifact(document, encoding["frozen_case_artifact_id"])
    frozen_case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    frozen_case["experiments"][0]["resources"]["compute_units"] += 1
    _rewrite_json_artifact(root, artifact, frozen_case)
    digest = _reseal(root, document)
    with pytest.raises(CausalFrontierError, match="executable action contract"):
        comparators.lock_reference_selections(root, digest, 1)


def test_encoder_world_strata_remain_separate_under_one_action_contract(protocol_fixture):
    root, document, _, _, _, _ = protocol_fixture
    encoding = document["encodings"][0]
    artifact = _artifact(document, encoding["frozen_case_artifact_id"])
    frozen_case = json.loads((root / artifact["path"]).read_text(encoding="utf-8"))
    worlds = [item for item in frozen_case["worlds"] if not item["is_residual"]]
    worlds[0]["admissible_option_ids"], worlds[1]["admissible_option_ids"] = (
        worlds[1]["admissible_option_ids"],
        worlds[0]["admissible_option_ids"],
    )
    _rewrite_json_artifact(root, artifact, frozen_case)
    result = comparators.lock_reference_selections(root, _reseal(root, document), 1)
    lanes = [item for item in result["reference_lanes"] if item["case_id"] == encoding["case_id"]]
    assert len(lanes) == 2
    assert len({item["encoder_id"] for item in lanes}) == 2
    assert len({item["analysis_sha256"] for item in lanes}) == 2
    assert len({item["shared_action_input_sha256"] for item in lanes}) == 1
    assert result["combined_encoder_case_selection_ready"] is False


def test_cli_protocol_commands_emit_json_and_exit_three(protocol_fixture, capsys):
    root, _, digest, opening, opening_digest, _ = protocol_fixture
    selection_code = main(
        [
            "lock-reference-selections",
            str(root),
            "--expected-manifest-sha256",
            digest,
            "--expected-sequence",
            "1",
        ]
    )
    selection = json.loads(capsys.readouterr().out)
    assert selection_code == 3
    assert selection["scientific_scoring_ready"] is False
    opening_code = main(
        [
            "open-synthetic-reveal",
            str(root),
            str(opening),
            "--expected-manifest-sha256",
            digest,
            "--expected-sequence",
            "1",
            "--expected-opening-sha256",
            opening_digest,
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert opening_code == 3
    assert report["scientific_scoring_ready"] is False
