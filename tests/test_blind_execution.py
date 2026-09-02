"""Hostile synthetic-only tests for the blinded execution successor."""

from __future__ import annotations

import inspect
import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from test_challenge import _build, _reseal

from causalfrontier import blind, challenge
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.reveal import reveal_commitment

NONCE_HEX = "42" * 32
NONCE = bytes.fromhex(NONCE_HEX)
HIGH = (
    b"context\tintervention\tresponse_index\tnegative_control_index\n"
    b"context_a\tcandidate\t8\t1\n"
    b"context_a\tcomparator\t2\t1\n"
    b"context_b\tcandidate\t7\t4\n"
    b"context_b\tcomparator\t3\t4\n"
    b"held_out\tcandidate\t12\t7\n"
    b"held_out\tcomparator\t2\t7\n"
)
MALFORMED = b"wrong\theader\ncommitted\tmeasurement\n"


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _race_spec(document: dict, root: Path, digest: str, required_replicates: int = 2) -> tuple[Path, str]:
    preflight, cases = challenge.load_protocol_cases(root, digest, document["sequence"])
    case_specs = []
    for case_id, lanes in sorted(cases.items()):
        actions = sorted(item["id"] for item in lanes[0]["case"]["experiments"])
        case_specs.append(
            {
                "case_id": case_id,
                "budget": {
                    "calendar_minutes": 10,
                    "human_minutes": 10,
                    "compute_units": 10,
                    "direct_cost_minor_units_same_currency_and_date_basis": 10,
                    "action_batches": 10,
                },
                "action_batch_tariffs": [
                    {
                        "experiment_id": action_id,
                        "resources": {
                            "calendar_minutes": 1,
                            "human_minutes": 1,
                            "compute_units": 1,
                            "direct_cost_minor_units_same_currency_and_date_basis": 1,
                            "action_batches": 1,
                        },
                    }
                    for action_id in actions
                ],
            }
        )
    spec = {
        "schema_version": blind.RACE_SCHEMA_VERSION,
        "id": "race:synthetic-blind-v1",
        "challenge_id": preflight["challenge_id"],
        "challenge_sequence": preflight["challenge_sequence"],
        "challenge_registration_sha256": preflight["challenge_registration_sha256"],
        "scope": "SYNTHETIC_PROTOCOL_TEST",
        "required_replicates": required_replicates,
        "resource_accounting_mode": blind.RESOURCE_ACCOUNTING_MODE,
        "resource_dimensions": list(blind.RESOURCE_DIMENSIONS),
        "policy_contract_sha256": blind.policy_contract_sha256(),
        "cases": case_specs,
    }
    path = root.parent / "race.json"
    return path, _write_json(path, spec)


def _oracle_payload(
    document: dict,
    challenge_root: Path,
    digest: str,
    race_digest: str,
    view: dict,
    oracle_root: Path,
) -> tuple[dict, set[str]]:
    _preflight, case_lanes = challenge.load_protocol_cases(challenge_root, digest, document["sequence"])
    low = (challenge_root / "cases/0-0/evidence/aggregate_response.tsv").read_bytes()
    payload_cases = []
    hidden_markers: set[str] = set()
    for case_index, case in enumerate(document["cases"]):
        case_id = case["id"]
        entrant_case = blind._opaque_id("case", case_id, challenge.challenge_registration_sha256(document), NONCE)
        actions = []
        for action_index, experiment in enumerate(case_lanes[case_id][0]["case"]["experiments"]):
            action_id = experiment["id"]
            entrant_action = blind._opaque_id(
                "action",
                "%s\0%s" % (case_id, action_id),
                challenge.challenge_registration_sha256(document),
                NONCE,
            )
            observations = []
            for replicate_index in (1, 2):
                if case["control_class"] == "POSITIVE":
                    raw = HIGH
                elif case["control_class"] == "FAILED_TRANSLATION":
                    raw = MALFORMED
                else:
                    raw = HIGH if replicate_index == 1 else low
                relative = "hidden/%d/%d/secret-role-%s-%d.tsv" % (
                    case_index,
                    action_index,
                    case["control_class"].lower(),
                    replicate_index,
                )
                target = oracle_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                hidden_markers.update({relative, sha256_bytes(raw), case["control_class"].lower()})
                observations.append(
                    {
                        "id": "observation:%d-%d-%d" % (case_index, action_index, replicate_index),
                        "replicate_index": replicate_index,
                        "path": relative,
                        "sha256": sha256_bytes(raw),
                        "media_type": "text/tab-separated-values",
                    }
                )
            actions.append(
                {
                    "experiment_id": action_id,
                    "entrant_action_id": entrant_action,
                    "observations": observations,
                }
            )
        payload_cases.append({"case_id": case_id, "entrant_case_id": entrant_case, "actions": actions})
    return (
        {
            "schema_version": blind.ORACLE_PAYLOAD_SCHEMA_VERSION,
            "challenge_registration_sha256": challenge.challenge_registration_sha256(document),
            "challenge_sequence": document["sequence"],
            "race_spec_sha256": race_digest,
            "entrant_view_sha256": view["view_sha256"],
            "policy_contract_sha256": blind.policy_contract_sha256(),
            "required_replicates": 2,
            "cases": payload_cases,
        },
        hidden_markers,
    )


def _build_blind_fixture(
    tmp_path: Path,
    raw_case: dict,
    case_root: Path,
    *,
    balanced_six_case_cohort: bool = False,
) -> dict:
    challenge_root = tmp_path / "challenge"
    document, digest = _build(
        challenge_root,
        raw_case,
        case_root,
        balanced_six_case_cohort=balanced_six_case_cohort,
    )
    race_path, race_digest = _race_spec(document, challenge_root, digest)
    view = blind.build_sanitized_entrant_view(
        challenge_root,
        digest,
        1,
        race_path,
        race_digest,
        NONCE,
    )
    view_path = tmp_path / "view.json"
    view_digest = _write_json(view_path, view)
    oracle_root = tmp_path / "oracle"
    oracle_root.mkdir()
    payload, hidden_markers = _oracle_payload(
        document,
        challenge_root,
        digest,
        race_digest,
        view,
        oracle_root,
    )
    payload_path = tmp_path / "payload.json"
    payload_digest = _write_json(payload_path, payload)
    nonce_path = tmp_path / "nonce.secret"
    nonce_raw = NONCE_HEX.encode("ascii") + b"\n"
    nonce_path.write_bytes(nonce_raw)
    nonce_digest = sha256_bytes(nonce_raw)
    commitment_preflight = blind.prepare_synthetic_observation_commitment(
        challenge_root,
        digest,
        1,
        race_path,
        race_digest,
        view_path,
        view_digest,
        oracle_root,
        payload_path,
        payload_digest,
        nonce_path,
        nonce_digest,
    )
    commitment_preflight_path = tmp_path / "commitment-preflight.json"
    commitment_preflight_checkpoint_digest = _write_json(
        commitment_preflight_path,
        commitment_preflight,
    )
    document["reveal_commitment_sha256"] = commitment_preflight["reveal_commitment_sha256"]
    digest = _reseal(challenge_root, document)
    assert (
        blind.build_sanitized_entrant_view(
            challenge_root,
            digest,
            1,
            race_path,
            race_digest,
            NONCE,
        )
        == view
    )
    selection = blind.lock_blind_reference_selections(view_path, view_digest)
    selection_path = tmp_path / "selection.json"
    selection_digest = _write_json(selection_path, selection)
    selection_envelope = blind.bind_blind_selection_precommitment(
        view_path,
        view_digest,
        selection_path,
        selection_digest,
        commitment_preflight_checkpoint_digest,
    )
    selection_envelope_path = tmp_path / "selection-envelope.json"
    selection_envelope_checkpoint_digest = _write_json(
        selection_envelope_path,
        selection_envelope,
    )
    opening = {
        "schema_version": blind.ORACLE_OPENING_SCHEMA_VERSION,
        "nonce_hex": NONCE_HEX,
        "payload": payload,
    }
    opening_path = oracle_root / blind.ORACLE_MANIFEST
    opening_digest = _write_json(opening_path, opening)
    aliases = {
        item["case_id"]: {
            "case": item["entrant_case_id"],
            "lane": next(case for case in view["cases"] if case["entrant_case_id"] == item["entrant_case_id"])["lanes"][
                0
            ]["entrant_lane_id"],
        }
        for item in payload["cases"]
    }
    return {
        "challenge_root": challenge_root,
        "document": document,
        "digest": digest,
        "race_path": race_path,
        "race_digest": race_digest,
        "view": view,
        "view_path": view_path,
        "view_digest": view_digest,
        "selection": selection,
        "selection_path": selection_path,
        "selection_digest": selection_digest,
        "selection_envelope": selection_envelope,
        "selection_envelope_path": selection_envelope_path,
        "selection_envelope_checkpoint_digest": selection_envelope_checkpoint_digest,
        "oracle_root": oracle_root,
        "opening_digest": opening_digest,
        "payload": payload,
        "payload_path": payload_path,
        "payload_digest": payload_digest,
        "commitment_preflight": commitment_preflight,
        "commitment_preflight_path": commitment_preflight_path,
        "commitment_preflight_checkpoint_digest": commitment_preflight_checkpoint_digest,
        "hidden_markers": hidden_markers,
        "aliases": aliases,
        "nonce_path": nonce_path,
        "nonce_digest": nonce_digest,
    }


@pytest.fixture
def blind_fixture(tmp_path: Path, raw_case: dict, case_root: Path):
    return _build_blind_fixture(tmp_path, raw_case, case_root)


def _execute(fixture: dict, case_id: str, policy: str = "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1") -> dict:
    alias = fixture["aliases"][case_id]
    return blind.execute_blind_synthetic_policy(
        fixture["challenge_root"],
        fixture["digest"],
        1,
        fixture["race_path"],
        fixture["race_digest"],
        fixture["view_path"],
        fixture["view_digest"],
        fixture["selection_path"],
        fixture["selection_digest"],
        fixture["selection_envelope_path"],
        fixture["selection_envelope_checkpoint_digest"],
        fixture["commitment_preflight_path"],
        fixture["commitment_preflight_checkpoint_digest"],
        fixture["oracle_root"],
        fixture["opening_digest"],
        alias["case"],
        alias["lane"],
        policy,
    )


def _cli_execution_argv(
    fixture: dict,
    case_id: str,
    policy: str = "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
) -> list[str]:
    alias = fixture["aliases"][case_id]
    return [
        "execute-blind-synthetic",
        str(fixture["challenge_root"]),
        str(fixture["race_path"]),
        str(fixture["view_path"]),
        str(fixture["selection_path"]),
        str(fixture["selection_envelope_path"]),
        str(fixture["commitment_preflight_path"]),
        str(fixture["oracle_root"]),
        alias["case"],
        alias["lane"],
        policy,
        "--expected-manifest-sha256",
        fixture["digest"],
        "--expected-sequence",
        "1",
        "--expected-race-spec-sha256",
        fixture["race_digest"],
        "--expected-view-sha256",
        fixture["view_digest"],
        "--expected-selection-sha256",
        fixture["selection_digest"],
        "--expected-selection-envelope-sha256",
        fixture["selection_envelope_checkpoint_digest"],
        "--expected-commitment-preflight-sha256",
        fixture["commitment_preflight_checkpoint_digest"],
        "--expected-opening-sha256",
        fixture["opening_digest"],
    ]


def _prepare_again(fixture: dict, payload: dict) -> dict:
    opening_path = fixture["oracle_root"] / blind.ORACLE_MANIFEST
    parked = fixture["commitment_preflight_path"].parent / "opening.parked"
    opening_path.replace(parked)
    try:
        payload_digest = _write_json(fixture["payload_path"], payload)
        return blind.prepare_synthetic_observation_commitment(
            fixture["challenge_root"],
            fixture["digest"],
            1,
            fixture["race_path"],
            fixture["race_digest"],
            fixture["view_path"],
            fixture["view_digest"],
            fixture["oracle_root"],
            fixture["payload_path"],
            payload_digest,
            fixture["nonce_path"],
            fixture["nonce_digest"],
        )
    finally:
        parked.replace(opening_path)


def _recommit_fixture(fixture: dict, payload: dict) -> None:
    opening_path = fixture["oracle_root"] / blind.ORACLE_MANIFEST
    opening_path.unlink()
    fixture["payload_digest"] = _write_json(fixture["payload_path"], payload)
    fixture["commitment_preflight"] = blind.prepare_synthetic_observation_commitment(
        fixture["challenge_root"],
        fixture["digest"],
        1,
        fixture["race_path"],
        fixture["race_digest"],
        fixture["view_path"],
        fixture["view_digest"],
        fixture["oracle_root"],
        fixture["payload_path"],
        fixture["payload_digest"],
        fixture["nonce_path"],
        fixture["nonce_digest"],
    )
    fixture["commitment_preflight_checkpoint_digest"] = _write_json(
        fixture["commitment_preflight_path"],
        fixture["commitment_preflight"],
    )
    fixture["document"]["reveal_commitment_sha256"] = fixture["commitment_preflight"]["reveal_commitment_sha256"]
    fixture["digest"] = _reseal(fixture["challenge_root"], fixture["document"])
    fixture["selection_envelope"] = blind.bind_blind_selection_precommitment(
        fixture["view_path"],
        fixture["view_digest"],
        fixture["selection_path"],
        fixture["selection_digest"],
        fixture["commitment_preflight_checkpoint_digest"],
    )
    fixture["selection_envelope_checkpoint_digest"] = _write_json(
        fixture["selection_envelope_path"],
        fixture["selection_envelope"],
    )
    fixture["payload"] = payload
    fixture["opening_digest"] = _write_json(
        opening_path,
        {
            "schema_version": blind.ORACLE_OPENING_SCHEMA_VERSION,
            "nonce_hex": NONCE_HEX,
            "payload": payload,
        },
    )


def test_view_has_opaque_ids_and_no_steward_or_oracle_canaries(blind_fixture):
    raw = canonical_bytes(blind_fixture["view"])
    registration_digest = challenge.challenge_registration_sha256(blind_fixture["document"])
    forbidden = {
        b"case:positive",
        b"case:failed-translation",
        b"case:ambiguous",
        b"POSITIVE",
        b"FAILED_TRANSLATION",
        b"AMBIGUOUS",
        b"encoder:alpha",
        b"encoder:beta",
        b"organization:alpha",
        b"organization:beta",
        NONCE_HEX.encode(),
        registration_digest.encode(),
        blind_fixture["race_digest"].encode(),
        sha256_bytes(NONCE).encode(),
    }
    forbidden.update(item.encode() for item in blind_fixture["hidden_markers"])
    assert all(marker not in raw for marker in forbidden)
    assert all(case["entrant_case_id"].startswith("entrant:case:") for case in blind_fixture["view"]["cases"])
    assert blind_fixture["view"]["environment_isolation_verified"] is False
    assert blind_fixture["view"]["scientific_scoring_ready"] is False
    assert set(blind_fixture["view"]) >= {
        "opaque_challenge_binding_sha256",
        "opaque_race_binding_sha256",
    }


def test_selector_interface_accepts_only_the_sanitized_view(blind_fixture):
    assert list(inspect.signature(blind.lock_blind_reference_selections).parameters) == [
        "view_path",
        "expected_view_sha256",
    ]
    first = blind.lock_blind_reference_selections(blind_fixture["view_path"], blind_fixture["view_digest"])
    second = blind.lock_blind_reference_selections(blind_fixture["view_path"], blind_fixture["view_digest"])
    assert first == second == blind_fixture["selection"]
    assert b"case:positive" not in canonical_bytes(first)
    assert first["reveal_input_accepted"] is False
    assert blind_fixture["commitment_preflight_checkpoint_digest"].encode() not in canonical_bytes(first)


def test_hidden_bytes_not_frozen_dossier_drive_classifier_and_bind_ledger(blind_fixture):
    result = _execute(blind_fixture, "case:positive")
    assert result["status"] == "SYNTHETIC_BLIND_OBSERVATIONS_CLASSIFIED_SCIENTIFIC_SCORING_DISABLED"
    assert len(result["action_reports"]) == 3
    assert all(
        {receipt["branch_token"] for receipt in action["classifier_results"]} == {"HIGH"}
        for action in result["action_reports"]
    )
    assert all(
        action["adjudication"]["state"] == "CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED"
        for action in result["action_reports"]
    )
    assert result["resources_used"]["action_batches"] == 3
    assert result["scientific_baseline_families_executed"] == []
    assert result["scientific_scoring_ready"] is False
    assert result["events"][0]["prev_digest"] == blind.GENESIS
    assert result["events"][-1]["digest"] == result["ledger_head"]
    for left, right in zip(result["events"], result["events"][1:], strict=False):
        assert right["prev_digest"] == left["digest"]


def test_repeated_episode_is_idempotent_and_does_not_mutate_a_balance(blind_fixture):
    first = _execute(blind_fixture, "case:positive")
    second = _execute(blind_fixture, "case:positive")
    assert first == second
    assert first["resources_used"] == {
        "calendar_minutes": 3,
        "human_minutes": 3,
        "compute_units": 3,
        "direct_cost_minor_units_same_currency_and_date_basis": 3,
        "action_batches": 3,
    }


def test_uniform_execution_order_uses_frozen_action_ids_not_nonce_derived_alias_order(blind_fixture):
    case_alias = blind_fixture["aliases"]["case:positive"]["case"]
    lane_alias = blind_fixture["aliases"]["case:positive"]["lane"]
    lane = next(
        item
        for item in blind_fixture["selection"]["reference_lanes"]
        if item["entrant_case_id"] == case_alias and item["entrant_lane_id"] == lane_alias
    )
    trace = next(
        item
        for item in lane["reference_policy_traces"]
        if item["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1"
    )
    positive = next(item for item in blind_fixture["payload"]["cases"] if item["case_id"] == "case:positive")
    alias_to_original = {item["entrant_action_id"]: item["experiment_id"] for item in positive["actions"]}
    locked_alias_order_opened = [
        alias_to_original[item["entrant_action_id"]] for item in trace["selections"] if item["action"] == "SELECT"
    ]
    canonical_original_order = sorted(alias_to_original.values())
    assert locked_alias_order_opened != canonical_original_order
    result = _execute(blind_fixture, "case:positive")
    assert [item["experiment_id"] for item in result["action_reports"]] == canonical_original_order


def test_same_observation_batch_is_interpreted_in_separate_encoder_lanes(blind_fixture):
    fixture = blind_fixture
    case_alias = fixture["aliases"]["case:positive"]["case"]
    view_case = next(item for item in fixture["view"]["cases"] if item["entrant_case_id"] == case_alias)
    reports = []
    for lane in view_case["lanes"]:
        fixture["aliases"]["case:positive"]["lane"] = lane["entrant_lane_id"]
        reports.append(_execute(fixture, "case:positive"))
    assert len(reports) == 2
    assert reports[0]["entrant_lane_id"] != reports[1]["entrant_lane_id"]
    assert reports[0]["episode_id"] != reports[1]["episode_id"]
    assert [item["adjudication"] for item in reports[0]["action_reports"]] == [
        item["adjudication"] for item in reports[1]["action_reports"]
    ]


def test_committed_malformed_measurements_derive_failure_not_integrity_error(blind_fixture):
    result = _execute(blind_fixture, "case:failed-translation")
    assert len(result["action_reports"]) == 3
    assert all(
        {receipt["branch_token"] for receipt in action["classifier_results"]} == {"FAILURE"}
        for action in result["action_reports"]
    )
    assert all(
        action["adjudication"]["state"] == "CONSISTENT_EXECUTION_FAILURE_BATCH_NO_UPDATE"
        for action in result["action_reports"]
    )


def test_informative_replication_discordance_never_majority_votes(blind_fixture):
    result = _execute(blind_fixture, "case:ambiguous")
    discordant = [
        action
        for action in result["action_reports"]
        if action["adjudication"]["state"] == "REPLICATION_DISCORDANT_NO_CALL"
    ]
    # The frozen dossier already drives the negative-control classifier HIGH;
    # the other two actions prove that HIGH/LOW disagreement is not majority-voted.
    assert len(discordant) == 2
    assert all(action["adjudication"]["aggregate_outcome_id"] is None for action in discordant)


@pytest.mark.parametrize(
    "policy,terminal",
    [("DO_NOTHING_OR_ABSTAIN_REFERENCE_V1", "ABSTAINED"), ("CAUSALFRONTIER_UNIQUE_MINIMAX_V1", "NO_CALL")],
)
def test_terminal_policies_read_no_observation_payload(blind_fixture, monkeypatch, policy, terminal):
    original = blind.receipt_io._snapshot
    opened = []

    def recording_snapshot(descriptor, relative):
        opened.append(relative)
        return original(descriptor, relative)

    monkeypatch.setattr(blind.receipt_io, "_snapshot", recording_snapshot)
    result = _execute(blind_fixture, "case:positive", policy)
    assert result["terminal_kind"] == terminal
    assert result["action_reports"] == []
    assert not any(item.startswith("hidden/") for item in opened)


def test_underfunded_uniform_enumeration_is_rejected_before_view_or_observation(blind_fixture, monkeypatch):
    fixture = blind_fixture
    race = json.loads(fixture["race_path"].read_text(encoding="utf-8"))
    positive = next(item for item in race["cases"] if item["case_id"] == "case:positive")
    positive["budget"] = {
        "calendar_minutes": 1,
        "human_minutes": 1,
        "compute_units": 1,
        "direct_cost_minor_units_same_currency_and_date_basis": 1,
        "action_batches": 1,
    }
    race_digest = _write_json(fixture["race_path"], race)
    original = blind.receipt_io._snapshot
    opened = []

    def recording_snapshot(descriptor, relative):
        opened.append(relative)
        return original(descriptor, relative)

    monkeypatch.setattr(blind.receipt_io, "_snapshot", recording_snapshot)
    with pytest.raises(CausalFrontierError, match="cannot fund one complete lane-specific uniform-enumeration pass"):
        blind.build_sanitized_entrant_view(
            fixture["challenge_root"],
            fixture["digest"],
            1,
            fixture["race_path"],
            race_digest,
            NONCE,
        )
    assert not any(item.startswith("hidden/") for item in opened)


def test_expensive_structurally_ineligible_action_does_not_invalidate_selectable_budget(blind_fixture, monkeypatch):
    fixture = blind_fixture
    race = json.loads(fixture["race_path"].read_text(encoding="utf-8"))
    blocked_action = race["cases"][0]["action_batch_tariffs"][0]["experiment_id"]
    for case in race["cases"]:
        tariff = next(item for item in case["action_batch_tariffs"] if item["experiment_id"] == blocked_action)
        tariff["resources"] = {
            "calendar_minutes": 100,
            "human_minutes": 100,
            "compute_units": 100,
            "direct_cost_minor_units_same_currency_and_date_basis": 100,
            "action_batches": 1,
        }
    race_digest = _write_json(fixture["race_path"], race)
    original_compile = blind.compile_case

    def compile_with_blocked_action(case):
        analysis = deepcopy(original_compile(case))
        target = next(item for item in analysis["experiments"] if item["id"] == blocked_action)
        target["decision_separating"] = False
        return analysis

    monkeypatch.setattr(blind, "compile_case", compile_with_blocked_action)
    view = blind.build_sanitized_entrant_view(
        fixture["challenge_root"],
        fixture["digest"],
        1,
        fixture["race_path"],
        race_digest,
        NONCE,
    )
    view_path = fixture["view_path"].parent / "blocked-action-view.json"
    view_digest = _write_json(view_path, view)
    selection = blind.lock_blind_reference_selections(view_path, view_digest)
    blocked_aliases = {
        blind._opaque_id(
            "action",
            "%s\0%s" % (case["case_id"], blocked_action),
            challenge.challenge_registration_sha256(fixture["document"]),
            NONCE,
        )
        for case in race["cases"]
    }
    assert all(
        item["entrant_action_id"] not in blocked_aliases
        for lane in selection["reference_lanes"]
        for trace in lane["reference_policy_traces"]
        for item in trace["selections"]
        if item["action"] == "SELECT"
    )


def test_observation_byte_drift_is_integrity_error_not_failure_branch(blind_fixture):
    observation = blind_fixture["payload"]["cases"][0]["actions"][0]["observations"][0]
    (blind_fixture["oracle_root"] / observation["path"]).write_bytes(HIGH.replace(b"context_a", b"context_z"))
    result = _execute(blind_fixture, blind_fixture["payload"]["cases"][0]["case_id"])
    assert result["integrity_valid"] is False
    assert result["terminal_kind"] == "INTEGRITY_OR_AUTHORITY_ABORT_INVALID"
    assert result["resources_used"]["action_batches"] == 1
    assert any(item["type"] == "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY" for item in result["events"])
    assert not any(
        receipt.get("branch_token") == "FAILURE"
        for action in result["action_reports"]
        for receipt in action["classifier_results"]
    )


def test_second_replicate_drift_aborts_batch_atomically_after_one_debit(blind_fixture):
    case = next(item for item in blind_fixture["payload"]["cases"] if item["case_id"] == "case:positive")
    first_action = min(case["actions"], key=lambda item: item["experiment_id"])
    second = first_action["observations"][1]
    (blind_fixture["oracle_root"] / second["path"]).write_bytes(HIGH.replace(b"context_a", b"context_z"))
    result = _execute(blind_fixture, "case:positive")
    assert result["integrity_valid"] is False
    assert result["resources_used"]["action_batches"] == 1
    assert result["action_reports"] == []
    assert not any(item["type"] == "OBSERVATION_CLASSIFIED" for item in result["events"])


def test_cli_integrity_abort_emits_invalid_json_and_exit_two(blind_fixture, capsys):
    case = next(item for item in blind_fixture["payload"]["cases"] if item["case_id"] == "case:positive")
    first_action = min(case["actions"], key=lambda item: item["experiment_id"])
    second = first_action["observations"][1]
    (blind_fixture["oracle_root"] / second["path"]).write_bytes(HIGH.replace(b"context_a", b"context_z"))
    code = main(_cli_execution_argv(blind_fixture, "case:positive"))
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert code == 2
    assert captured.err == ""
    assert output["integrity_valid"] is False
    assert output["terminal_kind"] == "INTEGRITY_OR_AUTHORITY_ABORT_INVALID"
    assert output["status"] == ("SYNTHETIC_POLICY_EXECUTION_ABORTED_INTEGRITY_INVALID_SCIENTIFIC_SCORING_DISABLED")


def test_checkpointed_preflight_and_steward_envelope_are_bound_into_execution(blind_fixture):
    result = _execute(blind_fixture, "case:positive")
    assert result["commitment_preflight_checkpoint_sha256"] == blind_fixture["commitment_preflight_checkpoint_digest"]
    assert result["selection_envelope_checkpoint_sha256"] == blind_fixture["selection_envelope_checkpoint_digest"]
    assert result["commitment_preflight_checkpoint_verified"] is True
    assert result["commitment_preflight_independent_attestation_verified"] is False
    assert result["precommitment_temporal_order_independently_verified"] is False
    assert result["current_full_oracle_byte_readiness_verified"] is False
    assert blind_fixture["commitment_preflight"]["oracle_opening_sha256"] == blind_fixture["opening_digest"]


def test_unselected_size_drift_invalidates_even_an_abstention(blind_fixture):
    observation = blind_fixture["payload"]["cases"][0]["actions"][0]["observations"][0]
    path = blind_fixture["oracle_root"] / observation["path"]
    path.write_bytes(path.read_bytes() + b"x")
    result = _execute(blind_fixture, "case:positive", "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1")
    assert result["integrity_valid"] is False
    assert result["terminal_kind"] == "INTEGRITY_OR_AUTHORITY_ABORT_INVALID"
    assert result["terminal_reason_codes"] == ["INTEGRITY_OR_AUTHORITY_ABORT_INVALID"]
    assert result["resources_used"]["action_batches"] == 0
    assert result["preflight_oracle_total_bytes_matched_at_execution_start"] is False
    assert any(
        event["payload"].get("reason_code") == "PREFLIGHT_ORACLE_TOTAL_BYTES_MISMATCH" for event in result["events"]
    )


def test_coherently_rehashed_preflight_total_forgery_is_structurally_invalid(blind_fixture):
    report = deepcopy(blind_fixture["commitment_preflight"])
    report["oracle_total_bytes_n"] += 1
    core = {key: value for key, value in report.items() if key != "commitment_preflight_sha256"}
    report["commitment_preflight_sha256"] = sha256_bytes(canonical_bytes(core))
    blind_fixture["commitment_preflight_checkpoint_digest"] = _write_json(
        blind_fixture["commitment_preflight_path"], report
    )
    blind_fixture["selection_envelope"] = blind.bind_blind_selection_precommitment(
        blind_fixture["view_path"],
        blind_fixture["view_digest"],
        blind_fixture["selection_path"],
        blind_fixture["selection_digest"],
        blind_fixture["commitment_preflight_checkpoint_digest"],
    )
    blind_fixture["selection_envelope_checkpoint_digest"] = _write_json(
        blind_fixture["selection_envelope_path"], blind_fixture["selection_envelope"]
    )
    result = _execute(blind_fixture, "case:positive", "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1")
    assert result["integrity_valid"] is False
    assert result["preflight_oracle_total_bytes_matched_at_execution_start"] is False


def test_preflight_external_checkpoint_rejects_byte_substitution_before_oracle_read(blind_fixture, monkeypatch):
    blind_fixture["commitment_preflight_path"].write_bytes(
        blind_fixture["commitment_preflight_path"].read_bytes() + b" "
    )
    opened = []
    original = blind.receipt_io._snapshot

    def recording_snapshot(descriptor, relative):
        opened.append(relative)
        return original(descriptor, relative)

    monkeypatch.setattr(blind.receipt_io, "_snapshot", recording_snapshot)
    with pytest.raises(CausalFrontierError, match="commitment preflight external checkpoint mismatch"):
        _execute(blind_fixture, "case:positive")
    assert not any(item.startswith("hidden/") or item == blind.ORACLE_MANIFEST for item in opened)


def test_opening_checkpoint_must_match_preflight_before_oracle_read(blind_fixture, monkeypatch):
    opened = []
    original = blind.receipt_io._snapshot

    def recording_snapshot(descriptor, relative):
        opened.append(relative)
        return original(descriptor, relative)

    monkeypatch.setattr(blind.receipt_io, "_snapshot", recording_snapshot)
    blind_fixture["opening_digest"] = "0" * 64
    with pytest.raises(CausalFrontierError, match="opening checkpoint differs from commitment preflight"):
        _execute(blind_fixture, "case:positive")
    assert blind.ORACLE_MANIFEST not in opened


def test_coherently_rehashed_preflight_semantic_forgery_is_rejected(blind_fixture):
    report = deepcopy(blind_fixture["commitment_preflight"])
    report["cases_n"] += 1
    core = {key: value for key, value in report.items() if key != "commitment_preflight_sha256"}
    report["commitment_preflight_sha256"] = sha256_bytes(canonical_bytes(core))
    blind_fixture["commitment_preflight_checkpoint_digest"] = _write_json(
        blind_fixture["commitment_preflight_path"], report
    )
    blind_fixture["selection_envelope"] = blind.bind_blind_selection_precommitment(
        blind_fixture["view_path"],
        blind_fixture["view_digest"],
        blind_fixture["selection_path"],
        blind_fixture["selection_digest"],
        blind_fixture["commitment_preflight_checkpoint_digest"],
    )
    blind_fixture["selection_envelope_checkpoint_digest"] = _write_json(
        blind_fixture["selection_envelope_path"], blind_fixture["selection_envelope"]
    )
    with pytest.raises(CausalFrontierError, match="inventory counts differ"):
        _execute(blind_fixture, "case:positive")


@pytest.mark.parametrize(
    "raw,match",
    [
        (b"\xff\xfe", "not UTF-8"),
        (
            b"patient_id\tintervention\tresponse_index\nP001\tcandidate\t1\n",
            "prohibited patient-level identifier",
        ),
        (
            b"context\tintervention\tresponse_index\tnegative_control_index\npatient_id:P001\tcandidate\t1\t0\n",
            "prohibited patient-level identifier",
        ),
    ],
)
def test_commitment_preflight_rejects_unsafe_observation_text_without_echo(blind_fixture, raw, match):
    payload = deepcopy(blind_fixture["payload"])
    observation = payload["cases"][0]["actions"][0]["observations"][0]
    (blind_fixture["oracle_root"] / observation["path"]).write_bytes(raw)
    observation["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match=match) as error:
        _prepare_again(blind_fixture, payload)
    assert "P001" not in str(error.value)


def test_privacy_marker_screen_cannot_be_bypassed_with_unicode_record_separator(blind_fixture):
    payload = deepcopy(blind_fixture["payload"])
    observation = payload["cases"][0]["actions"][0]["observations"][0]
    raw = ("context\tintervention\tresponse_index\tnegative_control_index\u0085ssn123\tcandidate\t1\t0\n").encode()
    (blind_fixture["oracle_root"] / observation["path"]).write_bytes(raw)
    observation["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="prohibited patient-level identifier") as error:
        _prepare_again(blind_fixture, payload)
    assert "ssn123" not in str(error.value).casefold()


def test_preflight_second_byte_pass_detects_same_length_replacement(blind_fixture, monkeypatch):
    payload = deepcopy(blind_fixture["payload"])
    observation = payload["cases"][0]["actions"][0]["observations"][0]
    target = blind_fixture["oracle_root"] / observation["path"]
    original_snapshot = blind.receipt_io._snapshot
    reads = 0

    def replacing_snapshot(descriptor, relative):
        nonlocal reads
        raw = original_snapshot(descriptor, relative)
        if relative == observation["path"]:
            reads += 1
            if reads == 1:
                target.write_bytes(raw.replace(b"context_a", b"context_z"))
        return raw

    monkeypatch.setattr(blind.receipt_io, "_snapshot", replacing_snapshot)
    with pytest.raises(CausalFrontierError, match="changed during commitment preflight"):
        _prepare_again(blind_fixture, payload)


def test_steward_redaction_does_not_expose_raw_classifier_result_confirmation_hash(blind_fixture):
    result = _execute(blind_fixture, "case:positive")
    assert result["audience"] == "STEWARD_ONLY_NOT_A_PUBLIC_UNLINKABLE_PROJECTION"
    assert result["public_unlinkable_projection_available"] is False
    case_lanes = challenge.load_protocol_cases(blind_fixture["challenge_root"], blind_fixture["digest"], 1)[1]
    case_value = next(item for item in blind_fixture["payload"]["cases"] if item["case_id"] == "case:positive")
    action = min(case_value["actions"], key=lambda item: item["experiment_id"])
    observation = action["observations"][0]
    raw = (blind_fixture["oracle_root"] / observation["path"]).read_bytes()
    raw_result = blind.execute_classifier_observation(
        case_lanes["case:positive"][0]["case"],
        action["experiment_id"],
        observation["id"],
        "replicate:%d" % observation["replicate_index"],
        raw,
        observation["sha256"],
    )
    public_bytes = canonical_bytes(result)
    assert raw_result["result_sha256"].encode() not in public_bytes
    assert b"classifier_result_sha256" not in public_bytes
    assert b"redacted_result_sha256" in public_bytes


def test_steward_report_labels_payload_digest_dictionary_linkability(blind_fixture):
    result = _execute(blind_fixture, "case:positive")
    assert result["oracle_payload_sha256"] == sha256_bytes(canonical_bytes(blind_fixture["payload"]))
    assert result["audience"] == "STEWARD_ONLY_NOT_A_PUBLIC_UNLINKABLE_PROJECTION"
    assert any("confirm guesses" in item for item in result["nonclaims"])


def test_commitment_preflight_rejects_observation_one_byte_over_classifier_limit(blind_fixture):
    payload = deepcopy(blind_fixture["payload"])
    observation = payload["cases"][0]["actions"][0]["observations"][0]
    raw = b"x" * (blind.CLASSIFIER_INPUT_MAX_BYTES + 1)
    (blind_fixture["oracle_root"] / observation["path"]).write_bytes(raw)
    observation["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="classifier input byte limit"):
        _prepare_again(blind_fixture, payload)


def test_blind_report_redacts_group_keyed_metrics_and_observation_identifiers(blind_fixture):
    payload = deepcopy(blind_fixture["payload"])
    canary = b"ALICE-SMITH-739201"
    positive = next(item for item in payload["cases"] if item["case_id"] == "case:positive")
    for action in positive["actions"]:
        for observation in action["observations"]:
            path = blind_fixture["oracle_root"] / observation["path"]
            raw = path.read_bytes().replace(b"context_a", canary)
            path.write_bytes(raw)
            observation["sha256"] = sha256_bytes(raw)
    _recommit_fixture(blind_fixture, payload)
    result = _execute(blind_fixture, "case:positive")
    assert canary not in canonical_bytes(result)
    assert all(
        receipt["group_keyed_metrics_omitted"] is True
        and receipt["direct_observation_identifier_field_omitted"] is True
        and receipt["direct_observation_digest_field_omitted"] is True
        and "metrics" not in receipt
        and "observation_sha256" not in receipt
        for action in result["action_reports"]
        for receipt in action["classifier_results"]
    )


@pytest.mark.parametrize(
    "marker",
    ["m_r_n", "s.s.n", "d-o-b", "m\u200dr\u200dn", "patientmrn", "subjectssn", "visitdob"],
)
def test_short_privacy_markers_cannot_be_fragmented(blind_fixture, marker):
    payload = deepcopy(blind_fixture["payload"])
    observation = payload["cases"][0]["actions"][0]["observations"][0]
    raw = (marker + "\tintervention\tresponse_index\tnegative_control_index\n").encode()
    (blind_fixture["oracle_root"] / observation["path"]).write_bytes(raw)
    observation["sha256"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="prohibited patient-level identifier"):
        _prepare_again(blind_fixture, payload)


def test_terminal_without_observation_uses_nonclassification_status(blind_fixture):
    result = _execute(blind_fixture, "case:positive", "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1")
    assert result["action_reports"] == []
    assert result["status"] == (
        "SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED"
    )


def test_view_validator_rejects_semantic_text_disguised_as_opaque_alias(blind_fixture):
    view = deepcopy(blind_fixture["view"])
    view["cases"][0]["entrant_case_id"] = "entrant:case:case:positive"
    core = {key: value for key, value in view.items() if key != "view_sha256"}
    view["view_sha256"] = sha256_bytes(canonical_bytes(core))
    digest = _write_json(blind_fixture["view_path"], view)
    with pytest.raises(CausalFrontierError, match="exact opaque alias"):
        blind.lock_blind_reference_selections(blind_fixture["view_path"], digest)


def test_steward_envelope_builder_rejects_overclaiming_selection(blind_fixture):
    selection = deepcopy(blind_fixture["selection"])
    selection["reveal_input_accepted"] = True
    selection["scientific_scoring_ready"] = True
    core = {key: value for key, value in selection.items() if key != "selection_lock_sha256"}
    selection["selection_lock_sha256"] = sha256_bytes(canonical_bytes(core))
    selection_digest = _write_json(blind_fixture["selection_path"], selection)
    with pytest.raises(CausalFrontierError, match="overclaims"):
        blind.bind_blind_selection_precommitment(
            blind_fixture["view_path"],
            blind_fixture["view_digest"],
            blind_fixture["selection_path"],
            selection_digest,
            blind_fixture["commitment_preflight_checkpoint_digest"],
        )


@pytest.mark.parametrize("extra_key", ["replicate_outcome_ids", "branch_token", "outcome_id"])
def test_successor_commitment_rejects_organizer_authored_labels(blind_fixture, extra_key):
    payload = deepcopy(blind_fixture["payload"])
    payload["cases"][0]["actions"][0][extra_key] = "forged"
    payload_digest = _write_json(blind_fixture["payload_path"], payload)
    with pytest.raises(CausalFrontierError, match="schema mismatch"):
        blind.prepare_synthetic_observation_commitment(
            blind_fixture["challenge_root"],
            blind_fixture["digest"],
            1,
            blind_fixture["race_path"],
            blind_fixture["race_digest"],
            blind_fixture["view_path"],
            blind_fixture["view_digest"],
            blind_fixture["oracle_root"],
            blind_fixture["payload_path"],
            payload_digest,
            blind_fixture["nonce_path"],
            blind_fixture["nonce_digest"],
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "reuse-path"])
def test_oracle_coordinate_inventory_fails_closed(blind_fixture, mutation):
    opening_path = blind_fixture["oracle_root"] / blind.ORACLE_MANIFEST
    opening = json.loads(opening_path.read_text(encoding="utf-8"))
    payload = opening["payload"]
    if mutation == "missing":
        payload["cases"][0]["actions"].pop()
    elif mutation == "duplicate":
        payload["cases"].append(deepcopy(payload["cases"][0]))
    elif mutation == "extra":
        extra = blind_fixture["oracle_root"] / "surplus.txt"
        extra.write_text("surplus\n", encoding="utf-8")
    else:
        payload["cases"][0]["actions"][0]["observations"][1]["path"] = payload["cases"][0]["actions"][0][
            "observations"
        ][0]["path"]
    if mutation != "extra":
        blind_fixture["document"]["reveal_commitment_sha256"] = reveal_commitment(payload, NONCE_HEX)
        blind_fixture["digest"] = _reseal(blind_fixture["challenge_root"], blind_fixture["document"])
        blind_fixture["opening_digest"] = _write_json(opening_path, opening)
    with pytest.raises(CausalFrontierError):
        _execute(blind_fixture, "case:positive")


def test_surplus_empty_directory_is_rejected(blind_fixture):
    (blind_fixture["oracle_root"] / "surplus-empty").mkdir()
    with pytest.raises(CausalFrontierError, match="filesystem inventory"):
        _execute(blind_fixture, "case:positive")


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "fifo"])
def test_unsafe_oracle_objects_fail_without_following_or_blocking(blind_fixture, unsafe):
    target = blind_fixture["oracle_root"] / "unsafe"
    opening = blind_fixture["oracle_root"] / blind.ORACLE_MANIFEST
    if unsafe == "symlink":
        target.symlink_to(opening)
    elif unsafe == "hardlink":
        os.link(opening, target)
    else:
        os.mkfifo(target)
    with pytest.raises(CausalFrontierError):
        _execute(blind_fixture, "case:positive")


def test_selection_checkpoint_and_replay_are_both_required(blind_fixture):
    selection = deepcopy(blind_fixture["selection"])
    trace = selection["reference_lanes"][0]["reference_policy_traces"][0]
    trace["reason_codes"] = ["ATTACKER_SELECTED_REASON"]
    core = {key: value for key, value in selection.items() if key != "selection_lock_sha256"}
    selection["selection_lock_sha256"] = sha256_bytes(canonical_bytes(core))
    blind_fixture["selection_digest"] = _write_json(blind_fixture["selection_path"], selection)
    with pytest.raises(CausalFrontierError, match="does not replay"):
        _execute(blind_fixture, "case:positive")


@pytest.mark.parametrize("value", [2.0, True, 0, 9])
def test_commitment_builder_rejects_invalid_replicate_counts(blind_fixture, value):
    payload = deepcopy(blind_fixture["payload"])
    payload["required_replicates"] = value
    payload_digest = _write_json(blind_fixture["payload_path"], payload)
    with pytest.raises(CausalFrontierError):
        blind.prepare_synthetic_observation_commitment(
            blind_fixture["challenge_root"],
            blind_fixture["digest"],
            1,
            blind_fixture["race_path"],
            blind_fixture["race_digest"],
            blind_fixture["view_path"],
            blind_fixture["view_digest"],
            blind_fixture["oracle_root"],
            blind_fixture["payload_path"],
            payload_digest,
            blind_fixture["nonce_path"],
            blind_fixture["nonce_digest"],
        )


def test_wrong_commitment_is_authenticated_before_secret_semantics(blind_fixture):
    opening_path = blind_fixture["oracle_root"] / blind.ORACLE_MANIFEST
    opening = json.loads(opening_path.read_text(encoding="utf-8"))
    opening["payload"]["cases"][0]["case_id"] = "case:unknown-secret"
    blind_fixture["opening_digest"] = _write_json(opening_path, opening)
    with pytest.raises(CausalFrontierError, match="authentication failed") as error:
        blind._open_oracle(
            blind_fixture["oracle_root"],
            blind_fixture["opening_digest"],
            blind_fixture["commitment_preflight"]["reveal_commitment_sha256"],
        )
    assert "unknown-secret" not in str(error.value)


def test_unauthenticated_duplicate_key_error_is_collapsed_without_echo(blind_fixture):
    opening_path = blind_fixture["oracle_root"] / blind.ORACLE_MANIFEST
    canary = "SECRET-CANARY-739201"
    raw = ('{"%s":1,"%s":2}\n' % (canary, canary)).encode()
    opening_path.write_bytes(raw)
    blind_fixture["opening_digest"] = sha256_bytes(raw)
    with pytest.raises(CausalFrontierError, match="oracle authentication failed") as error:
        blind._open_oracle(
            blind_fixture["oracle_root"],
            blind_fixture["opening_digest"],
            blind_fixture["commitment_preflight"]["reveal_commitment_sha256"],
        )
    assert canary not in str(error.value)


def test_cli_blind_workflow_emits_structural_json_and_exit_three(blind_fixture, capsys):
    fixture = blind_fixture
    code = main(
        [
            "build-sanitized-view",
            str(fixture["challenge_root"]),
            str(fixture["race_path"]),
            str(fixture["nonce_path"]),
            "--expected-manifest-sha256",
            fixture["digest"],
            "--expected-sequence",
            "1",
            "--expected-race-spec-sha256",
            fixture["race_digest"],
            "--expected-nonce-sha256",
            fixture["nonce_digest"],
        ]
    )
    assert code == 3
    assert json.loads(capsys.readouterr().out) == fixture["view"]

    opening_path = fixture["oracle_root"] / blind.ORACLE_MANIFEST
    parked = fixture["commitment_preflight_path"].parent / "cli-opening.parked"
    opening_path.replace(parked)
    try:
        code = main(
            [
                "prepare-observation-commitment",
                str(fixture["challenge_root"]),
                str(fixture["race_path"]),
                str(fixture["view_path"]),
                str(fixture["oracle_root"]),
                str(fixture["payload_path"]),
                str(fixture["nonce_path"]),
                "--expected-manifest-sha256",
                fixture["digest"],
                "--expected-sequence",
                "1",
                "--expected-race-spec-sha256",
                fixture["race_digest"],
                "--expected-view-sha256",
                fixture["view_digest"],
                "--expected-payload-sha256",
                fixture["payload_digest"],
                "--expected-nonce-sha256",
                fixture["nonce_digest"],
            ]
        )
    finally:
        parked.replace(opening_path)
    assert code == 3
    assert json.loads(capsys.readouterr().out) == fixture["commitment_preflight"]

    code = main(
        [
            "lock-blind-selections",
            str(fixture["view_path"]),
            "--expected-view-sha256",
            fixture["view_digest"],
        ]
    )
    assert code == 3
    assert json.loads(capsys.readouterr().out) == fixture["selection"]

    code = main(
        [
            "bind-blind-selection-precommitment",
            str(fixture["view_path"]),
            str(fixture["selection_path"]),
            "--expected-view-sha256",
            fixture["view_digest"],
            "--expected-selection-sha256",
            fixture["selection_digest"],
            "--expected-commitment-preflight-sha256",
            fixture["commitment_preflight_checkpoint_digest"],
        ]
    )
    assert code == 3
    assert json.loads(capsys.readouterr().out) == fixture["selection_envelope"]

    alias = fixture["aliases"]["case:positive"]
    code = main(
        [
            "execute-blind-synthetic",
            str(fixture["challenge_root"]),
            str(fixture["race_path"]),
            str(fixture["view_path"]),
            str(fixture["selection_path"]),
            str(fixture["selection_envelope_path"]),
            str(fixture["commitment_preflight_path"]),
            str(fixture["oracle_root"]),
            alias["case"],
            alias["lane"],
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "--expected-manifest-sha256",
            fixture["digest"],
            "--expected-sequence",
            "1",
            "--expected-race-spec-sha256",
            fixture["race_digest"],
            "--expected-view-sha256",
            fixture["view_digest"],
            "--expected-selection-sha256",
            fixture["selection_digest"],
            "--expected-selection-envelope-sha256",
            fixture["selection_envelope_checkpoint_digest"],
            "--expected-commitment-preflight-sha256",
            fixture["commitment_preflight_checkpoint_digest"],
            "--expected-opening-sha256",
            fixture["opening_digest"],
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 3
    assert output["scientific_scoring_ready"] is False
    assert output["status"] == "SYNTHETIC_BLIND_OBSERVATIONS_CLASSIFIED_SCIENTIFIC_SCORING_DISABLED"
