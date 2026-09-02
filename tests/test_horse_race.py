"""Hostile tests for complete-matrix synthetic horse-race orchestration."""

from __future__ import annotations

import inspect
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest
from test_blind_execution import _build_blind_fixture, _write_json

import causalfrontier.cli as cli_module
from causalfrontier import blind, horse_race
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main


@pytest.fixture
def horse_fixture(tmp_path: Path, raw_case: dict, case_root: Path) -> dict:
    return _build_blind_fixture(
        tmp_path,
        raw_case,
        case_root,
        balanced_six_case_cohort=True,
    )


def _prepare(fixture: dict) -> dict:
    return horse_race.prepare_synthetic_horse_race_plan(
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
        fixture["opening_digest"],
    )


def _execute(fixture: dict, plan_path: Path, plan_digest: str) -> dict:
    return horse_race.execute_synthetic_horse_race(
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
        plan_path,
        plan_digest,
        fixture["oracle_root"],
        fixture["opening_digest"],
    )


def _execution_cli_argv(fixture: dict, plan_path: Path, plan_digest: str) -> list[str]:
    return [
        "execute-synthetic-horse-race",
        str(fixture["challenge_root"]),
        str(fixture["race_path"]),
        str(fixture["view_path"]),
        str(fixture["selection_path"]),
        str(fixture["selection_envelope_path"]),
        str(fixture["commitment_preflight_path"]),
        str(plan_path),
        str(fixture["oracle_root"]),
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
        "--expected-plan-sha256",
        plan_digest,
        "--expected-opening-sha256",
        fixture["opening_digest"],
    ]


def _rehash_execution(receipt: dict) -> None:
    previous = blind.GENESIS
    for index, event in enumerate(receipt["events"], start=1):
        event["seq"] = index
        event["prev_digest"] = previous
        core = {key: value for key, value in event.items() if key != "digest"}
        event["digest"] = sha256_bytes(blind.EVENT_DOMAIN_TAG + canonical_bytes(core))
        previous = event["digest"]
    receipt["ledger_head"] = previous
    core = {key: value for key, value in receipt.items() if key != "execution_report_sha256"}
    receipt["execution_report_sha256"] = sha256_bytes(canonical_bytes(core))


def _rehash_report_episode(report: dict, plan: dict, index: int) -> None:
    receipt = report["episode_receipts"][index]
    _rehash_execution(receipt)
    cell = plan["matrix_cells"][index]
    order_rules = {item["policy_id"]: item["rule"] for item in plan["policy_execution_order_contract"]}
    report["episode_summaries"][index] = horse_race._episode_summary(
        receipt,
        cell,
        order_rules[cell["policy_id"]],
    )
    core = {key: value for key, value in report.items() if key != "report_sha256"}
    report["report_sha256"] = sha256_bytes(canonical_bytes(core))


def test_plan_freezes_total_matrix_without_reading_oracle(horse_fixture, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("oracle opening was read during matrix planning")

    monkeypatch.setattr(blind, "_open_oracle", forbidden)
    plan = _prepare(horse_fixture)
    assert plan["status"] == horse_race.PLAN_STATUS
    assert plan["cases_n"] == 6
    assert plan["domains_n"] == 3
    assert plan["controls_n"] == 3
    assert plan["lanes_per_case"] == 2
    assert plan["policies_n"] == 3
    assert plan["matrix_cells_n"] == 36
    assert len({item["matrix_cell_id"] for item in plan["matrix_cells"]}) == 36
    assert plan["oracle_opening_read_during_planning"] is False
    assert plan["true_random_policy_registered"] is False
    assert plan["scientific_scoring_ready"] is False
    raw = canonical_bytes(plan)
    assert all(case_id.encode() not in raw for case_id in horse_fixture["aliases"])


def test_balance_gate_rejects_imbalance_confounding_and_duplicate_cells(horse_fixture):
    manifest = deepcopy(horse_fixture["document"])
    manifest["cases"][0]["control_class"] = "AMBIGUOUS"
    with pytest.raises(CausalFrontierError, match="two cases per control"):
        horse_race._validate_balance(manifest)

    manifest = deepcopy(horse_fixture["document"])
    manifest["cases"][1]["domain"] = manifest["cases"][0]["domain"]
    manifest["cases"][1]["control_class"] = manifest["cases"][0]["control_class"]
    with pytest.raises(CausalFrontierError, match="duplicated"):
        horse_race._validate_balance(manifest)


def test_executor_has_no_case_lane_or_policy_selector_parameters():
    parameters = inspect.signature(horse_race.execute_synthetic_horse_race).parameters
    assert "entrant_case_id" not in parameters
    assert "entrant_lane_id" not in parameters
    assert "policy_id" not in parameters


def test_plan_cli_returns_structural_abstention_and_no_steward_case_ids(horse_fixture, capsys):
    code = main(
        [
            "prepare-synthetic-horse-race",
            str(horse_fixture["challenge_root"]),
            str(horse_fixture["race_path"]),
            str(horse_fixture["view_path"]),
            str(horse_fixture["selection_path"]),
            str(horse_fixture["selection_envelope_path"]),
            str(horse_fixture["commitment_preflight_path"]),
            "--expected-manifest-sha256",
            horse_fixture["digest"],
            "--expected-sequence",
            "1",
            "--expected-race-spec-sha256",
            horse_fixture["race_digest"],
            "--expected-view-sha256",
            horse_fixture["view_digest"],
            "--expected-selection-sha256",
            horse_fixture["selection_digest"],
            "--expected-selection-envelope-sha256",
            horse_fixture["selection_envelope_checkpoint_digest"],
            "--expected-commitment-preflight-sha256",
            horse_fixture["commitment_preflight_checkpoint_digest"],
            "--expected-opening-sha256",
            horse_fixture["opening_digest"],
        ]
    )
    output = capsys.readouterr()
    assert code == 3
    assert output.err == ""
    assert horse_race.PLAN_STATUS in output.out
    assert all(case_id not in output.out for case_id in horse_fixture["aliases"])


def test_complete_matrix_cli_replays_every_cell_and_preserves_nonclaims(horse_fixture, tmp_path, capsys):
    plan = _prepare(horse_fixture)
    plan_path = tmp_path / "horse-race-plan.json"
    plan_digest = _write_json(plan_path, plan)
    assert main(_execution_cli_argv(horse_fixture, plan_path, plan_digest)) == 3
    output = capsys.readouterr()
    assert output.err == ""
    report = json.loads(output.out)
    assert report["status"] == horse_race.REPORT_STATUS
    assert report["expected_matrix_cells_n"] == report["executed_matrix_cells_n"] == 36
    assert report["matrix_complete"] is True
    assert report["all_episode_integrity_valid"] is True
    assert report["challenge_unchanged_during_matrix_execution"] is True
    assert report["challenge_preflight_sha256_before"] == report["challenge_preflight_sha256_after"]
    assert len({item["matrix_cell_id"] for item in report["episode_summaries"]}) == 36
    assert Counter(item["policy_id"] for item in report["episode_summaries"]) == Counter(
        dict.fromkeys(plan["policy_ids"], 12)
    )
    candidate = [
        item for item in report["episode_summaries"] if item["policy_id"] == "CAUSALFRONTIER_UNIQUE_MINIMAX_V1"
    ]
    abstain = [
        item for item in report["episode_summaries"] if item["policy_id"] == "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1"
    ]
    uniform = [
        item for item in report["episode_summaries"] if item["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1"
    ]
    assert Counter(item["terminal_kind"] for item in candidate) == Counter({"NO_CALL": 12})
    assert Counter(item["terminal_kind"] for item in abstain) == Counter({"ABSTAINED": 12})
    assert len(uniform) == 12
    assert "policy_aggregates" not in report
    assert report["scientific_baseline_families_executed"] == []
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None
    assert report["calibration_evaluated"] is False
    assert report["scientific_scoring_ready"] is False
    gates = {item["id"]: item["status"] for item in report["gates"]}
    assert gates["branch_totality"] == "PASS"
    assert gates["control_validity"] == "NO_CALL"
    assert gates["encoder_independence"] == "NO_CALL"
    assert gates["encoding_agreement"] == "NO_CALL"
    assert all(
        item["execution_order_rule"] == "LOCKED_SET_EXECUTED_IN_OPENED_CANONICAL_FROZEN_ACTION_ID_ORDER"
        and item["actions_adjudicated_n"] == len(item["executed_entrant_action_ids"])
        for item in uniform
    )
    report_path = tmp_path / "horse-race-report.json"
    report_digest = _write_json(report_path, report)
    assert (
        main(
            [
                "verify-synthetic-horse-race-report",
                str(report_path),
                str(plan_path),
                "--expected-report-sha256",
                report_digest,
                "--expected-plan-sha256",
                plan_digest,
            ]
        )
        == 3
    )
    verification_output = capsys.readouterr()
    assert verification_output.err == ""
    verification = json.loads(verification_output.out)
    assert verification["status"] == "VALID_STRUCTURAL_REPORT_SCIENTIFIC_SCORING_DISABLED"
    assert verification["contained_execution_integrity_valid"] is True
    assert verification["winner"] is None
    assert verification["scientific_scoring_ready"] is False

    forged = deepcopy(report)
    forged["winner"] = "CAUSALFRONTIER_UNIQUE_MINIMAX_V1"
    report_core = {key: value for key, value in forged.items() if key != "report_sha256"}
    forged["report_sha256"] = sha256_bytes(canonical_bytes(report_core))
    forged_path = tmp_path / "forged-report.json"
    forged_digest = _write_json(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="overclaims"):
        horse_race.verify_synthetic_horse_race_report(
            forged_path,
            forged_digest,
            plan_path,
            plan_digest,
        )

    forged = deepcopy(report)
    forged_summary = next(item for item in forged["episode_summaries"] if len(item["executed_entrant_action_ids"]) > 1)
    forged_summary["executed_entrant_action_ids"].reverse()
    summary_core = {key: value for key, value in forged_summary.items() if key != "episode_summary_sha256"}
    forged_summary["episode_summary_sha256"] = sha256_bytes(canonical_bytes(summary_core))
    report_core = {key: value for key, value in forged.items() if key != "report_sha256"}
    forged["report_sha256"] = sha256_bytes(canonical_bytes(report_core))
    forged_path = tmp_path / "forged-summary-report.json"
    forged_digest = _write_json(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="differs from its execution receipt"):
        horse_race.verify_synthetic_horse_race_report(
            forged_path,
            forged_digest,
            plan_path,
            plan_digest,
        )


def test_mutated_or_partial_plan_cannot_be_recheckpointed_into_execution(horse_fixture, tmp_path):
    plan = _prepare(horse_fixture)
    plan["matrix_cells"].pop()
    plan["matrix_cells_n"] -= 1
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = horse_race.sha256_bytes(canonical_bytes(core))
    plan_path = tmp_path / "partial-plan.json"
    plan_digest = _write_json(plan_path, plan)
    with pytest.raises(CausalFrontierError, match="matrix is not total"):
        _execute(horse_fixture, plan_path, plan_digest)


def test_non_string_policy_id_is_a_controlled_plan_error(horse_fixture):
    plan = _prepare(horse_fixture)
    plan["policy_ids"][0] = {"hostile": "unhashable"}
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = sha256_bytes(canonical_bytes(core))
    with pytest.raises(CausalFrontierError, match="policy id"):
        horse_race._validate_plan(plan)


def test_full_size_fabricated_matrix_coordinate_fails_cartesian_validation(horse_fixture):
    plan = _prepare(horse_fixture)
    cell = plan["matrix_cells"][0]
    cell["entrant_case_id"] = "entrant:case:" + "f" * 64
    cell_core = {key: value for key, value in cell.items() if key != "matrix_cell_id"}
    cell["matrix_cell_id"] = "matrix-cell:%s" % sha256_bytes(canonical_bytes(cell_core))
    plan["matrix_cells"] = sorted(
        plan["matrix_cells"],
        key=lambda item: (item["entrant_case_id"], item["entrant_lane_id"], item["policy_id"]),
    )
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = sha256_bytes(canonical_bytes(core))
    with pytest.raises(CausalFrontierError, match="complete Cartesian product"):
        horse_race._validate_plan(plan)


@pytest.mark.parametrize(
    "bad_output",
    [
        {
            "status": horse_race.REPORT_STATUS,
            "all_episode_integrity_valid": None,
            "matrix_complete": True,
            "challenge_unchanged_during_matrix_execution": True,
            "scientific_scoring_ready": False,
        },
        {
            "status": horse_race.REPORT_STATUS,
            "all_episode_integrity_valid": True,
            "matrix_complete": False,
            "challenge_unchanged_during_matrix_execution": True,
            "scientific_scoring_ready": False,
        },
        {
            "status": horse_race.REPORT_STATUS,
            "all_episode_integrity_valid": True,
            "matrix_complete": True,
            "challenge_unchanged_during_matrix_execution": True,
            "scientific_scoring_ready": True,
        },
    ],
)
def test_execution_cli_fails_closed_on_nonexact_success(monkeypatch, horse_fixture, tmp_path, bad_output):
    monkeypatch.setattr(cli_module, "execute_synthetic_horse_race", lambda *_args, **_kwargs: bad_output)
    plan_path = tmp_path / "unused-plan.json"
    plan_path.write_text("{}\n", encoding="utf-8")
    code = cli_module.main(_execution_cli_argv(horse_fixture, plan_path, "0" * 64))
    assert code == 2


def test_verification_cli_fails_closed_on_overclaiming_success(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli_module,
        "verify_synthetic_horse_race_report",
        lambda *_args, **_kwargs: {
            "status": horse_race.VALID_VERIFICATION_STATUS,
            "contained_execution_integrity_valid": True,
            "winner": None,
            "ranking": [],
            "acceleration_ratio": None,
            "scientific_scoring_ready": True,
        },
    )
    report_path = tmp_path / "unused-report.json"
    plan_path = tmp_path / "unused-plan.json"
    report_path.write_text("{}\n", encoding="utf-8")
    plan_path.write_text("{}\n", encoding="utf-8")
    assert (
        cli_module.main(
            [
                "verify-synthetic-horse-race-report",
                str(report_path),
                str(plan_path),
                "--expected-report-sha256",
                "0" * 64,
                "--expected-plan-sha256",
                "1" * 64,
            ]
        )
        == 2
    )


def test_live_orchestrator_rejects_rehashed_faulty_episode_receipt(horse_fixture, tmp_path, monkeypatch):
    plan = _prepare(horse_fixture)
    plan_path = tmp_path / "horse-race-plan.json"
    plan_digest = _write_json(plan_path, plan)
    original = blind.execute_blind_synthetic_policy

    def faulty(*args, **kwargs):
        receipt = original(*args, **kwargs)
        if receipt["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1":
            receipt["action_reports"] = []
            receipt["resources_used"] = dict.fromkeys(blind.RESOURCE_DIMENSIONS, 0)
            receipt["terminal_kind"] = "NO_CALL"
            receipt["terminal_reason_codes"] = ["NO_CALL"]
            receipt["status"] = (
                "SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED"
            )
            core = {key: value for key, value in receipt.items() if key != "execution_report_sha256"}
            receipt["execution_report_sha256"] = sha256_bytes(canonical_bytes(core))
        return receipt

    monkeypatch.setattr(blind, "execute_blind_synthetic_policy", faulty)
    with pytest.raises(CausalFrontierError, match=r"uniform enumeration|no-call|debits differ|not adjudicated"):
        _execute(horse_fixture, plan_path, plan_digest)


def test_saved_verifier_rejects_fully_rehashed_impossible_episode_lifecycles(horse_fixture, tmp_path):
    plan = _prepare(horse_fixture)
    plan_path = tmp_path / "horse-race-plan.json"
    plan_digest = _write_json(plan_path, plan)
    report = _execute(horse_fixture, plan_path, plan_digest)
    uniform_index = next(
        index
        for index, receipt in enumerate(report["episode_receipts"])
        if receipt["policy_id"] == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1" and receipt["action_reports"]
    )

    for label, expected_error in (
        ("abstained-after-actions", "terminal state differs"),
        ("invented-episode-id", "episode registration differs"),
        ("registration-binding-drift", "episode registration differs"),
        ("opening-checkpoint-drift", "overclaims or changes its contract"),
        ("preflight-mismatch-without-abort", "integrity-abort event"),
    ):
        forged = deepcopy(report)
        receipt = forged["episode_receipts"][uniform_index]
        if label == "abstained-after-actions":
            receipt["terminal_kind"] = "ABSTAINED"
            receipt["terminal_reason_codes"] = ["ABSTAINED"]
            receipt["events"][-1]["payload"]["terminal_kind"] = "ABSTAINED"
            receipt["events"][-1]["payload"]["terminal_reason_codes"] = ["ABSTAINED"]
        elif label == "invented-episode-id":
            receipt["episode_id"] = "episode:" + "f" * 64
            for event in receipt["events"]:
                event["episode_id"] = receipt["episode_id"]
        elif label == "registration-binding-drift":
            receipt["events"][0]["payload"]["challenge_manifest_sha256"] = "f" * 64
        elif label == "opening-checkpoint-drift":
            receipt["oracle_opening_sha256"] = "f" * 64
        else:
            receipt["preflight_oracle_total_bytes_matched_at_execution_start"] = False
        _rehash_report_episode(forged, plan, uniform_index)
        forged_path = tmp_path / (label + ".json")
        forged_digest = _write_json(forged_path, forged)
        with pytest.raises(CausalFrontierError) as error:
            horse_race.verify_synthetic_horse_race_report(
                forged_path,
                forged_digest,
                plan_path,
                plan_digest,
            )
        assert expected_error in str(error.value)


def test_plan_rejects_self_consistent_replicate_contract_drift(horse_fixture, tmp_path):
    commitment = deepcopy(horse_fixture["commitment_preflight"])
    commitment["required_replicates"] = 3
    commitment["observations_n"] = commitment["actions_n"] * 3
    core = {key: value for key, value in commitment.items() if key != "commitment_preflight_sha256"}
    commitment["commitment_preflight_sha256"] = sha256_bytes(canonical_bytes(core))
    commitment_path = tmp_path / "drifted-commitment.json"
    commitment_digest = _write_json(commitment_path, commitment)
    envelope = blind.bind_blind_selection_precommitment(
        horse_fixture["view_path"],
        horse_fixture["view_digest"],
        horse_fixture["selection_path"],
        horse_fixture["selection_digest"],
        commitment_digest,
    )
    envelope_path = tmp_path / "drifted-envelope.json"
    envelope_digest = _write_json(envelope_path, envelope)
    with pytest.raises(CausalFrontierError, match="different registrations or checkpoints"):
        horse_race.prepare_synthetic_horse_race_plan(
            horse_fixture["challenge_root"],
            horse_fixture["digest"],
            1,
            horse_fixture["race_path"],
            horse_fixture["race_digest"],
            horse_fixture["view_path"],
            horse_fixture["view_digest"],
            horse_fixture["selection_path"],
            horse_fixture["selection_digest"],
            envelope_path,
            envelope_digest,
            commitment_path,
            commitment_digest,
            horse_fixture["opening_digest"],
        )


def test_three_case_protocol_cannot_be_promoted_to_horse_race(tmp_path, raw_case, case_root):
    blind_fixture = _build_blind_fixture(tmp_path, raw_case, case_root)
    with pytest.raises(CausalFrontierError, match="case counts differ"):
        _prepare(blind_fixture)
