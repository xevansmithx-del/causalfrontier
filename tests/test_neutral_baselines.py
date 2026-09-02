"""Hostile tests for the policy-neutral baseline substrate."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier import neutral
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

SEEDS = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)


def _vector(**overrides: int) -> dict[str, int]:
    value = dict.fromkeys(neutral.COST_DIMENSIONS, 0)
    value.update(overrides)
    return value


def _prior() -> dict:
    core = {
        "schema_version": neutral.PRIOR_SCHEMA_VERSION,
        "status": "DECLARED_PRE_CUTOFF_SOURCE_DIGESTS_TEMPORAL_VALIDITY_UNVERIFIED",
        "authorship": "INDEPENDENT_ORGANIZER_DECLARED_NOT_VERIFIED",
        "knowledge_cutoff": "2026-08-31T23:59:59Z",
        "rubric_sha256": sha256_bytes(b"synthetic informed-OFAT rubric"),
        "source_receipt_sha256s": sorted(
            [sha256_bytes(b"synthetic source receipt b"), sha256_bytes(b"synthetic source receipt a")]
        ),
        "parameter_priorities": [
            {"factor_id": "factor:a", "rank": 2},
            {"factor_id": "factor:b", "rank": 1},
        ],
        "value_priorities": [
            {"factor_id": "factor:a", "value_id": "value:a-high", "rank": 1},
            {"factor_id": "factor:a", "value_id": "value:a-low", "rank": 2},
            {"factor_id": "factor:b", "value_id": "value:b-alt", "rank": 1},
        ],
        "independence_verified": False,
    }
    return {**core, "prior_sha256": sha256_bytes(canonical_bytes(core))}


def _action(identity: str, order: int, a_value: str, b_value: str) -> dict:
    return {
        "action_id": identity,
        "neutral_order_index": order,
        "assignment": [
            {"factor_id": "factor:a", "value_id": a_value},
            {"factor_id": "factor:b", "value_id": b_value},
        ],
        "execution_gate": {"status": "PASS", "reason": "DECLARED_AUTHORITY_AND_GATES_PASS"},
        "action_tariff": _vector(action_batches=1),
        "reset_tariff": _vector(reset_batches=1),
    }


def _factors() -> list[dict]:
    return [
        {
            "factor_id": "factor:a",
            "neutral_order_index": 1,
            "value_kind": "CATEGORICAL",
            "baseline_value_id": "value:a-base",
            "values": [
                {"value_id": "value:a-base", "neutral_order_index": 1},
                {"value_id": "value:a-low", "neutral_order_index": 2},
                {"value_id": "value:a-high", "neutral_order_index": 3},
            ],
        },
        {
            "factor_id": "factor:b",
            "neutral_order_index": 2,
            "value_kind": "ORDINAL",
            "baseline_value_id": "value:b-base",
            "values": [
                {"value_id": "value:b-base", "neutral_order_index": 1},
                {"value_id": "value:b-alt", "neutral_order_index": 2},
            ],
        },
    ]


def _baseline_assignment() -> list[dict]:
    return [
        {"factor_id": "factor:a", "value_id": "value:a-base"},
        {"factor_id": "factor:b", "value_id": "value:b-base"},
    ]


def _common_input(actions: list[dict], factors: list[dict], baseline_assignment: list[dict]) -> dict:
    factor_space_core = {"factors": factors, "baseline_assignment": baseline_assignment}
    core = {
        "schema_version": neutral.COMMON_INPUT_SCHEMA_VERSION,
        "status": neutral.COMMON_INPUT_STATUS,
        "scope": "SYNTHETIC_PROTOCOL_TEST",
        "case_id": "case:neutral-synthetic",
        "knowledge_cutoff": "2026-09-01T00:00:00Z",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "dossier_sha256": sha256_bytes(b"synthetic precompilation dossier"),
        "source_artifact_sha256s": sorted([sha256_bytes(b"synthetic source b"), sha256_bytes(b"synthetic source a")]),
        "granted_authorities": ["SOFTWARE", "SYNTHETIC_DATA"],
        "gates": [
            {"gate_id": "gate:read-only", "status": "PASS", "authority": "SOFTWARE"},
            {"gate_id": "gate:synthetic", "status": "PASS", "authority": "SYNTHETIC_DATA"},
        ],
        "factor_space_sha256": sha256_bytes(neutral.FACTOR_SPACE_DOMAIN_TAG + canonical_bytes(factor_space_core)),
        "actions": [
            {
                "action_id": action["action_id"],
                "neutral_order_index": action["neutral_order_index"],
                "execution_class": "READ_ONLY_COMPUTATION",
                "required_gate_ids": ["gate:read-only", "gate:synthetic"],
                "required_authorities": ["SOFTWARE", "SYNTHETIC_DATA"],
                "action_payload_sha256": sha256_bytes(
                    neutral.ACTION_PAYLOAD_DOMAIN_TAG
                    + canonical_bytes(
                        {
                            "action_id": action["action_id"],
                            "assignment": action["assignment"],
                            "action_tariff": action["action_tariff"],
                            "reset_tariff": action["reset_tariff"],
                        }
                    )
                ),
            }
            for action in actions
        ],
        "candidate_derived_fields_absence_declared": True,
        "semantic_blinding_verified": False,
    }
    return {**core, "common_input_sha256": sha256_bytes(canonical_bytes(core))}


def _catalog() -> dict:
    actions = [
        _action("action:a-low", 1, "value:a-low", "value:b-base"),
        _action("action:a-high", 2, "value:a-high", "value:b-base"),
        _action("action:b-alt", 3, "value:a-base", "value:b-alt"),
        _action("action:interaction", 4, "value:a-high", "value:b-alt"),
    ]
    factors = _factors()
    baseline_assignment = _baseline_assignment()
    common_input = _common_input(actions, factors, baseline_assignment)
    authorized_action_universe_core = {
        "case_id": "case:neutral-synthetic",
        "factor_space_sha256": common_input["factor_space_sha256"],
        "authorized_actions": sorted(
            (
                {
                    "action_id": action["action_id"],
                    "action_payload_sha256": common_action["action_payload_sha256"],
                }
                for action, common_action in zip(actions, common_input["actions"], strict=True)
            ),
            key=lambda item: item["action_id"],
        ),
    }
    core = {
        "schema_version": neutral.CATALOG_SCHEMA_VERSION,
        "status": neutral.CATALOG_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "scope": "SYNTHETIC_PROTOCOL_TEST",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "case_id": "case:neutral-synthetic",
        "knowledge_cutoff": "2026-09-01T00:00:00Z",
        "common_input": common_input,
        "common_input_sha256": common_input["common_input_sha256"],
        "input_tier": neutral.INPUT_TIER,
        "execution_unit": neutral.EXECUTION_UNIT,
        "execution_gate_basis": "ORGANIZER_PRECOMMITTED_AUTHORITY_AND_GATE_CHECKS_ONLY",
        "reset_rule": neutral.RESET_RULE,
        "resource_accounting_mode": neutral.RESOURCE_ACCOUNTING_MODE,
        "cost_dimensions": list(neutral.COST_DIMENSIONS),
        "budget": _vector(
            policy_invocations=1,
            selection_operations=4,
            reset_batches=3,
            action_batches=3,
        ),
        "factors": factors,
        "baseline_assignment": baseline_assignment,
        "actions": actions,
        "informed_prior": _prior(),
        "authorized_action_universe_sha256": sha256_bytes(
            neutral.AUTHORIZED_ACTION_UNIVERSE_DOMAIN_TAG + canonical_bytes(authorized_action_universe_core)
        ),
        "candidate_derived_fields_absence_declared": True,
        "common_input_structural_neutrality_verified": True,
        "execution_gate_derivation_verified": True,
        "semantic_policy_neutrality_verified": False,
        "real_resource_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(neutral.CATALOG_NONCLAIMS),
    }
    return {**core, "catalog_sha256": sha256_bytes(canonical_bytes(core))}


def _write(path: Path, value: dict) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _reseal(value: dict, field: str) -> None:
    core = {key: item for key, item in value.items() if key != field}
    value[field] = sha256_bytes(canonical_bytes(core))


def _reseal_common_bindings(catalog: dict) -> None:
    common = catalog["common_input"]
    factor_space_core = {
        "factors": catalog["factors"],
        "baseline_assignment": catalog["baseline_assignment"],
    }
    common["factor_space_sha256"] = sha256_bytes(neutral.FACTOR_SPACE_DOMAIN_TAG + canonical_bytes(factor_space_core))
    catalog_actions = {action["action_id"]: action for action in catalog["actions"]}
    for common_action in common["actions"]:
        action = catalog_actions[common_action["action_id"]]
        action_payload_core = {
            "action_id": action["action_id"],
            "assignment": action["assignment"],
            "action_tariff": action["action_tariff"],
            "reset_tariff": action["reset_tariff"],
        }
        common_action["action_payload_sha256"] = sha256_bytes(
            neutral.ACTION_PAYLOAD_DOMAIN_TAG + canonical_bytes(action_payload_core)
        )
    _reseal(common, "common_input_sha256")
    catalog["common_input_sha256"] = common["common_input_sha256"]
    authorized_action_universe_core = {
        "case_id": catalog["case_id"],
        "factor_space_sha256": common["factor_space_sha256"],
        "authorized_actions": sorted(
            (
                {
                    "action_id": action["action_id"],
                    "action_payload_sha256": next(
                        item["action_payload_sha256"]
                        for item in common["actions"]
                        if item["action_id"] == action["action_id"]
                    ),
                }
                for action in catalog["actions"]
                if action["execution_gate"]["status"] == "PASS"
            ),
            key=lambda item: item["action_id"],
        ),
    }
    catalog["authorized_action_universe_sha256"] = sha256_bytes(
        neutral.AUTHORIZED_ACTION_UNIVERSE_DOMAIN_TAG + canonical_bytes(authorized_action_universe_core)
    )
    _reseal(catalog, "catalog_sha256")


@pytest.fixture
def neutral_fixture(tmp_path: Path) -> dict:
    catalog = _catalog()
    catalog_path = tmp_path / "catalog.json"
    catalog_checkpoint = _write(catalog_path, catalog)
    commitments = [neutral.seed_commitment_sha256(seed, catalog["authorized_action_universe_sha256"]) for seed in SEEDS]
    plan = neutral.prepare_neutral_baseline_plan(catalog_path, catalog_checkpoint, commitments)
    plan_path = tmp_path / "plan.json"
    plan_checkpoint = _write(plan_path, plan)
    lock = neutral.lock_neutral_baseline_orders(
        catalog_path,
        catalog_checkpoint,
        plan_path,
        plan_checkpoint,
        SEEDS,
    )
    lock_path = tmp_path / "lock.json"
    lock_checkpoint = _write(lock_path, lock)
    report = neutral.exercise_neutral_baselines(
        catalog_path,
        catalog_checkpoint,
        plan_path,
        plan_checkpoint,
        lock_path,
        lock_checkpoint,
    )
    report_path = tmp_path / "report.json"
    report_checkpoint = _write(report_path, report)
    return {
        "catalog": catalog,
        "catalog_path": catalog_path,
        "catalog_checkpoint": catalog_checkpoint,
        "plan": plan,
        "plan_path": plan_path,
        "plan_checkpoint": plan_checkpoint,
        "lock": lock,
        "lock_path": lock_path,
        "lock_checkpoint": lock_checkpoint,
        "report": report,
        "report_path": report_path,
        "report_checkpoint": report_checkpoint,
    }


def test_complete_pipeline_is_case_level_seed_complete_replayable_and_no_score(neutral_fixture):
    plan = neutral_fixture["plan"]
    lock = neutral_fixture["lock"]
    report = neutral_fixture["report"]
    assert plan["matrix_cells_n"] == len(SEEDS) + 2
    assert plan["execution_unit"] == neutral.EXECUTION_UNIT
    assert plan["seeds_opened_during_planning"] is False
    assert "seed_hex" not in canonical_bytes(plan).decode("utf-8")
    assert lock["seed_openings_n"] == len(SEEDS)
    assert lock["all_precommitted_seeds_opened"] is True
    assert report["receipts_n"] == len(SEEDS) + 2
    assert report["all_precommitted_seed_receipts_retained"] is True
    assert report["best_seed_selected"] is False
    assert report["scientific_baseline_families_executed"] == []
    assert report["winner"] is None
    assert report["ranking"] == []
    assert report["acceleration_ratio"] is None
    assert report["real_resource_verified"] is False
    assert report["scientific_scoring_ready"] is False
    assert all(
        receipt["score_core"]["common_input_sha256"] == neutral_fixture["catalog"]["common_input_sha256"]
        for receipt in report["receipts"]
    )
    assert all(len(receipt["score_core"]["executed_action_ids"]) == 3 for receipt in report["receipts"])
    verification = neutral.verify_neutral_baseline_exercise(
        neutral_fixture["catalog_path"],
        neutral_fixture["catalog_checkpoint"],
        neutral_fixture["plan_path"],
        neutral_fixture["plan_checkpoint"],
        neutral_fixture["lock_path"],
        neutral_fixture["lock_checkpoint"],
        neutral_fixture["report_path"],
        neutral_fixture["report_checkpoint"],
    )
    assert verification["status"] == neutral.VERIFICATION_STATUS
    assert verification["score_cores_replayed_n"] == len(SEEDS) + 2
    assert verification["common_input_sha256"] == neutral_fixture["catalog"]["common_input_sha256"]
    assert verification["common_input_structural_neutrality_verified"] is True
    assert verification["factor_space_and_action_payloads_replayed"] is True
    assert verification["execution_gate_derivation_verified"] is True
    assert verification["semantic_policy_neutrality_verified"] is False
    assert verification["precompilation_timing_and_currentness_verified"] is False
    assert verification["rollback_protection_verified"] is False
    assert verification["authority_declarations_attested"] is False
    assert verification["telemetry_authenticity_verified"] is False
    assert verification["cohort_uniqueness_verified"] is False
    assert verification["real_resource_verified"] is False


def test_random_uses_full_authorized_catalog_while_ofat_uses_proved_geometry(neutral_fixture):
    traces = neutral_fixture["lock"]["traces"]
    random_traces = traces[: len(SEEDS)]
    blind, informed = traces[-2:]
    expected_all = {"action:a-low", "action:a-high", "action:b-alt", "action:interaction"}
    assert all(set(trace["ordered_action_ids"]) == expected_all for trace in random_traces)
    assert blind["ordered_action_ids"] == ["action:a-low", "action:a-high", "action:b-alt"]
    assert informed["ordered_action_ids"] == ["action:b-alt", "action:a-high", "action:a-low"]
    assert "action:interaction" not in blind["ordered_action_ids"]
    assert "action:interaction" not in informed["ordered_action_ids"]


def test_seed_commitment_and_portable_random_order_have_fixed_golden_vector(neutral_fixture):
    assert [trace["ordered_action_ids"] for trace in neutral_fixture["lock"]["traces"][:3]] == [
        ["action:interaction", "action:a-high", "action:b-alt", "action:a-low"],
        ["action:interaction", "action:b-alt", "action:a-low", "action:a-high"],
        ["action:b-alt", "action:a-high", "action:a-low", "action:interaction"],
    ]
    universe = neutral_fixture["catalog"]["authorized_action_universe_sha256"]
    assert neutral.seed_commitment_sha256(SEEDS[0], universe) != neutral.seed_commitment_sha256(SEEDS[0], "0" * 64)
    with pytest.raises(CausalFrontierError, match="exactly 32 bytes"):
        neutral.seed_commitment_sha256(b"short", universe)
    with pytest.raises(CausalFrontierError, match="lowercase SHA-256"):
        neutral.seed_commitment_sha256(SEEDS[0], "not-a-digest")


def test_catalog_rejects_candidate_outputs_and_invalid_ofat_geometry_after_rehash():
    catalog = _catalog()
    catalog["actions"][0]["eligible_action_ids"] = ["action:a-low"]
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="candidate-derived"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["actions"][2]["assignment"][0]["value_id"] = "value:a-low"
    _reseal_common_bindings(catalog)
    with pytest.raises(CausalFrontierError, match="exactly one single-factor action"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["actions"][3]["assignment"] = deepcopy(catalog["actions"][2]["assignment"])
    _reseal_common_bindings(catalog)
    with pytest.raises(CausalFrontierError, match="duplicate assignments"):
        neutral.validate_neutral_action_catalog(catalog)


def test_common_input_binds_factor_space_action_payloads_and_nested_candidate_absence():
    catalog = _catalog()
    catalog["factors"][0]["value_kind"] = "ORDINAL"
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="factor space differs"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["actions"][0]["action_tariff"]["authorized_tool_units"] = 1
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="action payload differs"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["common_input"]["actions"][0]["eligible_action_ids"] = ["action:a-low"]
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="candidate-derived"):
        neutral.validate_neutral_action_catalog(catalog)


def test_gate_replay_and_unknown_action_fail_closed_after_rehash():
    catalog = _catalog()
    catalog["common_input"]["gates"][1]["status"] = "OPEN"
    _reseal_common_bindings(catalog)
    with pytest.raises(CausalFrontierError, match="execution gate does not replay"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["actions"][0]["action_id"] = "action:unknown"
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="absent from the common input"):
        neutral.validate_neutral_action_catalog(catalog)


def test_seeded_random_order_is_invariant_to_organizer_action_reindexing():
    original = neutral.validate_neutral_action_catalog(_catalog())
    reindexed = _catalog()
    new_orders = {
        "action:a-low": 4,
        "action:a-high": 3,
        "action:b-alt": 2,
        "action:interaction": 1,
    }
    for action in reindexed["actions"]:
        action["neutral_order_index"] = new_orders[action["action_id"]]
    reindexed["actions"].sort(key=lambda action: action["neutral_order_index"])
    for action in reindexed["common_input"]["actions"]:
        action["neutral_order_index"] = new_orders[action["action_id"]]
    reindexed["common_input"]["actions"].sort(key=lambda action: action["neutral_order_index"])
    _reseal_common_bindings(reindexed)
    reindexed = neutral.validate_neutral_action_catalog(reindexed)
    assert reindexed["authorized_action_universe_sha256"] == original["authorized_action_universe_sha256"]
    assert [neutral._random_order(reindexed, seed) for seed in SEEDS] == [
        neutral._random_order(original, seed) for seed in SEEDS
    ]


def test_informed_prior_must_be_complete_pre_cutoff_and_independently_labeled():
    catalog = _catalog()
    catalog["informed_prior"]["value_priorities"].pop()
    _reseal(catalog["informed_prior"], "prior_sha256")
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="rank every nonbaseline"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["informed_prior"]["knowledge_cutoff"] = "2026-09-02T00:00:00Z"
    _reseal(catalog["informed_prior"], "prior_sha256")
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="follows the catalog"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["informed_prior"]["independence_verified"] = True
    _reseal(catalog["informed_prior"], "prior_sha256")
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="overclaims"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["informed_prior"]["source_receipt_sha256s"] = [{}]
    _reseal(catalog["informed_prior"], "prior_sha256")
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="source receipts"):
        neutral.validate_neutral_action_catalog(catalog)


def test_order_only_tariffs_reject_phantom_operations_pair_overflow_and_underfunded_ofat():
    catalog = _catalog()
    catalog["actions"][0]["action_tariff"]["oracle_bytes_delivered"] = 1
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="declared batch"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["budget"]["authorized_tool_units"] = neutral.MAX_COUNTER
    catalog["actions"][0]["action_tariff"]["authorized_tool_units"] = neutral.MAX_COUNTER
    catalog["actions"][0]["reset_tariff"]["authorized_tool_units"] = 1
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="overflow"):
        neutral.validate_neutral_action_catalog(catalog)

    catalog = _catalog()
    catalog["budget"]["action_batches"] = 2
    catalog["budget"]["reset_batches"] = 2
    _reseal(catalog, "catalog_sha256")
    with pytest.raises(CausalFrontierError, match="complete blind and informed OFAT"):
        neutral.validate_neutral_action_catalog(catalog)


def test_plan_requires_multiple_unique_seed_commitments(neutral_fixture):
    with pytest.raises(CausalFrontierError, match="multi-seed"):
        neutral.prepare_neutral_baseline_plan(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            [neutral.seed_commitment_sha256(SEEDS[0], neutral_fixture["catalog"]["authorized_action_universe_sha256"])],
        )
    with pytest.raises(CausalFrontierError, match="unique"):
        neutral.prepare_neutral_baseline_plan(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            [neutral.seed_commitment_sha256(SEEDS[0], neutral_fixture["catalog"]["authorized_action_universe_sha256"])]
            * 2,
        )
    with pytest.raises(CausalFrontierError, match="does not match"):
        neutral.lock_neutral_baseline_orders(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            neutral_fixture["plan_path"],
            neutral_fixture["plan_checkpoint"],
            (SEEDS[0], SEEDS[1], b"\x04" * 32),
        )


def test_plan_rejects_a_matrix_that_cannot_round_trip_through_checkpoint_limit(neutral_fixture, monkeypatch):
    monkeypatch.setattr(neutral, "MAX_ORDERED_ACTION_REFERENCES", 1)
    with pytest.raises(CausalFrontierError, match="action-reference limit"):
        neutral.prepare_neutral_baseline_plan(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            [
                neutral.seed_commitment_sha256(seed, neutral_fixture["catalog"]["authorized_action_universe_sha256"])
                for seed in SEEDS
            ],
        )


def test_protocol_costs_are_event_derived_and_budget_never_overruns(neutral_fixture):
    budget = neutral_fixture["catalog"]["budget"]
    for receipt in neutral_fixture["report"]["receipts"]:
        core = receipt["score_core"]
        assert core["resources_used"] == _vector(
            policy_invocations=1,
            selection_operations=4,
            reset_batches=3,
            action_batches=3,
        )
        assert all(core["resources_used"][key] <= budget[key] for key in neutral.COST_DIMENSIONS)
        assert len(core["events"]) == 7
        assert core["events"][0]["kind"] == "POLICY_SELECTION"
        assert sum(event["kind"] == "RESET_TO_COMMON_BASELINE" for event in core["events"]) == 3
        assert sum(event["kind"] == "ACTION_PROTOCOL_BATCH" for event in core["events"]) == 3
        if core["policy_id"] == neutral.RANDOM_POLICY_ID:
            assert core["terminal_kind"] == "ORDER_EXHAUSTED_WITH_BUDGET_SKIPS"
        else:
            assert core["terminal_kind"] == "ORDER_EXHAUSTED"
        assert core["real_resource_verified"] is False
        assert core["scientific_acceleration_eligible"] is False


def test_fully_rehashed_forged_score_core_is_rejected(neutral_fixture, tmp_path):
    forged = deepcopy(neutral_fixture["report"])
    receipt = forged["receipts"][0]
    receipt["score_core"]["resources_used"]["action_batches"] = 1
    receipt["score_core_sha256"] = sha256_bytes(neutral.SCORE_CORE_DOMAIN_TAG + canonical_bytes(receipt["score_core"]))
    receipt_core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = sha256_bytes(neutral.RECEIPT_DOMAIN_TAG + canonical_bytes(receipt_core))
    _reseal(forged, "report_sha256")
    forged_path = tmp_path / "forged.json"
    forged_checkpoint = _write(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="does not replay"):
        neutral.verify_neutral_baseline_exercise(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            neutral_fixture["plan_path"],
            neutral_fixture["plan_checkpoint"],
            neutral_fixture["lock_path"],
            neutral_fixture["lock_checkpoint"],
            forged_path,
            forged_checkpoint,
        )


def test_observational_telemetry_changes_full_receipts_but_never_score_cores(neutral_fixture):
    captured = neutral.exercise_neutral_baselines(
        neutral_fixture["catalog_path"],
        neutral_fixture["catalog_checkpoint"],
        neutral_fixture["plan_path"],
        neutral_fixture["plan_checkpoint"],
        neutral_fixture["lock_path"],
        neutral_fixture["lock_checkpoint"],
        capture_observational_telemetry=True,
    )
    plain = neutral_fixture["report"]
    assert [item["score_core_sha256"] for item in captured["receipts"]] == [
        item["score_core_sha256"] for item in plain["receipts"]
    ]
    assert all(item["telemetry"]["score_relevant"] is False for item in captured["receipts"])
    assert all(item["telemetry"]["process_tree_complete"] is False for item in captured["receipts"])
    assert any(
        left["receipt_sha256"] != right["receipt_sha256"]
        for left, right in zip(captured["receipts"], plain["receipts"], strict=True)
    )


def test_telemetry_cannot_be_promoted_into_score_after_full_rehash(neutral_fixture, tmp_path):
    forged = deepcopy(neutral_fixture["report"])
    receipt = forged["receipts"][0]
    receipt["telemetry"]["score_relevant"] = True
    receipt["telemetry_sha256"] = sha256_bytes(neutral.TELEMETRY_DOMAIN_TAG + canonical_bytes(receipt["telemetry"]))
    receipt_core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = sha256_bytes(neutral.RECEIPT_DOMAIN_TAG + canonical_bytes(receipt_core))
    _reseal(forged, "report_sha256")
    forged_path = tmp_path / "forged-telemetry.json"
    forged_checkpoint = _write(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="cannot be score-relevant"):
        neutral.verify_neutral_baseline_exercise(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            neutral_fixture["plan_path"],
            neutral_fixture["plan_checkpoint"],
            neutral_fixture["lock_path"],
            neutral_fixture["lock_checkpoint"],
            forged_path,
            forged_checkpoint,
        )


def test_declared_telemetry_provider_and_rss_coherence_fail_closed(neutral_fixture, tmp_path):
    forged = deepcopy(neutral_fixture["report"])
    receipt = forged["receipts"][0]
    telemetry = receipt["telemetry"]
    telemetry.update(
        {
            "status": "DECLARED_SAME_PROCESS_OBSERVATION_AUTHENTICITY_UNVERIFIED",
            "provider": "FORGED_PROVIDER",
            "scope": "CURRENT_PROCESS_CUMULATIVE_NOT_ISOLATED",
            "platform": "Synthetic",
            "python_implementation": "synthetic",
            "python_version": "0",
            "wall_elapsed_ns": 1,
            "process_cpu_elapsed_ns": 1,
            "self_user_cpu_us": 1,
            "self_system_cpu_us": 1,
            "max_rss_raw_start": 10,
            "max_rss_raw_end": 1,
            "max_rss_raw_unit": "BYTES",
        }
    )
    receipt["telemetry_sha256"] = sha256_bytes(neutral.TELEMETRY_DOMAIN_TAG + canonical_bytes(telemetry))
    receipt_core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = sha256_bytes(neutral.RECEIPT_DOMAIN_TAG + canonical_bytes(receipt_core))
    _reseal(forged, "report_sha256")
    forged_path = tmp_path / "forged-provider.json"
    forged_checkpoint = _write(forged_path, forged)
    with pytest.raises(CausalFrontierError, match="provider or scope"):
        neutral.verify_neutral_baseline_exercise(
            neutral_fixture["catalog_path"],
            neutral_fixture["catalog_checkpoint"],
            neutral_fixture["plan_path"],
            neutral_fixture["plan_checkpoint"],
            neutral_fixture["lock_path"],
            neutral_fixture["lock_checkpoint"],
            forged_path,
            forged_checkpoint,
        )


def test_exact_external_checkpoints_fail_closed(neutral_fixture):
    with pytest.raises(CausalFrontierError, match="checkpoint mismatch"):
        neutral.load_neutral_action_catalog(neutral_fixture["catalog_path"], "0" * 64)
