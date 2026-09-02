"""Hostile tests for the no-write registry-candidate boundary."""

from __future__ import annotations

import inspect
import json
import os
import socket
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from test_blind_execution import NONCE, NONCE_HEX, _build_blind_fixture, _race_spec
from test_challenge import _build, _refresh_receipt_report, _reseal, _rewrite_json_artifact

from causalfrontier import blind, challenge, receipts, registry
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.classifier import classifier_sha256, execute_classifier
from causalfrontier.cli import main
from causalfrontier.model import branch_plan_sha256, validate_case


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


@pytest.fixture
def registry_fixture(tmp_path: Path, raw_case: dict, case_root: Path) -> dict:
    return _build_blind_fixture(
        tmp_path,
        raw_case,
        case_root,
        balanced_six_case_cohort=True,
    )


def _assess(fixture: dict) -> dict:
    return registry.assess_registry_candidate(
        fixture["challenge_root"],
        fixture["digest"],
        1,
        fixture["race_path"],
        fixture["race_digest"],
        fixture["view_path"],
        fixture["view_digest"],
        fixture["nonce_path"],
        fixture["nonce_digest"],
    )


def _registry_cli_args(fixture: dict | None = None) -> list[str]:
    digest = fixture["digest"] if fixture else "0" * 64
    race_digest = fixture["race_digest"] if fixture else digest
    view_digest = fixture["view_digest"] if fixture else digest
    nonce_digest = fixture["nonce_digest"] if fixture else digest
    return [
        "assess-registry-candidate",
        "challenge",
        "race.json",
        "view.json",
        "nonce.secret",
        "--expected-manifest-sha256",
        digest,
        "--expected-sequence",
        "1",
        "--expected-race-spec-sha256",
        race_digest,
        "--expected-view-sha256",
        view_digest,
        "--expected-nonce-sha256",
        nonce_digest,
    ]


def test_existing_six_case_label_clones_fail_closed(registry_fixture: dict):
    report = _assess(registry_fixture)

    assert report["status"] == registry.STATUS
    assert report["assessment_state"] == "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED"
    assert report["cases_n"] == 6
    assert report["declared_domains_n"] == 3
    assert report["structural_collision_pairs_n"] == 15
    assert report["structural_collision_group_sizes"] == [6]
    assert report["registration_write_performed"] is False
    assert report["candidate_registered"] is False
    assert report["semantic_cohort_uniqueness_verified"] is False
    assert report["domain_independence_verified"] is False
    assert report["encoder_independence_verified"] is False
    assert report["prospective_registration_verified"] is False
    assert report["scientific_scoring_ready"] is False
    assert report["assessment_sha256"] == sha256_bytes(
        canonical_bytes({key: value for key, value in report.items() if key != "assessment_sha256"})
    )
    layer_reports = {item["layer"]: item for item in report["layer_equivalence"]}
    for layer in registry.ALL_LAYERS:
        assert layer_reports[layer]["verified_equivalence_class_sizes"] == [6]
        assert layer_reports[layer]["equal_pairs_n"] == 15
        assert layer_reports[layer]["no_call_pairs_n"] == 0


def test_steward_report_has_no_case_mapping_nonce_or_source_digest(registry_fixture: dict):
    report_text = json.dumps(_assess(registry_fixture), sort_keys=True)
    forbidden = {
        *(item["id"] for item in registry_fixture["document"]["cases"]),
        *(item["domain"] for item in registry_fixture["document"]["cases"]),
        *(item["control_class"] for item in registry_fixture["document"]["cases"]),
        *(item["id"] for item in registry_fixture["document"]["encoders"]),
        *(item["organization_id"] for item in registry_fixture["document"]["encoders"]),
        *(item["sha256"] for item in registry_fixture["document"]["artifacts"] if item["role"] == "FROZEN_CASE_SOURCE"),
        "42" * 32,
    }
    assert all(marker not in report_text for marker in forbidden)


def test_assessment_does_not_mutate_bound_inputs(registry_fixture: dict):
    paths = [
        *sorted(path for path in registry_fixture["challenge_root"].rglob("*") if path.is_file()),
        registry_fixture["race_path"],
        registry_fixture["view_path"],
        registry_fixture["nonce_path"],
    ]

    def snapshot() -> dict[str, tuple[int, int, int, str]]:
        return {
            str(path): (
                path.stat().st_mode,
                path.stat().st_size,
                path.stat().st_mtime_ns,
                sha256_bytes(path.read_bytes()),
            )
            for path in paths
        }

    container = registry_fixture["challenge_root"].parent

    def inventory() -> list[str]:
        return sorted(path.relative_to(container).as_posix() for path in container.rglob("*"))

    before = snapshot()
    before_inventory = inventory()
    _assess(registry_fixture)
    assert snapshot() == before
    assert inventory() == before_inventory


def test_assessment_has_no_write_process_or_network_capability(registry_fixture: dict, monkeypatch):
    real_open = os.open

    def guarded_open(path, flags, *args, **kwargs):
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        if flags & write_flags:
            raise AssertionError("registry attempted a descriptor write")
        return real_open(path, flags, *args, **kwargs)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("registry attempted an out-of-bound capability")

    with monkeypatch.context() as context:
        context.setattr(os, "open", guarded_open)
        for method in (
            "chmod",
            "hardlink_to",
            "mkdir",
            "rename",
            "replace",
            "rmdir",
            "symlink_to",
            "touch",
            "unlink",
            "write_bytes",
            "write_text",
        ):
            context.setattr(Path, method, forbidden)
        context.setattr(subprocess, "Popen", forbidden)
        context.setattr(subprocess, "run", forbidden)
        context.setattr(socket, "socket", forbidden)
        _assess(registry_fixture)


def test_registry_api_and_cli_have_no_designated_outcome_channel(registry_fixture: dict, capsys):
    parameters = set(inspect.signature(registry.assess_registry_candidate).parameters)
    assert not parameters & {"oracle", "opening", "outcome", "reveal", "score", "fingerprints"}

    code = main(
        [
            "assess-registry-candidate",
            str(registry_fixture["challenge_root"]),
            str(registry_fixture["race_path"]),
            str(registry_fixture["view_path"]),
            str(registry_fixture["nonce_path"]),
            "--expected-manifest-sha256",
            registry_fixture["digest"],
            "--expected-sequence",
            "1",
            "--expected-race-spec-sha256",
            registry_fixture["race_digest"],
            "--expected-view-sha256",
            registry_fixture["view_digest"],
            "--expected-nonce-sha256",
            registry_fixture["nonce_digest"],
        ]
    )
    assert code == 3
    report = json.loads(capsys.readouterr().out)
    assert report["assessment_state"] == "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED"
    assert report["designated_outcome_input_accepted"] is False
    assert report["content_outcome_isolation_verified"] is False
    gates = {gate["id"]: gate["state"] for gate in report["gates"]}
    assert gates["EXPLICIT_OUTCOME_CHANNEL_ABSENCE"] == "PASS"
    assert gates["CONTENT_OUTCOME_ISOLATION"] == "NO_CALL"


def test_cli_rejects_overclaims_extra_fields_and_stale_hash_before_emit(registry_fixture: dict, monkeypatch, capsys):
    base = _assess(registry_fixture)
    pairs_n = base["cases_n"] * (base["cases_n"] - 1) // 2
    mutations = []

    def reseal(forged: dict) -> None:
        core = {key: forged[key] for key in registry.REPORT_CORE_KEYS}
        forged["assessment_sha256"] = sha256_bytes(canonical_bytes(core))

    def set_structural_gate(forged: dict, state: str) -> None:
        gate_state, reason = registry.STRUCTURAL_GATE_BY_STATE[state]
        gate = next(item for item in forged["gates"] if item["id"] == "STRUCTURAL_CLONE_DETECTION")
        gate["state"] = gate_state
        gate["reason"] = reason

    for field in sorted(registry.FIXED_FALSE_FIELDS):
        forged = deepcopy(base)
        forged[field] = True
        reseal(forged)
        mutations.append((field, forged))
    for field in ("raw_nonce", "case_mapping", "winner", "scientific_score"):
        forged = deepcopy(base)
        forged[field] = "FORGED_PRIVATE_OR_AUTHORITY_MARKER"
        mutations.append((field, forged))
    for field in (
        "challenge_manifest_sha256",
        "race_spec_sha256",
        "entrant_view_checkpoint_sha256",
        "nonce_checkpoint_sha256",
    ):
        forged = deepcopy(base)
        forged[field] = "42" * 32
        reseal(forged)
        mutations.append((field, forged))
    forged = deepcopy(base)
    forged["challenge_sequence"] += 1
    reseal(forged)
    mutations.append(("challenge_sequence", forged))
    forged = deepcopy(base)
    forged["pair_collision_patterns"][0]["raw_nonce"] = "FORGED_PRIVATE_OR_AUTHORITY_MARKER"
    reseal(forged)
    mutations.append(("nested_pattern", forged))
    forged = deepcopy(base)
    forged["gates"][0]["reason"] = "FORGED_PRIVATE_OR_AUTHORITY_MARKER"
    reseal(forged)
    mutations.append(("gate_reason", forged))
    forged = deepcopy(base)
    forged["pair_collision_patterns"][0]["matched_layers"].remove("STEWARD_FULL")
    full_layer = next(item for item in forged["layer_equivalence"] if item["layer"] == "STEWARD_FULL")
    full_layer.update(
        {
            "verified_equivalence_class_sizes": [1] * forged["cases_n"],
            "equal_pairs_n": 0,
            "unequal_pairs_n": pairs_n,
            "no_call_pairs_n": 0,
        }
    )
    forged["structural_collision_pairs_n"] = 0
    forged["structural_collision_group_sizes"] = []
    forged["unresolved_similarity_pairs_n"] = 0
    forged["assessment_state"] = "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED"
    set_structural_gate(forged, forged["assessment_state"])
    reseal(forged)
    mutations.append(("inconsistent_unresolved_pass", forged))
    forged = deepcopy(base)
    forged["pair_collision_patterns"] = [{"matched_layers": [], "pairs_n": pairs_n}]
    for layer in forged["layer_equivalence"]:
        is_graph = layer["layer"] in registry.GRAPH_LAYERS
        layer.update(
            {
                "verified_equivalence_class_sizes": [1] * forged["cases_n"],
                "equal_pairs_n": 0,
                "unequal_pairs_n": 0 if is_graph else pairs_n,
                "no_call_pairs_n": pairs_n if is_graph else 0,
            }
        )
    forged["structural_collision_pairs_n"] = 0
    forged["structural_collision_group_sizes"] = []
    forged["unresolved_similarity_pairs_n"] = 0
    forged["canonicalization_no_call_pairs_n"] = 0
    forged["assessment_state"] = "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED"
    set_structural_gate(forged, forged["assessment_state"])
    reseal(forged)
    mutations.append(("inconsistent_canonicalization_pass", forged))
    forged = deepcopy(base)
    forged["layer_equivalence"][0]["verified_equivalence_class_sizes"] = [5, 1]
    reseal(forged)
    mutations.append(("impossible_equivalence_class", forged))
    forged = deepcopy(base)
    forged["structural_collision_group_sizes"] = [2]
    reseal(forged)
    mutations.append(("inconsistent_collision_group_sizes", forged))
    forged = deepcopy(base)
    forged["assessment_sha256"] = "0" * 64
    mutations.append(("stale_hash", forged))

    for marker, forged in mutations:
        monkeypatch.setattr(
            "causalfrontier.cli.assess_registry_candidate",
            lambda *_args, _forged=forged: _forged,
        )
        assert main(_registry_cli_args(registry_fixture)) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "causalfrontier: registry assessment violated fixed no-authority postconditions\n"
        assert marker not in captured.err
        assert "FORGED_PRIVATE_OR_AUTHORITY_MARKER" not in captured.err


def test_coherently_rehashed_nonreplayed_view_is_rejected(registry_fixture: dict, tmp_path: Path):
    changed = deepcopy(registry_fixture["view"])
    changed["cases"][0]["budget"]["calendar_minutes"] += 1
    core = {key: value for key, value in changed.items() if key != "view_sha256"}
    changed["view_sha256"] = sha256_bytes(canonical_bytes(core))
    changed_path = tmp_path / "changed-view.json"
    changed_digest = _write_json(changed_path, changed)

    with pytest.raises(CausalFrontierError, match="does not exactly replay"):
        registry.assess_registry_candidate(
            registry_fixture["challenge_root"],
            registry_fixture["digest"],
            1,
            registry_fixture["race_path"],
            registry_fixture["race_digest"],
            changed_path,
            changed_digest,
            registry_fixture["nonce_path"],
            registry_fixture["nonce_digest"],
        )


def test_nonce_rotation_changes_aliases_not_registry_geometry(registry_fixture: dict, tmp_path: Path):
    rotated_nonce = bytes.fromhex("43" * 32)
    rotated_nonce_path = tmp_path / "rotated-nonce.secret"
    rotated_nonce_raw = rotated_nonce.hex().encode("ascii") + b"\n"
    rotated_nonce_path.write_bytes(rotated_nonce_raw)
    rotated_nonce_digest = sha256_bytes(rotated_nonce_raw)
    rotated_view = blind.build_sanitized_entrant_view(
        registry_fixture["challenge_root"],
        registry_fixture["digest"],
        1,
        registry_fixture["race_path"],
        registry_fixture["race_digest"],
        rotated_nonce,
    )
    rotated_view_path = tmp_path / "rotated-view.json"
    rotated_view_digest = _write_json(rotated_view_path, rotated_view)
    rotated = registry.assess_registry_candidate(
        registry_fixture["challenge_root"],
        registry_fixture["digest"],
        1,
        registry_fixture["race_path"],
        registry_fixture["race_digest"],
        rotated_view_path,
        rotated_view_digest,
        rotated_nonce_path,
        rotated_nonce_digest,
    )
    original = _assess(registry_fixture)

    assert rotated_view["cases"][0]["entrant_case_id"] != registry_fixture["view"]["cases"][0]["entrant_case_id"]
    assert rotated["layer_equivalence"] == original["layer_equivalence"]
    assert rotated["pair_collision_patterns"] == original["pair_collision_patterns"]
    assert rotated["assessment_state"] == original["assessment_state"]


def test_nonce_rotation_preserves_distinct_case_geometry_binding(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "challenge-distinct-budgets"
    document, digest = _build(root, raw_case, case_root, balanced_six_case_cohort=True)
    race_path, _race_digest = _race_spec(document, root, digest)
    race = json.loads(race_path.read_text(encoding="utf-8"))
    expected_calendar_by_case: dict[str, int] = {}
    for index, case_spec in enumerate(race["cases"]):
        case_spec["budget"]["calendar_minutes"] = 100 + index
        case_spec["budget"]["compute_units"] = 100 + index
        case_spec["action_batch_tariffs"][0]["resources"]["compute_units"] = 20 + index
        expected_calendar_by_case[case_spec["case_id"]] = 100 + index
    race_digest = _write_json(race_path, race)
    rotated_nonce = bytes.fromhex("43" * 32)
    original_view = blind.build_sanitized_entrant_view(root, digest, 1, race_path, race_digest, NONCE)
    rotated_view = blind.build_sanitized_entrant_view(root, digest, 1, race_path, race_digest, rotated_nonce)
    original_by_alias = {item["entrant_case_id"]: item for item in original_view["cases"]}
    rotated_by_alias = {item["entrant_case_id"]: item for item in rotated_view["cases"]}
    registration_sha256 = challenge.challenge_registration_sha256(document)

    for case_entry in document["cases"]:
        original_alias = blind._opaque_id("case", case_entry["id"], registration_sha256, NONCE)
        rotated_alias = blind._opaque_id("case", case_entry["id"], registration_sha256, rotated_nonce)
        original_case = original_by_alias[original_alias]
        rotated_case = rotated_by_alias[rotated_alias]
        assert original_alias != rotated_alias
        expected_calendar = expected_calendar_by_case[case_entry["id"]]
        assert original_case["budget"]["calendar_minutes"] == expected_calendar
        assert rotated_case["budget"]["calendar_minutes"] == expected_calendar
        assert (
            registry._graphs_isomorphic(
                registry._entrant_case_graph(original_view, original_case),
                registry._entrant_case_graph(rotated_view, rotated_case),
            )
            is True
        )


def test_coherent_field_reencoding_fails_closed(tmp_path: Path, raw_case: dict, case_root: Path):
    root = tmp_path / "challenge-reencoded"
    encoded_case = deepcopy(raw_case)
    content_markers = {
        "OBSERVED_OUTCOME_QUESTION_HIGH",
        "OBSERVED_OUTCOME_PROTOCOL_HIGH",
        "OBSERVED_OUTCOME_DESCRIPTION_HIGH",
        "OBSERVED_OUTCOME_QUERY_HIGH",
        "OBSERVED_OUTCOME_UNUSED_COLUMN_HIGH",
    }
    encoded_case["decision"]["question"] = "OBSERVED_OUTCOME_QUESTION_HIGH"
    encoded_case["provenance"][0]["description"] = "OBSERVED_OUTCOME_DESCRIPTION_HIGH"
    encoded_case["provenance"][0]["submitted_query"] = "OBSERVED_OUTCOME_QUERY_HIGH"
    encoded_case["provenance"][0]["executed_query"] = "OBSERVED_OUTCOME_QUERY_HIGH"
    for experiment in encoded_case["experiments"]:
        experiment["protocol"] = "OBSERVED_OUTCOME_PROTOCOL_HIGH"
    document, _initial_digest = _build(
        root,
        encoded_case,
        case_root,
        balanced_six_case_cohort=True,
    )
    by_path = {artifact["path"]: artifact for artifact in document["artifacts"]}
    original = (case_root / encoded_case["provenance"][0]["path"]).read_bytes()
    for case_index, case_entry in enumerate(document["cases"]):
        replacements = {
            "negative_control_index": "negative_%d" % case_index,
            "response_index": "response_%d" % case_index,
            "intervention": "treatment_%d" % case_index,
            "context_a": "group_%d_a" % case_index,
            "context_b": "group_%d_b" % case_index,
            "held_out": "group_%d_held" % case_index,
            "candidate": "candidate_%d" % case_index,
            "comparator": "comparator_%d" % case_index,
            "context": "cohort_%d" % case_index,
        }
        text = original.decode("utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        inert_columns = [
            "OBSERVED_OUTCOME_UNUSED_COLUMN_HIGH_%d_%d" % (case_index, column_index)
            for column_index in range(case_index + 1)
        ]
        text = (
            "\n".join(
                line + "\t" + "\t".join(inert_columns if line_index == 0 else ["HIGH"] * len(inert_columns))
                for line_index, line in enumerate(text.splitlines())
            )
            + "\n"
        )
        source_raw = text.encode("utf-8")
        source_sha256 = sha256_bytes(source_raw)
        encodings = [item for item in document["encodings"] if item["case_id"] == case_entry["id"]]
        for encoding in encodings:
            case_artifact = next(
                item for item in document["artifacts"] if item["id"] == encoding["frozen_case_artifact_id"]
            )
            case_document = json.loads((root / case_artifact["path"]).read_text(encoding="utf-8"))
            source = case_document["provenance"][0]
            source_path = (Path(case_artifact["path"]).parent / source["path"]).as_posix()
            (root / source_path).write_bytes(source_raw)
            by_path[source_path]["sha256"] = source["sha256"] = source_sha256
            for experiment in case_document["experiments"]:
                classifier = experiment["classifier"]
                rule = classifier["rule"]
                classifier["input_columns"] = [replacements.get(value, value) for value in classifier["input_columns"]]
                classifier["input_columns"].extend(inert_columns)
                for key in (
                    "group_column",
                    "intervention_column",
                    "value_column",
                    "candidate_value",
                    "comparator_value",
                    "heldout_group",
                ):
                    if key in rule:
                        rule[key] = replacements.get(rule[key], rule[key])
                if "training_groups" in rule:
                    rule["training_groups"] = [replacements.get(value, value) for value in rule["training_groups"]]
                experiment["classifier_sha256"] = classifier_sha256(classifier)
                experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
            _rewrite_json_artifact(root, case_artifact, case_document)
        receipt_prefix = case_entry["receipt_bundle_path"]
        raw_path = "%s/raw/response.txt" % receipt_prefix
        (root / raw_path).write_bytes(source_raw)
        by_path[raw_path]["sha256"] = source_sha256
        set_path = "%s/%s" % (receipt_prefix, receipts.MANIFEST)
        receipt_set = json.loads((root / set_path).read_text(encoding="utf-8"))
        receipt_set["receipts"][0]["raw_response"]["sha256"] = source_sha256
        _rewrite_json_artifact(root, by_path[set_path], receipt_set)
        _refresh_receipt_report(root, document, case_index)

    digest = _reseal(root, document)
    race_path, race_digest = _race_spec(document, root, digest)
    view = blind.build_sanitized_entrant_view(root, digest, 1, race_path, race_digest, NONCE)
    view_path = tmp_path / "reencoded-view.json"
    view_digest = _write_json(view_path, view)
    nonce_path = tmp_path / "reencoded-nonce.secret"
    nonce_raw = NONCE_HEX.encode("ascii") + b"\n"
    nonce_path.write_bytes(nonce_raw)
    report = registry.assess_registry_candidate(
        root,
        digest,
        1,
        race_path,
        race_digest,
        view_path,
        view_digest,
        nonce_path,
        sha256_bytes(nonce_raw),
    )
    assert report["assessment_state"] == "NO_CALL_STRUCTURAL_SIMILARITY"
    assert report["structural_collision_pairs_n"] == 0
    assert report["unresolved_similarity_pairs_n"] == 15
    patterns = {tuple(item["matched_layers"]): item["pairs_n"] for item in report["pair_collision_patterns"]}
    assert patterns == {("CAUSAL_TOPOLOGY", "ENTRANT_GEOMETRY"): 15}
    report_text = json.dumps(report, sort_keys=True)
    assert all(marker not in report_text for marker in content_markers)
    gates = {gate["id"]: gate["state"] for gate in report["gates"]}
    assert gates["EXPLICIT_OUTCOME_CHANNEL_ABSENCE"] == "PASS"
    assert gates["CONTENT_OUTCOME_ISOLATION"] == "NO_CALL"
    assert report["designated_outcome_input_accepted"] is False
    assert report["content_outcome_isolation_verified"] is False


def _bijective_rename(case: dict) -> dict:
    renamed = deepcopy(case)
    source_ids = {item["id"]: "renamed-source:%d" % index for index, item in enumerate(case["provenance"])}
    option_ids = {item["id"]: "renamed-option:%d" % index for index, item in enumerate(case["decision"]["options"])}
    world_ids = {item["id"]: "renamed-world:%d" % index for index, item in enumerate(case["worlds"])}
    gate_ids = {item["id"]: "renamed-gate:%d" % index for index, item in enumerate(case["gates"])}
    experiment_ids = {item["id"]: "renamed-experiment:%d" % index for index, item in enumerate(case["experiments"])}
    outcome_ids = {
        (experiment["id"], outcome["id"]): "renamed-outcome:%d:%d" % (experiment_index, outcome_index)
        for experiment_index, experiment in enumerate(case["experiments"])
        for outcome_index, outcome in enumerate(experiment["outcomes"])
    }

    renamed["case_id"] = "renamed-case"
    renamed["title"] = "Entirely different presentation"
    renamed["purpose"] = "Presentation fields do not define structural identity"
    renamed["decision"]["id"] = "renamed-decision"
    renamed["decision"]["question"] = "Renamed question"
    renamed["decision"]["defer_option_id"] = option_ids[case["decision"]["defer_option_id"]]
    for option in renamed["decision"]["options"]:
        original_id = option["id"]
        option["id"] = option_ids[original_id]
        option["label"] = "Renamed option"
    for source in renamed["provenance"]:
        source["id"] = source_ids[source["id"]]
        source["description"] = "Renamed source presentation"
        source["source_locator"] = "synthetic://renamed"
        source["submitted_query"] = "renamed"
        source["executed_query"] = "renamed"
    for world in renamed["worlds"]:
        original_id = world["id"]
        world["id"] = world_ids[original_id]
        world["label"] = "Renamed world"
        world["admissible_option_ids"] = [option_ids[item] for item in world["admissible_option_ids"]]
        world["source_ids"] = [source_ids[item] for item in world["source_ids"]]
    for gate in renamed["gates"]:
        gate["id"] = gate_ids[gate["id"]]
        gate["label"] = "Renamed gate"
    for experiment, original in zip(renamed["experiments"], case["experiments"], strict=True):
        original_experiment_id = original["id"]
        experiment["id"] = experiment_ids[original_experiment_id]
        experiment["label"] = "Renamed experiment"
        experiment["protocol"] = "Renamed protocol"
        experiment["required_gate_ids"] = [gate_ids[item] for item in experiment["required_gate_ids"]]
        classifier = experiment["classifier"]
        classifier["source_id"] = source_ids[classifier["source_id"]]
        classifier["outcome_map"] = {
            token: outcome_ids[(original_experiment_id, outcome_id)]
            for token, outcome_id in classifier["outcome_map"].items()
        }
        for outcome in experiment["outcomes"]:
            outcome["id"] = outcome_ids[(original_experiment_id, outcome["id"])]
            outcome["label"] = "Renamed outcome"
        for prediction in experiment["predictions"]:
            prediction["world_id"] = world_ids[prediction["world_id"]]
            prediction["outcome_id"] = outcome_ids[(original_experiment_id, prediction["outcome_id"])]
            prediction["source_ids"] = [source_ids[item] for item in prediction["source_ids"]]
        experiment["classifier_sha256"] = classifier_sha256(classifier)
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    for field in ("provenance", "worlds", "gates", "experiments"):
        renamed[field].reverse()
    renamed["decision"]["options"].reverse()
    return validate_case(renamed)


def test_exact_graph_equivalence_is_id_label_order_and_presentation_invariant(raw_case: dict):
    original = validate_case(raw_case)
    renamed = _bijective_rename(original)

    for include_bytes, include_resources in ((True, True), (False, False), (False, True)):
        left = registry._steward_lane_graph(
            original,
            include_bytes=include_bytes,
            include_resources=include_resources,
        )
        right = registry._steward_lane_graph(
            renamed,
            include_bytes=include_bytes,
            include_resources=include_resources,
        )
        assert registry._graphs_isomorphic(left, right) is True


def test_internal_graph_keys_are_injective_for_delimiter_bearing_opaque_ids(raw_case: dict):
    changed = deepcopy(raw_case)
    for index, new_experiment_id, new_outcome_id in (
        (0, "experiment:a", "outcome:b:c"),
        (1, "experiment:a:outcome:b", "c"),
    ):
        experiment = changed["experiments"][index]
        old_outcome_id = experiment["outcomes"][0]["id"]
        experiment["id"] = new_experiment_id
        experiment["outcomes"][0]["id"] = new_outcome_id
        experiment["classifier"]["outcome_map"] = {
            token: new_outcome_id if outcome_id == old_outcome_id else outcome_id
            for token, outcome_id in experiment["classifier"]["outcome_map"].items()
        }
        for prediction in experiment["predictions"]:
            if prediction["outcome_id"] == old_outcome_id:
                prediction["outcome_id"] = new_outcome_id
        experiment["classifier_sha256"] = classifier_sha256(experiment["classifier"])
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    changed = validate_case(changed)
    renamed = _bijective_rename(changed)

    for include_bytes, include_resources in ((True, True), (False, False), (False, True)):
        left = registry._steward_lane_graph(
            changed,
            include_bytes=include_bytes,
            include_resources=include_resources,
        )
        right = registry._steward_lane_graph(
            renamed,
            include_bytes=include_bytes,
            include_resources=include_resources,
        )
        assert len(left["nodes"]) == len(right["nodes"])
        assert registry._graphs_isomorphic(left, right) is True


def test_meaningful_contract_change_does_not_compare_equal(raw_case: dict):
    original = validate_case(raw_case)
    changed = deepcopy(original)
    changed["experiments"][0]["resources"]["compute_units"] += 1
    changed = validate_case(changed)

    original_full = registry._steward_lane_graph(original, include_bytes=True, include_resources=True)
    changed_full = registry._steward_lane_graph(changed, include_bytes=True, include_resources=True)
    original_topology = registry._steward_lane_graph(original, include_bytes=False, include_resources=False)
    changed_topology = registry._steward_lane_graph(changed, include_bytes=False, include_resources=False)
    assert registry._graphs_isomorphic(original_full, changed_full) is False
    assert registry._graphs_isomorphic(original_topology, changed_topology) is True


def test_operational_classifier_selector_swap_does_not_compare_equal(raw_case: dict, case_root: Path):
    original = validate_case(raw_case)
    changed = deepcopy(original)
    classifier = changed["experiments"][0]["classifier"]
    rule = classifier["rule"]
    rule["candidate_value"], rule["comparator_value"] = rule["comparator_value"], rule["candidate_value"]
    changed["experiments"][0]["classifier_sha256"] = classifier_sha256(classifier)
    changed["experiments"][0]["branch_plan_sha256"] = branch_plan_sha256(changed["experiments"][0])
    changed = validate_case(changed)
    experiment_id = original["experiments"][0]["id"]
    assert execute_classifier(original, case_root, experiment_id)["branch_token"] == "LOW"
    assert execute_classifier(changed, case_root, experiment_id)["branch_token"] == "CONTRADICTION"

    full_left = registry._steward_lane_graph(original, include_bytes=True, include_resources=True)
    full_right = registry._steward_lane_graph(changed, include_bytes=True, include_resources=True)
    topology_left = registry._steward_lane_graph(original, include_bytes=False, include_resources=False)
    topology_right = registry._steward_lane_graph(changed, include_bytes=False, include_resources=False)
    execution_left = registry._steward_lane_graph(original, include_bytes=False, include_resources=True)
    execution_right = registry._steward_lane_graph(changed, include_bytes=False, include_resources=True)
    assert registry._graphs_isomorphic(full_left, full_right) is False
    assert registry._graphs_isomorphic(topology_left, topology_right) is True
    assert registry._graphs_isomorphic(execution_left, execution_right) is False


def test_prose_only_difference_is_a_structural_collision_not_semantic_identity(raw_case: dict):
    original = validate_case(raw_case)
    changed = deepcopy(original)
    changed["decision"]["question"] = "A scientifically different decision stated only in free text"
    for experiment in changed["experiments"]:
        experiment["protocol"] = "A substantively different action described only in free text"
    changed = validate_case(changed)

    left = registry._steward_lane_graph(original, include_bytes=True, include_resources=True)
    right = registry._steward_lane_graph(changed, include_bytes=True, include_resources=True)
    assert registry._graphs_isomorphic(left, right) is True


def test_search_exhaustion_is_no_call(monkeypatch):
    left = registry._graph()
    right = registry._graph()
    for index in range(4):
        registry._node(left, "left:%d" % index, "SYMMETRIC", {})
        registry._node(right, "right:%d" % index, "SYMMETRIC", {})
    monkeypatch.setattr(registry, "MAX_ISOMORPHISM_SEARCH_STATES", 0)
    assert registry._graphs_isomorphic(registry._finish_graph(left), registry._finish_graph(right)) is None


def test_fixed_budget_id_tie_breaking_never_turns_an_isomorphism_into_false():
    edges = [
        (0, 6),
        (0, 7),
        (0, 29),
        (1, 8),
        (1, 9),
        (1, 26),
        (2, 3),
        (2, 8),
        (2, 10),
        (3, 11),
        (3, 24),
        (4, 11),
        (4, 26),
        (4, 29),
        (5, 9),
        (5, 15),
        (5, 28),
        (6, 12),
        (6, 21),
        (7, 22),
        (7, 28),
        (8, 18),
        (9, 20),
        (10, 17),
        (10, 19),
        (11, 25),
        (12, 14),
        (12, 27),
        (13, 15),
        (13, 22),
        (13, 27),
        (14, 20),
        (14, 21),
        (15, 20),
        (16, 19),
        (16, 23),
        (16, 24),
        (17, 19),
        (17, 21),
        (18, 22),
        (18, 23),
        (23, 26),
        (24, 27),
        (25, 28),
        (25, 29),
    ]

    def build(names: dict[int, str]) -> dict:
        graph = registry._graph()
        for index in range(30):
            registry._node(graph, names[index], "SYMMETRIC", {})
        for left, right in edges:
            registry._edge(graph, names[left], "RELATION", names[right])
            registry._edge(graph, names[right], "RELATION", names[left])
        return registry._finish_graph(graph)

    left = build({index: "left:%02d" % index for index in range(30)})
    right_forward = build({index: "right:%02d" % index for index in range(30)})
    right_reverse = build({index: "right:%02d" % (29 - index) for index in range(30)})
    results = (
        registry._graphs_isomorphic(left, right_forward),
        registry._graphs_isomorphic(left, right_reverse),
    )
    assert results[0] is True
    assert all(result in {True, None} for result in results)


def test_large_uniquely_colored_graph_uses_forced_iterative_mapping():
    left = registry._graph()
    right = registry._graph()
    for index in range(500):
        registry._node(left, "left:%d" % index, "UNIQUE", {"index": index})
        registry._node(right, "right:%d" % index, "UNIQUE", {"index": index})
    assert registry._graphs_isomorphic(registry._finish_graph(left), registry._finish_graph(right)) is True


@pytest.mark.parametrize(
    "right_edges",
    [
        [("right:1", "RELATION", "right:0")],
        [("right:0", "OTHER_RELATION", "right:1")],
        [("right:0", "RELATION", "right:1"), ("right:0", "RELATION", "right:1")],
    ],
)
def test_exact_graph_comparison_preserves_direction_label_and_multiplicity(right_edges):
    left = registry._graph()
    right = registry._graph()
    for index in range(2):
        registry._node(left, "left:%d" % index, "NODE", {"role": index})
        registry._node(right, "right:%d" % index, "NODE", {"role": index})
    registry._edge(left, "left:0", "RELATION", "left:1")
    for source, label, target in right_edges:
        registry._edge(right, source, label, target)
    assert registry._graphs_isomorphic(registry._finish_graph(left), registry._finish_graph(right)) is False


def test_encoder_lane_order_is_not_case_identity():
    lane_a = registry._graph()
    lane_b = registry._graph()
    renamed_a = registry._graph()
    renamed_b = registry._graph()
    registry._node(lane_a, "a", "LANE_GRAPH", {"variant": "A"})
    registry._node(lane_b, "b", "LANE_GRAPH", {"variant": "B"})
    registry._node(renamed_a, "renamed-a", "LANE_GRAPH", {"variant": "A"})
    registry._node(renamed_b, "renamed-b", "LANE_GRAPH", {"variant": "B"})
    assert (
        registry._case_graphs_isomorphic(
            [registry._finish_graph(lane_a), registry._finish_graph(lane_b)],
            [registry._finish_graph(renamed_b), registry._finish_graph(renamed_a)],
        )
        is True
    )


def test_graph_node_limit_is_enforced_incrementally():
    graph = registry._graph()
    for index in range(registry.MAX_GRAPH_NODES):
        registry._node(graph, "node:%d" % index, "NODE", {})
    with pytest.raises(CausalFrontierError, match="node contract"):
        registry._node(graph, "one-too-many", "NODE", {})


def test_valid_case_above_graph_cap_returns_structured_no_call(tmp_path: Path, raw_case: dict, case_root: Path):
    expanded = deepcopy(raw_case)
    base_experiment = expanded["experiments"][0]
    expanded["experiments"] = []
    for index in range(30):
        experiment = deepcopy(base_experiment)
        experiment["id"] = "experiment:copy-%02d" % index
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
        expanded["experiments"].append(experiment)
    expanded = validate_case(expanded)

    root = tmp_path / "challenge-graph-cap"
    document, digest = _build(root, expanded, case_root)
    race_path, _race_digest = _race_spec(document, root, digest)
    race = json.loads(race_path.read_text(encoding="utf-8"))
    for case_spec in race["cases"]:
        case_spec["budget"] = dict.fromkeys(blind.RESOURCE_DIMENSIONS, 1000)
    race_digest = _write_json(race_path, race)
    view = blind.build_sanitized_entrant_view(root, digest, 1, race_path, race_digest, NONCE)
    view_path = tmp_path / "graph-cap-view.json"
    view_digest = _write_json(view_path, view)
    nonce_path = tmp_path / "graph-cap-nonce.secret"
    nonce_raw = NONCE_HEX.encode("ascii") + b"\n"
    nonce_path.write_bytes(nonce_raw)
    report = registry.assess_registry_candidate(
        root,
        digest,
        1,
        race_path,
        race_digest,
        view_path,
        view_digest,
        nonce_path,
        sha256_bytes(nonce_raw),
    )

    assert report["assessment_state"] == "NO_CALL_CANONICALIZATION_LIMIT"
    assert report["canonicalization_no_call_pairs_n"] == 3
    assert report["candidate_registered"] is False
    layer_reports = {item["layer"]: item for item in report["layer_equivalence"]}
    for layer in registry.GRAPH_LAYERS:
        assert layer_reports[layer]["no_call_pairs_n"] == 3
