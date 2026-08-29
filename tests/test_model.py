from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from causalfrontier.canonical import CausalFrontierError, read_json_bytes
from causalfrontier.model import branch_plan_sha256, load_case, validate_case


def _rebind(experiment):
    experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)


def test_public_synthetic_case_loads(case_root: Path):
    case = load_case(case_root)
    assert case["case_id"] == "synthetic-aggregate-response"
    assert {item["data_class"] for item in case["provenance"]} == {"SYNTHETIC"}


def test_duplicate_json_key_is_rejected():
    with pytest.raises(CausalFrontierError, match="duplicate JSON key"):
        read_json_bytes(b'{"case_id":"a","case_id":"b"}')


def test_float_is_rejected_even_if_finite():
    with pytest.raises(CausalFrontierError, match="floating-point JSON"):
        read_json_bytes(b'{"resource":0.5}')


def test_prior_leakage_key_is_rejected(mutable_case):
    mutable_case["experiments"][0]["posterior"] = {"world:residual": 1}
    with pytest.raises(CausalFrontierError, match="forbidden"):
        validate_case(mutable_case)


def test_observed_outcome_leakage_key_is_rejected(mutable_case):
    mutable_case["experiments"][0]["observed_outcome"] = "outcome:global-invariant"
    with pytest.raises(CausalFrontierError, match="forbidden"):
        validate_case(mutable_case)


def test_branch_plan_digest_rejects_post_freeze_edit(mutable_case):
    mutable_case["experiments"][0]["outcomes"][0]["label"] = "Edited after freeze"
    with pytest.raises(CausalFrontierError, match="branch plan digest mismatch"):
        validate_case(mutable_case)


def test_total_outcome_partition_is_required(mutable_case):
    experiment = mutable_case["experiments"][0]
    removed = next(item["id"] for item in experiment["outcomes"] if item["class"] == "NO_CALL")
    experiment["outcomes"] = [item for item in experiment["outcomes"] if item["id"] != removed]
    experiment["predictions"] = [item for item in experiment["predictions"] if item["outcome_id"] != removed]
    _rebind(experiment)
    with pytest.raises(CausalFrontierError, match="must predeclare"):
        validate_case(mutable_case)


def test_prediction_cartesian_product_is_required(mutable_case):
    experiment = mutable_case["experiments"][0]
    experiment["predictions"].pop()
    _rebind(experiment)
    with pytest.raises(CausalFrontierError, match="prediction matrix is not total"):
        validate_case(mutable_case)


def test_residual_world_cannot_be_eliminated_by_informative_branch(mutable_case):
    experiment = mutable_case["experiments"][0]
    prediction = next(
        item
        for item in experiment["predictions"]
        if item["world_id"] == "world:residual" and item["outcome_id"] == "outcome:global-invariant"
    )
    prediction["relation"] = "EXCLUDES"
    _rebind(experiment)
    with pytest.raises(CausalFrontierError, match="residual world must remain UNKNOWN"):
        validate_case(mutable_case)


def test_failure_branch_cannot_leak_a_world_update(mutable_case):
    experiment = mutable_case["experiments"][0]
    prediction = next(item for item in experiment["predictions"] if item["outcome_id"] == "outcome:global-failure")
    prediction["relation"] = "EXCLUDES"
    _rebind(experiment)
    with pytest.raises(CausalFrontierError, match="must preserve every world"):
        validate_case(mutable_case)


def test_exactly_one_residual_is_required(mutable_case):
    mutable_case["worlds"][0]["is_residual"] = True
    mutable_case["worlds"][0]["admissible_option_ids"] = ["option:defer"]
    with pytest.raises(CausalFrontierError, match="exactly one residual"):
        validate_case(mutable_case)


def test_alpha_boundary_cannot_claim_clinical_authority(mutable_case):
    mutable_case["boundary"]["clinical_authority"] = True
    with pytest.raises(CausalFrontierError, match="alpha boundary is immutable"):
        validate_case(mutable_case)


def test_high_authority_gate_cannot_be_marked_satisfied(mutable_case):
    mutable_case["gates"][0]["authority"] = "CLINICAL"
    with pytest.raises(CausalFrontierError, match="cannot satisfy CLINICAL"):
        validate_case(mutable_case)


def test_provenance_digest_mismatch_fails(copied_case: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    source.write_text(source.read_text(encoding="utf-8") + "extra\trow\t0\t0\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="digest mismatch"):
        load_case(copied_case)


def test_unmanifested_case_file_fails(copied_case: Path):
    (copied_case / "undeclared.txt").write_text("not in provenance\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="inventory differs"):
        load_case(copied_case)


def test_public_aggregate_source_cannot_claim_synthetic_authority(mutable_case):
    mutable_case["provenance"][0]["data_class"] = "PUBLIC_AGGREGATE"
    with pytest.raises(CausalFrontierError, match="public aggregate source"):
        validate_case(mutable_case)


def test_case_json_is_valid_plain_json(case_root: Path):
    parsed = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
    assert parsed["schema_version"] == "causalfrontier.case.v1"


def test_impossible_calendar_timestamp_is_rejected(mutable_case):
    mutable_case["frozen_at"] = "2026-02-30T00:00:00Z"
    with pytest.raises(CausalFrontierError, match="whole-second RFC3339 UTC"):
        validate_case(mutable_case)


def test_post_cutoff_source_is_rejected(mutable_case):
    mutable_case["evidence_cutoff"] = "2012-12-31T23:59:59Z"
    with pytest.raises(CausalFrontierError, match="after the evidence cutoff"):
        validate_case(mutable_case)


def test_semantically_usable_source_requires_complete_coverage(mutable_case):
    mutable_case["provenance"][0]["coverage_complete"] = False
    with pytest.raises(CausalFrontierError, match="coverage is incomplete"):
        validate_case(mutable_case)


def test_case_root_symlink_is_rejected(case_root: Path, tmp_path: Path):
    linked = tmp_path / "case-link"
    linked.symlink_to(case_root, target_is_directory=True)
    with pytest.raises(CausalFrontierError, match="must not be a symlink"):
        load_case(linked)


def test_hardlinked_provenance_file_is_rejected(copied_case: Path, tmp_path: Path):
    source = copied_case / "evidence" / "aggregate_response.tsv"
    external = tmp_path / "external.tsv"
    source.replace(external)
    os.link(external, source)
    with pytest.raises(CausalFrontierError, match="single-link regular file"):
        load_case(copied_case)


def test_nested_case_json_is_not_exempt_from_inventory(copied_case: Path):
    nested = copied_case / "evidence" / "case.json"
    nested.write_text("{}\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="inventory differs"):
        load_case(copied_case)


def test_malformed_provenance_path_fails_as_schema_error(mutable_case):
    mutable_case["provenance"][0]["path"] = []
    with pytest.raises(CausalFrontierError, match="provenance path"):
        validate_case(mutable_case)


def test_synthetic_source_cannot_claim_public_semantics(mutable_case):
    mutable_case["provenance"][0]["semantic_state"] = "USABLE_FOR_DECLARED_SCOPE"
    with pytest.raises(CausalFrontierError, match="synthetic source"):
        validate_case(mutable_case)


def test_experiment_must_bind_every_declared_gate(mutable_case):
    experiment = mutable_case["experiments"][0]
    experiment["required_gate_ids"].pop()
    with pytest.raises(CausalFrontierError, match="bind every declared"):
        validate_case(mutable_case)


def test_experiment_must_bind_world_source_authority(mutable_case):
    for experiment in mutable_case["experiments"]:
        experiment["required_authorities"] = [
            authority for authority in experiment["required_authorities"] if authority != "SYNTHETIC_DATA"
        ]
    with pytest.raises(CausalFrontierError, match="omits implied authorities"):
        validate_case(mutable_case)


def test_contradiction_must_preserve_open_residual(mutable_case):
    experiment = mutable_case["experiments"][0]
    prediction = next(
        item
        for item in experiment["predictions"]
        if item["world_id"] == "world:residual" and item["outcome_id"] == "outcome:global-contradiction"
    )
    prediction["relation"] = "EXCLUDES"
    _rebind(experiment)
    with pytest.raises(CausalFrontierError, match="preserving the residual"):
        validate_case(mutable_case)


def test_equivalent_world_refinement_does_not_change_selection(mutable_case):
    from causalfrontier.frontier import compile_case

    baseline = compile_case(mutable_case)
    original = next(item for item in mutable_case["worlds"] if item["id"] == "world:invariant-mechanism")
    replica = deepcopy(original)
    replica["id"] = "world:invariant-mechanism-replica"
    replica["label"] = "Equivalent invariant-mechanism refinement"
    mutable_case["worlds"].append(replica)
    for experiment in mutable_case["experiments"]:
        originals = [
            deepcopy(item) for item in experiment["predictions"] if item["world_id"] == "world:invariant-mechanism"
        ]
        for prediction in originals:
            prediction["world_id"] = replica["id"]
            experiment["predictions"].append(prediction)
        _rebind(experiment)

    refined = compile_case(mutable_case)
    assert refined["frontiers"] == baseline["frontiers"]
    assert refined["minimax"] == baseline["minimax"]
