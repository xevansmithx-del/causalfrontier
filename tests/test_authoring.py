from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy

import pytest

import causalfrontier.authoring as authoring
from causalfrontier import freeze_draft
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, read_json, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.frontier import compile_case
from causalfrontier.model import load_case


@pytest.fixture
def draft_root(case_root, tmp_path):
    root = tmp_path / "draft"
    shutil.copytree(case_root, root)
    draft = read_json(root / "case.json")
    draft["schema_version"] = authoring.DRAFT_SCHEMA_VERSION
    for source in draft["provenance"]:
        source["sha256"] = None
    for experiment in draft["experiments"]:
        experiment["classifier_sha256"] = None
        experiment["branch_plan_sha256"] = None
    (root / "case.json").unlink()
    _write_draft(root, draft)
    return root


def _write_draft(root, draft):
    (root / "draft.json").write_bytes(canonical_bytes(draft) + b"\n")


def _bytes(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_author_to_complete_cli_workflow(draft_root, case_root, tmp_path, capsys):
    before = _bytes(draft_root)
    destination = tmp_path / "frozen"
    assert main(["freeze-draft", str(draft_root), str(destination)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == authoring.STATUS
    assert report["scientific_scoring_ready"] is False
    assert report["draft_sha256"] == sha256_bytes(before["draft.json"])
    assert compile_case(load_case(destination)) == compile_case(load_case(case_root))
    assert _bytes(draft_root) == before
    assert (destination / "evidence/aggregate_response.tsv").read_bytes() == before["evidence/aggregate_response.tsv"]
    assert not (destination / "draft.json").exists()
    assert load_case(destination)["frozen_at"] == load_case(case_root)["frozen_at"]
    for command in ("analyze", "classify"):
        assert main([command, str(destination)]) == 0
        assert json.loads(capsys.readouterr().out)
    capsule = tmp_path / "capsule"
    assert main(["compile", str(destination), str(capsule)]) == 0
    compiled = json.loads(capsys.readouterr().out)
    assert main(["verify", str(capsule)]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["manifest_sha256"] == compiled["manifest_sha256"]


def test_changed_authored_relation_changes_branch_digest(draft_root, case_root, tmp_path):
    draft = read_json(draft_root / "draft.json")
    experiment = draft["experiments"][0]
    prediction = next(item for item in experiment["predictions"] if item["relation"] == "SURVIVES")
    prediction["relation"] = "UNKNOWN"
    _write_draft(draft_root, draft)
    freeze_draft(draft_root, tmp_path / "new")
    current = load_case(tmp_path / "new")
    old = {item["id"]: item for item in load_case(case_root)["experiments"]}
    changed = next(item for item in current["experiments"] if item["id"] == experiment["id"])
    assert changed["classifier_sha256"] == old[experiment["id"]]["classifier_sha256"]
    assert changed["branch_plan_sha256"] != old[experiment["id"]]["branch_plan_sha256"]
    assert (
        next(
            item["relation"]
            for item in changed["predictions"]
            if (item["world_id"], item["outcome_id"]) == (prediction["world_id"], prediction["outcome_id"])
        )
        == "UNKNOWN"
    )


def test_source_edit_is_bound_without_rewriting_bytes(draft_root, tmp_path):
    source = draft_root / "evidence/aggregate_response.tsv"
    before = source.read_bytes()
    source.write_bytes(before.replace(b"\n", b"\r\n"))
    expected = source.read_bytes()
    assert expected != before
    report = freeze_draft(draft_root, tmp_path / "new")
    assert report["sources"][0]["sha256"] == sha256_bytes(expected)
    assert (tmp_path / "new/evidence/aggregate_response.tsv").read_bytes() == expected


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(schema_version="causalfrontier.case.v1"),
        lambda d: d["provenance"][0].update(sha256="0" * 64),
        lambda d: d["provenance"][0].pop("sha256"),
        lambda d: d["experiments"][0].update(classifier_sha256="0" * 64),
        lambda d: d["experiments"][0].update(branch_plan_sha256="0" * 64),
        lambda d: d["experiments"][0]["predictions"].pop(),
        lambda d: d["experiments"][0].update(predictions=None),
        lambda d: d["experiments"][0]["classifier"]["rule"].update(kind={}),
        lambda d: d["experiments"][0]["classifier"]["rule"].update(kind=[]),
        lambda d: d["experiments"][0]["predictions"][0].pop("source_ids"),
        lambda d: d["experiments"][0]["outcomes"][0].pop("class"),
        lambda d: d["experiments"][0].pop("outcome_partition"),
        lambda d: d["experiments"][0].update(required_authorities=[]),
        lambda d: d["boundary"].update(clinical_authority=True),
        lambda d: d.update(frozen_at="2020-01-01T00:00:00Z"),
        lambda d: d.update(prior=1),
        lambda d: d.update(unregistered_field="extra"),
        lambda d: d["worlds"].pop(),
        lambda d: d["provenance"][0].update(path="../outside.tsv"),
        lambda d: d["provenance"][0].update(path="/outside.tsv"),
        lambda d: d["provenance"][0].update(path="case.json"),
        lambda d: d["provenance"][0].update(path="draft.json"),
    ],
)
def test_invalid_authoring_never_creates_output(draft_root, tmp_path, mutation):
    draft = read_json(draft_root / "draft.json")
    mutation(draft)
    _write_draft(draft_root, draft)
    before = _bytes(draft_root)
    with pytest.raises(CausalFrontierError):
        freeze_draft(draft_root, tmp_path / "new")
    assert not (tmp_path / "new").exists()
    assert _bytes(draft_root) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "extra", "empty-directory", "invalid-utf8", "large"])
def test_unsafe_or_unmanifested_input_rejected(draft_root, tmp_path, kind):
    source = draft_root / "evidence/aggregate_response.tsv"
    if kind in {"symlink", "hardlink"}:
        outside = tmp_path / "original.tsv"
        source.rename(outside)
        source.symlink_to(outside) if kind == "symlink" else os.link(outside, source)
    elif kind == "fifo":
        source.unlink()
        os.mkfifo(source)
    elif kind == "extra":
        (draft_root / "unmanifested.txt").write_text("extra")
    elif kind == "empty-directory":
        (draft_root / "empty").mkdir()
    elif kind == "invalid-utf8":
        source.write_bytes(b"\xff")
    else:
        source.write_bytes(b"x" * (authoring.SOURCE_TEXT_LIMIT + 1))
    with pytest.raises(CausalFrontierError):
        freeze_draft(draft_root, tmp_path / "new")
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "broken-symlink"])
def test_destination_no_clobber(draft_root, tmp_path, kind):
    destination = tmp_path / "existing"
    if kind == "directory":
        destination.mkdir()
    elif kind == "file":
        destination.write_text("keep")
    else:
        destination.symlink_to(draft_root if kind == "symlink" else tmp_path / "absent", target_is_directory=True)
    before = destination.lstat()
    with pytest.raises(CausalFrontierError, match="overwrite"):
        freeze_draft(draft_root, destination)
    assert destination.lstat() == before


def test_nested_output_and_symlink_roots_rejected(draft_root, tmp_path):
    for destination in (draft_root / "nested", draft_root / ".." / "new"):
        with pytest.raises(CausalFrontierError):
            freeze_draft(draft_root, destination)
    alias = tmp_path / "alias"
    alias.symlink_to(draft_root, target_is_directory=True)
    with pytest.raises(CausalFrontierError):
        freeze_draft(alias, tmp_path / "new")
    with pytest.raises(CausalFrontierError):
        freeze_draft(draft_root, alias / "new")


def test_case_insensitive_alias_cannot_put_output_inside_draft(draft_root):
    alias = draft_root.with_name(draft_root.name.upper())
    if not alias.exists() or not alias.samefile(draft_root):
        pytest.skip("requires a case-insensitive filesystem")
    before = _bytes(draft_root)
    with pytest.raises(CausalFrontierError, match="outside"):
        freeze_draft(draft_root, alias / "frozen")
    assert _bytes(draft_root) == before
    assert not (draft_root / "frozen").exists()


@pytest.mark.parametrize("kind", [{}, []])
def test_invalid_classifier_kind_cli_uses_json_error(draft_root, tmp_path, capsys, kind):
    draft = read_json(draft_root / "draft.json")
    draft["experiments"][0]["classifier"]["rule"]["kind"] = kind
    _write_draft(draft_root, draft)
    assert main(["--error-format", "json", "freeze-draft", str(draft_root), str(tmp_path / "new")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["reason_code"] == "VALIDATION_REJECTED"


def test_failure_after_creation_removes_only_created_destination(draft_root, tmp_path, monkeypatch):
    def fail(_root):
        raise CausalFrontierError("injected replay failure")

    monkeypatch.setattr(authoring, "load_case", fail)
    with pytest.raises(CausalFrontierError, match="injected"):
        freeze_draft(draft_root, tmp_path / "new")
    assert not (tmp_path / "new").exists()
    assert (draft_root / "draft.json").exists()


def test_changed_input_rejected_before_creation(draft_root, tmp_path, monkeypatch):
    snapshot = authoring.receipt_io._snapshot
    calls = 0

    def changing_snapshot(fd, relative):
        nonlocal calls
        calls += 1
        raw = snapshot(fd, relative)
        return raw + b"\n" if calls == 3 else raw

    monkeypatch.setattr(authoring.receipt_io, "_snapshot", changing_snapshot)
    with pytest.raises(CausalFrontierError, match="changed"):
        freeze_draft(draft_root, tmp_path / "new")
    assert not (tmp_path / "new").exists()


def test_cli_error_has_no_success_receipt(draft_root, tmp_path, capsys):
    assert main(["--error-format", "json", "freeze-draft", str(draft_root), str(tmp_path / "absent/new")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["reason_code"] == "INPUT_MISSING"
    assert not (tmp_path / "absent").exists()


def test_normal_optimized_authoring_byte_parity(draft_root, tmp_path, project_root):
    outputs = []
    roots = []
    for optimized, seed in ((False, "1"), (True, "77")):
        destination = tmp_path / ("optimized" if optimized else "normal")
        command = [sys.executable, *(["-O"] if optimized else []), "-m", "causalfrontier", "freeze-draft"]
        process = subprocess.run(
            [*command, str(draft_root), str(destination)],
            capture_output=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(project_root / "src")},
        )
        outputs.append(process.stdout)
        roots.append(_bytes(destination))
    assert outputs[0] == outputs[1]
    assert roots[0] == roots[1]


@pytest.mark.parametrize("depth", [33, 500, 700])
@pytest.mark.parametrize("error_format", ["text", "json"])
def test_nested_draft_rejected_before_preparation_without_echo(
    draft_root, tmp_path, monkeypatch, capsys, depth, error_format
):
    marker = "SYNTHETIC_REJECTED_PAYLOAD_DO_NOT_ECHO"
    draft = read_json(draft_root / "draft.json")
    nested = marker
    for _ in range(depth):
        nested = [nested]
    draft[marker] = nested
    _write_draft(draft_root, draft)
    before = _bytes(draft_root)

    def forbidden(*_args):
        pytest.fail("the structural guard must reject before draft preparation")

    monkeypatch.setattr(authoring, "_prepare_draft", forbidden)
    assert main(["--error-format", error_format, "freeze-draft", str(draft_root), str(tmp_path / "new")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert marker not in captured.err
    assert "Traceback" not in captured.err
    if error_format == "json":
        error = json.loads(captured.err)
        assert error["reason_code"] == "AUTHORING_INPUT_LIMIT_EXCEEDED"
        assert error["operation"] == "freeze_draft"
    assert not (tmp_path / "new").exists()
    assert _bytes(draft_root) == before


@pytest.mark.parametrize("bound", ["nodes", "container", "experiments", "outcomes", "predictions"])
def test_authoring_work_bounds_reject_before_source_preparation(draft_root, tmp_path, monkeypatch, bound):
    draft = read_json(draft_root / "draft.json")
    if bound == "nodes":
        draft["unregistered_field"] = [[None] * 1024 for _ in range(64)]
    elif bound == "container":
        draft["unregistered_field"] = [None] * 8193
    elif bound == "experiments":
        draft["experiments"] = [deepcopy(draft["experiments"][0]) for _ in range(33)]
    elif bound == "outcomes":
        draft["experiments"][0]["outcomes"] = [None] * 257
    else:
        draft["experiments"][0]["predictions"] = [None] * 4097
    _write_draft(draft_root, draft)
    before = _bytes(draft_root)
    observed = []
    snapshot = authoring.receipt_io._snapshot

    def reading(descriptor, relative):
        observed.append(relative)
        return snapshot(descriptor, relative)

    def forbidden(*_args):
        pytest.fail("excessive work must not reach preparation")

    monkeypatch.setattr(authoring.receipt_io, "_snapshot", reading)
    monkeypatch.setattr(authoring, "_prepare_draft", forbidden)
    with pytest.raises(CausalFrontierError) as caught:
        freeze_draft(draft_root, tmp_path / "new")
    assert caught.value.reason_code == "AUTHORING_INPUT_LIMIT_EXCEEDED"
    assert observed == ["draft.json"]
    assert not (tmp_path / "new").exists()
    assert _bytes(draft_root) == before


def test_exact_experiment_work_limit_is_accepted_without_truncation(draft_root, tmp_path):
    draft = read_json(draft_root / "draft.json")
    template = draft["experiments"][0]
    draft["experiments"] = [{**deepcopy(template), "id": "experiment:copy-%03d" % index} for index in range(32)]
    _write_draft(draft_root, draft)
    report = freeze_draft(draft_root, tmp_path / "new")
    assert report["status"] == authoring.STATUS
    assert len(load_case(tmp_path / "new")["experiments"]) == 32


def test_unsupported_guard_input_uses_authoring_specific_payload_free_error():
    marker = "SYNTHETIC_REJECTED_PAYLOAD_DO_NOT_ECHO"
    with pytest.raises(CausalFrontierError) as caught:
        authoring._guard_draft({"experiments": marker})
    assert caught.value.reason_code == "AUTHORING_INPUT_REJECTED"
    assert caught.value.operation == "freeze_draft"
    assert marker not in str(caught.value)


@pytest.mark.parametrize("phase", ["prepare", "final-replay"])
@pytest.mark.parametrize("error_format", ["text", "json"])
def test_unexpected_recursion_failure_is_structured_and_cleanup_safe(
    draft_root, tmp_path, monkeypatch, capsys, phase, error_format
):
    marker = "SYNTHETIC_RECURSION_DETAIL_DO_NOT_ECHO"

    def failing(*_args):
        raise RecursionError(marker)

    monkeypatch.setattr(authoring, "_prepare_draft" if phase == "prepare" else "load_case", failing)
    before = _bytes(draft_root)
    assert main(["--error-format", error_format, "freeze-draft", str(draft_root), str(tmp_path / "new")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert marker not in captured.err
    assert "Traceback" not in captured.err
    if error_format == "json":
        assert json.loads(captured.err)["reason_code"] == "AUTHORING_INPUT_LIMIT_EXCEEDED"
    assert not (tmp_path / "new").exists()
    assert _bytes(draft_root) == before


def test_normal_optimized_nested_draft_rejection_byte_parity(draft_root, tmp_path, project_root):
    marker = "SYNTHETIC_REJECTED_PAYLOAD_DO_NOT_ECHO"
    draft = read_json(draft_root / "draft.json")
    nested = marker
    for _ in range(500):
        nested = [nested]
    draft[marker] = nested
    _write_draft(draft_root, draft)
    errors = []
    for optimized, seed in ((False, "1"), (True, "77")):
        destination = tmp_path / ("optimized" if optimized else "normal")
        command = [sys.executable, *(["-O"] if optimized else []), "-B", "-m", "causalfrontier"]
        process = subprocess.run(
            [*command, "--error-format", "json", "freeze-draft", str(draft_root), str(destination)],
            capture_output=True,
            check=False,
            timeout=30,
            env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(project_root / "src")},
        )
        assert process.returncode == 2 and process.stdout == b""
        assert marker.encode() not in process.stderr and b"Traceback" not in process.stderr
        assert json.loads(process.stderr)["reason_code"] == "AUTHORING_INPUT_LIMIT_EXCEEDED"
        assert not destination.exists()
        errors.append(process.stderr)
    assert errors[0] == errors[1]
