"""Checkpointed transport for declared groups and exact replay reports."""

from __future__ import annotations

import json
import os

import pytest

import causalfrontier
from causalfrontier import cli, group_assumptions
from causalfrontier.canonical import MAX_JSON_BYTES, canonical_bytes, sha256_bytes
from causalfrontier.frontier import compile_case
from causalfrontier.model import load_case


def make_manifest(case):
    experiment = case["experiments"][0]
    informative = {row["id"] for row in experiment["outcomes"] if row["class"] == "INFORMATIVE"}
    members = [
        {"experiment_id": experiment["id"], "outcome_id": row["outcome_id"], "world_id": row["world_id"]}
        for row in experiment["predictions"]
        if row["outcome_id"] in informative and row["relation"] == "SURVIVES"
    ]
    return {
        "schema_version": "causalfrontier.assumption-groups.v1",
        "case_sha256": compile_case(case)["case_sha256"],
        "groups": [{"id": "group:synthetic", "rationale": "Declared synthetic cell bundle only.", "members": members}],
    }


def _write(path, value):
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _inputs(case_root, tmp_path):
    case = load_case(case_root)
    manifest = make_manifest(case)
    path = tmp_path / "groups.json"
    digest = _write(path, manifest)
    report = tmp_path / "group-audit.json"
    report_digest = _write(report, group_assumptions.audit_assumption_groups(case, manifest))
    return path, digest, report, report_digest


def _args(case_root, path, digest, report=None, report_digest=None):
    command = "audit-assumption-groups" if report is None else "verify-group-assumption-audit"
    result = [command, str(case_root), str(path), "--expected-manifest-sha256", digest]
    if report is not None:
        result.extend([str(report), "--expected-report-sha256", report_digest])
    return result


def test_public_api():
    for name in ("audit_assumption_groups", "verify_group_assumption_audit"):
        assert name in causalfrontier.__all__
        assert getattr(causalfrontier, name) is getattr(group_assumptions, name)


def test_roundtrip_is_read_only_structural(case_root, tmp_path, capsys, monkeypatch):
    path, digest, report, _ = _inputs(case_root, tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("group audit must not execute a classifier")

    monkeypatch.setattr(cli, "execute_classifiers", forbidden)
    before = {p.relative_to(case_root): p.read_bytes() for p in case_root.rglob("*") if p.is_file()}
    assert cli.main(_args(case_root, path, digest)) == 3
    emitted = capsys.readouterr()
    assert emitted.err == ""
    case = load_case(case_root)
    manifest = json.loads(path.read_bytes())
    assert json.loads(emitted.out) == group_assumptions.audit_assumption_groups(case, manifest)
    report.write_bytes(emitted.out.encode())
    assert cli.main(_args(case_root, path, digest, report, sha256_bytes(report.read_bytes()))) == 3
    verified = capsys.readouterr()
    assert verified.err == ""
    assert json.loads(verified.out) == group_assumptions.verify_group_assumption_audit(
        case, manifest, json.loads(report.read_bytes())
    )
    assert before == {p.relative_to(case_root): p.read_bytes() for p in case_root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("which", ["manifest", "report"])
def test_exact_serialized_checkpoint(case_root, tmp_path, capsys, which):
    path, digest, report, report_digest = _inputs(case_root, tmp_path)
    changed = path if which == "manifest" else report
    changed.write_bytes(changed.read_bytes() + b" ")
    assert cli.main(_args(case_root, path, digest, report, report_digest)) == 2
    assert "checkpoint mismatch" in capsys.readouterr().err


@pytest.mark.parametrize("which", ["manifest", "report"])
@pytest.mark.parametrize("kind", ["symlink", "parent_symlink", "hardlink", "directory", "fifo", "oversize"])
def test_unsafe_transport(case_root, tmp_path, capsys, which, kind):
    path, digest, report, report_digest = _inputs(case_root, tmp_path)
    original = path if which == "manifest" else report
    target = tmp_path / "unsafe.json"
    if kind == "symlink":
        target.symlink_to(original)
    elif kind == "parent_symlink":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        target = link / original.name
    elif kind == "hardlink":
        os.link(original, target)
    elif kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        with target.open("wb") as stream:
            stream.truncate(MAX_JSON_BYTES + 1)
    if which == "manifest":
        path = target
    else:
        report = target
    assert cli.main(["--error-format", "json", *_args(case_root, path, digest, report, report_digest)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(tmp_path) not in captured.err
    assert json.loads(captured.err)


@pytest.mark.parametrize("raw", [b"[]", b'{"groups":[],"groups":[]}', b'{"n":1.5}', b'{"n":NaN}', b"\xff"])
@pytest.mark.parametrize("which", ["manifest", "report"])
def test_hostile_json(case_root, tmp_path, capsys, raw, which):
    path, digest, report, report_digest = _inputs(case_root, tmp_path)
    target = path if which == "manifest" else report
    target.write_bytes(raw)
    if which == "manifest":
        digest = sha256_bytes(raw)
    else:
        report_digest = sha256_bytes(raw)
    assert cli.main(_args(case_root, path, digest, report, report_digest)) == 2
    assert capsys.readouterr().out == ""


def test_refuses_changed_source_bytes(copied_case, tmp_path, capsys):
    path, digest, report, report_digest = _inputs(copied_case, tmp_path)
    case = json.loads((copied_case / "case.json").read_bytes())
    source = copied_case / case["provenance"][0]["path"]
    source.write_bytes(source.read_bytes() + b"\n")
    assert cli.main(_args(copied_case, path, digest, report, report_digest)) == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("command", ["audit-assumption-groups", "verify-group-assumption-audit"])
def test_requires_checkpoint(case_root, command):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args([command, str(case_root), "groups.json"])
    assert exc.value.code == 2
