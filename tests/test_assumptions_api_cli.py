"""Exact transport and public entry points for single-cell withdrawal audits."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import causalfrontier
from causalfrontier import assumptions, cli
from causalfrontier.canonical import MAX_JSON_BYTES, canonical_bytes, sha256_bytes
from causalfrontier.model import load_case


def _report(tmp_path: Path, case_root: Path):
    path = tmp_path / "audit.json"
    raw = canonical_bytes(assumptions.audit_assumptions(load_case(case_root))) + b"\n"
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


def _verify_args(case_root, path, digest):
    return ["verify-assumption-audit", str(case_root), str(path), "--expected-report-sha256", digest]


def test_public_api():
    for name in ("audit_assumptions", "verify_assumption_audit"):
        assert name in causalfrontier.__all__
        assert getattr(causalfrontier, name) is getattr(assumptions, name)


def test_cli_roundtrip_is_read_only_and_structural(case_root, tmp_path, capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("audit must not execute a classifier")

    monkeypatch.setattr(cli, "execute_classifiers", forbidden)
    before = {p.relative_to(case_root): p.read_bytes() for p in case_root.rglob("*") if p.is_file()}
    assert cli.main(["audit-assumptions", str(case_root)]) == 3
    emitted = capsys.readouterr()
    assert emitted.err == ""
    assert json.loads(emitted.out) == assumptions.audit_assumptions(load_case(case_root))
    path = tmp_path / "audit.json"
    raw = emitted.out.encode()
    path.write_bytes(raw)
    assert cli.main(_verify_args(case_root, path, sha256_bytes(raw))) == 3
    verified = capsys.readouterr()
    assert verified.err == ""
    assert json.loads(verified.out) == assumptions.verify_assumption_audit(load_case(case_root), json.loads(raw))
    assert before == {p.relative_to(case_root): p.read_bytes() for p in case_root.rglob("*") if p.is_file()}


def test_cli_checkpoint_is_exact_serialized_bytes(case_root, tmp_path, capsys):
    path, digest = _report(tmp_path, case_root)
    path.write_bytes(path.read_bytes() + b" ")
    assert cli.main(_verify_args(case_root, path, digest)) == 2
    assert "checkpoint mismatch" in capsys.readouterr().err


def test_cli_rejects_rehashed_forgery(case_root, tmp_path, capsys):
    path, _ = _report(tmp_path, case_root)
    value = json.loads(path.read_bytes())
    value["rows"] = value["rows"][:-1]
    value.pop("audit_sha256")
    value["audit_sha256"] = sha256_bytes(assumptions.AUDIT_DOMAIN + canonical_bytes(value))
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    assert cli.main(_verify_args(case_root, path, sha256_bytes(raw))) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


@pytest.mark.parametrize("kind", ["symlink", "parent_symlink", "hardlink", "directory", "fifo", "oversize"])
def test_cli_refuses_unsafe_report_transport(case_root, tmp_path, capsys, kind):
    path, digest = _report(tmp_path, case_root)
    target = tmp_path / "unsafe.json"
    if kind == "symlink":
        target.symlink_to(path)
    elif kind == "parent_symlink":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        target = link / path.name
    elif kind == "hardlink":
        os.link(path, target)
    elif kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        with target.open("wb") as stream:
            stream.truncate(MAX_JSON_BYTES + 1)
    assert cli.main(["--error-format", "json", *_verify_args(case_root, target, digest)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(tmp_path) not in captured.err
    assert json.loads(captured.err)


@pytest.mark.parametrize("raw", [b"[]", b'{"rows":[],"rows":[]}', b'{"n":1.5}', b'{"n":NaN}', b"\xff"])
def test_cli_refuses_hostile_json(case_root, tmp_path, capsys, raw):
    path = tmp_path / "hostile.json"
    path.write_bytes(raw)
    assert cli.main(_verify_args(case_root, path, sha256_bytes(raw))) == 2
    assert capsys.readouterr().out == ""


def test_cli_requires_checkpoint(case_root):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args(["verify-assumption-audit", str(case_root), "audit.json"])
    assert exc.value.code == 2


def test_cli_refuses_changed_source_bytes(copied_case, tmp_path, capsys):
    path, digest = _report(tmp_path, copied_case)
    case = json.loads((copied_case / "case.json").read_bytes())
    source = copied_case / case["provenance"][0]["path"]
    source.write_bytes(source.read_bytes() + b"\n")
    assert cli.main(_verify_args(copied_case, path, digest)) == 2
    assert capsys.readouterr().out == ""
