"""Opt-in JSON covers caught runtime exceptions, without changing success data."""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from causalfrontier import cli
from causalfrontier.canonical import CausalFrontierError


@pytest.mark.parametrize(
    "error,code,operation,number",
    [
        (
            OSError(errno.EACCES, "private denial", "/private/credential"),
            "ENVIRONMENT_DENIED",
            "command_io",
            errno.EACCES,
        ),
        (
            CausalFrontierError("private evidence", reason_code="INPUT_CHANGED", operation="receipt_read"),
            "INPUT_CHANGED",
            "receipt_read",
            None,
        ),
        (ValueError("private invalid value"), "VALIDATION_REJECTED", None, None),
    ],
)
def test_json_error_omits_exception_text(
    monkeypatch: pytest.MonkeyPatch, capsys, error, code, operation, number
) -> None:
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(cli, "load_case", fail)
    assert cli.main(["--error-format", "json", "analyze", "synthetic"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "schema_version": "causalfrontier.error.v1",
        "reason_code": code,
        "operation": operation,
        "errno": number,
    }
    assert "private" not in captured.err


def test_default_error_text_is_unchanged(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def fail(*_args, **_kwargs):
        raise CausalFrontierError("original diagnostic message")

    monkeypatch.setattr(cli, "load_case", fail)
    assert cli.main(["analyze", "synthetic"]) == 2
    assert capsys.readouterr().err == "causalfrontier: original diagnostic message\n"


def test_success_bytes_unchanged_by_error_format(case_root: Path, capsys) -> None:
    assert cli.main(["analyze", str(case_root)]) == 0
    plain = capsys.readouterr()
    assert cli.main(["--error-format", "json", "analyze", str(case_root)]) == 0
    structured = capsys.readouterr()
    assert plain == structured


@pytest.mark.parametrize("status,exit_code", [("READY_FOR_LOCAL_VERIFICATION", 0), ("BLOCKED", 2), ("INCOMPLETE", 3)])
def test_doctor_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys, status: str, exit_code: int) -> None:
    monkeypatch.setattr(cli, "diagnose_environment", lambda *_: {"status": status})
    assert cli.main(["doctor"]) == exit_code
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"status": status}
    assert captured.err == ""


def test_missing_checkpoint_argument_is_runtime_json(capsys) -> None:
    assert cli.main(["--error-format", "json", "doctor", "--openssl-binary", "synthetic"]) == 2
    assert json.loads(capsys.readouterr().err)["reason_code"] == "OPENSSL_CHECKPOINT_REQUIRED"


def test_argument_parser_errors_remain_text(capsys) -> None:
    with pytest.raises(SystemExit) as captured:
        cli.main(["--error-format", "json", "not-a-command"])
    assert captured.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
