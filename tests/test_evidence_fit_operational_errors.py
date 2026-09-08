"""Operational evidence-fit failures stay distinguishable from input rejection."""

from __future__ import annotations

import errno
import json
import os

import pytest
from test_evidence_fit import _run
from test_evidence_fit import bundle as bundle

from causalfrontier import cli, receipts
from causalfrontier import evidence_fit as fit
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes

IO_CASES = [
    (errno.EACCES, "ENVIRONMENT_DENIED"),
    (errno.ENOENT, "INPUT_MISSING"),
    (errno.EIO, "IO_FAILURE"),
]
SAFE_MESSAGE = "evidence-fit filesystem cannot be read safely"
PRIVATE_DETAIL = "/private/synthetic/credential-do-not-disclose"


@pytest.fixture
def prepared(bundle):
    report = canonical_bytes(_run(bundle)) + b"\n"
    root, _, extraction = bundle
    raw = canonical_bytes(extraction) + b"\n"
    extraction_path = root.parent / "extraction.json"
    report_path = root.parent / "report.json"
    extraction_path.write_bytes(raw)
    report_path.write_bytes(report)
    api_args = (root, extraction["receipt_set_sha256"], raw, sha256_bytes(raw))
    cli_args = [
        str(root),
        str(extraction_path),
        "--expected-set-sha256",
        extraction["receipt_set_sha256"],
        "--expected-extraction-sha256",
        sha256_bytes(raw),
    ]
    return api_args, cli_args, report, report_path


def _api_call(method, prepared):
    arguments, _, report, _ = prepared
    if method == "audit":
        return fit.audit_evidence_fit(*arguments)
    return fit.verify_evidence_fit(*arguments, report, sha256_bytes(report))


def _cli_arguments(method, prepared):
    _, arguments, report, report_path = prepared
    if method == "audit":
        return ["audit-evidence-fit", *arguments]
    return ["verify-evidence-fit", *arguments, str(report_path), "--expected-report-sha256", sha256_bytes(report)]


def _deny_open(monkeypatch, name, number, *, occurrence=None):
    original = os.open
    hits = []

    def denied(path, *args, **kwargs):
        if path == name:
            hits.append(path)
            if occurrence is None or len(hits) == occurrence:
                raise OSError(number, PRIVATE_DETAIL, PRIVATE_DETAIL)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    return hits


@pytest.mark.parametrize("method", ["audit", "verify"])
@pytest.mark.parametrize("number,reason", IO_CASES)
@pytest.mark.parametrize("manifest_open", [1, 2, 3], ids=["first-snapshot", "first-preflight", "final-preflight"])
def test_api_reports_os_failure_at_each_receipt_acquisition(
    prepared, monkeypatch, method, number, reason, manifest_open
):
    hits = _deny_open(monkeypatch, receipts.MANIFEST, number, occurrence=manifest_open)
    with pytest.raises(CausalFrontierError) as captured:
        _api_call(method, prepared)
    assert len(hits) == manifest_open
    # Verification calls the audited acquisition: retain its originating phase.
    operation = "evidence_fit.audit_evidence_fit" if manifest_open == 1 else "receipts.preflight_receipts"
    assert captured.value.diagnostic() == {"reason_code": reason, "operation": operation, "errno": number}
    assert str(captured.value) == SAFE_MESSAGE
    assert PRIVATE_DETAIL not in json.dumps(captured.value.diagnostic())


@pytest.mark.parametrize("number,reason", IO_CASES)
@pytest.mark.parametrize(
    "method,name", [("audit", "extraction.json"), ("verify", "extraction.json"), ("verify", "report.json")]
)
def test_cli_preserves_transport_io_metadata_without_private_text(
    prepared, monkeypatch, capsys, method, name, number, reason
):
    hits = _deny_open(monkeypatch, name, number)
    arguments = _cli_arguments(method, prepared)
    assert cli.main(arguments) == 2
    plain = capsys.readouterr()
    assert plain.out == ""
    assert plain.err == "causalfrontier: " + SAFE_MESSAGE + "\n"
    assert cli.main(["--error-format", "json", *arguments]) == 2
    structured = capsys.readouterr()
    assert structured.out == ""
    assert json.loads(structured.err) == {
        "schema_version": "causalfrontier.error.v1",
        "reason_code": reason,
        "operation": "cli._read_evidence_bytes",
        "errno": number,
    }
    assert len(hits) == 2
    assert PRIVATE_DETAIL not in structured.err
    assert str(prepared[3].parent) not in structured.err


@pytest.mark.parametrize("entrypoint", ["audit", "verify", "cli-audit", "cli-verify"])
@pytest.mark.parametrize("number", [errno.ELOOP, errno.ENOTDIR])
def test_raw_unsafe_path_errors_remain_generic_input_rejections(prepared, monkeypatch, capsys, entrypoint, number):
    is_cli = entrypoint.startswith("cli-")
    hits = _deny_open(monkeypatch, "extraction.json" if is_cli else receipts.MANIFEST, number)
    expected = {
        "reason_code": "EVIDENCE_FIT_REJECTED",
        "operation": "cli.evidence_fit" if is_cli else "evidence_fit",
        "errno": None,
    }
    if is_cli:
        arguments = _cli_arguments(entrypoint.removeprefix("cli-"), prepared)
        assert cli.main(arguments) == 2
        plain = capsys.readouterr()
        assert plain.out == ""
        assert plain.err == "causalfrontier: evidence-fit input rejected\n"
        assert cli.main(["--error-format", "json", *arguments]) == 2
        structured = capsys.readouterr()
        assert structured.out == ""
        assert json.loads(structured.err) == {"schema_version": "causalfrontier.error.v1", **expected}
        assert len(hits) == 2
    else:
        with pytest.raises(CausalFrontierError) as caught:
            _api_call(entrypoint, prepared)
        assert caught.value.diagnostic() == expected
        assert str(caught.value) == "evidence-fit input rejected"
        assert len(hits) == 1


@pytest.mark.parametrize("entrypoint", ["audit", "verify", "cli-audit", "cli-verify"])
def test_missing_no_follow_support_remains_an_environment_failure(prepared, monkeypatch, capsys, entrypoint):
    expected = {
        "reason_code": "ENVIRONMENT_UNSUPPORTED",
        "operation": "receipts._open_directory",
        "errno": None,
    }
    with monkeypatch.context() as patch:
        patch.delattr(os, "O_NOFOLLOW")
        if entrypoint.startswith("cli-"):
            arguments = _cli_arguments(entrypoint.removeprefix("cli-"), prepared)
            assert cli.main(["--error-format", "json", *arguments]) == 2
            captured = capsys.readouterr()
            assert captured.out == ""
            assert json.loads(captured.err) == {"schema_version": "causalfrontier.error.v1", **expected}
        else:
            with pytest.raises(CausalFrontierError) as caught:
                _api_call(entrypoint, prepared)
            assert caught.value.diagnostic() == expected
            assert str(caught.value) == SAFE_MESSAGE


@pytest.mark.parametrize("entrypoint", ["audit", "verify", "cli-audit", "cli-verify"])
@pytest.mark.parametrize("reason", ["SAFE_PATH_REJECTED", "UNREGISTERED_REASON"])
def test_other_receipt_rejections_do_not_inherit_operational_metadata(
    prepared, monkeypatch, capsys, entrypoint, reason
):
    def rejected(*_args, **_kwargs):
        raise CausalFrontierError(
            PRIVATE_DETAIL,
            reason_code=reason,
            operation=PRIVATE_DETAIL,
            errno=None if reason == "SAFE_PATH_REJECTED" else errno.EACCES,
        )

    monkeypatch.setattr(receipts, "_snapshot", rejected)
    if entrypoint.startswith("cli-"):
        arguments = _cli_arguments(entrypoint.removeprefix("cli-"), prepared)
        assert cli.main(["--error-format", "json", *arguments]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert json.loads(captured.err) == {
            "schema_version": "causalfrontier.error.v1",
            "reason_code": "EVIDENCE_FIT_REJECTED",
            "operation": "cli.evidence_fit",
            "errno": None,
        }
        assert PRIVATE_DETAIL not in captured.err
    else:
        with pytest.raises(CausalFrontierError) as caught:
            _api_call(entrypoint, prepared)
        assert caught.value.diagnostic() == {
            "reason_code": "EVIDENCE_FIT_REJECTED",
            "operation": "evidence_fit",
            "errno": None,
        }
        assert str(caught.value) == "evidence-fit input rejected"
