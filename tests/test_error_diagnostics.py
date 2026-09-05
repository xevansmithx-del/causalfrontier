"""Observable software failures carry codes without disclosing private text."""

from __future__ import annotations

import errno
import json
import os
from contextlib import ExitStack
from pathlib import Path

import pytest

from causalfrontier import attestation, receipts
from causalfrontier.canonical import CausalFrontierError, io_error


def test_error_remains_a_value_error_with_unchanged_human_message() -> None:
    message = "untrusted source mentions /private/synthetic/report.json and a credential"
    error = CausalFrontierError(message)
    assert isinstance(error, ValueError)
    assert str(error) == message
    assert error.args == (message,)
    assert error.diagnostic() == {"reason_code": "VALIDATION_REJECTED", "operation": None, "errno": None}
    assert message not in json.dumps(error.diagnostic())


@pytest.mark.parametrize(
    ("number", "expected"),
    [
        (errno.EACCES, "ENVIRONMENT_DENIED"),
        (errno.EPERM, "ENVIRONMENT_DENIED"),
        (errno.ENOENT, "INPUT_MISSING"),
        (errno.ELOOP, "SAFE_PATH_REJECTED"),
        (errno.ENOTDIR, "SAFE_PATH_REJECTED"),
        (errno.EIO, "IO_FAILURE"),
        (errno.EMFILE, "IO_FAILURE"),
        (None, "IO_FAILURE"),
    ],
)
def test_os_diagnostics_use_numeric_evidence_and_exclude_paths(number: int | None, expected: str) -> None:
    raw = OSError(number, "EACCES ENOENT misleading arbitrary strerror", "/private/synthetic/credential.txt")
    error = io_error(raw, "unchanged human message", operation="receipt_read")
    assert error.diagnostic() == {"reason_code": expected, "operation": "receipt_read", "errno": number}
    assert str(error) == "unchanged human message"
    assert "/private/synthetic" not in json.dumps(error.diagnostic())
    assert "strerror" not in json.dumps(error.diagnostic())


@pytest.mark.parametrize("number", [errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR, errno.EIO])
def test_receipt_wrapper_preserves_os_reason(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, number: int) -> None:
    def denied(*_args, **_kwargs):
        raise OSError(number, "private denial detail", "/private/synthetic/receipt")

    monkeypatch.setattr(receipts, "_root_descriptor", denied)
    with pytest.raises(CausalFrontierError, match="receipt filesystem cannot be read safely") as captured:
        receipts.preflight_receipts(tmp_path, "0" * 64)
    expected = io_error(OSError(number, ""), "", operation="receipts.preflight_receipts").diagnostic()
    assert captured.value.diagnostic() == expected


def test_hardlinked_payload_has_a_distinct_safe_file_rejection(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    path = root / "payload.txt"
    path.write_bytes(b"synthetic\n")
    os.link(path, root / "alias.txt")
    with ExitStack() as stack:
        descriptor = receipts._root_descriptor(stack, root)
        with pytest.raises(CausalFrontierError) as captured:
            receipts._snapshot(descriptor, path.name)
    assert captured.value.reason_code == "SAFE_FILE_REJECTED"
    assert captured.value.errno is None


def test_symlink_root_is_a_safe_path_rejection(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    target = root / "target"
    target.mkdir()
    link = root / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(CausalFrontierError) as captured:
        receipts.preflight_receipts(link, "0" * 64)
    assert captured.value.reason_code == "SAFE_PATH_REJECTED"
    assert captured.value.errno in {errno.ENOTDIR, errno.ELOOP}


def test_payload_race_has_a_distinct_input_changed_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    payload = root / "payload.txt"
    payload.write_bytes(b"synthetic\n")
    original = receipts.os.read
    changed = False

    def change_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        raw = original(descriptor, size)
        if not changed:
            changed = True
            payload.write_bytes(b"different bytes\n")
        return raw

    monkeypatch.setattr(receipts.os, "read", change_after_read)
    with ExitStack() as stack:
        descriptor = receipts._root_descriptor(stack, root)
        with pytest.raises(CausalFrontierError) as captured:
            receipts._snapshot(descriptor, payload.name)
    assert captured.value.reason_code == "INPUT_CHANGED"


@pytest.mark.parametrize("number", [errno.EACCES, errno.ENOENT, errno.ENOEXEC])
def test_subprocess_launch_error_records_phase_without_private_os_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, number: int
) -> None:
    def denied(*_args, **_kwargs):
        raise OSError(number, "private loader path", "/private/synthetic/binary")

    monkeypatch.setattr(attestation.subprocess, "Popen", denied)
    with pytest.raises(CausalFrontierError) as captured:
        attestation._run_openssl(Path("unused"), ["version"], "test", tmp_path, tmp_path / "config")
    assert captured.value.operation == "openssl_launch"
    assert captured.value.errno == number
    assert "private" not in json.dumps(captured.value.diagnostic())


def test_subprocess_nonzero_exit_is_not_evidence_classification(tmp_path: Path) -> None:
    with pytest.raises(CausalFrontierError) as captured:
        attestation._run_openssl(
            Path("/bin/sh"), ["-c", "printf private-loader-detail >&2; exit 3"], "test", tmp_path, tmp_path / "config"
        )
    assert captured.value.diagnostic() == {
        "reason_code": "SUBPROCESS_NONZERO_EXIT",
        "operation": "openssl_execution",
        "errno": None,
    }
    assert "private-loader-detail" not in str(captured.value)


def test_subprocess_timeout_has_a_distinct_reason(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(attestation, "OPENSSL_TIMEOUT_SECONDS", 0.1)
    with pytest.raises(CausalFrontierError) as captured:
        attestation._run_openssl(Path("/bin/sh"), ["-c", "/bin/sleep 5"], "test", tmp_path, tmp_path / "config")
    assert captured.value.reason_code == "SUBPROCESS_TIMEOUT"
    assert captured.value.operation == "openssl_execution"


def test_subprocess_output_limit_has_a_distinct_reason(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(attestation, "MAX_SUBPROCESS_OUTPUT_BYTES", 8)
    with pytest.raises(CausalFrontierError) as captured:
        attestation._run_openssl(
            Path("/bin/sh"), ["-c", "printf 0123456789abcdef"], "test", tmp_path, tmp_path / "config"
        )
    assert captured.value.reason_code == "SUBPROCESS_OUTPUT_LIMIT"
