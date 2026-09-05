"""Prerequisite reporting does not execute an uncheckpointed PATH candidate."""

from __future__ import annotations

import errno
import hashlib
import json
from pathlib import Path

import pytest

from causalfrontier import doctor
from causalfrontier.canonical import CausalFrontierError


def _binary(tmp_path: Path, body: bytes = b"#!/bin/sh\nprintf 'OpenSSL 3.6.3 synthetic\\n'\n") -> tuple[Path, str]:
    path = tmp_path.resolve() / "synthetic-openssl"
    path.write_bytes(body)
    path.chmod(0o700)
    return path, hashlib.sha256(body).hexdigest()


def test_default_never_executes_path_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("default doctor must not execute a candidate")

    monkeypatch.setattr(doctor.attestation, "_run_openssl", forbidden)
    monkeypatch.setattr(doctor.shutil, "which", lambda _: "/private/arbitrary/openssl")
    report = doctor.diagnose_environment()
    assert report["status"] == "INCOMPLETE"
    assert report["checks"][-1] == {
        "check": "openssl",
        "status": "NOT_RUN",
        "reason_code": "OPENSSL_CHECKPOINT_REQUIRED",
        "path_candidate_present": True,
    }
    assert "/private" not in json.dumps(report)
    for field in (
        "network_requests_by_doctor",
        "package_installation_by_doctor",
        "scientific_validation",
        "release_validation",
        "independent_reproduction",
    ):
        assert report[field] is False


@pytest.mark.parametrize("path,digest", [(Path("synthetic"), None), (None, "a" * 64)])
def test_paired_checkpoint_arguments_are_required(path, digest) -> None:
    with pytest.raises(CausalFrontierError) as captured:
        doctor.diagnose_environment(path, digest)
    assert captured.value.reason_code == "OPENSSL_CHECKPOINT_REQUIRED"


def test_bad_digest_rejected_before_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "_probe_local_storage", lambda: pytest.fail("invalid arguments must fail first"))
    with pytest.raises(CausalFrontierError):
        doctor.diagnose_environment(Path("synthetic"), "not-a-digest")


def test_checkpointed_replay_reports_numeric_version_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, digest = _binary(tmp_path, b"#!/bin/sh\nprintf 'OpenSSL 3.6.3 /private/build/path\\n'\n")
    roots = []
    original = doctor.attestation._run_openssl

    def capture(binary, arguments, label, root, config):
        roots.append(root)
        assert config.read_bytes() == doctor.attestation.OPENSSL_CONFIG
        assert binary != tmp_path / "synthetic-openssl"
        return original(binary, arguments, label, root, config)

    monkeypatch.setattr(doctor.attestation, "_run_openssl", capture)
    report = doctor.diagnose_environment(binary, digest)
    assert report["status"] == "READY_FOR_LOCAL_VERIFICATION"
    assert report["checks"][-1]["version"] == "3.6.3"
    assert report["checks"][-1]["binary_sha256"] == digest
    assert report["checks"][-1]["independent_trust_verified"] is False
    assert report["executable_replay_requested"] is True
    assert report["subprocess_side_effects"] == "NOT_MONITORED"
    assert "/private" not in json.dumps(report)
    assert roots and all(not root.exists() for root in roots)


@pytest.mark.parametrize(
    "body,code",
    [
        (b"#!/bin/sh\nprintf 'LibreSSL 3.3.6\\n'\n", "OPENSSL_VERSION_UNSUPPORTED"),
        (b"#!/bin/sh\nprintf 'private failure' >&2\nexit 4\n", "SUBPROCESS_NONZERO_EXIT"),
    ],
)
def test_failed_replay_is_classified_without_echoing_output(tmp_path: Path, body: bytes, code: str) -> None:
    binary, digest = _binary(tmp_path, body)
    report = doctor.diagnose_environment(binary, digest)
    assert report["status"] == "BLOCKED"
    assert report["checks"][-1]["reason_code"] == code
    assert "private failure" not in json.dumps(report)


@pytest.mark.parametrize(
    "mutation,code",
    [("hardlink", "SAFE_FILE_REJECTED"), ("mode", "SAFE_FILE_REJECTED"), ("digest", "VALIDATION_REJECTED")],
)
def test_guard_rejections_do_not_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, code: str
) -> None:
    binary, digest = _binary(tmp_path)
    if mutation == "hardlink":
        (binary.parent / "alias").hardlink_to(binary)
    elif mutation == "mode":
        binary.chmod(0o600)
    else:
        digest = "0" * 64
    monkeypatch.setattr(doctor.attestation, "_run_openssl", lambda *_: pytest.fail("rejected binary must not run"))
    report = doctor.diagnose_environment(binary, digest)
    assert report["status"] == "BLOCKED"
    assert report["checks"][-1]["reason_code"] == code


@pytest.mark.parametrize("number,code", [(errno.EACCES, "ENVIRONMENT_DENIED"), (errno.ENOENT, "INPUT_MISSING")])
def test_storage_os_failure_preserves_numeric_reason(monkeypatch: pytest.MonkeyPatch, number: int, code: str) -> None:
    def fail(*_args, **_kwargs):
        raise OSError(number, "private mount information", "/private/data")

    monkeypatch.setattr(doctor, "TemporaryDirectory", fail)
    report = doctor.diagnose_environment()
    assert report["status"] == "BLOCKED"
    assert report["checks"][2]["reason_code"] == code
    assert report["checks"][2]["errno"] == number
    assert report["checks"][-1]["reason_code"] == "PREREQUISITE_FAILED"
    assert "/private" not in json.dumps(report)


def test_unsupported_platform_does_not_probe_files_or_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(doctor.os, "O_NOFOLLOW")
    monkeypatch.setattr(doctor, "_probe_local_storage", lambda: pytest.fail("unsupported platform"))
    report = doctor.diagnose_environment(Path("unused"), "a" * 64)
    assert report["status"] == "BLOCKED"
    assert report["checks"][1]["reason_code"] == "UNSUPPORTED_PLATFORM"
    assert report["checks"][2]["status"] == "NOT_RUN"
    assert report["checks"][3]["status"] == "NOT_RUN"


def test_sqlite_probe_closes_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = doctor.sqlite3.connect(":memory:")
    monkeypatch.setattr(doctor.sqlite3, "connect", lambda _: connection)
    assert doctor._probe_local_storage()["status"] == "PASS"
    with pytest.raises(doctor.sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
