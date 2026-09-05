"""Bounded local prerequisite checks with a path-free, machine-readable report."""

from __future__ import annotations

import os
import platform
import re
import shutil
import sqlite3
import sys
from contextlib import ExitStack, closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import attestation, receipts
from .canonical import CausalFrontierError, io_error, require_sha256
from .version import DISTRIBUTION_VERSION

REPORT_SCHEMA = "causalfrontier.environment-report.v1"


def _check(name: str, status: str, reason_code: str, **details: Any) -> dict[str, Any]:
    return {"check": name, "status": status, "reason_code": reason_code, **details}


def _failure(name: str, error: CausalFrontierError) -> dict[str, Any]:
    return _check(name, "FAIL", **error.diagnostic())


def _probe_local_storage() -> dict[str, Any]:
    """Exercise the same descriptor readers as receipts on a new private file."""

    try:
        with TemporaryDirectory(prefix="causalfrontier-doctor-") as temporary:
            root = Path(temporary).resolve(strict=True)
            attestation._write_private(root / "probe.txt", b"synthetic prerequisite probe\n")
            with ExitStack() as stack:
                descriptor = receipts._root_descriptor(stack, root)
                raw = receipts._snapshot(descriptor, "probe.txt")
                if raw != b"synthetic prerequisite probe\n":
                    raise CausalFrontierError(
                        "local prerequisite file changed",
                        reason_code="INPUT_CHANGED",
                        operation="doctor_storage",
                    )
            with closing(sqlite3.connect(":memory:")) as connection:
                result = connection.execute("SELECT 1").fetchone()
                if result != (1,):
                    return _check("local_storage", "FAIL", "SQLITE_UNAVAILABLE")
        return _check("local_storage", "PASS", "LOCAL_STORAGE_PROBE_PASSED")
    except OSError as exc:
        return _failure("local_storage", io_error(exc, "local storage unavailable", operation="doctor_storage"))
    except CausalFrontierError as exc:
        return _failure("local_storage", exc)
    except sqlite3.Error:
        return _check("local_storage", "FAIL", "SQLITE_UNAVAILABLE")


def _probe_openssl(binary: Path, expected_sha256: str) -> dict[str, Any]:
    """Replay only a caller-checkpointed executable through production guards."""

    try:
        raw, digest = attestation._read_openssl_binary(binary, expected_sha256)
        with TemporaryDirectory(prefix="causalfrontier-doctor-openssl-") as temporary:
            root = Path(temporary).resolve(strict=True)
            snapshot = root / "openssl-verifier"
            config = root / "openssl.cnf"
            (root / "empty-cert-directory").mkdir(mode=0o700)
            attestation._write_private(snapshot, raw)
            snapshot.chmod(0o500)
            attestation._write_private(config, attestation.OPENSSL_CONFIG)
            version = attestation._run_openssl(snapshot, ["version"], "doctor version", root, config).strip()
            if attestation.OPENSSL_VERSION.fullmatch(version) is None:
                return _check("openssl", "FAIL", "OPENSSL_VERSION_UNSUPPORTED", binary_sha256=digest)
            # Do not echo arbitrary executable output, build paths, or provider text.
            match = re.match(r"OpenSSL (3\.[0-9]+\.[0-9]+)", version)
            if match is None:
                return _check("openssl", "FAIL", "OPENSSL_VERSION_UNSUPPORTED", binary_sha256=digest)
            numeric_version = match.group(1)
            replay_raw, _ = attestation._read_openssl_binary(snapshot, digest)
            if replay_raw != raw:
                raise CausalFrontierError(
                    "OpenSSL prerequisite snapshot changed",
                    reason_code="INPUT_CHANGED",
                    operation="doctor_openssl",
                )
        return _check(
            "openssl",
            "PASS",
            "OPENSSL_ISOLATED_REPLAY_PASSED",
            binary_sha256=digest,
            version=numeric_version,
            caller_checkpoint_matched=True,
            independent_trust_verified=False,
        )
    except OSError as exc:
        return _failure("openssl", io_error(exc, "OpenSSL prerequisite unavailable", operation="doctor_openssl"))
    except CausalFrontierError as exc:
        return _failure("openssl", exc)


def diagnose_environment(
    openssl_binary: Path | None = None,
    expected_openssl_sha256: str | None = None,
) -> dict[str, Any]:
    """Inspect prerequisites; execution requires an explicit path and byte checkpoint.

    Doctor-owned code makes no network or package-manager requests and reads no
    evidence. The default discovery checks PATH but reports only a boolean.
    Private probe files are cleaned up. The caller selects a trusted executable;
    a digest binds bytes and is not a sandbox or third-party trust assertion.
    """

    if (openssl_binary is None) != (expected_openssl_sha256 is None):
        raise CausalFrontierError(
            "doctor requires both --openssl-binary and --expected-openssl-sha256",
            reason_code="OPENSSL_CHECKPOINT_REQUIRED",
            operation="doctor_arguments",
        )
    if expected_openssl_sha256 is not None:
        require_sha256(expected_openssl_sha256, "doctor OpenSSL checkpoint")
    python_supported = sys.implementation.name == "cpython" and (3, 10) <= sys.version_info[:2] <= (3, 14)
    posix_supported = os.name == "posix" and all(
        hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "killpg")
    )
    checks = [
        _check(
            "python",
            "PASS" if python_supported else "FAIL",
            "SUPPORTED_CPYTHON" if python_supported else "UNSUPPORTED_RUNTIME",
        ),
        _check(
            "posix",
            "PASS" if posix_supported else "FAIL",
            "POSIX_CAPABILITIES_PRESENT" if posix_supported else "UNSUPPORTED_PLATFORM",
        ),
    ]
    if posix_supported:
        checks.append(_probe_local_storage())
    else:
        checks.append(_check("local_storage", "NOT_RUN", "PREREQUISITE_FAILED"))
    if any(check["status"] == "FAIL" for check in checks):
        checks.append(_check("openssl", "NOT_RUN", "PREREQUISITE_FAILED"))
    elif openssl_binary is not None and expected_openssl_sha256 is not None:
        checks.append(_probe_openssl(openssl_binary, expected_openssl_sha256))
    else:
        checks.append(
            _check(
                "openssl",
                "NOT_RUN",
                "OPENSSL_CHECKPOINT_REQUIRED",
                path_candidate_present=shutil.which("openssl") is not None,
            )
        )
    status = "READY_FOR_LOCAL_VERIFICATION"
    if any(check["status"] == "FAIL" for check in checks):
        status = "BLOCKED"
    elif any(check["status"] == "NOT_RUN" for check in checks):
        status = "INCOMPLETE"
    return {
        "schema_version": REPORT_SCHEMA,
        "status": status,
        "distribution_version": DISTRIBUTION_VERSION,
        "runtime": {
            "implementation": sys.implementation.name,
            "python": ".".join(str(part) for part in sys.version_info[:3]),
            "system": platform.system(),
            "machine": platform.machine(),
            "sqlite": sqlite3.sqlite_version,
        },
        "checks": checks,
        "network_requests_by_doctor": False,
        "package_installation_by_doctor": False,
        "executable_replay_requested": openssl_binary is not None,
        "subprocess_side_effects": "NOT_MONITORED",
        "scientific_validation": False,
        "release_validation": False,
        "independent_reproduction": False,
        "scope": "LOCAL_PREREQUISITES_ONLY",
    }
