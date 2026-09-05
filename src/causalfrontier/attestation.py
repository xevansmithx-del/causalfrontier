"""Fail-closed RFC 3161 offline signed-target-imprint evidence verification.

This module deliberately delegates CMS, X.509, and Time-Stamp Protocol
verification to a caller-checkpointed OpenSSL 3 executable.  It replays both
the nonce-bearing request and the exact target bytes against the response.
The result verifies narrow offline signature evidence under a pinned TSA policy.
Without revocation evidence it does not make an unqualified timestamp or digest-
existence claim, and it is not evidence that a source was public, complete,
scientifically valid, or independently governed.
"""

from __future__ import annotations

import base64
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import ExitStack, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    require_exact_keys,
    require_id,
    require_sha256,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

ATTESTATION_SCHEMA_VERSION = "causalfrontier.rfc3161-attestation.v1"
TRUST_POLICY_SCHEMA_VERSION = "causalfrontier.rfc3161-trust-policy.v1"
REPORT_SCHEMA_VERSION = "causalfrontier.rfc3161-verification-report.v1"
ATTESTATION_MANIFEST = "attestation.json"
TRUST_POLICY_MANIFEST = "trust-policy.json"
SCHEME = "RFC3161_RFC5816_SHA256_TIME_STAMP_RESPONSE"
ASSERTION = "TARGET_DIGEST_EXISTENCE_EVIDENCE_NO_LATER_THAN"
VERIFICATION_PROFILE = "OPENSSL3_QUERY_TARGET_REPLAY_X509_STRICT_CMS_SHA256_SIGNED_ACCURACY"
REVOCATION_POLICY = "OFFLINE_REVOCATION_NOT_CHECKED"
INDEPENDENCE_STATE = "CALLER_DECLARED_NOT_INDEPENDENTLY_AUDITED"
TARGET_HASH_ALGORITHM = "sha256"
MAX_OPENSSL_BYTES = 128 * 1024 * 1024
MAX_SUBPROCESS_OUTPUT_BYTES = 64 * 1024
OPENSSL_TIMEOUT_SECONDS = 15
OPENSSL_CONFIG = (
    b"openssl_conf = openssl_init\n"
    b"[openssl_init]\n"
    b"providers = providers\n"
    b"[providers]\n"
    b"default = default_provider\n"
    b"[default_provider]\n"
    b"activate = 1\n"
)
OID = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,31}\Z")
OPENSSL_VERSION = re.compile(r"OpenSSL 3\.[0-9]+\.[0-9]+(?:[ -].*)?\Z")
OPENSSL_TIME = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>[0-9]{1,2})\s+"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?\s+(?P<year>[0-9]{4})\s+GMT\Z"
)
OPENSSL_ACCURACY = re.compile(
    r"(?P<seconds>unspecified|0x[0-9A-F]+) seconds, "
    r"(?P<millis>unspecified|0x[0-9A-F]+) millis, "
    r"(?P<micros>unspecified|0x[0-9A-F]+) micros\Z"
)
SHA256_OID = "2.16.840.1.101.3.4.2.1"
ESS_SIGNING_CERTIFICATE_V1_OID = "1.2.840.113549.1.9.16.2.12"
ESS_SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47"
OPENSSL_HEX_INTEGER = re.compile(r"0x[0-9A-F]+\Z")
PUBLIC_KEY_PEM = re.compile(
    r"-----BEGIN PUBLIC KEY-----\n(?P<body>(?:[A-Za-z0-9+/=]{1,64}\n)+)"
    r"-----END PUBLIC KEY-----\n?\Z"
)
CERTIFICATE_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\n(?P<body>(?:[A-Za-z0-9+/=]{1,64}\n)+)"
    r"-----END CERTIFICATE-----\n?\Z"
)
CANONICAL_KEY_DOMAIN_TAG = b"causalfrontier.canonical-public-key-material.v1\x00"
SUPPORTED_CERTIFICATE_KEY_ALGORITHMS = frozenset({"rsaEncryption", "rsassaPss", "id-ecPublicKey", "ED25519", "ED448"})

NONCLAIMS = (
    "Offline signature verification without revocation does not establish an unqualified cryptographic "
    "timestamp or target-digest existence claim.",
    "Recursive DER canonicality is not established; only exact top-level ASN.1 framing is checked before "
    "OpenSSL parsing.",
    "A timestamp on acquired bytes does not establish that a source was public, complete, or available at that time.",
    "The caller-pinned trust anchor and organization label do not prove witness independence or policy governance.",
    "The intended signer identity and certificate validity over the complete signed-accuracy interval are not "
    "verified.",
    "Offline verification does not establish certificate revocation status or current trust-root status.",
    "The OpenSSL executable is byte-checkpointed and replayed, not independently certified by this report.",
    "A binary checkpoint does not make OpenSSL, its dynamic libraries, or its provider runtime hermetic.",
    "No scientific, biological, clinical, patient, human-decision, material, or publication authority is granted.",
    "No outcome is opened, adjudicated, or scored, and no acceleration or health-impact claim is made.",
)


def _bounded_integer(value: Any, field: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def _oid(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 200 or OID.fullmatch(value) is None:
        raise CausalFrontierError("%s must be a dotted numeric object identifier" % field)
    return value


def _artifact(value: Any, field: str, media_type: str) -> tuple[str, str]:
    item = require_exact_keys(value, {"path", "sha256", "media_type"}, field)
    path = receipt_io._relative(item["path"])
    digest = require_sha256(item["sha256"], "%s digest" % field)
    if item["media_type"] != media_type:
        raise CausalFrontierError("%s media type differs" % field)
    return path, digest


def _load_closed_bundle(
    root: Path, manifest_name: str, expected_manifest_sha256: str
) -> tuple[dict[str, Any], dict[str, bytes]]:
    require_sha256(expected_manifest_sha256, "%s external checkpoint" % manifest_name)
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, manifest_name)
            if sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("%s external checkpoint mismatch" % manifest_name)
            receipt_io._screen(raw_manifest)
            manifest = read_json_bytes(raw_manifest, manifest_name)
            receipt_io._screen(canonical_bytes(manifest))
            if not isinstance(manifest, dict):
                raise CausalFrontierError("%s must be an object" % manifest_name)
            inventory = receipt_io._inventory(descriptor)
            snapshots = {manifest_name: raw_manifest}
            total_bytes = len(raw_manifest)
            for relative in sorted(inventory - {manifest_name}):
                snapshot = receipt_io._snapshot(descriptor, relative)
                total_bytes += len(snapshot)
                if total_bytes > receipt_io.MAX_TOTAL_BYTES:
                    raise CausalFrontierError("%s bundle exceeds the total byte limit" % manifest_name)
                snapshots[relative] = snapshot
            if receipt_io._inventory(descriptor) != inventory:
                raise CausalFrontierError(
                    "%s inventory changed during verification" % manifest_name,
                    reason_code="INPUT_CHANGED",
                    operation="attestation._load_closed_bundle",
                )
            if receipt_io._snapshot(descriptor, manifest_name) != raw_manifest:
                raise CausalFrontierError(
                    "%s changed during verification" % manifest_name,
                    reason_code="INPUT_CHANGED",
                    operation="attestation._load_closed_bundle",
                )
    except OSError as exc:
        raise io_error(
            exc, "%s bundle cannot be read safely" % manifest_name, operation="attestation._load_closed_bundle"
        ) from None
    if snapshots.get(manifest_name) != raw_manifest:
        raise CausalFrontierError(
            "%s changed during verification" % manifest_name,
            reason_code="INPUT_CHANGED",
            operation="attestation._load_closed_bundle",
        )
    return manifest, snapshots


def _validate_trust_policy(
    value: Any,
    snapshots: dict[str, bytes],
    expected_checkpoint_sha256: str,
) -> tuple[dict[str, Any], bytes, bytes | None]:
    policy = require_exact_keys(
        value,
        {
            "schema_version",
            "id",
            "fixed_parameter",
            "boundary",
            "scheme",
            "verification_profile",
            "target_hash_algorithm",
            "tsa_organization_id",
            "accepted_policy_oids",
            "maximum_accuracy_seconds",
            "trust_anchor",
            "untrusted_chain",
            "revocation_policy",
            "independence_state",
        },
        "RFC 3161 trust policy",
    )
    if (
        policy["schema_version"] != TRUST_POLICY_SCHEMA_VERSION
        or policy["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(policy["boundary"]) != BOUNDARY_CANONICAL
        or policy["scheme"] != SCHEME
        or policy["verification_profile"] != VERIFICATION_PROFILE
        or policy["target_hash_algorithm"] != TARGET_HASH_ALGORITHM
        or policy["revocation_policy"] != REVOCATION_POLICY
        or policy["independence_state"] != INDEPENDENCE_STATE
    ):
        raise CausalFrontierError("RFC 3161 trust policy changes a fixed contract")
    require_id(policy["id"], "RFC 3161 trust policy id")
    require_id(policy["tsa_organization_id"], "TSA organization id")
    oids = policy["accepted_policy_oids"]
    if not isinstance(oids, list) or not 1 <= len(oids) <= 8:
        raise CausalFrontierError("RFC 3161 trust policy needs accepted policy OIDs")
    normalized_oids = [_oid(item, "accepted TSA policy OID") for item in oids]
    if normalized_oids != sorted(set(normalized_oids)):
        raise CausalFrontierError("accepted TSA policy OIDs must be unique and canonical")
    maximum_accuracy = _bounded_integer(
        policy["maximum_accuracy_seconds"], "maximum accepted signed TSA accuracy", maximum=3600
    )
    if maximum_accuracy == 0:
        raise CausalFrontierError("maximum accepted signed TSA accuracy must be positive")
    anchor_path, anchor_sha256 = _artifact(policy["trust_anchor"], "trust anchor", "application/x-pem-file")
    if snapshots.get(anchor_path) is None or sha256_bytes(snapshots[anchor_path]) != anchor_sha256:
        raise CausalFrontierError("RFC 3161 trust anchor digest mismatch")
    receipt_io._screen(snapshots[anchor_path])
    _require_single_certificate_pem(snapshots[anchor_path], "RFC 3161 trust anchor")
    chain_bytes = None
    expected_files = {TRUST_POLICY_MANIFEST, anchor_path}
    if policy["untrusted_chain"] is not None:
        chain_path, chain_sha256 = _artifact(
            policy["untrusted_chain"], "untrusted certificate chain", "application/x-pem-file"
        )
        if (
            chain_path == anchor_path
            or snapshots.get(chain_path) is None
            or sha256_bytes(snapshots[chain_path]) != chain_sha256
        ):
            raise CausalFrontierError("RFC 3161 untrusted-chain digest mismatch")
        receipt_io._screen(snapshots[chain_path])
        chain_bytes = snapshots[chain_path]
        expected_files.add(chain_path)
    if set(snapshots) != expected_files:
        raise CausalFrontierError(
            "RFC 3161 trust-policy inventory differs",
            reason_code="INVENTORY_MISMATCH",
            operation="attestation._validate_trust_policy",
        )
    if sha256_bytes(snapshots[TRUST_POLICY_MANIFEST]) != expected_checkpoint_sha256:
        raise CausalFrontierError("RFC 3161 trust-policy checkpoint changed")
    return policy, snapshots[anchor_path], chain_bytes


def _validate_attestation(
    value: Any,
    snapshots: dict[str, bytes],
    expected_checkpoint_sha256: str,
    trust_policy: dict[str, Any],
    trust_policy_checkpoint_sha256: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    attestation = require_exact_keys(
        value,
        {
            "schema_version",
            "id",
            "fixed_parameter",
            "boundary",
            "scheme",
            "assertion",
            "trust_policy_id",
            "trust_policy_checkpoint_sha256",
            "target_sha256",
            "not_after",
            "request",
            "response",
        },
        "RFC 3161 attestation",
    )
    if (
        attestation["schema_version"] != ATTESTATION_SCHEMA_VERSION
        or attestation["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(attestation["boundary"]) != BOUNDARY_CANONICAL
        or attestation["scheme"] != SCHEME
        or attestation["assertion"] != ASSERTION
        or attestation["trust_policy_id"] != trust_policy["id"]
        or attestation["trust_policy_checkpoint_sha256"] != trust_policy_checkpoint_sha256
    ):
        raise CausalFrontierError("RFC 3161 attestation changes a fixed or trust-policy binding")
    require_id(attestation["id"], "RFC 3161 attestation id")
    require_sha256(attestation["target_sha256"], "RFC 3161 target digest")
    require_utc_timestamp(attestation["not_after"], "RFC 3161 not-after bound")
    request_path, request_sha256 = _artifact(attestation["request"], "RFC 3161 request", "application/timestamp-query")
    response_path, response_sha256 = _artifact(
        attestation["response"], "RFC 3161 response", "application/timestamp-reply"
    )
    if request_path == response_path:
        raise CausalFrontierError("RFC 3161 request and response paths must differ")
    if snapshots.get(request_path) is None or sha256_bytes(snapshots[request_path]) != request_sha256:
        raise CausalFrontierError("RFC 3161 request digest mismatch")
    if snapshots.get(response_path) is None or sha256_bytes(snapshots[response_path]) != response_sha256:
        raise CausalFrontierError("RFC 3161 response digest mismatch")
    if set(snapshots) != {ATTESTATION_MANIFEST, request_path, response_path}:
        raise CausalFrontierError(
            "RFC 3161 attestation inventory differs",
            reason_code="INVENTORY_MISMATCH",
            operation="attestation._validate_attestation",
        )
    if sha256_bytes(snapshots[ATTESTATION_MANIFEST]) != expected_checkpoint_sha256:
        raise CausalFrontierError("RFC 3161 attestation checkpoint changed")
    _require_single_sequence(snapshots[request_path], "RFC 3161 request")
    _require_single_sequence(snapshots[response_path], "RFC 3161 response")
    return attestation, snapshots[request_path], snapshots[response_path]


def _require_single_sequence(raw: bytes, field: str) -> None:
    """Require one definite-length top-level ASN.1 SEQUENCE with no trailing bytes.

    This deliberately does not claim recursive DER canonicality. OpenSSL accepts
    some BER encodings, so the report keeps strict DER conformance at NO_CALL.
    """

    if len(raw) < 2 or raw[0] != 0x30:
        raise CausalFrontierError("%s is not one top-level ASN.1 SEQUENCE" % field)
    first_length = raw[1]
    if first_length < 0x80:
        content_length = first_length
        header_length = 2
    else:
        length_octets = first_length & 0x7F
        if length_octets == 0 or length_octets > 4 or len(raw) < 2 + length_octets or raw[2] == 0:
            raise CausalFrontierError("%s has nonminimal or indefinite top-level ASN.1 length" % field)
        content_length = int.from_bytes(raw[2 : 2 + length_octets], "big")
        header_length = 2 + length_octets
        if content_length < 0x80:
            raise CausalFrontierError("%s uses nonminimal top-level ASN.1 length" % field)
    if header_length + content_length != len(raw):
        raise CausalFrontierError("%s has trailing, concatenated, or truncated ASN.1 bytes" % field)


def _public_key_spki_der(value: str) -> bytes:
    """Decode OpenSSL's canonical public-key PEM to the underlying SPKI DER."""

    match = PUBLIC_KEY_PEM.fullmatch(value)
    if match is None:
        raise CausalFrontierError("OpenSSL trust-anchor public key output is not canonical PEM")
    try:
        raw = base64.b64decode("".join(match.group("body").splitlines()), validate=True)
    except (ValueError, base64.binascii.Error):
        raise CausalFrontierError("OpenSSL trust-anchor public key output has invalid base64") from None
    _require_single_sequence(raw, "trust-anchor subject public key info")
    return raw


def _require_single_certificate_pem(raw: bytes, field: str) -> None:
    """Reject a CAfile that could hide additional trusted certificates."""

    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise CausalFrontierError("%s is not canonical certificate PEM" % field) from None
    match = CERTIFICATE_PEM.fullmatch(text)
    if match is None:
        raise CausalFrontierError("%s must contain exactly one canonical certificate" % field)
    try:
        der = base64.b64decode("".join(match.group("body").splitlines()), validate=True)
    except (ValueError, base64.binascii.Error):
        raise CausalFrontierError("%s certificate PEM has invalid base64" % field) from None
    _require_single_sequence(der, field)


def _read_target(path: Path, expected_sha256: str) -> bytes:
    require_sha256(expected_sha256, "RFC 3161 target external checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError as exc:
        raise io_error(exc, "RFC 3161 target cannot be read safely", operation="attestation._read_target") from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("RFC 3161 target external checkpoint mismatch")
    receipt_io._screen(raw)
    return raw


def _read_openssl_binary(path: Path, expected_sha256: str) -> tuple[bytes, str]:
    require_sha256(expected_sha256, "OpenSSL binary external checkpoint")
    try:
        resolved = path.resolve(strict=True)
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > MAX_OPENSSL_BYTES
                or before.st_mode & 0o111 == 0
            ):
                raise CausalFrontierError(
                    "OpenSSL verifier must be a bounded executable regular file",
                    reason_code="SAFE_FILE_REJECTED",
                    operation="attestation._read_openssl_binary",
                )
            chunks = []
            remaining = MAX_OPENSSL_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise io_error(
            exc, "OpenSSL verifier cannot be read safely", operation="attestation._read_openssl_binary"
        ) from None
    except RuntimeError:
        raise CausalFrontierError(
            "OpenSSL verifier cannot be read safely",
            reason_code="SAFE_PATH_REJECTED",
            operation="attestation._read_openssl_binary",
        ) from None
    if (
        len(raw) > MAX_OPENSSL_BYTES
        or len(raw) != before.st_size
        or (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
    ):
        raise CausalFrontierError(
            "OpenSSL verifier changed while being read",
            reason_code="INPUT_CHANGED",
            operation="attestation._read_openssl_binary",
        )
    digest = sha256_bytes(raw)
    if digest != expected_sha256:
        raise CausalFrontierError("OpenSSL binary external checkpoint mismatch")
    return raw, digest


def _run_openssl(binary: Path, arguments: list[str], label: str, working_root: Path, config: Path) -> str:
    if not hasattr(os, "killpg"):
        raise CausalFrontierError(
            "RFC 3161 verifier requires POSIX process-group isolation",
            reason_code="ENVIRONMENT_UNSUPPORTED",
            operation="openssl_process_isolation",
        )
    try:
        selector = selectors.DefaultSelector()
    except OSError as exc:
        raise io_error(
            exc, "OpenSSL %s output isolation is unavailable" % label, operation="openssl_output_isolation"
        ) from None
    try:
        process = subprocess.Popen(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_root,
            env={
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "OPENSSL_CONF": str(config),
                "SSL_CERT_FILE": str(working_root / "trust-anchor.pem"),
                "SSL_CERT_DIR": str(working_root / "empty-cert-directory"),
                "PATH": "",
            },
            start_new_session=True,
        )
    except OSError as exc:
        selector.close()
        raise io_error(exc, "OpenSSL %s could not complete" % label, operation="openssl_launch") from None

    if process.stdout is None or process.stderr is None:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
        selector.close()
        raise CausalFrontierError(
            "OpenSSL %s output pipes are unavailable" % label,
            reason_code="SUBPROCESS_OUTPUT_UNAVAILABLE",
            operation="openssl_output",
        )
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + OPENSSL_TIMEOUT_SECONDS
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(str(binary), OPENSSL_TIMEOUT_SECONDS)
            for key, _events in selector.select(min(remaining, 0.25)):
                stream = key.fileobj
                buffer = streams[stream]
                chunk = os.read(stream.fileno(), min(65536, MAX_SUBPROCESS_OUTPUT_BYTES - len(buffer) + 1))
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > MAX_SUBPROCESS_OUTPUT_BYTES:
                    raise CausalFrontierError(
                        "OpenSSL %s output exceeds the verification limit" % label,
                        reason_code="SUBPROCESS_OUTPUT_LIMIT",
                        operation="openssl_output",
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(str(binary), OPENSSL_TIMEOUT_SECONDS)
        returncode = process.wait(timeout=remaining)
    except OSError as exc:
        raise io_error(exc, "OpenSSL %s could not complete" % label, operation="openssl_execution") from None
    except subprocess.TimeoutExpired:
        raise CausalFrontierError(
            "OpenSSL %s could not complete" % label,
            reason_code="SUBPROCESS_TIMEOUT",
            operation="openssl_execution",
        ) from None
    finally:
        selector.close()
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
        for stream in streams:
            if not stream.closed:
                stream.close()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
    if returncode != 0:
        raise CausalFrontierError(
            "OpenSSL %s rejected the RFC 3161 evidence" % label,
            reason_code="SUBPROCESS_NONZERO_EXIT",
            operation="openssl_execution",
        )
    try:
        return bytes(streams[process.stdout]).decode("utf-8")
    except UnicodeError:
        raise CausalFrontierError(
            "OpenSSL %s output is not UTF-8" % label,
            reason_code="SUBPROCESS_OUTPUT_INVALID",
            operation="openssl_output",
        ) from None


def _field(text: str, label: str) -> str:
    prefix = label + ":"
    values = [line.strip()[len(prefix) :].strip() for line in text.splitlines() if line.strip().startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise CausalFrontierError("OpenSSL RFC 3161 text lacks one unambiguous %s" % label)
    return values[0]


def _certificate_public_key_algorithm(certificate_text: str, field: str) -> str:
    algorithm = _field(certificate_text, "Public Key Algorithm")
    if algorithm not in SUPPORTED_CERTIFICATE_KEY_ALGORITHMS:
        raise CausalFrontierError("%s uses an unsupported public-key algorithm" % field)
    return algorithm


def _canonical_public_key_material_sha256(
    binary: Path,
    public_key: Path,
    algorithm: str,
    output: Path,
    label: str,
    working_root: Path,
    config: Path,
) -> str:
    """Fingerprint mathematical key material after key-type-aware normalization."""

    if algorithm in {"rsaEncryption", "rsassaPss"}:
        family = "RSA"
        arguments = [
            "rsa",
            "-pubin",
            "-in",
            str(public_key),
            "-RSAPublicKey_out",
            "-outform",
            "DER",
            "-out",
            str(output),
        ]
    else:
        family = algorithm
        arguments = [
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-pubout",
            "-outform",
            "DER",
        ]
        if algorithm == "id-ecPublicKey":
            family = "EC"
            arguments.extend(["-ec_conv_form", "uncompressed", "-ec_param_enc", "named_curve"])
        arguments.extend(["-out", str(output)])
    _run_openssl(binary, arguments, "%s canonical key-material projection" % label, working_root, config)
    try:
        raw = output.read_bytes()
    except OSError as exc:
        raise io_error(
            exc,
            "%s canonical key-material projection is unreadable" % label,
            operation="attestation._canonical_public_key_material_sha256",
        ) from None
    if not raw or len(raw) > MAX_SUBPROCESS_OUTPUT_BYTES:
        raise CausalFrontierError("%s canonical key-material projection is outside bounds" % label)
    _require_single_sequence(raw, "%s canonical key material" % label)
    return sha256_bytes(CANONICAL_KEY_DOMAIN_TAG + family.encode("ascii") + b"\x00" + raw)


def _parse_token_time(value: str) -> tuple[datetime, int]:
    match = OPENSSL_TIME.fullmatch(value)
    if match is None:
        raise CausalFrontierError("OpenSSL RFC 3161 time uses an unsupported format")
    try:
        base = datetime.strptime(
            "%s %s %s:%s:%s %s"
            % (
                match.group("month"),
                match.group("day"),
                match.group("hour"),
                match.group("minute"),
                match.group("second"),
                match.group("year"),
            ),
            "%b %d %H:%M:%S %Y",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        raise CausalFrontierError("OpenSSL RFC 3161 time is not a real UTC instant") from None
    fraction = match.group("fraction")
    fractional_ceiling_seconds = 1 if fraction is not None and any(char != "0" for char in fraction) else 0
    return base, fractional_ceiling_seconds


def _parse_signed_accuracy(value: str, maximum_seconds: int) -> tuple[int, int]:
    match = OPENSSL_ACCURACY.fullmatch(value)
    if match is None:
        raise CausalFrontierError("RFC 3161 token must contain explicit signed accuracy")

    def component(name: str, maximum: int) -> int:
        encoded = match.group(name)
        if encoded == "unspecified":
            return 0
        parsed = int(encoded[2:], 16)
        if not 1 <= parsed <= maximum:
            raise CausalFrontierError("RFC 3161 signed accuracy component is outside policy limits")
        return parsed

    seconds = component("seconds", 3600)
    millis = component("millis", 999)
    micros = component("micros", 999)
    accuracy_microseconds = seconds * 1_000_000 + millis * 1_000 + micros
    if accuracy_microseconds == 0:
        raise CausalFrontierError("RFC 3161 token signed accuracy is unspecified")
    if accuracy_microseconds > maximum_seconds * 1_000_000:
        raise CausalFrontierError("RFC 3161 token signed accuracy exceeds the checkpointed policy")
    ceiling_seconds = (accuracy_microseconds + 999_999) // 1_000_000
    return accuracy_microseconds, ceiling_seconds


def _require_sha256_cms_signer(text: str) -> None:
    if text.count("    signerInfos:\n") != 1:
        raise CausalFrontierError("RFC 3161 token must contain one unambiguous signer-info set")
    signer_text = text.split("    signerInfos:\n", 1)[1]
    signer_versions = re.findall(r"^        version: [0-9]+$", signer_text, flags=re.MULTILINE)
    if len(signer_versions) != 1:
        raise CausalFrontierError("RFC 3161 token must contain exactly one signer info")
    if text.count("    encapContentInfo: \n") != 1:
        raise CausalFrontierError("RFC 3161 CMS content structure is ambiguous")
    digest_header = text.split("    encapContentInfo: \n", 1)[0]
    digest_set = re.findall(r"^        algorithm: ([^\s]+) \(([^)]+)\)$", digest_header, flags=re.MULTILINE)
    if digest_set != [("sha256", SHA256_OID)]:
        raise CausalFrontierError("RFC 3161 CMS digest set must contain only SHA-256")
    signer_digests = re.findall(
        r"^        digestAlgorithm: \n          algorithm: ([^\s]+) \(([^)]+)\)$",
        signer_text,
        flags=re.MULTILINE,
    )
    if signer_digests != [("sha256", SHA256_OID)] or "sha1" in text.lower():
        raise CausalFrontierError("RFC 3161 CMS signer digest must be SHA-256 with no SHA-1 algorithms")
    v1_line = "            object: id-smime-aa-signingCertificate (%s)" % ESS_SIGNING_CERTIFICATE_V1_OID
    v2_line = "            object: id-smime-aa-signingCertificateV2 (%s)" % ESS_SIGNING_CERTIFICATE_V2_OID
    if text.count(v1_line) != 0 or text.count(v2_line) != 1:
        raise CausalFrontierError("RFC 3161 CMS signer must use exactly one ESS SHA-256 certificate binding")
    if text.count("        signatureAlgorithm: \n") != 1:
        raise CausalFrontierError("RFC 3161 CMS signer signature structure is ambiguous")
    ess_block = text.split(v2_line, 1)[1].split("        signatureAlgorithm: \n", 1)[0]
    ess_hashes = re.findall(r"\[HEX DUMP\]:([0-9A-F]+)$", ess_block, flags=re.MULTILINE)
    if len(ess_hashes) != 1 or len(ess_hashes[0]) != 64 or "OBJECT:" in ess_block:
        raise CausalFrontierError("RFC 3161 ESSCertIDv2 must use the default SHA-256 certificate hash")


def _write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CausalFrontierError("temporary RFC 3161 snapshot could not be written")
            view = view[written:]
    finally:
        os.close(descriptor)


def _verification_arguments(
    mode: str,
    target: Path,
    request: Path,
    response: Path,
    anchor: Path,
    chain: Path | None,
    attime: int,
) -> list[str]:
    if mode == "query":
        arguments = ["ts", "-verify", "-queryfile", str(request)]
    elif mode == "target":
        arguments = ["ts", "-verify", "-data", str(target)]
    else:
        raise CausalFrontierError("unregistered RFC 3161 verification mode")
    arguments.extend(
        [
            "-in",
            str(response),
            "-CAfile",
            str(anchor),
            "-attime",
            str(attime),
            "-purpose",
            "timestampsign",
            "-auth_level",
            "2",
            "-x509_strict",
        ]
    )
    if chain is not None:
        arguments.extend(["-untrusted", str(chain)])
    return arguments


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def verify_rfc3161_attestation(
    target_path: Path,
    expected_target_sha256: str,
    attestation_root: Path,
    expected_attestation_checkpoint_sha256: str,
    trust_policy_root: Path,
    expected_trust_policy_checkpoint_sha256: str,
    openssl_path: Path,
    expected_openssl_sha256: str,
    expected_not_after: str,
) -> dict[str, Any]:
    """Verify one timestamp response without granting scientific admissibility."""

    expected_not_after = require_utc_timestamp(expected_not_after, "caller-checkpointed RFC 3161 not-after bound")
    target = _read_target(target_path, expected_target_sha256)
    trust_value, trust_snapshots = _load_closed_bundle(
        trust_policy_root, TRUST_POLICY_MANIFEST, expected_trust_policy_checkpoint_sha256
    )
    trust_policy, trust_anchor, untrusted_chain = _validate_trust_policy(
        trust_value, trust_snapshots, expected_trust_policy_checkpoint_sha256
    )
    attestation_value, attestation_snapshots = _load_closed_bundle(
        attestation_root, ATTESTATION_MANIFEST, expected_attestation_checkpoint_sha256
    )
    attestation, request, response = _validate_attestation(
        attestation_value,
        attestation_snapshots,
        expected_attestation_checkpoint_sha256,
        trust_policy,
        expected_trust_policy_checkpoint_sha256,
    )
    if attestation["target_sha256"] != expected_target_sha256 or sha256_bytes(target) != expected_target_sha256:
        raise CausalFrontierError("RFC 3161 attestation targets different bytes")
    if attestation["not_after"] != expected_not_after:
        raise CausalFrontierError("RFC 3161 not-after bound differs from the caller checkpoint")
    openssl_bytes, openssl_digest = _read_openssl_binary(openssl_path, expected_openssl_sha256)

    with tempfile.TemporaryDirectory(prefix="causalfrontier-rfc3161-") as temporary:
        root = Path(temporary)
        openssl_binary = root / "openssl-verifier"
        target_file = root / "target.bin"
        request_file = root / "request.tsq"
        response_file = root / "response.tsr"
        token_file = root / "token.der"
        signer_certificate_file = root / "timestamp-signer.pem"
        signed_content_file = root / "timestamp-content.der"
        anchor_file = root / "trust-anchor.pem"
        anchor_public_key_file = root / "trust-anchor-public-key.pem"
        anchor_canonical_key_file = root / "trust-anchor-canonical-key.der"
        signer_public_key_file = root / "timestamp-signer-public-key.pem"
        signer_canonical_key_file = root / "timestamp-signer-canonical-key.der"
        chain_file = root / "untrusted-chain.pem" if untrusted_chain is not None else None
        config_file = root / "openssl.cnf"
        (root / "empty-cert-directory").mkdir(mode=0o700)
        for path, raw in (
            (openssl_binary, openssl_bytes),
            (target_file, target),
            (request_file, request),
            (response_file, response),
            (anchor_file, trust_anchor),
        ):
            _write_private(path, raw)
        openssl_binary.chmod(0o500)
        if chain_file is not None and untrusted_chain is not None:
            _write_private(chain_file, untrusted_chain)
        _write_private(config_file, OPENSSL_CONFIG)

        version = _run_openssl(openssl_binary, ["version"], "version inspection", root, config_file).strip()
        if OPENSSL_VERSION.fullmatch(version) is None:
            raise CausalFrontierError("RFC 3161 verifier requires an exact OpenSSL 3 version identity")
        trust_anchor_certificate_text = _run_openssl(
            openssl_binary,
            ["x509", "-in", str(anchor_file), "-text", "-noout"],
            "trust-anchor certificate inspection",
            root,
            config_file,
        )
        trust_anchor_key_algorithm = _certificate_public_key_algorithm(
            trust_anchor_certificate_text, "RFC 3161 trust anchor"
        )
        trust_anchor_public_key = _run_openssl(
            openssl_binary,
            ["x509", "-in", str(anchor_file), "-pubkey", "-noout"],
            "trust-anchor public-key inspection",
            root,
            config_file,
        )
        trust_anchor_spki_digest = sha256_bytes(_public_key_spki_der(trust_anchor_public_key))
        _write_private(anchor_public_key_file, trust_anchor_public_key.encode("ascii"))
        trust_anchor_key_material_digest = _canonical_public_key_material_sha256(
            openssl_binary,
            anchor_public_key_file,
            trust_anchor_key_algorithm,
            anchor_canonical_key_file,
            "trust-anchor",
            root,
            config_file,
        )
        request_text = _run_openssl(
            openssl_binary,
            ["ts", "-query", "-in", str(request_file), "-text"],
            "request inspection",
            root,
            config_file,
        )
        response_text = _run_openssl(
            openssl_binary,
            ["ts", "-reply", "-in", str(response_file), "-text"],
            "response inspection",
            root,
            config_file,
        )
        _run_openssl(
            openssl_binary,
            [
                "ts",
                "-reply",
                "-in",
                str(response_file),
                "-token_out",
                "-out",
                str(token_file),
            ],
            "timestamp-token extraction",
            root,
            config_file,
        )
        cms_text = _run_openssl(
            openssl_binary,
            ["cms", "-cmsout", "-inform", "DER", "-in", str(token_file), "-print"],
            "CMS signer-algorithm inspection",
            root,
            config_file,
        )
        _require_sha256_cms_signer(cms_text)
        _run_openssl(
            openssl_binary,
            [
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                str(token_file),
                "-noverify",
                "-signer",
                str(signer_certificate_file),
                "-out",
                str(signed_content_file),
            ],
            "CMS signer-certificate extraction",
            root,
            config_file,
        )
        timestamp_signer_certificate_text = _run_openssl(
            openssl_binary,
            ["x509", "-in", str(signer_certificate_file), "-text", "-noout"],
            "timestamp-signer certificate inspection",
            root,
            config_file,
        )
        timestamp_signer_key_algorithm = _certificate_public_key_algorithm(
            timestamp_signer_certificate_text, "RFC 3161 timestamp signer"
        )
        timestamp_signer_public_key = _run_openssl(
            openssl_binary,
            ["x509", "-in", str(signer_certificate_file), "-pubkey", "-noout"],
            "timestamp-signer public-key inspection",
            root,
            config_file,
        )
        timestamp_signer_spki_digest = sha256_bytes(_public_key_spki_der(timestamp_signer_public_key))
        _write_private(signer_public_key_file, timestamp_signer_public_key.encode("ascii"))
        timestamp_signer_key_material_digest = _canonical_public_key_material_sha256(
            openssl_binary,
            signer_public_key_file,
            timestamp_signer_key_algorithm,
            signer_canonical_key_file,
            "timestamp-signer",
            root,
            config_file,
        )
        if _field(response_text, "Status") != "Granted.":
            raise CausalFrontierError("RFC 3161 response status is not an unmodified grant")
        if (
            _field(request_text, "Hash Algorithm") != TARGET_HASH_ALGORITHM
            or _field(response_text, "Hash Algorithm") != TARGET_HASH_ALGORITHM
        ):
            raise CausalFrontierError("RFC 3161 request and response must use SHA-256")
        request_policy = _oid(_field(request_text, "Policy OID"), "RFC 3161 request policy OID")
        response_policy = _oid(_field(response_text, "Policy OID"), "RFC 3161 response policy OID")
        if request_policy != response_policy or response_policy not in trust_policy["accepted_policy_oids"]:
            raise CausalFrontierError("RFC 3161 TSA policy is not accepted by the checkpointed trust policy")
        request_nonce = _field(request_text, "Nonce")
        response_nonce = _field(response_text, "Nonce")
        if (
            OPENSSL_HEX_INTEGER.fullmatch(request_nonce) is None
            or OPENSSL_HEX_INTEGER.fullmatch(response_nonce) is None
            or request_nonce != response_nonce
        ):
            raise CausalFrontierError("RFC 3161 nonce is absent or differs")
        if _field(request_text, "Certificate required") != "yes":
            raise CausalFrontierError("RFC 3161 request must require the TSA certificate")
        signed_accuracy_text = _field(response_text, "Accuracy")
        signed_accuracy_microseconds, signed_accuracy_ceiling_seconds = _parse_signed_accuracy(
            signed_accuracy_text, trust_policy["maximum_accuracy_seconds"]
        )
        generated_at, fractional_ceiling_seconds = _parse_token_time(_field(response_text, "Time stamp"))
        token_serial = _field(response_text, "Serial number")
        if OPENSSL_HEX_INTEGER.fullmatch(token_serial) is None:
            raise CausalFrontierError("RFC 3161 token serial uses an unsupported format")
        attime = int(generated_at.timestamp())
        _run_openssl(
            openssl_binary,
            _verification_arguments("query", target_file, request_file, response_file, anchor_file, chain_file, attime),
            "nonce-bearing request verification",
            root,
            config_file,
        )
        _run_openssl(
            openssl_binary,
            _verification_arguments(
                "target", target_file, request_file, response_file, anchor_file, chain_file, attime
            ),
            "target-byte verification",
            root,
            config_file,
        )

        if sha256_bytes(openssl_binary.read_bytes()) != expected_openssl_sha256:
            raise CausalFrontierError(
                "private OpenSSL executable snapshot changed during verification",
                reason_code="INPUT_CHANGED",
                operation="attestation.verify_rfc3161_attestation",
            )
        token_digest = sha256_bytes(token_file.read_bytes())

    maximum_accuracy_seconds = trust_policy["maximum_accuracy_seconds"]
    upper_bound = generated_at + timedelta(seconds=signed_accuracy_ceiling_seconds + fractional_ceiling_seconds)
    not_after = datetime.strptime(attestation["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    before_cutoff = upper_bound <= not_after
    upper_bound_text = upper_bound.strftime("%Y-%m-%dT%H:%M:%SZ")
    gates = sorted(
        [
            _gate("closed_inventory", "PASS", "ATTESTATION_AND_TRUST_POLICY_EXACT_BYTES_REPLAYED"),
            _gate(
                "asn1_top_level_framing",
                "PASS",
                "REQUEST_AND_RESPONSE_ARE_SINGLE_DEFINITE_LENGTH_SEQUENCES_WITHOUT_TRAILING_BYTES",
            ),
            _gate(
                "canonical_der",
                "NO_CALL",
                "OPENSSL_ACCEPTANCE_DOES_NOT_ESTABLISH_RECURSIVE_DER_CANONICALITY",
            ),
            _gate("target_binding", "PASS", "SIGNED_MESSAGE_IMPRINT_MATCHES_EXACT_CHECKPOINTED_TARGET_BYTES"),
            _gate("request_nonce", "PASS", "NONCE_BEARING_QUERY_AND_RESPONSE_REPLAYED_TOGETHER"),
            _gate(
                "signature_chain_at_signed_gentime",
                "PASS",
                "OPENSSL3_X509_STRICT_AT_SIGNED_GENTIME_UNDER_CHECKPOINTED_TRUST_ANCHOR",
            ),
            _gate(
                "certificate_validity_accuracy_interval",
                "NO_CALL",
                "CERTIFICATE_PATH_NOT_CHECKED_AT_BOTH_SIGNED_ACCURACY_INTERVAL_ENDPOINTS",
            ),
            _gate(
                "cms_signer_digest",
                "PASS",
                "ONE_SHA256_SIGNER_INFO_WITH_DEFAULT_SHA256_ESSCERTIDV2_AND_NO_SHA1_ALGORITHM_TEXT",
            ),
            _gate("signed_accuracy", "PASS", "TOKEN_SIGNED_ACCURACY_WITHIN_CHECKPOINTED_POLICY_MAXIMUM"),
            _gate("tsa_policy", "PASS", "SIGNED_POLICY_OID_ACCEPTED_BY_CHECKPOINTED_TRUST_POLICY"),
            _gate(
                "timestamp_before_not_after",
                "PASS" if before_cutoff else "NO_CALL",
                "POLICY_DERIVED_TIME_UPPER_BOUND_NO_LATER_THAN_CALLER_CHECKPOINTED_LIMIT"
                if before_cutoff
                else "POLICY_DERIVED_TIME_UPPER_BOUND_FOLLOWS_CALLER_CHECKPOINTED_LIMIT",
            ),
            _gate("source_public_availability", "NO_CALL", "TARGET_IMPRINT_EVIDENCE_IS_NOT_SOURCE_AVAILABILITY"),
            _gate("tsa_independence", "NO_CALL", "ORGANIZATION_ID_AND_POLICY_ARE_CALLER_DECLARED"),
            _gate("trust_anchor_currentness", "NO_CALL", "OFFLINE_CHECKPOINT_NOT_A_CURRENT_TRUST_ROOT_REFRESH"),
            _gate("certificate_revocation", "NO_CALL", "OFFLINE_REVOCATION_NOT_CHECKED"),
            _gate("privacy", "NO_CALL", "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"),
            _gate("scientific_scoring", "NO_CALL", "TIMESTAMP_VERIFICATION_DOES_NOT_AUTHORIZE_SCIENTIFIC_SCORING"),
        ],
        key=lambda item: item["id"],
    )
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": (
            "RFC3161_OFFLINE_SIGNATURE_EVIDENCE_VALID_WITHOUT_REVOCATION_"
            "TARGET_IMPRINT_BOUND_PASSES_LIMIT_SCIENTIFIC_SCORING_DISABLED"
        )
        if before_cutoff
        else ("RFC3161_OFFLINE_SIGNATURE_EVIDENCE_VALID_WITHOUT_REVOCATION_TARGET_IMPRINT_BOUND_FOLLOWS_LIMIT"),
        "implementation_status": "LOCAL_UNRELEASED_RFC3161_VERIFIER",
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "attestation_id": attestation["id"],
        "attestation_checkpoint_sha256": expected_attestation_checkpoint_sha256,
        "trust_policy_id": trust_policy["id"],
        "trust_policy_checkpoint_sha256": expected_trust_policy_checkpoint_sha256,
        "trust_anchor_sha256": sha256_bytes(trust_anchor),
        "trust_anchor_spki_sha256": trust_anchor_spki_digest,
        "trust_anchor_key_algorithm": trust_anchor_key_algorithm,
        "trust_anchor_key_material_sha256": trust_anchor_key_material_digest,
        "tsa_signer_spki_sha256": timestamp_signer_spki_digest,
        "tsa_signer_key_algorithm": timestamp_signer_key_algorithm,
        "tsa_signer_key_material_sha256": timestamp_signer_key_material_digest,
        "tsa_organization_id": trust_policy["tsa_organization_id"],
        "tsa_policy_oid": response_policy,
        "target_checkpoint_sha256": expected_target_sha256,
        "request_sha256": sha256_bytes(request),
        "response_sha256": sha256_bytes(response),
        "timestamp_token_sha256": token_digest,
        "signed_token_serial": token_serial,
        "openssl_binary_sha256": openssl_digest,
        "openssl_executed_from_private_byte_snapshot": True,
        "openssl_version": version,
        "openssl_config_sha256": sha256_bytes(OPENSSL_CONFIG),
        "openssl_authentication_level": 2,
        "openssl_runtime_hermeticity_verified": False,
        "validation_time_basis": "SIGNED_TOKEN_GENTIME_CERTIFICATE_PATH_CHECK_WITHOUT_REVOCATION",
        "signed_time_text": _field(response_text, "Time stamp"),
        "signed_accuracy_text": signed_accuracy_text,
        "signed_accuracy_microseconds": signed_accuracy_microseconds,
        "policy_checked_time_upper_bound": upper_bound_text,
        "caller_checkpointed_not_after": expected_not_after,
        "maximum_accepted_signed_accuracy_seconds_from_trust_policy": maximum_accuracy_seconds,
        "canonical_der_verified": False,
        "cryptographic_timestamp_verified": False,
        "cryptographic_timestamp_signature_verified_without_revocation": True,
        "request_response_binding_verified": True,
        "target_response_binding_verified": True,
        "expected_policy_oid_verified": True,
        "cms_single_sha256_signer_verified": True,
        "nonce_binding_verified": True,
        "imprint_algorithm_allowed": True,
        "signed_accuracy_within_policy_verified": True,
        "tsa_signature_and_chain_verified": False,
        "tsa_signature_and_chain_at_signed_gentime_verified_without_revocation": True,
        "target_digest_existence_before_not_after_verified": False,
        "target_digest_existence_before_not_after_under_offline_nonrevocation_policy_verified": False,
        "signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity": (
            before_cutoff
        ),
        "source_public_availability_before_not_after_verified": False,
        "source_authorship_verified": False,
        "source_semantic_currentness_verified": False,
        "witness_signer_identity_verified": False,
        "witness_independence_verified": False,
        "certificate_revocation_checked": False,
        "certificate_validity_over_signed_accuracy_interval_verified": False,
        "long_term_validity_verified": False,
        "rollback_currentness_verified": False,
        "prospective_cohort_admissibility_verified": False,
        "historical_scoring_ready": False,
        "scientific_scoring_ready": False,
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "report_sha256": sha256_bytes(canonical_bytes(core))}
