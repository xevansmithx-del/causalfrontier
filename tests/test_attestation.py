"""Hostile tests for RFC 3161 signed-target-imprint evidence verification."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from causalfrontier import attestation
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary

POLICY_OID = "1.2.3.4.1"


def _run(arguments: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("test OpenSSL setup failed: %s" % result.stderr.decode("utf-8", errors="replace"))


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _binary_sha256(path: Path) -> str:
    return sha256_bytes(path.resolve(strict=True).read_bytes())


def _build_timestamp(
    openssl: Path,
    work: Path,
    target: Path,
    query: Path,
    response: Path,
    *,
    no_nonce: bool = False,
    no_policy: bool = False,
    digest: str = "sha256",
    config_name: str = "tsa.cnf",
) -> None:
    query_arguments = [
        str(openssl),
        "ts",
        "-query",
        "-data",
        str(target),
        "-%s" % digest,
        "-cert",
        "-out",
        str(query),
    ]
    if not no_policy:
        query_arguments[query_arguments.index("-cert") : query_arguments.index("-cert")] = ["-tspolicy", POLICY_OID]
    if no_nonce:
        query_arguments.insert(-2, "-no_nonce")
    _run(query_arguments)
    _run(
        [
            str(openssl),
            "ts",
            "-reply",
            "-queryfile",
            str(query),
            "-config",
            str(work / config_name),
            "-out",
            str(response),
        ]
    )


@pytest.fixture(scope="module")
def rfc3161_fixture(tmp_path_factory: pytest.TempPathFactory):
    found = shutil.which("openssl")
    if found is None:
        pytest.skip("OpenSSL is unavailable")
    openssl = Path(found).resolve(strict=True)
    version = subprocess.run(
        [str(openssl), "version"], capture_output=True, text=True, timeout=10, check=False
    ).stdout.strip()
    if attestation.OPENSSL_VERSION.fullmatch(version) is None:
        pytest.skip("OpenSSL 3 is required")
    root = tmp_path_factory.mktemp("rfc3161")
    work = root / "work"
    trust = root / "trust"
    bundle = root / "attestation"
    work.mkdir()
    trust.mkdir()
    bundle.mkdir()
    target = root / "target.json"
    target.write_bytes(b'{"scope":"synthetic-rfc3161-test"}\n')
    env = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
    _run(
        [
            str(openssl),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(work / "ca.key"),
            "-out",
            str(work / "ca.pem"),
            "-subj",
            "/CN=CausalFrontier Synthetic Test Root",
            "-days",
            "2",
            "-sha256",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        env=env,
    )
    _run(
        [
            str(openssl),
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(work / "tsa.key"),
            "-out",
            str(work / "tsa.csr"),
            "-subj",
            "/CN=CausalFrontier Synthetic Test TSA",
            "-sha256",
        ],
        env=env,
    )
    (work / "tsa-ext.cnf").write_text(
        "\n".join(
            [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature",
                "extendedKeyUsage=critical,timeStamping",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _run(
        [
            str(openssl),
            "x509",
            "-req",
            "-in",
            str(work / "tsa.csr"),
            "-CA",
            str(work / "ca.pem"),
            "-CAkey",
            str(work / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(work / "tsa.pem"),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(work / "tsa-ext.cnf"),
        ],
        env=env,
    )
    (work / "tsa.serial").write_text("01\n", encoding="ascii")
    tsa_config_lines = [
        "[tsa]",
        "default_tsa=tsa_config",
        "[tsa_config]",
        "serial=%s" % (work / "tsa.serial"),
        "signer_cert=%s" % (work / "tsa.pem"),
        "signer_key=%s" % (work / "tsa.key"),
        "signer_digest=sha256",
        "default_policy=%s" % POLICY_OID,
        "other_policies=%s" % POLICY_OID,
        "digests=sha256,sha1",
        "accuracy=secs:1",
        "ordering=no",
        "tsa_name=yes",
        "ess_cert_id_chain=no",
        "ess_cert_id_alg=sha256",
        "",
    ]
    (work / "tsa.cnf").write_text("\n".join(tsa_config_lines), encoding="utf-8")
    (work / "tsa-sha1.cnf").write_text(
        "\n".join(["signer_digest=sha1" if line == "signer_digest=sha256" else line for line in tsa_config_lines]),
        encoding="utf-8",
    )
    (work / "tsa-no-accuracy.cnf").write_text(
        "\n".join([line for line in tsa_config_lines if line != "accuracy=secs:1"]),
        encoding="utf-8",
    )
    (work / "tsa-ess-sha1.cnf").write_text(
        "\n".join(["ess_cert_id_alg=sha1" if line == "ess_cert_id_alg=sha256" else line for line in tsa_config_lines]),
        encoding="utf-8",
    )
    request = bundle / "request.tsq"
    response = bundle / "response.tsr"
    _build_timestamp(openssl, work, target, request, response)
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-no-nonce.tsq",
        work / "response-no-nonce.tsr",
        no_nonce=True,
    )
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-no-policy.tsq",
        work / "response-no-policy.tsr",
        no_policy=True,
    )
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-sha1.tsq",
        work / "response-sha1.tsr",
        digest="sha1",
    )
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-signer-sha1.tsq",
        work / "response-signer-sha1.tsr",
        config_name="tsa-sha1.cnf",
    )
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-no-accuracy.tsq",
        work / "response-no-accuracy.tsr",
        config_name="tsa-no-accuracy.cnf",
    )
    _build_timestamp(
        openssl,
        work,
        target,
        work / "request-ess-sha1.tsq",
        work / "response-ess-sha1.tsr",
        config_name="tsa-ess-sha1.cnf",
    )
    _run(
        [
            str(openssl),
            "ts",
            "-reply",
            "-in",
            str(response),
            "-token_out",
            "-out",
            str(work / "token-only.der"),
        ]
    )
    _run(
        [
            str(openssl),
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(work / "wrong-ca.key"),
            "-out",
            str(work / "wrong-ca.pem"),
            "-subj",
            "/CN=CausalFrontier Wrong Synthetic Root",
            "-days",
            "2",
            "-sha256",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        env=env,
    )
    shutil.copy2(work / "ca.pem", trust / "root.pem")
    trust_policy = {
        "schema_version": attestation.TRUST_POLICY_SCHEMA_VERSION,
        "id": "trust-policy:synthetic-rfc3161",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scheme": attestation.SCHEME,
        "verification_profile": attestation.VERIFICATION_PROFILE,
        "target_hash_algorithm": attestation.TARGET_HASH_ALGORITHM,
        "tsa_organization_id": "organization:synthetic-test-tsa",
        "accepted_policy_oids": [POLICY_OID],
        "maximum_accuracy_seconds": 1,
        "trust_anchor": {
            "path": "root.pem",
            "sha256": sha256_bytes((trust / "root.pem").read_bytes()),
            "media_type": "application/x-pem-file",
        },
        "untrusted_chain": None,
        "revocation_policy": attestation.REVOCATION_POLICY,
        "independence_state": attestation.INDEPENDENCE_STATE,
    }
    trust_digest = _write_json(trust / attestation.TRUST_POLICY_MANIFEST, trust_policy)
    not_after = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp = {
        "schema_version": attestation.ATTESTATION_SCHEMA_VERSION,
        "id": "attestation:synthetic-rfc3161",
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scheme": attestation.SCHEME,
        "assertion": attestation.ASSERTION,
        "trust_policy_id": trust_policy["id"],
        "trust_policy_checkpoint_sha256": trust_digest,
        "target_sha256": sha256_bytes(target.read_bytes()),
        "not_after": not_after,
        "request": {
            "path": "request.tsq",
            "sha256": sha256_bytes(request.read_bytes()),
            "media_type": "application/timestamp-query",
        },
        "response": {
            "path": "response.tsr",
            "sha256": sha256_bytes(response.read_bytes()),
            "media_type": "application/timestamp-reply",
        },
    }
    attestation_digest = _write_json(bundle / attestation.ATTESTATION_MANIFEST, timestamp)
    return {
        "root": root,
        "work": work,
        "target": target,
        "target_digest": sha256_bytes(target.read_bytes()),
        "trust": trust,
        "trust_digest": trust_digest,
        "bundle": bundle,
        "attestation_digest": attestation_digest,
        "openssl": openssl,
        "openssl_digest": _binary_sha256(openssl),
        "not_after": not_after,
    }


def _verify(fixture: dict, **overrides):
    values = {
        "target_path": fixture["target"],
        "expected_target_sha256": fixture["target_digest"],
        "attestation_root": fixture["bundle"],
        "expected_attestation_checkpoint_sha256": fixture["attestation_digest"],
        "trust_policy_root": fixture["trust"],
        "expected_trust_policy_checkpoint_sha256": fixture["trust_digest"],
        "openssl_path": fixture["openssl"],
        "expected_openssl_sha256": fixture["openssl_digest"],
        "expected_not_after": fixture["not_after"],
    }
    values.update(overrides)
    return attestation.verify_rfc3161_attestation(**values)


def _copy_fixture(fixture: dict, tmp_path: Path) -> dict:
    target = tmp_path / "target.json"
    shutil.copy2(fixture["target"], target)
    trust = tmp_path / "trust"
    bundle = tmp_path / "attestation"
    shutil.copytree(fixture["trust"], trust)
    shutil.copytree(fixture["bundle"], bundle)
    return {
        **fixture,
        "target": target,
        "target_digest": sha256_bytes(target.read_bytes()),
        "trust": trust,
        "bundle": bundle,
    }


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_valid_rfc3161_replays_query_target_and_pinned_trust(rfc3161_fixture):
    report = _verify(rfc3161_fixture)
    gates = {item["id"]: item for item in report["gates"]}
    assert (
        report["status"] == "RFC3161_OFFLINE_SIGNATURE_EVIDENCE_VALID_WITHOUT_REVOCATION_"
        "TARGET_IMPRINT_BOUND_PASSES_LIMIT_SCIENTIFIC_SCORING_DISABLED"
    )
    assert report["cryptographic_timestamp_verified"] is False
    assert report["cryptographic_timestamp_signature_verified_without_revocation"] is True
    assert report["cms_single_sha256_signer_verified"] is True
    assert report["signed_accuracy_within_policy_verified"] is True
    assert report["signed_accuracy_microseconds"] == 1_000_000
    assert report["signed_token_serial"].startswith("0x")
    assert report["target_digest_existence_before_not_after_verified"] is False
    assert report["target_digest_existence_before_not_after_under_offline_nonrevocation_policy_verified"] is False
    assert (
        report["signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"]
        is True
    )
    assert report["canonical_der_verified"] is False
    assert report["tsa_signature_and_chain_verified"] is False
    assert report["tsa_signature_and_chain_at_signed_gentime_verified_without_revocation"] is True
    assert report["certificate_validity_over_signed_accuracy_interval_verified"] is False
    assert report["source_public_availability_before_not_after_verified"] is False
    assert report["witness_signer_identity_verified"] is False
    assert report["witness_independence_verified"] is False
    assert report["certificate_revocation_checked"] is False
    assert report["scientific_scoring_ready"] is False
    assert gates["target_binding"]["status"] == "PASS"
    assert gates["request_nonce"]["status"] == "PASS"
    assert gates["source_public_availability"]["status"] == "NO_CALL"
    assert gates["tsa_independence"]["status"] == "NO_CALL"
    assert len(report["report_sha256"]) == 64


def test_valid_but_late_timestamp_abstains_instead_of_backdating(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["not_after"] = "2000-01-01T00:00:00Z"
    digest = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    report = _verify(
        fixture,
        expected_attestation_checkpoint_sha256=digest,
        expected_not_after=document["not_after"],
    )
    assert (
        report["status"] == "RFC3161_OFFLINE_SIGNATURE_EVIDENCE_VALID_WITHOUT_REVOCATION_"
        "TARGET_IMPRINT_BOUND_FOLLOWS_LIMIT"
    )
    assert report["cryptographic_timestamp_verified"] is False
    assert report["cryptographic_timestamp_signature_verified_without_revocation"] is True
    assert report["target_digest_existence_before_not_after_verified"] is False
    assert report["target_digest_existence_before_not_after_under_offline_nonrevocation_policy_verified"] is False
    assert (
        report["signed_target_imprint_time_bound_under_caller_policy_verified_without_revocation_or_signer_identity"]
        is False
    )
    gate = next(item for item in report["gates"] if item["id"] == "timestamp_before_not_after")
    assert gate["status"] == "NO_CALL"


def test_coherent_target_and_manifest_substitution_still_fails_signed_imprint(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    fixture["target"].write_bytes(b'{"scope":"coherently-substituted"}\n')
    replacement_digest = sha256_bytes(fixture["target"].read_bytes())
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["target_sha256"] = replacement_digest
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="target-byte verification rejected"):
        _verify(
            fixture,
            expected_target_sha256=replacement_digest,
            expected_attestation_checkpoint_sha256=checkpoint,
        )


def test_attestation_cannot_switch_to_a_caller_rewritten_policy(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    policy = _json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST)
    policy["accepted_policy_oids"] = ["1.2.3.4.999"]
    policy_checkpoint = _write_json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST, policy)
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["trust_policy_checkpoint_sha256"] = policy_checkpoint
    attestation_checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="policy is not accepted"):
        _verify(
            fixture,
            expected_trust_policy_checkpoint_sha256=policy_checkpoint,
            expected_attestation_checkpoint_sha256=attestation_checkpoint,
        )


def test_nonce_free_request_is_rejected_even_when_signature_and_target_match(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    request = rfc3161_fixture["work"] / "request-no-nonce.tsq"
    response = rfc3161_fixture["work"] / "response-no-nonce.tsr"
    shutil.copy2(request, fixture["bundle"] / "request.tsq")
    shutil.copy2(response, fixture["bundle"] / "response.tsr")
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="nonce"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_openssl_binary_is_an_external_checkpoint(rfc3161_fixture):
    with pytest.raises(CausalFrontierError, match="OpenSSL binary external checkpoint mismatch"):
        _verify(rfc3161_fixture, expected_openssl_sha256="0" * 64)


def test_bundle_total_bytes_are_bounded_before_retention(rfc3161_fixture, monkeypatch):
    manifest_bytes = (rfc3161_fixture["trust"] / attestation.TRUST_POLICY_MANIFEST).stat().st_size
    monkeypatch.setattr(attestation.receipt_io, "MAX_TOTAL_BYTES", manifest_bytes)
    with pytest.raises(CausalFrontierError, match="bundle exceeds the total byte limit"):
        _verify(rfc3161_fixture)


def test_subprocess_output_is_terminated_at_the_stream_limit(rfc3161_fixture, tmp_path):
    flooding_executable = tmp_path / "flooding-openssl"
    flooding_executable.write_text(
        "#!/bin/sh\nwhile :; do printf '0123456789abcdef0123456789abcdef\\n'; done\n",
        encoding="utf-8",
    )
    flooding_executable.chmod(0o700)
    with pytest.raises(CausalFrontierError, match="output exceeds the verification limit"):
        _verify(
            rfc3161_fixture,
            openssl_path=flooding_executable,
            expected_openssl_sha256=_binary_sha256(flooding_executable),
        )


def test_forked_verifier_descendant_cannot_survive_rejection(rfc3161_fixture, tmp_path):
    child_pid_path = tmp_path / "child.pid"
    forking_executable = tmp_path / "forking-openssl"
    forking_executable.write_text(
        '#!/bin/sh\n/bin/sleep 30 &\nprintf \'%s\\n\' "$!" > "%s"\n'
        "while :; do printf '0123456789abcdef0123456789abcdef\\n'; done\n" % ("%s", child_pid_path),
        encoding="utf-8",
    )
    forking_executable.chmod(0o700)
    with pytest.raises(CausalFrontierError, match="output exceeds the verification limit"):
        _verify(
            rfc3161_fixture,
            openssl_path=forking_executable,
            expected_openssl_sha256=_binary_sha256(forking_executable),
        )
    child_pid = int(child_pid_path.read_text(encoding="utf-8").strip())
    for _attempt in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail("forked verifier descendant survived process-group termination")


def test_not_after_must_match_the_caller_checkpoint_before_openssl_runs(rfc3161_fixture, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("OpenSSL bytes must not be read after a cutoff mismatch")

    monkeypatch.setattr(attestation, "_read_openssl_binary", forbidden)
    with pytest.raises(CausalFrontierError, match="not-after bound differs"):
        _verify(rfc3161_fixture, expected_not_after="2000-01-01T00:00:00Z")


def test_verified_private_binary_snapshot_survives_original_path_replacement(rfc3161_fixture, tmp_path, monkeypatch):
    openssl_copy = tmp_path / "openssl-copy"
    shutil.copy2(rfc3161_fixture["openssl"], openssl_copy)
    openssl_copy.chmod(0o700)
    original_run = attestation._run_openssl
    replaced = False

    def replace_original_after_snapshot(binary, arguments, label, working_root, config):
        nonlocal replaced
        if not replaced:
            openssl_copy.write_bytes(b"transient attacker replacement")
            openssl_copy.chmod(0o700)
            replaced = True
        return original_run(binary, arguments, label, working_root, config)

    monkeypatch.setattr(attestation, "_run_openssl", replace_original_after_snapshot)
    report = _verify(
        rfc3161_fixture,
        openssl_path=openssl_copy,
        expected_openssl_sha256=_binary_sha256(rfc3161_fixture["openssl"]),
    )
    assert replaced is True
    assert report["openssl_executed_from_private_byte_snapshot"] is True
    assert report["cryptographic_timestamp_signature_verified_without_revocation"] is True


@pytest.mark.parametrize(("artifact", "expected"), [("request.tsq", "request"), ("response.tsr", "response")])
def test_der_with_trailing_bytes_is_rejected_before_openssl(rfc3161_fixture, tmp_path, artifact, expected):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    path = fixture["bundle"] / artifact
    path.write_bytes(path.read_bytes() + b"trailing")
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document[expected]["sha256"] = sha256_bytes(path.read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match=r"trailing, concatenated, or truncated ASN.1"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_noncanonical_ber_true_never_receives_a_canonical_der_claim(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    request = fixture["bundle"] / "request.tsq"
    raw = request.read_bytes()
    assert raw.endswith(b"\x01\x01\xff")
    request.write_bytes(raw[:-1] + b"\x01")
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes(request.read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    report = _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)
    gates = {item["id"]: item for item in report["gates"]}
    assert report["canonical_der_verified"] is False
    assert gates["canonical_der"]["status"] == "NO_CALL"


def test_sha1_cms_signer_digest_is_rejected(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    for name in ("request", "response"):
        extension = "tsq" if name == "request" else "tsr"
        shutil.copy2(
            rfc3161_fixture["work"] / ("%s-signer-sha1.%s" % (name, extension)),
            fixture["bundle"] / ("%s.%s" % (name, extension)),
        )
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="CMS digest set must contain only SHA-256"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_unspecified_signed_accuracy_is_rejected(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    for name in ("request", "response"):
        extension = "tsq" if name == "request" else "tsr"
        shutil.copy2(
            rfc3161_fixture["work"] / ("%s-no-accuracy.%s" % (name, extension)),
            fixture["bundle"] / ("%s.%s" % (name, extension)),
        )
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="must contain explicit signed accuracy"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_sha1_ess_certificate_binding_is_rejected(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    for name in ("request", "response"):
        extension = "tsq" if name == "request" else "tsr"
        shutil.copy2(
            rfc3161_fixture["work"] / ("%s-ess-sha1.%s" % (name, extension)),
            fixture["bundle"] / ("%s.%s" % (name, extension)),
        )
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="ESS SHA-256 certificate binding"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_token_only_der_cannot_be_relabelled_as_a_timestamp_response(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    response = fixture["bundle"] / "response.tsr"
    shutil.copy2(rfc3161_fixture["work"] / "token-only.der", response)
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["response"]["sha256"] = sha256_bytes(response.read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="response inspection rejected"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_missing_requested_policy_is_rejected(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    request = rfc3161_fixture["work"] / "request-no-policy.tsq"
    response = rfc3161_fixture["work"] / "response-no-policy.tsr"
    shutil.copy2(request, fixture["bundle"] / "request.tsq")
    shutil.copy2(response, fixture["bundle"] / "response.tsr")
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="policy OID"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_sha1_imprint_is_rejected_even_when_tsa_signature_is_valid(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    request = rfc3161_fixture["work"] / "request-sha1.tsq"
    response = rfc3161_fixture["work"] / "response-sha1.tsr"
    shutil.copy2(request, fixture["bundle"] / "request.tsq")
    shutil.copy2(response, fixture["bundle"] / "response.tsr")
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((fixture["bundle"] / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((fixture["bundle"] / "response.tsr").read_bytes())
    checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="must use SHA-256"):
        _verify(fixture, expected_attestation_checkpoint_sha256=checkpoint)


def test_attacker_chosen_self_signed_root_cannot_validate_original_token(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    shutil.copy2(rfc3161_fixture["work"] / "wrong-ca.pem", fixture["trust"] / "root.pem")
    policy = _json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST)
    policy["trust_anchor"]["sha256"] = sha256_bytes((fixture["trust"] / "root.pem").read_bytes())
    policy_checkpoint = _write_json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST, policy)
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["trust_policy_checkpoint_sha256"] = policy_checkpoint
    attestation_checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="request verification rejected"):
        _verify(
            fixture,
            expected_trust_policy_checkpoint_sha256=policy_checkpoint,
            expected_attestation_checkpoint_sha256=attestation_checkpoint,
        )


def test_decoy_plus_shared_hidden_ca_bundle_is_rejected(rfc3161_fixture, tmp_path):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    original = (fixture["trust"] / "root.pem").read_bytes()
    decoy = (rfc3161_fixture["work"] / "wrong-ca.pem").read_bytes()
    (fixture["trust"] / "root.pem").write_bytes(decoy + original)
    policy = _json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST)
    policy["trust_anchor"]["sha256"] = sha256_bytes((fixture["trust"] / "root.pem").read_bytes())
    policy_checkpoint = _write_json(fixture["trust"] / attestation.TRUST_POLICY_MANIFEST, policy)
    document = _json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST)
    document["trust_policy_checkpoint_sha256"] = policy_checkpoint
    attestation_checkpoint = _write_json(fixture["bundle"] / attestation.ATTESTATION_MANIFEST, document)
    with pytest.raises(CausalFrontierError, match="exactly one canonical certificate"):
        _verify(
            fixture,
            expected_trust_policy_checkpoint_sha256=policy_checkpoint,
            expected_attestation_checkpoint_sha256=attestation_checkpoint,
        )


def test_ambient_openssl_configuration_and_cert_paths_are_ignored(rfc3161_fixture, monkeypatch):
    monkeypatch.setenv("OPENSSL_CONF", "/definitely/not/the/checkpointed/config")
    monkeypatch.setenv("OPENSSL_MODULES", "/definitely/not/a/provider-directory")
    monkeypatch.setenv("SSL_CERT_FILE", "/definitely/not/a/trust-anchor")
    monkeypatch.setenv("SSL_CERT_DIR", "/definitely/not/a/trust-directory")
    report = _verify(rfc3161_fixture)
    assert report["cryptographic_timestamp_signature_verified_without_revocation"] is True
    assert report["openssl_runtime_hermeticity_verified"] is False


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_unsafe_attestation_files_fail_closed(rfc3161_fixture, tmp_path, unsafe_kind):
    fixture = _copy_fixture(rfc3161_fixture, tmp_path)
    response = fixture["bundle"] / "response.tsr"
    if unsafe_kind == "symlink":
        external = tmp_path / "external.tsr"
        shutil.copy2(response, external)
        response.unlink()
        response.symlink_to(external)
    else:
        os.link(response, tmp_path / "external-hardlink.tsr")
    with pytest.raises(CausalFrontierError):
        _verify(fixture)


def test_cli_emits_abstention_exit_even_for_valid_digest_existence_proof(rfc3161_fixture, capsys):
    fixture = rfc3161_fixture
    code = main(
        [
            "verify-rfc3161-attestation",
            str(fixture["target"]),
            str(fixture["bundle"]),
            str(fixture["trust"]),
            str(fixture["openssl"]),
            "--expected-target-sha256",
            fixture["target_digest"],
            "--expected-attestation-checkpoint-sha256",
            fixture["attestation_digest"],
            "--expected-trust-policy-checkpoint-sha256",
            fixture["trust_digest"],
            "--expected-openssl-sha256",
            fixture["openssl_digest"],
            "--expected-not-after",
            fixture["not_after"],
        ]
    )
    captured = capsys.readouterr()
    assert code == 3
    output = json.loads(captured.out)
    assert output["cryptographic_timestamp_verified"] is False
    assert output["cryptographic_timestamp_signature_verified_without_revocation"] is True
    assert output["source_public_availability_before_not_after_verified"] is False
    assert output["scientific_scoring_ready"] is False
