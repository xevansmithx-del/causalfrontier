"""Hostile tests for the dual-witness pre-generation lock and epoch."""

from __future__ import annotations

import inspect
import json
import os
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sentinel_fixture import build_sentinel_fixture

import causalfrontier
import causalfrontier.sentinel_witness as witness
from causalfrontier import attestation
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes
from causalfrontier.cli import main
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _run(arguments: list[str]) -> None:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> str:
    raw = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _openssl_sha256(path: Path) -> str:
    return sha256_bytes(path.resolve(strict=True).read_bytes())


def _anchor_spki_sha256(openssl: Path, anchor: Path) -> str:
    result = subprocess.run(
        [str(openssl), "x509", "-in", str(anchor), "-pubkey", "-noout"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot inspect synthetic trust anchor")
    return sha256_bytes(attestation._public_key_spki_der(result.stdout.decode("utf-8")))


def _build_tsa(
    openssl: Path,
    base: Path,
    lock_root: Path,
    label: str,
    organization_id: str,
    policy_oid: str,
    *,
    root_key_source: Path | None = None,
    root_certificate_source: Path | None = None,
    signer_key_source: Path | None = None,
) -> dict:
    work = base / ("work-" + label)
    trust = lock_root / ("witness-" + label) / "trust-policy"
    bundle = lock_root / ("witness-" + label) / "attestation"
    work.mkdir(parents=True)
    trust.mkdir(parents=True)
    bundle.mkdir(parents=True)
    if root_certificate_source is not None:
        if root_key_source is None:
            raise RuntimeError("prebuilt synthetic root requires its private key")
        shutil.copy2(root_key_source, work / "ca.key")
        shutil.copy2(root_certificate_source, work / "ca.pem")
        root_key_arguments = None
    elif root_key_source is None:
        root_key_arguments = ["-newkey", "rsa:2048", "-nodes", "-keyout", str(work / "ca.key")]
    else:
        shutil.copy2(root_key_source, work / "ca.key")
        root_key_arguments = ["-new", "-key", str(work / "ca.key")]
    if root_key_arguments is not None:
        _run(
            [
                str(openssl),
                "req",
                "-x509",
                *root_key_arguments,
                "-out",
                str(work / "ca.pem"),
                "-subj",
                "/CN=CausalFrontier Synthetic Witness %s Root" % label.upper(),
                "-days",
                "2",
                "-sha256",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )
    if signer_key_source is None:
        signer_key_arguments = [
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(work / "tsa.key"),
        ]
    else:
        shutil.copy2(signer_key_source, work / "tsa.key")
        signer_key_arguments = ["-new", "-key", str(work / "tsa.key")]
    _run(
        [
            str(openssl),
            "req",
            *signer_key_arguments,
            "-out",
            str(work / "tsa.csr"),
            "-subj",
            "/CN=CausalFrontier Synthetic Witness %s TSA" % label.upper(),
            "-sha256",
        ]
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
        ]
    )
    (work / "tsa.serial").write_text("01\n", encoding="ascii")
    (work / "tsa.cnf").write_text(
        "\n".join(
            [
                "[tsa]",
                "default_tsa=tsa_config",
                "[tsa_config]",
                "serial=%s" % (work / "tsa.serial"),
                "signer_cert=%s" % (work / "tsa.pem"),
                "signer_key=%s" % (work / "tsa.key"),
                "signer_digest=sha256",
                "default_policy=%s" % policy_oid,
                "other_policies=%s" % policy_oid,
                "digests=sha256",
                "accuracy=secs:1",
                "ordering=no",
                "tsa_name=yes",
                "ess_cert_id_chain=no",
                "ess_cert_id_alg=sha256",
                "",
            ]
        ),
        encoding="utf-8",
    )
    shutil.copy2(work / "ca.pem", trust / "root.pem")
    policy = {
        "schema_version": attestation.TRUST_POLICY_SCHEMA_VERSION,
        "id": "trust-policy:synthetic-witness-%s" % label,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scheme": attestation.SCHEME,
        "verification_profile": attestation.VERIFICATION_PROFILE,
        "target_hash_algorithm": attestation.TARGET_HASH_ALGORITHM,
        "tsa_organization_id": organization_id,
        "accepted_policy_oids": [policy_oid],
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
    trust_checkpoint = _write_json(trust / attestation.TRUST_POLICY_MANIFEST, policy)
    return {
        "label": label,
        "work": work,
        "trust": trust,
        "trust_checkpoint": trust_checkpoint,
        "trust_policy": policy,
        "bundle": bundle,
        "organization_id": organization_id,
        "policy_oid": policy_oid,
        "anchor_sha256": policy["trust_anchor"]["sha256"],
        "anchor_spki_sha256": _anchor_spki_sha256(openssl, trust / "root.pem"),
        "signer_spki_sha256": _anchor_spki_sha256(openssl, work / "tsa.pem"),
        "attestation_id": "attestation:synthetic-witness-%s" % label,
    }


def _timestamp(openssl: Path, tsa: dict, target: Path, not_after: str) -> str:
    request = tsa["bundle"] / "request.tsq"
    response = tsa["bundle"] / "response.tsr"
    _run(
        [
            str(openssl),
            "ts",
            "-query",
            "-data",
            str(target),
            "-sha256",
            "-tspolicy",
            tsa["policy_oid"],
            "-cert",
            "-out",
            str(request),
        ]
    )
    _run(
        [
            str(openssl),
            "ts",
            "-reply",
            "-queryfile",
            str(request),
            "-config",
            str(tsa["work"] / "tsa.cnf"),
            "-out",
            str(response),
        ]
    )
    target_checkpoint = sha256_bytes(target.read_bytes())
    manifest = {
        "schema_version": attestation.ATTESTATION_SCHEMA_VERSION,
        "id": tsa["attestation_id"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scheme": attestation.SCHEME,
        "assertion": attestation.ASSERTION,
        "trust_policy_id": tsa["trust_policy"]["id"],
        "trust_policy_checkpoint_sha256": tsa["trust_checkpoint"],
        "target_sha256": target_checkpoint,
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
    return _write_json(tsa["bundle"] / attestation.ATTESTATION_MANIFEST, manifest)


def _seal_target(target: dict) -> None:
    core = {key: value for key, value in target.items() if key != "target_sha256"}
    target["target_sha256"] = sha256_bytes(witness.TARGET_DOMAIN_TAG + canonical_bytes(core))


def _seal_lock(manifest: dict) -> None:
    core = {key: value for key, value in manifest.items() if key != "lock_sha256"}
    manifest["lock_sha256"] = sha256_bytes(witness.LOCK_DOMAIN_TAG + canonical_bytes(core))


def _build_alternate_encoding_ec_roots(openssl: Path, base: Path) -> tuple[Path, Path, Path]:
    root = base / "shared-ec-roots"
    root.mkdir()
    key = root / "ca.key"
    _run(
        [
            str(openssl),
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(key),
        ]
    )
    for form in ("uncompressed", "compressed"):
        _run(
            [
                str(openssl),
                "pkey",
                "-in",
                str(key),
                "-pubout",
                "-ec_conv_form",
                form,
                "-out",
                str(root / ("public-" + form + ".pem")),
            ]
        )
    _run(
        [
            str(openssl),
            "req",
            "-new",
            "-key",
            str(key),
            "-subj",
            "/CN=CausalFrontier Shared Mathematical EC Root",
            "-out",
            str(root / "ca.csr"),
        ]
    )
    (root / "ca-ext.cnf").write_text(
        "\n".join(
            [
                "basicConstraints=critical,CA:TRUE",
                "keyUsage=critical,keyCertSign,cRLSign",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
                "",
            ]
        ),
        encoding="utf-8",
    )
    certificates = []
    for index, form in enumerate(("uncompressed", "compressed"), start=1):
        certificate = root / ("root-" + form + ".pem")
        _run(
            [
                str(openssl),
                "x509",
                "-req",
                "-in",
                str(root / "ca.csr"),
                "-signkey",
                str(key),
                "-force_pubkey",
                str(root / ("public-" + form + ".pem")),
                "-set_serial",
                str(index),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(root / "ca-ext.cnf"),
                "-out",
                str(certificate),
            ]
        )
        certificates.append(certificate)
    return key, certificates[0], certificates[1]


def _build_fixture(
    base: Path,
    *,
    deadline_offset_seconds: int = 86_400,
    shared_root_key: bool = False,
    shared_signer_key: bool = False,
    alternate_ec_root_encoding: bool = False,
    seed_outer_registry_digest_collision: bool = False,
) -> dict:
    found = shutil.which("openssl")
    if found is None:
        pytest.skip("OpenSSL is unavailable")
    openssl = Path(found).resolve(strict=True)
    version = subprocess.run(
        [str(openssl), "version"], capture_output=True, text=True, timeout=10, check=False
    ).stdout.strip()
    if attestation.OPENSSL_VERSION.fullmatch(version) is None:
        pytest.skip("OpenSSL 3 is required")
    sentinel_fixture = build_sentinel_fixture(
        base / "sentinel",
        seed_outer_registry_digest_collision=seed_outer_registry_digest_collision,
    )
    lock_root = base / "dual-witness-lock"
    lock_root.mkdir()
    organization_registry = sentinel_fixture["manifest"]["organizations"]
    registry_path = lock_root / "organization-registry.json"
    registry_checkpoint = _write_json(registry_path, organization_registry)
    openssl_checkpoint = _openssl_sha256(openssl)
    alternate_root_key = None
    alternate_root_a = None
    alternate_root_b = None
    if alternate_ec_root_encoding:
        alternate_root_key, alternate_root_a, alternate_root_b = _build_alternate_encoding_ec_roots(openssl, base)
    tsa_a = _build_tsa(
        openssl,
        base,
        lock_root,
        "a",
        "organization:external-witness-a",
        "1.2.3.4.101",
        root_key_source=alternate_root_key,
        root_certificate_source=alternate_root_a,
    )
    tsa_b = _build_tsa(
        openssl,
        base,
        lock_root,
        "b",
        "organization:external-witness-b",
        "1.2.3.4.102",
        root_key_source=(
            alternate_root_key if alternate_ec_root_encoding else tsa_a["work"] / "ca.key" if shared_root_key else None
        ),
        root_certificate_source=alternate_root_b,
        signer_key_source=tsa_a["work"] / "tsa.key" if shared_signer_key else None,
    )
    tsas = [tsa_a, tsa_b]
    not_after = (datetime.now(timezone.utc) + timedelta(seconds=deadline_offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    target = {
        "schema_version": witness.TARGET_SCHEMA_VERSION,
        "status": witness.TARGET_STATUS,
        "lock_id": "lock:sentinel-dual-witness:1",
        "sequence": 1,
        "predecessor_lock_preflight_sha256": None,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "goal_claim_contract_sha256": sentinel_fixture["generation_plan"]["goal_claim_contract_sha256"],
        "generation_plan_id": sentinel_fixture["generation_plan"]["plan_id"],
        "generation_plan_checkpoint_sha256": sentinel_fixture["generation_plan_sha256"],
        "generation_plan_sha256": sentinel_fixture["generation_plan"]["plan_sha256"],
        "organization_registry_checkpoint_sha256": registry_checkpoint,
        "organization_registry_sha256": sentinel_fixture["generation_plan"]["organization_registry_sha256"],
        "witness_completion_not_after": not_after,
        "witnesses": [
            {
                "witness_id": "witness:%s" % tsa["label"],
                "witness_organization_id": tsa["organization_id"],
                "controller_group_id": "controller:external-witness-%s" % tsa["label"],
                "store_group_id": "store:external-witness-%s" % tsa["label"],
                "attestation_id": tsa["attestation_id"],
                "trust_policy_id": tsa["trust_policy"]["id"],
                "trust_policy_checkpoint_sha256": tsa["trust_checkpoint"],
                "trust_anchor_sha256": tsa["anchor_sha256"],
                "trust_anchor_spki_sha256": tsa["anchor_spki_sha256"],
                "tsa_signer_spki_sha256": tsa["signer_spki_sha256"],
                "openssl_binary_sha256": openssl_checkpoint,
                "independence_state": witness.INDEPENDENCE_STATE,
            }
            for tsa in tsas
        ],
        "generated_artifact_input_absent": True,
        "outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "scoring_disabled": True,
    }
    _seal_target(target)
    target_path = lock_root / "lock-target.json"
    target_checkpoint = _write_json(target_path, target)
    for tsa in tsas:
        tsa["attestation_checkpoint"] = _timestamp(openssl, tsa, target_path, not_after)
    manifest = {
        "schema_version": witness.LOCK_SCHEMA_VERSION,
        "status": witness.LOCK_STATUS,
        "lock_id": target["lock_id"],
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "target": {
            "path": "lock-target.json",
            "sha256": target_checkpoint,
            "media_type": "application/json",
        },
        "target_sha256": target["target_sha256"],
        "organization_registry": {
            "path": "organization-registry.json",
            "sha256": registry_checkpoint,
            "media_type": "application/json",
        },
        "organization_registry_sha256": target["organization_registry_sha256"],
        "generation_plan_checkpoint_sha256": target["generation_plan_checkpoint_sha256"],
        "generation_plan_sha256": target["generation_plan_sha256"],
        "witnesses": [
            {
                "witness_id": "witness:%s" % tsa["label"],
                "attestation_root": "witness-%s/attestation" % tsa["label"],
                "attestation_checkpoint_sha256": tsa["attestation_checkpoint"],
                "trust_policy_root": "witness-%s/trust-policy" % tsa["label"],
                "trust_policy_checkpoint_sha256": tsa["trust_checkpoint"],
            }
            for tsa in tsas
        ],
        "generated_artifact_input_absent": True,
        "outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "scoring_disabled": True,
    }
    _seal_lock(manifest)
    manifest_path = lock_root / witness.LOCK_MANIFEST
    manifest_checkpoint = _write_json(manifest_path, manifest)
    return {
        "root": lock_root,
        "manifest_path": manifest_path,
        "manifest": manifest,
        "manifest_sha256": manifest_checkpoint,
        "target_path": target_path,
        "target": target,
        "generation_plan_path": sentinel_fixture["generation_plan_path"],
        "generation_plan_sha256": sentinel_fixture["generation_plan_sha256"],
        "openssl": openssl,
        "openssl_sha256": openssl_checkpoint,
    }


@pytest.fixture(scope="module")
def dual_fixture(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _build_fixture(tmp_path_factory.mktemp("dual-witness"))


def _copy_fixture(fixture: dict, tmp_path: Path) -> dict:
    root = tmp_path / "dual-witness-lock"
    shutil.copytree(fixture["root"], root)
    generation_plan = tmp_path / "sentinel-generation-plan.json"
    shutil.copy2(fixture["generation_plan_path"], generation_plan)
    return {
        **fixture,
        "root": root,
        "manifest_path": root / witness.LOCK_MANIFEST,
        "manifest": _json(root / witness.LOCK_MANIFEST),
        "target_path": root / "lock-target.json",
        "target": _json(root / "lock-target.json"),
        "generation_plan_path": generation_plan,
    }


def _preflight(fixture: dict, **overrides) -> dict:
    values = {
        "root": fixture["root"],
        "expected_lock_manifest_sha256": fixture["manifest_sha256"],
        "generation_plan_path": fixture["generation_plan_path"],
        "expected_generation_plan_sha256": fixture["generation_plan_sha256"],
        "expected_sequence": 1,
        "openssl_paths": [fixture["openssl"], fixture["openssl"]],
        "expected_openssl_sha256s": [fixture["openssl_sha256"], fixture["openssl_sha256"]],
    }
    values.update(overrides)
    return witness.preflight_sentinel_dual_witness_lock(**values)


def _rewrite_lock(fixture: dict) -> None:
    _seal_lock(fixture["manifest"])
    fixture["manifest_sha256"] = _write_json(fixture["manifest_path"], fixture["manifest"])


def _rewrite_target_and_lock(fixture: dict) -> None:
    _seal_target(fixture["target"])
    checkpoint = _write_json(fixture["target_path"], fixture["target"])
    fixture["manifest"]["target"]["sha256"] = checkpoint
    fixture["manifest"]["target_sha256"] = fixture["target"]["target_sha256"]
    _rewrite_lock(fixture)


def test_clean_dual_witness_lock_derives_epoch_without_admission(dual_fixture: dict) -> None:
    report = _preflight(dual_fixture)
    assert report["status"] == witness.PREFLIGHT_STATUS
    assert report["closed_dual_witness_bundle_replayed"] is True
    assert report["both_raw_rfc3161_bundles_replayed_against_same_target"] is True
    assert report["both_signed_target_imprint_time_bounds_replayed_without_revocation_or_signer_identity"] is True
    assert report["distinct_trust_anchor_spkis_verified"] is True
    assert report["distinct_trust_anchor_key_material_verified"] is True
    assert report["distinct_tsa_signer_spkis_verified"] is True
    assert report["distinct_tsa_signer_key_material_verified"] is True
    assert report["generation_epoch_derived"] is True
    assert len(report["generation_epoch_sha256"]) == 64
    assert len(report["witnesses"]) == 2
    assert all(report[field] is False for field in witness.FIXED_FALSE_FIELDS)
    gates = {item["id"]: item for item in report["gates"]}
    assert gates["generation_epoch_derivation"]["status"] == "PASS"
    assert gates["generated_artifact_phase_binding"]["status"] == "NO_CALL"
    assert gates["witness_independence"]["status"] == "NO_CALL"
    assert gates["scientific_scoring"]["status"] == "NO_CALL"


def test_replay_is_deterministic_and_public_verifier_rebuilds(dual_fixture: dict) -> None:
    report = _preflight(dual_fixture)
    assert _preflight(dual_fixture) == report
    assert (
        witness.verify_sentinel_dual_witness_lock_preflight(
            report,
            dual_fixture["root"],
            dual_fixture["manifest_sha256"],
            dual_fixture["generation_plan_path"],
            dual_fixture["generation_plan_sha256"],
            1,
            [dual_fixture["openssl"], dual_fixture["openssl"]],
            [dual_fixture["openssl_sha256"], dual_fixture["openssl_sha256"]],
        )
        == report
    )


@pytest.mark.parametrize("field", sorted(witness.FIXED_FALSE_FIELDS))
def test_coherently_rehashed_authority_escalation_is_rejected(dual_fixture: dict, field: str) -> None:
    report = deepcopy(_preflight(dual_fixture))
    report[field] = True
    core = {key: value for key, value in report.items() if key != "preflight_sha256"}
    report["preflight_sha256"] = sha256_bytes(witness.PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    with pytest.raises(CausalFrontierError, match="differs from exact deterministic replay"):
        witness.verify_sentinel_dual_witness_lock_preflight(
            report,
            dual_fixture["root"],
            dual_fixture["manifest_sha256"],
            dual_fixture["generation_plan_path"],
            dual_fixture["generation_plan_sha256"],
            1,
            [dual_fixture["openssl"], dual_fixture["openssl"]],
            [dual_fixture["openssl_sha256"], dual_fixture["openssl_sha256"]],
        )


def test_public_api_and_cli_preserve_safe_abstention(dual_fixture: dict, capsys) -> None:
    assert causalfrontier.preflight_sentinel_dual_witness_lock is witness.preflight_sentinel_dual_witness_lock
    assert (
        causalfrontier.verify_sentinel_dual_witness_lock_preflight
        is witness.verify_sentinel_dual_witness_lock_preflight
    )
    code = main(
        [
            "preflight-sentinel-dual-witness-lock",
            str(dual_fixture["root"]),
            str(dual_fixture["generation_plan_path"]),
            "--expected-lock-manifest-sha256",
            dual_fixture["manifest_sha256"],
            "--expected-generation-plan-sha256",
            dual_fixture["generation_plan_sha256"],
            "--expected-sequence",
            "1",
            "--openssl",
            str(dual_fixture["openssl"]),
            "--openssl",
            str(dual_fixture["openssl"]),
            "--expected-openssl-sha256",
            dual_fixture["openssl_sha256"],
            "--expected-openssl-sha256",
            dual_fixture["openssl_sha256"],
        ]
    )
    assert code == 3
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == witness.PREFLIGHT_STATUS
    assert output["cohort_admitted"] is False
    assert output["scientific_scoring_ready"] is False


def test_lock_api_accepts_no_artifact_outcome_opening_or_score_input() -> None:
    parameters = set(inspect.signature(witness.preflight_sentinel_dual_witness_lock).parameters)
    assert parameters == {
        "root",
        "expected_lock_manifest_sha256",
        "generation_plan_path",
        "expected_generation_plan_sha256",
        "expected_sequence",
        "openssl_paths",
        "expected_openssl_sha256s",
    }
    assert not parameters & {"artifact", "payload", "outcome", "opening", "score", "result", "winner"}


@pytest.mark.parametrize("sequence", [False, 0, 2])
def test_wrong_boolean_zero_or_drifted_sequence_rejected(dual_fixture: dict, sequence: object) -> None:
    with pytest.raises(CausalFrontierError, match="sequence"):
        _preflight(dual_fixture, expected_sequence=sequence)


def test_raw_generation_plan_substitution_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    document = _json(fixture["generation_plan_path"])
    fixture["generation_plan_path"].write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    substituted = sha256_bytes(fixture["generation_plan_path"].read_bytes())
    with pytest.raises(CausalFrontierError, match="binds a different generation plan"):
        _preflight(fixture, expected_generation_plan_sha256=substituted)


def test_noncanonical_target_encoding_rejected_before_attestation(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target_path"].write_text(json.dumps(fixture["target"], indent=2) + "\n", encoding="utf-8")
    fixture["manifest"]["target"]["sha256"] = sha256_bytes(fixture["target_path"].read_bytes())
    _rewrite_lock(fixture)
    with pytest.raises(CausalFrontierError, match="single canonical JSON encoding"):
        _preflight(fixture)


def test_casefold_controller_alias_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["controller_group_id"] = fixture["target"]["witnesses"][0][
        "controller_group_id"
    ].upper()
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share a witness or governance identity"):
        _preflight(fixture)


def test_controller_store_cross_dimension_alias_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["store_group_id"] = fixture["target"]["witnesses"][0]["controller_group_id"]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share a witness or governance identity"):
        _preflight(fixture)


def test_attestation_id_cannot_alias_another_witness_governance_id(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["attestation_id"] = fixture["target"]["witnesses"][0]["controller_group_id"]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share a witness or governance identity"):
        _preflight(fixture)


def test_witness_registry_participant_alias_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    registry = json.loads((fixture["root"] / "organization-registry.json").read_text(encoding="utf-8"))
    fixture["target"]["witnesses"][0]["controller_group_id"] = registry[0]["controller_group_id"]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="aliases a sentinel participant"):
        _preflight(fixture)


def test_trust_policy_id_cannot_alias_a_registry_participant(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    registry = json.loads((fixture["root"] / "organization-registry.json").read_text(encoding="utf-8"))
    fixture["target"]["witnesses"][0]["trust_policy_id"] = registry[0]["organization_id"]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="aliases a sentinel participant"):
        _preflight(fixture)


def test_equal_anchor_bytes_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["trust_anchor_sha256"] = fixture["target"]["witnesses"][0]["trust_anchor_sha256"]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share trust_anchor_sha256"):
        _preflight(fixture)


def test_reissued_anchor_same_spki_declaration_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["trust_anchor_spki_sha256"] = fixture["target"]["witnesses"][0][
        "trust_anchor_spki_sha256"
    ]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share trust_anchor_spki_sha256"):
        _preflight(fixture)


def test_same_tsa_signer_spki_declaration_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["target"]["witnesses"][1]["tsa_signer_spki_sha256"] = fixture["target"]["witnesses"][0][
        "tsa_signer_spki_sha256"
    ]
    _rewrite_target_and_lock(fixture)
    with pytest.raises(CausalFrontierError, match="share tsa_signer_spki_sha256"):
        _preflight(fixture)


def test_actual_reissued_root_same_rsa_key_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path / "shared-root-key", shared_root_key=True)
    left = fixture["target"]["witnesses"][0]
    right = fixture["target"]["witnesses"][1]
    assert left["trust_anchor_sha256"] != right["trust_anchor_sha256"]
    assert left["trust_anchor_spki_sha256"] == right["trust_anchor_spki_sha256"]
    with pytest.raises(CausalFrontierError, match="share trust_anchor_spki_sha256"):
        _preflight(fixture)


def test_actual_reissued_tsa_signer_same_rsa_key_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path / "shared-signer-key", shared_signer_key=True)
    left = fixture["target"]["witnesses"][0]
    right = fixture["target"]["witnesses"][1]
    assert left["tsa_signer_spki_sha256"] == right["tsa_signer_spki_sha256"]
    with pytest.raises(CausalFrontierError, match="share tsa_signer_spki_sha256"):
        _preflight(fixture)


def test_same_ec_root_key_with_alternate_spki_encodings_is_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path / "alternate-ec", alternate_ec_root_encoding=True)
    left = fixture["target"]["witnesses"][0]
    right = fixture["target"]["witnesses"][1]
    assert left["trust_anchor_sha256"] != right["trust_anchor_sha256"]
    assert left["trust_anchor_spki_sha256"] != right["trust_anchor_spki_sha256"]
    with pytest.raises(CausalFrontierError, match="reuses trust_anchor_key_material_sha256"):
        _preflight(fixture)


def test_one_attestation_target_substitution_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    manifest_path = fixture["root"] / "witness-b" / "attestation" / attestation.ATTESTATION_MANIFEST
    document = _json(manifest_path)
    document["target_sha256"] = sha256_bytes(b"different target")
    checkpoint = _write_json(manifest_path, document)
    fixture["manifest"]["witnesses"][1]["attestation_checkpoint_sha256"] = checkpoint
    _rewrite_lock(fixture)
    with pytest.raises(CausalFrontierError, match="targets different bytes"):
        _preflight(fixture)


def test_same_token_renamed_as_second_witness_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    left = fixture["root"] / "witness-a" / "attestation"
    right = fixture["root"] / "witness-b" / "attestation"
    for name in ("request.tsq", "response.tsr"):
        shutil.copy2(left / name, right / name)
    document = _json(right / attestation.ATTESTATION_MANIFEST)
    document["request"]["sha256"] = sha256_bytes((right / "request.tsq").read_bytes())
    document["response"]["sha256"] = sha256_bytes((right / "response.tsr").read_bytes())
    checkpoint = _write_json(right / attestation.ATTESTATION_MANIFEST, document)
    fixture["manifest"]["witnesses"][1]["attestation_checkpoint_sha256"] = checkpoint
    _rewrite_lock(fixture)
    with pytest.raises(CausalFrontierError):
        _preflight(fixture)


def test_swapped_trust_policy_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    fixture["manifest"]["witnesses"][0]["trust_policy_root"] = "witness-b/trust-policy"
    fixture["manifest"]["witnesses"][1]["trust_policy_root"] = "witness-a/trust-policy"
    _rewrite_lock(fixture)
    with pytest.raises(CausalFrontierError):
        _preflight(fixture)


def test_late_signed_time_bound_rejected(tmp_path: Path) -> None:
    fixture = _build_fixture(tmp_path / "late", deadline_offset_seconds=-60)
    with pytest.raises(CausalFrontierError, match="signed time bound follows"):
        _preflight(fixture)


def test_orphan_file_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    (fixture["root"] / "orphan.txt").write_text("orphan\n", encoding="utf-8")
    with pytest.raises(CausalFrontierError, match="orphan"):
        _preflight(fixture)


def test_unsafe_symlink_and_hardlink_rejected(dual_fixture: dict, tmp_path: Path) -> None:
    for unsafe in ("symlink", "hardlink"):
        case = tmp_path / unsafe
        case.mkdir()
        fixture = _copy_fixture(dual_fixture, case)
        source = fixture["root"] / "lock-target.json"
        target = fixture["root"] / ("unsafe-" + unsafe)
        if unsafe == "symlink":
            target.symlink_to(source)
        else:
            os.link(source, target)
        with pytest.raises(CausalFrontierError):
            _preflight(fixture)


def test_missing_extra_and_wrong_runtime_rejected(dual_fixture: dict) -> None:
    with pytest.raises(CausalFrontierError, match="exactly two"):
        _preflight(dual_fixture, openssl_paths=[dual_fixture["openssl"]])
    with pytest.raises(CausalFrontierError, match="exactly two"):
        _preflight(
            dual_fixture,
            openssl_paths=[dual_fixture["openssl"]] * 3,
            expected_openssl_sha256s=[dual_fixture["openssl_sha256"]] * 3,
        )
    with pytest.raises(CausalFrontierError, match="runtime differs"):
        _preflight(
            dual_fixture,
            expected_openssl_sha256s=[dual_fixture["openssl_sha256"], sha256_bytes(b"wrong runtime")],
        )
    with pytest.raises(CausalFrontierError, match="exactly two"):
        _preflight(dual_fixture, openssl_paths=None)
    with pytest.raises(CausalFrontierError, match="exactly two"):
        _preflight(
            dual_fixture,
            openssl_paths=iter([dual_fixture["openssl"], dual_fixture["openssl"]]),
        )


def test_private_snapshot_zero_progress_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(witness.os, "write", lambda _descriptor, _raw: 0)
    with pytest.raises(CausalFrontierError, match="did not progress"):
        witness._write_private_snapshot(tmp_path, "snapshot.bin", b"nonempty")


def test_bundle_drift_during_replay_rejected(
    dual_fixture: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _copy_fixture(dual_fixture, tmp_path)
    original = witness.receipt_io._snapshot
    calls = {"target": 0}

    def drifting_snapshot(descriptor: int, relative: str) -> bytes:
        raw = original(descriptor, relative)
        if relative == "lock-target.json":
            calls["target"] += 1
            # Initial outer snapshot, then one staged read per witness, then
            # the retained-descriptor end snapshot.
            if calls["target"] == 4:
                return raw + b" "
        return raw

    monkeypatch.setattr(witness.receipt_io, "_snapshot", drifting_snapshot)
    with pytest.raises(CausalFrontierError, match="changed during replay"):
        _preflight(fixture)
