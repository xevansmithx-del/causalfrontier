"""Read-only known-hindsight calibration tripwire.

This module binds three historical calibration roles, two frozen policy outputs,
and complete declared resource ledgers before opening a committed oracle.  It is
an integrity tripwire, not a benchmark scorer.  In particular, a complete set of
passes cannot make known-hindsight cases prospective, remove model-training
contamination, establish temporal custody, or grant patient, clinical, human,
or material authority.

Both public functions are deliberately offline and read-only.  They execute no
artifact content, open no network connection, spawn no subprocess, and write no
file.
"""

from __future__ import annotations

import hmac
import re
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

MANIFEST = "calibration-tripwire.json"
MANIFEST_SCHEMA_VERSION = "causalfrontier.calibration-tripwire.v1"
OUTPUT_SCHEMA_VERSION = "causalfrontier.calibration-policy-output.v1"
LEDGER_SCHEMA_VERSION = "causalfrontier.calibration-resource-ledger.v1"
LOCK_SCHEMA_VERSION = "causalfrontier.calibration-tripwire-lock.v1"
OPENING_SCHEMA_VERSION = "causalfrontier.calibration-tripwire-opening.v1"
OPENING_PAYLOAD_SCHEMA_VERSION = "causalfrontier.calibration-tripwire-opening-payload.v1"
REPORT_SCHEMA_VERSION = "causalfrontier.calibration-tripwire-report.v1"

LOCK_STATUS = "CALIBRATION_TRIPWIRE_LOCKED_OPENING_NOT_READ_SCORING_DISABLED"
REPORT_PASS_STATUS = "CALIBRATION_TRIPWIRE_PASSED_KNOWN_HINDSIGHT_SCIENTIFIC_SCORING_DISABLED"
REPORT_BLOCKED_STATUS = "CALIBRATION_TRIPWIRE_NOT_PASSED_SCIENTIFIC_SCORING_DISABLED"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_KNOWN_HINDSIGHT_CALIBRATION_TRIPWIRE"

INPUT_INVENTORY_DOMAIN_TAG = b"causalfrontier.calibration-input-inventory.v1\0"
EXECUTION_CHECKPOINT_DOMAIN_TAG = b"causalfrontier.calibration-execution-checkpoint.v1\0"
LOCK_DOMAIN_TAG = b"causalfrontier.calibration-tripwire-lock.v1\0"
REVEAL_DOMAIN_TAG = b"causalfrontier.calibration-tripwire-reveal.v1\0"
REPORT_DOMAIN_TAG = b"causalfrontier.calibration-tripwire-report.v1\0"

EXECUTION_CHECKPOINT_SCHEME = "SHA256_DOMAIN_SEPARATED_CANONICAL_THREE_INPUT_INVENTORY_SIX_OUTPUT_SIX_LEDGER_DIGESTS"
REVEAL_COMMITMENT_SCHEME = "SHA256_DOMAIN_SEPARATED_CANONICAL_PAYLOAD_PLUS_32_BYTE_NONCE"
RESOURCE_ACCOUNTING_MODE = "DECLARED_EXPLORATORY_COUNTERS_NOT_AUDITED_TIME_OR_COST"

CONTROL_ROLES = ("POSITIVE", "FAILED_TRANSLATION", "AMBIGUOUS")
POLICIES = ("CAUSALFRONTIER", "SIMPLE_RULE_PREDECLARED")
ACTIONS = frozenset({"NEXT_FALSIFICATION", "REJECT_TRANSLATION", "NO_CALL"})
REQUIRED_BEHAVIOR = {
    "POSITIVE": "NEXT_FALSIFICATION",
    "FAILED_TRANSLATION": "REJECT_TRANSLATION",
    "AMBIGUOUS": "NO_CALL",
}
LEDGER_STAGES = (
    "preprocessing",
    "retrieval",
    "model_tool_calls",
    "retries",
    "human",
    "compute",
    "calendar",
    "direct_cost",
)

MAX_INPUTS_PER_CONTROL = 24
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_COUNTER = 1_000_000_000_000
GENESIS = "0" * 64
OPAQUE_CONTROL_RE = re.compile(r"entrant:control:[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{64}\Z")
DATA_CLASSES = frozenset({"PUBLIC_AGGREGATE", "PUBLIC_METADATA", "SYNTHETIC"})
AUTHORITIES = frozenset({"PUBLIC_DATA", "SYNTHETIC_DATA"})

LOCK_NONCLAIMS = (
    "This lock binds known-hindsight calibration artifacts and never makes them prospective primary cases.",
    "A caller checkpoint and local hash replay do not establish independent time, custody, or rollback resistance.",
    "Opaque identifiers hide labels syntactically only; the steward manifest exposes roles and blinding is unverified.",
    "Declared exploratory resource counters are not audited time, labor, compute, or fully loaded cost.",
    "Input text is structurally screened; data-class declarations do not certify the absence of sensitive content.",
    "Roles, required behaviors, and control semantics are steward declarations without independent adjudication.",
    "No machine-verifiable total branch contract is present in this calibration bundle.",
    "Three-way action labels do not verify the scientific semantics of the proposed falsification or rejection.",
    "No opening is read and no patient datum, experiment, policy code, or artifact content is executed.",
    "No patient, clinical, human-decision, biological-material, scoring, publication, or release authority is granted.",
)

REPORT_NONCLAIMS = (
    "Calibration PASS means only that a frozen action matches a committed known-hindsight role oracle.",
    "Modern-model training exposure and content-level outcome leakage remain unresolved after every PASS.",
    "Declared availability timestamps are not independent temporal attestations of the exact source bytes.",
    "Committed reveal-source digests and availability declarations do not verify the source bytes or their actual "
    "public availability.",
    "Caller-preserved local checkpoints do not establish independent custody or rollback resistance.",
    "Roles, required behaviors, control identities, and scientific semantics are steward declarations.",
    "No machine-verifiable total branch contract is present in this calibration bundle.",
    "A label-role match is not calibrated abstention or validation of the action's scientific semantics.",
    "Policy outputs and resource ledgers are byte-bound declarations, not independently generated or audited facts.",
    "The simple-rule policy is retained as a diagnostic and cannot create a winner, ranking, or comparison claim.",
    "Known-hindsight calibration controls never enter primary effect estimation or scientific performance scoring.",
    "No patient, clinical, human-decision, biological-material, scoring, publication, or release authority is granted.",
)


def _nonzero_sha256(value: Any, field: str) -> str:
    digest = require_sha256(value, field)
    if digest == GENESIS:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return digest


def _bounded_counter(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def _relative_path(value: Any, field: str) -> str:
    try:
        relative = receipt_io._relative(value)
    except CausalFrontierError:
        raise CausalFrontierError("%s must be a canonical relative artifact path" % field) from None
    if relative.casefold() == MANIFEST.casefold():
        raise CausalFrontierError("%s must not alias the calibration manifest" % field)
    return relative


def _opaque_control_id(value: Any, field: str) -> str:
    identity = require_id(value, field)
    if OPAQUE_CONTROL_RE.fullmatch(identity) is None:
        raise CausalFrontierError("%s must be an exact opaque control identifier" % field)
    return identity


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    receipt_io._screen(canonical_bytes(value))
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    return value


def _read_checkpointed_json(path: Path, expected_sha256: str, label: str) -> tuple[bytes, dict[str, Any]]:
    checkpoint = _nonzero_sha256(expected_sha256, "%s external checkpoint" % label)
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError:
        raise CausalFrontierError("%s cannot be read safely" % label) from None
    if not hmac.compare_digest(sha256_bytes(raw), checkpoint):
        raise CausalFrontierError("%s external checkpoint mismatch" % label)
    return raw, _strict_json(raw, label)


def _input_descriptor(value: Any, cutoff: str, field: str) -> dict[str, Any]:
    item = require_exact_keys(value, {"path", "sha256", "available_at", "data_class", "authority"}, field)
    path = _relative_path(item["path"], "%s.path" % field)
    digest = _nonzero_sha256(item["sha256"], "%s.sha256" % field)
    available_at = require_utc_timestamp(item["available_at"], "%s.available_at" % field)
    if available_at > cutoff:
        raise CausalFrontierError("calibration input was declared available after its knowledge cutoff")
    data_class = require_enum(item["data_class"], set(DATA_CLASSES), "%s.data_class" % field)
    authority = require_enum(item["authority"], set(AUTHORITIES), "%s.authority" % field)
    expected_authority = "SYNTHETIC_DATA" if data_class == "SYNTHETIC" else "PUBLIC_DATA"
    if authority != expected_authority:
        raise CausalFrontierError("calibration input data class and authority differ")
    return {
        "path": path,
        "sha256": digest,
        "available_at": available_at,
        "data_class": data_class,
        "authority": authority,
    }


def _artifact_descriptor(value: Any, field: str) -> dict[str, str]:
    item = require_exact_keys(value, {"policy_id", "path", "sha256"}, field)
    return {
        "policy_id": require_enum(item["policy_id"], set(POLICIES), "%s.policy_id" % field),
        "path": _relative_path(item["path"], "%s.path" % field),
        "sha256": _nonzero_sha256(item["sha256"], "%s.sha256" % field),
    }


def _validate_control(value: Any, role: str, index: int) -> dict[str, Any]:
    field = "calibration control[%d]" % index
    control = require_exact_keys(
        value,
        {
            "role",
            "opaque_id",
            "knowledge_cutoff",
            "required_behavior",
            "inputs",
            "outputs",
            "resource_ledgers",
        },
        field,
    )
    if control["role"] != role:
        raise CausalFrontierError("calibration controls must use canonical role order")
    opaque_id = _opaque_control_id(control["opaque_id"], "%s.opaque_id" % field)
    cutoff = require_utc_timestamp(control["knowledge_cutoff"], "%s.knowledge_cutoff" % field)
    if control["required_behavior"] != REQUIRED_BEHAVIOR[role]:
        raise CausalFrontierError("calibration role required behavior differs from the fixed contract")

    raw_inputs = control["inputs"]
    if not isinstance(raw_inputs, list) or not 1 <= len(raw_inputs) <= MAX_INPUTS_PER_CONTROL:
        raise CausalFrontierError("every calibration control must have a bounded nonempty input inventory")
    inputs = [_input_descriptor(item, cutoff, "%s.inputs[%d]" % (field, i)) for i, item in enumerate(raw_inputs)]
    input_paths = [item["path"] for item in inputs]
    if input_paths != sorted(input_paths) or len({path.casefold() for path in input_paths}) != len(input_paths):
        raise CausalFrontierError("calibration input descriptors must be uniquely sorted by canonical path")

    outputs = control["outputs"]
    ledgers = control["resource_ledgers"]
    if not isinstance(outputs, list) or not isinstance(ledgers, list):
        raise CausalFrontierError("calibration output and ledger descriptors must be lists")
    if len(outputs) != len(POLICIES) or len(ledgers) != len(POLICIES):
        raise CausalFrontierError("every calibration control must bind exactly two outputs and two ledgers")
    normalized_outputs = [_artifact_descriptor(item, "%s.outputs[%d]" % (field, i)) for i, item in enumerate(outputs)]
    normalized_ledgers = [
        _artifact_descriptor(item, "%s.resource_ledgers[%d]" % (field, i)) for i, item in enumerate(ledgers)
    ]
    if [item["policy_id"] for item in normalized_outputs] != list(POLICIES) or [
        item["policy_id"] for item in normalized_ledgers
    ] != list(POLICIES):
        raise CausalFrontierError("calibration policy descriptors must use the fixed policy order")
    return {
        "role": role,
        "opaque_id": opaque_id,
        "knowledge_cutoff": cutoff,
        "required_behavior": control["required_behavior"],
        "inputs": inputs,
        "outputs": normalized_outputs,
        "resource_ledgers": normalized_ledgers,
    }


def _validate_manifest(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = require_exact_keys(
        value,
        {
            "schema_version",
            "id",
            "fixed_parameter",
            "boundary",
            "known_hindsight",
            "prospective",
            "model_contamination_unresolved",
            "calibration_only",
            "primary_performance_eligible",
            "scientific_scoring_ready",
            "reveal_commitment_scheme",
            "reveal_commitment_sha256",
            "policies",
            "controls",
        },
        "calibration tripwire manifest",
    )
    if (
        manifest["schema_version"] != MANIFEST_SCHEMA_VERSION
        or manifest["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(manifest["boundary"]) != BOUNDARY_CANONICAL
        or manifest["known_hindsight"] is not True
        or manifest["prospective"] is not False
        or manifest["model_contamination_unresolved"] is not True
        or manifest["calibration_only"] is not True
        or manifest["primary_performance_eligible"] is not False
        or manifest["scientific_scoring_ready"] is not False
        or manifest["reveal_commitment_scheme"] != REVEAL_COMMITMENT_SCHEME
        or manifest["policies"] != list(POLICIES)
    ):
        raise CausalFrontierError("calibration manifest targets another contract or overclaims its boundary")
    require_id(manifest["id"], "calibration tripwire id")
    _nonzero_sha256(manifest["reveal_commitment_sha256"], "calibration reveal commitment")
    raw_controls = manifest["controls"]
    if not isinstance(raw_controls, list) or len(raw_controls) != len(CONTROL_ROLES):
        raise CausalFrontierError("calibration manifest must contain exactly three controls")
    controls = [
        _validate_control(item, role, index)
        for index, (item, role) in enumerate(zip(raw_controls, CONTROL_ROLES, strict=True))
    ]
    opaque_ids = [item["opaque_id"] for item in controls]
    if len({identity.casefold() for identity in opaque_ids}) != len(opaque_ids):
        raise CausalFrontierError("calibration opaque control identifiers must be unique")
    input_digest_multisets = [tuple(sorted(item["sha256"] for item in control["inputs"])) for control in controls]
    if len(set(input_digest_multisets)) != len(input_digest_multisets):
        raise CausalFrontierError("calibration controls must not use identical complete input digest multisets")
    return manifest, controls


def _validate_output(value: Any, control: dict[str, Any], policy_id: str) -> dict[str, Any]:
    output = require_exact_keys(value, {"schema_version", "opaque_id", "policy_id", "action"}, "policy output")
    if (
        output["schema_version"] != OUTPUT_SCHEMA_VERSION
        or output["opaque_id"] != control["opaque_id"]
        or output["policy_id"] != policy_id
    ):
        raise CausalFrontierError("calibration policy output targets another control or policy")
    require_enum(output["action"], set(ACTIONS), "calibration policy action")
    return output


def _validate_ledger(value: Any, control: dict[str, Any], policy_id: str) -> dict[str, Any]:
    ledger = require_exact_keys(
        value,
        {"schema_version", "opaque_id", "policy_id", "stages", "complete", "reveal_accessed"},
        "resource ledger",
    )
    if (
        ledger["schema_version"] != LEDGER_SCHEMA_VERSION
        or ledger["opaque_id"] != control["opaque_id"]
        or ledger["policy_id"] != policy_id
        or ledger["complete"] is not True
        or ledger["reveal_accessed"] is not False
    ):
        raise CausalFrontierError("calibration resource ledger is incomplete, opened, or misbound")
    stages = require_exact_keys(ledger["stages"], set(LEDGER_STAGES), "resource ledger stages")
    counters = {stage: _bounded_counter(stages[stage], "resource ledger %s" % stage) for stage in LEDGER_STAGES}
    if sum(counters.values()) == 0:
        raise CausalFrontierError("calibration resource ledger must not be an all-zero placeholder")
    return {**ledger, "stages": counters}


def _execution_components(controls: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {
        "input_inventory_sha256s": [item["input_inventory_sha256"] for item in controls],
        "output_raw_sha256s": [
            binding["output_sha256"] for control in controls for binding in control["policy_bindings"]
        ],
        "resource_ledger_raw_sha256s": [
            binding["resource_ledger_sha256"] for control in controls for binding in control["policy_bindings"]
        ],
    }


def _execution_checkpoint(controls: list[dict[str, Any]]) -> str:
    components = _execution_components(controls)
    if (
        len(components["input_inventory_sha256s"]) != 3
        or len(components["output_raw_sha256s"]) != 6
        or len(components["resource_ledger_raw_sha256s"]) != 6
    ):
        raise CausalFrontierError("calibration execution checkpoint component count differs")
    return sha256_bytes(EXECUTION_CHECKPOINT_DOMAIN_TAG + canonical_bytes(components))


def _load_bundle(root: Path, expected_manifest_sha256: str) -> dict[str, Any]:
    manifest_checkpoint = _nonzero_sha256(expected_manifest_sha256, "external calibration manifest checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, MANIFEST)
            if not hmac.compare_digest(sha256_bytes(raw_manifest), manifest_checkpoint):
                raise CausalFrontierError("external calibration manifest checkpoint mismatch")
            manifest_value = _strict_json(raw_manifest, MANIFEST)
            manifest, controls = _validate_manifest(manifest_value)

            descriptor_by_path: dict[str, dict[str, Any]] = {}
            kind_by_path: dict[str, tuple[str, int, int | None]] = {}
            for control_index, control in enumerate(controls):
                for item in control["inputs"]:
                    if item["path"] in descriptor_by_path:
                        raise CausalFrontierError("calibration artifact path is reused")
                    descriptor_by_path[item["path"]] = item
                    kind_by_path[item["path"]] = ("input", control_index, None)
                for policy_index, item in enumerate(control["outputs"]):
                    if item["path"] in descriptor_by_path:
                        raise CausalFrontierError("calibration artifact path is reused")
                    descriptor_by_path[item["path"]] = item
                    kind_by_path[item["path"]] = ("output", control_index, policy_index)
                for policy_index, item in enumerate(control["resource_ledgers"]):
                    if item["path"] in descriptor_by_path:
                        raise CausalFrontierError("calibration artifact path is reused")
                    descriptor_by_path[item["path"]] = item
                    kind_by_path[item["path"]] = ("ledger", control_index, policy_index)
            paths = list(descriptor_by_path)
            if len({path.casefold() for path in paths}) != len(paths):
                raise CausalFrontierError("calibration artifact paths contain a casefold collision")
            expected_files = {MANIFEST, *paths}
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError("calibration root file inventory differs")

            snapshots: dict[str, bytes] = {}
            parsed_outputs: dict[tuple[int, int], dict[str, Any]] = {}
            parsed_ledgers: dict[tuple[int, int], dict[str, Any]] = {}
            total_bytes = len(raw_manifest)
            for path in sorted(paths):
                raw = receipt_io._snapshot(descriptor, path)
                snapshots[path] = raw
                total_bytes += len(raw)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("calibration bundle exceeds its total byte limit")
                expected_digest = descriptor_by_path[path]["sha256"]
                if not hmac.compare_digest(sha256_bytes(raw), expected_digest):
                    raise CausalFrontierError("calibration artifact digest mismatch")
                receipt_io._screen(raw)
                kind, control_index, policy_index = kind_by_path[path]
                if kind == "input":
                    _strict_json(raw, "calibration input")
                elif kind == "output":
                    if policy_index is None:
                        raise CausalFrontierError("calibration output is missing its fixed policy coordinate")
                    parsed_outputs[(control_index, policy_index)] = _validate_output(
                        _strict_json(raw, "calibration policy output"), controls[control_index], POLICIES[policy_index]
                    )
                elif kind == "ledger":
                    if policy_index is None:
                        raise CausalFrontierError("calibration ledger is missing its fixed policy coordinate")
                    parsed_ledgers[(control_index, policy_index)] = _validate_ledger(
                        _strict_json(raw, "calibration resource ledger"),
                        controls[control_index],
                        POLICIES[policy_index],
                    )
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError("calibration root inventory changed while being read")
            for path, original in sorted(snapshots.items()):
                if receipt_io._snapshot(descriptor, path) != original:
                    raise CausalFrontierError("calibration artifact changed during preflight")
            if receipt_io._snapshot(descriptor, MANIFEST) != raw_manifest:
                raise CausalFrontierError("calibration manifest changed during preflight")
    except OSError:
        raise CausalFrontierError("calibration filesystem cannot be read safely") from None

    bound_controls = []
    for control_index, control in enumerate(controls):
        inventory_digest = sha256_bytes(INPUT_INVENTORY_DOMAIN_TAG + canonical_bytes(control["inputs"]))
        bindings = []
        for policy_index, policy_id in enumerate(POLICIES):
            output = parsed_outputs[(control_index, policy_index)]
            ledger = parsed_ledgers[(control_index, policy_index)]
            bindings.append(
                {
                    "policy_id": policy_id,
                    "action": output["action"],
                    "output_sha256": control["outputs"][policy_index]["sha256"],
                    "resource_ledger_sha256": control["resource_ledgers"][policy_index]["sha256"],
                    "resource_counters": ledger["stages"],
                    "resource_ledger_complete": True,
                    "reveal_accessed": False,
                }
            )
        bound_controls.append(
            {
                "role": control["role"],
                "opaque_id": control["opaque_id"],
                "knowledge_cutoff": control["knowledge_cutoff"],
                "required_behavior": control["required_behavior"],
                "inputs_n": len(control["inputs"]),
                "input_raw_sha256s": [item["sha256"] for item in control["inputs"]],
                "input_inventory_sha256": inventory_digest,
                "policy_bindings": bindings,
            }
        )
    return {
        "manifest": manifest,
        "manifest_checkpoint_sha256": manifest_checkpoint,
        "canonical_manifest_sha256": sha256_bytes(canonical_bytes(manifest)),
        "controls": bound_controls,
        "execution_components": _execution_components(bound_controls),
        "execution_checkpoint_sha256": _execution_checkpoint(bound_controls),
        "input_files_n": sum(item["inputs_n"] for item in bound_controls),
    }


def _build_lock(bundle: dict[str, Any], expected_execution_checkpoint_sha256: str) -> dict[str, Any]:
    execution_checkpoint = _nonzero_sha256(
        expected_execution_checkpoint_sha256, "external calibration execution checkpoint"
    )
    if not hmac.compare_digest(bundle["execution_checkpoint_sha256"], execution_checkpoint):
        raise CausalFrontierError("external calibration execution checkpoint mismatch")
    manifest = bundle["manifest"]
    candidate_always_abstains = all(
        control["policy_bindings"][0]["action"] == "NO_CALL" for control in bundle["controls"]
    )
    core = {
        "schema_version": LOCK_SCHEMA_VERSION,
        "status": LOCK_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "tripwire_id": manifest["id"],
        "manifest_checkpoint_sha256": bundle["manifest_checkpoint_sha256"],
        "canonical_manifest_sha256": bundle["canonical_manifest_sha256"],
        "execution_checkpoint_scheme": EXECUTION_CHECKPOINT_SCHEME,
        "execution_checkpoint_sha256": execution_checkpoint,
        "execution_checkpoint_components": bundle["execution_components"],
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": manifest["reveal_commitment_sha256"],
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "controls_n": len(CONTROL_ROLES),
        "input_files_n": bundle["input_files_n"],
        "outputs_n": len(CONTROL_ROLES) * len(POLICIES),
        "resource_ledgers_n": len(CONTROL_ROLES) * len(POLICIES),
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "controls": bundle["controls"],
        "input_digest_multisets_distinct_verified": True,
        "candidate_always_abstain_equivalent": candidate_always_abstains,
        "opening_read": False,
        "temporal_attestation_verified": False,
        "content_outcome_isolation_verified": False,
        "independent_output_generation_verified": False,
        "policy_generation_independence_verified": False,
        "real_resource_measurement_verified": False,
        "blinding_verified": False,
        "privacy_certified": False,
        "independent_custody_verified": False,
        "rollback_resistance_verified": False,
        "branch_totality_verified": False,
        "control_semantic_validity_verified": False,
        "action_semantics_verified": False,
        "calibrated_abstention_verified": False,
        "winner": None,
        "ranking": [],
        "primary_scoring_ready": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(LOCK_NONCLAIMS),
    }
    return {**core, "lock_sha256": sha256_bytes(LOCK_DOMAIN_TAG + canonical_bytes(core))}


def lock_calibration_tripwire(
    root: Path,
    expected_manifest_sha256: str,
    expected_execution_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Bind exact inputs, outputs, and ledgers without reading an opening.

    ``expected_manifest_sha256`` is the raw manifest-file checkpoint.
    ``expected_execution_checkpoint_sha256`` is independently supplied and is
    recomputed from exactly three canonical input-inventory digests, six raw
    output digests, and six raw ledger digests in fixed role/policy order.
    """

    return _build_lock(_load_bundle(root, expected_manifest_sha256), expected_execution_checkpoint_sha256)


def _validate_lock(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    lock = require_exact_keys(value, set(expected), "calibration tripwire lock")
    _nonzero_sha256(lock["lock_sha256"], "calibration lock semantic digest")
    core = {key: lock[key] for key in lock if key != "lock_sha256"}
    if lock["lock_sha256"] != sha256_bytes(LOCK_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("calibration lock semantic digest mismatch")
    if canonical_bytes(lock) != canonical_bytes(expected):
        raise CausalFrontierError("calibration lock does not replay from the exact closed bundle")
    return lock


def _nonce_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or NONCE_RE.fullmatch(value) is None:
        raise CausalFrontierError("calibration reveal nonce must be exactly 32 lowercase hexadecimal bytes")
    return bytes.fromhex(value)


def _reveal_commitment(payload: dict[str, Any], nonce_hex: str) -> str:
    return sha256_bytes(REVEAL_DOMAIN_TAG + canonical_bytes(payload) + b"\0" + _nonce_bytes(nonce_hex))


def _validate_opening(value: Any, bundle: dict[str, Any]) -> dict[str, Any]:
    opening = require_exact_keys(value, {"schema_version", "nonce_hex", "payload"}, "calibration opening")
    if opening["schema_version"] != OPENING_SCHEMA_VERSION:
        raise CausalFrontierError("calibration opening has an unregistered schema")
    nonce_hex = opening["nonce_hex"]
    _nonce_bytes(nonce_hex)
    payload = require_exact_keys(
        opening["payload"], {"schema_version", "tripwire_id", "entries"}, "calibration opening payload"
    )
    if (
        payload["schema_version"] != OPENING_PAYLOAD_SCHEMA_VERSION
        or payload["tripwire_id"] != bundle["manifest"]["id"]
    ):
        raise CausalFrontierError("calibration opening targets another tripwire")
    entries = payload["entries"]
    if not isinstance(entries, list) or len(entries) != len(CONTROL_ROLES):
        raise CausalFrontierError("calibration opening must contain exactly three role entries")
    normalized_entries = []
    for index, (entry_value, control, role) in enumerate(zip(entries, bundle["controls"], CONTROL_ROLES, strict=True)):
        entry = require_exact_keys(
            entry_value,
            {"role", "opaque_id", "oracle_state", "reveal_source_sha256", "reveal_available_at"},
            "calibration opening entry[%d]" % index,
        )
        if entry["role"] != role or entry["opaque_id"] != control["opaque_id"]:
            raise CausalFrontierError("calibration opening entries must match canonical locked control identities")
        if entry["oracle_state"] != role:
            raise CausalFrontierError("calibration opening oracle state does not confirm its locked role")
        _nonzero_sha256(entry["reveal_source_sha256"], "calibration reveal source digest")
        available_at = require_utc_timestamp(entry["reveal_available_at"], "calibration reveal availability")
        if available_at <= control["knowledge_cutoff"]:
            raise CausalFrontierError("calibration reveal source must be declared available after the knowledge cutoff")
        normalized_entries.append(entry)
    if not hmac.compare_digest(_reveal_commitment(payload, nonce_hex), bundle["manifest"]["reveal_commitment_sha256"]):
        raise CausalFrontierError("calibration opening does not match the reveal commitment")
    return {**opening, "payload": {**payload, "entries": normalized_entries}}


def _policy_result(role: str, action: str) -> str:
    required = REQUIRED_BEHAVIOR[role]
    if action == required:
        return "PASS"
    if action == "NO_CALL":
        return "NO_CALL"
    return "FAIL"


def _build_report(
    bundle: dict[str, Any],
    lock: dict[str, Any],
    expected_lock_sha256: str,
    opening: dict[str, Any],
    expected_opening_sha256: str,
) -> dict[str, Any]:
    role_results = []
    for control, entry in zip(bundle["controls"], opening["payload"]["entries"], strict=True):
        policy_results = []
        for binding in control["policy_bindings"]:
            status = _policy_result(control["role"], binding["action"])
            policy_results.append(
                {
                    "policy_id": binding["policy_id"],
                    "action": binding["action"],
                    "status": status,
                    "diagnostic_only": binding["policy_id"] == "SIMPLE_RULE_PREDECLARED",
                    "output_sha256": binding["output_sha256"],
                    "resource_ledger_sha256": binding["resource_ledger_sha256"],
                    "resource_counters": binding["resource_counters"],
                    "resource_ledger_complete": True,
                    "real_resource_measurement_verified": False,
                }
            )
        candidate_status = policy_results[0]["status"]
        role_results.append(
            {
                "role": control["role"],
                "opaque_id": control["opaque_id"],
                "required_behavior": control["required_behavior"],
                "oracle_state": entry["oracle_state"],
                "reveal_source_sha256": entry["reveal_source_sha256"],
                "reveal_available_at": entry["reveal_available_at"],
                "policies": policy_results,
                "control_status": candidate_status,
            }
        )
    controls_passed_n = sum(item["control_status"] == "PASS" for item in role_results)
    all_pass = controls_passed_n == len(CONTROL_ROLES)
    candidate_always_abstains = all(item["policies"][0]["action"] == "NO_CALL" for item in role_results)
    block_reasons = ["KNOWN_HINDSIGHT_CALIBRATION_ONLY", "MODEL_CONTAMINATION_UNRESOLVED"]
    if not all_pass:
        block_reasons.append("ONE_OR_MORE_REQUIRED_CAUSALFRONTIER_CONTROL_RESULTS_NOT_PASS")
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": REPORT_PASS_STATUS if all_pass else REPORT_BLOCKED_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "tripwire_id": bundle["manifest"]["id"],
        "manifest_checkpoint_sha256": bundle["manifest_checkpoint_sha256"],
        "canonical_manifest_sha256": bundle["canonical_manifest_sha256"],
        "execution_checkpoint_scheme": EXECUTION_CHECKPOINT_SCHEME,
        "execution_checkpoint_sha256": bundle["execution_checkpoint_sha256"],
        "lock_checkpoint_sha256": expected_lock_sha256,
        "lock_sha256": lock["lock_sha256"],
        "opening_checkpoint_sha256": expected_opening_sha256,
        "opening_payload_sha256": sha256_bytes(canonical_bytes(opening["payload"])),
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": bundle["manifest"]["reveal_commitment_sha256"],
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "controls_n": len(CONTROL_ROLES),
        "controls_passed_n": controls_passed_n,
        "action_role_matches_n": controls_passed_n,
        "all_required_roles_pass": all_pass,
        "control_failure_blocks_primary_scoring": not all_pass,
        "primary_scoring_blocked": True,
        "primary_scoring_block_reasons": block_reasons,
        "role_results": role_results,
        "input_digest_multisets_distinct_verified": True,
        "candidate_always_abstain_equivalent": candidate_always_abstains,
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "simple_rule_diagnostic_only": True,
        "comparison_performed": False,
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "temporal_admissibility_verified": False,
        "temporal_attestation_verified": False,
        "content_outcome_isolation_verified": False,
        "independent_output_generation_verified": False,
        "policy_generation_independence_verified": False,
        "real_resource_measurement_verified": False,
        "blinding_verified": False,
        "privacy_certified": False,
        "independent_custody_verified": False,
        "rollback_resistance_verified": False,
        "branch_totality_verified": False,
        "control_semantic_validity_verified": False,
        "action_semantics_verified": False,
        "calibrated_abstention_verified": False,
        "primary_scoring_ready": False,
        "scientific_scoring_ready": False,
        "scientific_claim_ready": False,
        "nonclaims": list(REPORT_NONCLAIMS),
    }
    return {**core, "report_sha256": sha256_bytes(REPORT_DOMAIN_TAG + canonical_bytes(core))}


def _validate_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CausalFrontierError("calibration report must be an object")
    report = value
    expected_keys = {
        "schema_version",
        "status",
        "implementation_status",
        "base_compiler_version",
        "fixed_parameter",
        "boundary",
        "tripwire_id",
        "manifest_checkpoint_sha256",
        "canonical_manifest_sha256",
        "execution_checkpoint_scheme",
        "execution_checkpoint_sha256",
        "lock_checkpoint_sha256",
        "lock_sha256",
        "opening_checkpoint_sha256",
        "opening_payload_sha256",
        "reveal_commitment_scheme",
        "reveal_commitment_sha256",
        "known_hindsight",
        "prospective",
        "model_contamination_unresolved",
        "calibration_only",
        "primary_performance_eligible",
        "controls_n",
        "controls_passed_n",
        "action_role_matches_n",
        "all_required_roles_pass",
        "control_failure_blocks_primary_scoring",
        "primary_scoring_blocked",
        "primary_scoring_block_reasons",
        "role_results",
        "input_digest_multisets_distinct_verified",
        "candidate_always_abstain_equivalent",
        "resource_accounting_mode",
        "simple_rule_diagnostic_only",
        "comparison_performed",
        "winner",
        "ranking",
        "acceleration_ratio",
        "temporal_admissibility_verified",
        "temporal_attestation_verified",
        "content_outcome_isolation_verified",
        "independent_output_generation_verified",
        "policy_generation_independence_verified",
        "real_resource_measurement_verified",
        "blinding_verified",
        "privacy_certified",
        "independent_custody_verified",
        "rollback_resistance_verified",
        "branch_totality_verified",
        "control_semantic_validity_verified",
        "action_semantics_verified",
        "calibrated_abstention_verified",
        "primary_scoring_ready",
        "scientific_scoring_ready",
        "scientific_claim_ready",
        "nonclaims",
        "report_sha256",
    }
    require_exact_keys(report, expected_keys, "calibration report")
    _nonzero_sha256(report["report_sha256"], "calibration report semantic digest")
    core = {key: report[key] for key in report if key != "report_sha256"}
    if report["report_sha256"] != sha256_bytes(REPORT_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("calibration report semantic digest mismatch")
    return report


def evaluate_calibration_tripwire(
    root: Path,
    expected_manifest_sha256: str,
    expected_execution_checkpoint_sha256: str,
    lock_path: Path,
    expected_lock_sha256: str,
    opening_path: Path,
    expected_opening_sha256: str,
) -> dict[str, Any]:
    """Open and evaluate the exact locked tripwire; never enable scoring.

    The CausalFrontier policy determines each role's ``PASS``, ``FAIL``, or
    ``NO_CALL``.  The simple rule is retained only as a diagnostic.  A candidate
    ``NO_CALL`` is a PASS only for a committed opening that confirms the locked
    ``AMBIGUOUS`` role.  Any other candidate ``NO_CALL`` remains ``NO_CALL``.
    """

    bundle = _load_bundle(root, expected_manifest_sha256)
    expected_lock = _build_lock(bundle, expected_execution_checkpoint_sha256)
    raw_lock, lock_value = _read_checkpointed_json(lock_path, expected_lock_sha256, "calibration tripwire lock")
    lock = _validate_lock(lock_value, expected_lock)
    raw_opening, opening_value = _read_checkpointed_json(
        opening_path, expected_opening_sha256, "calibration tripwire opening"
    )
    opening = _validate_opening(opening_value, bundle)
    report = _validate_report(_build_report(bundle, lock, expected_lock_sha256, opening, expected_opening_sha256))

    # Replay every lock input and both external artifacts before returning.  The
    # comparison is over exact bytes as well as the deterministic semantic lock.
    replayed_lock = lock_calibration_tripwire(root, expected_manifest_sha256, expected_execution_checkpoint_sha256)
    second_lock_raw, second_lock_value = _read_checkpointed_json(
        lock_path, expected_lock_sha256, "calibration tripwire lock"
    )
    second_opening_raw, second_opening_value = _read_checkpointed_json(
        opening_path, expected_opening_sha256, "calibration tripwire opening"
    )
    if (
        canonical_bytes(replayed_lock) != canonical_bytes(expected_lock)
        or raw_lock != second_lock_raw
        or canonical_bytes(lock_value) != canonical_bytes(second_lock_value)
        or raw_opening != second_opening_raw
        or canonical_bytes(opening_value) != canonical_bytes(second_opening_value)
    ):
        raise CausalFrontierError("calibration inputs changed during deterministic report replay")
    return report
