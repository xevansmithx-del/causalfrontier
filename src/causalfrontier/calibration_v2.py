"""Role-hidden structured-action calibration protocol (V2).

V1 asks whether a frozen label matches a hidden historical role. V2 rehearses
the structural prerequisites for asking whether a policy turned cutoff-bounded
evidence into a bounded, falsifiable action whose complete branch table handles
the later observation.

The implementation is deliberately offline and read-only.  It validates exact
bytes, a syntactically role-hidden view, structured actions, a finite Cartesian
branch language, a committed outcome opening, a precommitted rubric, and
declared multi-reviewer votes.  It does not establish historical custody,
semantic blinding, reviewer independence, biomedical truth, prospective
performance, resource accuracy, or authority to execute an action.
"""

from __future__ import annotations

import hmac
import itertools
import os
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
    require_text,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

VIEW_MANIFEST = "calibration-v2-view.json"
VIEW_SCHEMA_VERSION = "causalfrontier.calibration-v2-role-hidden-view.v1"
VIEW_LOCK_SCHEMA_VERSION = "causalfrontier.calibration-v2-view-lock.v1"
SUBMISSION_SCHEMA_VERSION = "causalfrontier.calibration-v2-submission.v1"
BRANCH_SCHEMA_VERSION = "causalfrontier.calibration-v2-branch-contract.v1"
SUBMISSION_SEAL_SCHEMA_VERSION = "causalfrontier.calibration-v2-submission-seal.v1"
OPENING_SCHEMA_VERSION = "causalfrontier.calibration-v2-opening.v1"
OPENING_PAYLOAD_SCHEMA_VERSION = "causalfrontier.calibration-v2-opening-payload.v1"
RUBRIC_SCHEMA_VERSION = "causalfrontier.calibration-v2-rubric.v1"
ADJUDICATION_SCHEMA_VERSION = "causalfrontier.calibration-v2-adjudication.v1"
REPORT_SCHEMA_VERSION = "causalfrontier.calibration-v2-report.v1"

VIEW_LOCK_STATUS = "ROLE_HIDDEN_VIEW_STRUCTURALLY_SEALED_BLINDING_UNVERIFIED"
SUBMISSION_SEAL_STATUS = "STRUCTURED_ACTIONS_SEALED_OPENING_NOT_READ"
REPORT_STRUCTURAL_STATUS = "CALIBRATION_V2_STRUCTURAL_REHEARSAL_COMPLETE_INDEPENDENT_REVIEW_REQUIRED"
REPORT_BLOCKED_STATUS = "CALIBRATION_V2_METHOD_RECOVERY_NOT_PASSED"
IMPLEMENTATION_STATUS = "CALIBRATION_V2_STRUCTURAL_ACTION_PROTOCOL_NO_METHOD_RECOVERY_AUTHORITY"

VIEW_LOCK_DOMAIN_TAG = b"causalfrontier.calibration-v2-view-lock.v1\0"
SUBMISSION_SEAL_DOMAIN_TAG = b"causalfrontier.calibration-v2-submission-seal.v1\0"
REVEAL_DOMAIN_TAG = b"causalfrontier.calibration-v2-reveal.v1\0"
RUBRIC_DOMAIN_TAG = b"causalfrontier.calibration-v2-rubric.v1\0"
REPORT_DOMAIN_TAG = b"causalfrontier.calibration-v2-report.v1\0"
VIEW_CONTENT_DOMAIN_TAG = b"causalfrontier.calibration-v2-view-content.v1\0"

REVEAL_COMMITMENT_SCHEME = "SHA256_DOMAIN_SEPARATED_CANONICAL_PAYLOAD_PLUS_32_BYTE_NONCE"
RUBRIC_COMMITMENT_SCHEME = "SHA256_DOMAIN_SEPARATED_CANONICAL_RUBRIC_PLUS_32_BYTE_NONCE"
RESOURCE_ACCOUNTING_MODE = "DECLARED_INTEGER_COUNTERS_NOT_INDEPENDENTLY_METERED"

GENESIS = "0" * 64
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCES_PER_CASE = 24
MAX_CLAIMS_PER_CASE = 16
MAX_INFORMATION_REQUIREMENTS = 16
MAX_FEATURES_PER_CASE = 32
MAX_COUNTER = 10**15
MAX_TEXT = 4000
MAX_JSON_NESTING = 128
MAX_JSON_NODES = 100_000

OPAQUE_CASE_RE = re.compile(r"entrant:case:[0-9a-f]{64}\Z")
OPAQUE_SOURCE_RE = re.compile(r"entrant:source:[0-9a-f]{64}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{64}\Z")

CONTROL_ROLES = ("POSITIVE", "FAILED_TRANSLATION", "AMBIGUOUS")
DATA_CLASSES = frozenset({"PUBLIC_METADATA", "PUBLIC_AGGREGATE", "SYNTHETIC"})
AUTHORITIES = frozenset({"PUBLIC_DATA", "SYNTHETIC_DATA"})
DECISION_MODES = frozenset({"PROPOSE_FALSIFICATION", "BOUNDED_REJECTION", "REQUEST_INFORMATION"})
EVIDENCE_RELATIONS = frozenset({"SUPPORTS", "WEAKENS", "LIMITS_TRANSPORT", "CONTEXT_ONLY", "UNKNOWN"})
COMPLETION_STATES = frozenset({"COMPLETE", "ENTRANT_FAILURE"})
FAILURE_CODES = frozenset({"TIMEOUT", "CRASH", "INVALID_OUTPUT", "RESOURCE_EXHAUSTED"})

BRANCH_CLASSES = (
    "CONTRADICTION",
    "HARM_SIGNAL",
    "OPERATIONAL_FAILURE",
    "SUPPORTS_NEXT_FALSIFICATION",
    "TARGET_ENGAGEMENT_FAILURE",
    "TRANSLATION_FAILURE",
    "UNRESOLVED",
)
_SUCCESSOR_SPEC = (
    ("CONTRADICTION", "NO_CALL"),
    ("HARM_SIGNAL", "STOP_FOR_SAFETY"),
    ("OPERATIONAL_FAILURE", "REPAIR_OR_REPEAT"),
    ("SUPPORTS_NEXT_FALSIFICATION", "ADVANCE_FALSIFICATION"),
    ("TARGET_ENGAGEMENT_FAILURE", "REPAIR_OR_REPEAT"),
    ("TRANSLATION_FAILURE", "REJECT_BOUNDED_TRANSLATION"),
    ("UNRESOLVED", "NO_CALL"),
)
_CLAIM_STATE_SPEC = (
    ("CONTRADICTION", "UNKNOWN"),
    ("HARM_SIGNAL", "UNKNOWN"),
    ("OPERATIONAL_FAILURE", "UNKNOWN"),
    ("SUPPORTS_NEXT_FALSIFICATION", "SURVIVES"),
    ("TARGET_ENGAGEMENT_FAILURE", "UNKNOWN"),
    ("TRANSLATION_FAILURE", "EXCLUDED"),
    ("UNRESOLVED", "UNKNOWN"),
)
# Public snapshots cannot alter the private protocol specification.
SUCCESSOR_BY_BRANCH = dict(_SUCCESSOR_SPEC)
CLAIM_STATE_BY_BRANCH = dict(_CLAIM_STATE_SPEC)

_OBSERVATION_AXIS_SPEC = (
    ("execution_state", ("COMPLETE", "FAILED")),
    ("target_engagement", ("CONFIRMED", "NOT_CONFIRMED", "UNKNOWN")),
    ("translation_outcome", ("BENEFIT", "HARM", "NO_BENEFIT", "UNKNOWN")),
    ("evidence_consistency", ("CONSISTENT", "DISCORDANT", "INSUFFICIENT")),
)
AXIS_ORDER = tuple(axis_id for axis_id, _state_ids in _OBSERVATION_AXIS_SPEC)
# Public snapshots are convenient for fixture authors, but protocol validation is
# always rebuilt from the private immutable tuple above.  Mutating these objects
# therefore cannot mutate the validator's policy.
OBSERVATION_AXES = tuple(
    {"axis_id": axis_id, "state_ids": list(state_ids)} for axis_id, state_ids in _OBSERVATION_AXIS_SPEC
)
STATE_IDS_BY_AXIS = {axis_id: tuple(state_ids) for axis_id, state_ids in _OBSERVATION_AXIS_SPEC}
COORDINATE_COUNT = 72

DERIVATION_STAGES = (
    "TOOLUNIVERSE_CAPTURE",
    "GRACEGRAPH_CAPSULE",
    "GRACELOOP_FRONTIER",
    "CAUSALFRONTIER_STRUCTURED_ACTION",
)
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
ADJUDICATION_CRITERIA = (
    "EX_ANTE_ACTION_VALIDITY",
    "EVIDENCE_DEPENDENT_REASONING",
    "SUCCESSOR_SEMANTICS",
    "AUTHORITY_COMPLIANCE",
)
VERDICTS = frozenset({"PASS", "FAIL", "NO_CALL"})

HIDDEN_SOURCE_KEYS = frozenset(
    {
        "calibration_role",
        "control_role",
        "required_behavior",
        "opened_outcome_class",
        "oracle_state",
        "reveal_available_at",
        "reveal_source_sha256",
        "required_action_kind",
        "expected_action",
        "gold_label",
    }
)

_HIDDEN_KEY_FRAGMENTS = (
    "calibrationrole",
    "controlrole",
    "requiredbehavior",
    "requiredaction",
    "expectedaction",
    "goldlabel",
    "openedoutcome",
    "oracle",
    "revealsource",
)
_HIDDEN_ROLE_VALUES = frozenset(
    {
        "positive",
        "positivecontrol",
        "failedtranslation",
        "failedtranslationcontrol",
        "ambiguous",
        "ambiguouscontrol",
    }
)
_HIDDEN_VALUE_FRAGMENTS = (
    "positivecontrol",
    "failedtranslation",
    "ambiguouscontrol",
    "roleispositive",
    "rolepositive",
    "caseispositive",
    "assignedlabelpositive",
    "labelispositive",
    "roleisambiguous",
    "roleambiguous",
    "caseisambiguous",
    "assignedlabelambiguous",
    "labelisambiguous",
    "expectedaction",
    "requiredaction",
    "goldlabel",
    "controlrole",
    "calibrationrole",
)

VIEW_NONCLAIMS = (
    "Opaque identifiers and omitted role fields establish only a syntactically role-hidden interface.",
    "Recognizable biomedical content and model-training exposure leave semantic blinding unresolved.",
    "Declared source availability is not independent historical custody or temporal attestation.",
    "The exact finite observation language is mechanically closed but not scientifically exhaustive.",
    "Toolbox trace digests bind declarations; this preflight does not replay external tool executions.",
    "No patient, clinical, human-decision, wet-lab, biological-material, scoring, or execution authority is granted.",
)
SEAL_NONCLAIMS = (
    "A complete structured action is a schema-valid proposal, not an independently valid scientific plan.",
    "Candidate declarations do not prove that only the role-hidden view was used.",
    "Declared resource counters are not audited time, labor, compute, network, or cost measurements.",
    "Cartesian totality over fixed states is not biological or semantic exhaustiveness.",
    "No opening or rubric is read while sealing the submission.",
    "No patient, clinical, human-decision, wet-lab, biological-material, scoring, or execution authority is granted.",
)
REPORT_NONCLAIMS = (
    "This implementation cannot issue a method-recovery pass; any future externally reviewed pass would remain "
    "calibration-only and outside prospective primary performance.",
    "Pre-cutoff action fields and later opened observations occupy separate commitment phases; neither is "
    "independently semantically verified.",
    "Historical controls, recognizable entities, and model-training exposure leave contamination unresolved.",
    "Reviewer and organization identifiers are declarations; actual independence and credentials are unverified.",
    "The opening supplies exact committed observation fields, not source-byte classification or independently "
    "adjudicated biomedical truth.",
    "Committed rubric and caller checkpoints do not establish external time, custody, or rollback resistance.",
    "Declared resource counters do not support efficiency, cost, or acceleration comparisons.",
    "Three historical controls cannot establish calibrated abstention or cross-domain generality.",
    "No patient, clinical, human-decision, wet-lab, biological-material, scoring, publication, or execution "
    "authority is granted.",
)


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _nonzero_sha256(value: Any, field: str) -> str:
    digest = require_sha256(value, field)
    if digest == GENESIS:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return digest


def _counter(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def _sorted_ids(value: Any, field: str, *, minimum: int = 0, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise CausalFrontierError("%s has invalid size or type" % field)
    result = [require_id(item, field) for item in value]
    if result != sorted(set(result)):
        raise CausalFrontierError("%s must be sorted and unique" % field)
    return result


def _opaque_case(value: Any, field: str) -> str:
    identity = require_id(value, field)
    if OPAQUE_CASE_RE.fullmatch(identity) is None:
        raise CausalFrontierError("%s must be an opaque case identifier" % field)
    return identity


def _opaque_source(value: Any, field: str) -> str:
    identity = require_id(value, field)
    if OPAQUE_SOURCE_RE.fullmatch(identity) is None:
        raise CausalFrontierError("%s must be an opaque source identifier" % field)
    return identity


def _relative(value: Any, field: str) -> str:
    try:
        result = receipt_io._relative(value)
    except CausalFrontierError:
        raise CausalFrontierError("%s must be a canonical relative path" % field) from None
    if result.casefold() == VIEW_MANIFEST.casefold():
        raise CausalFrontierError("%s must not alias the V2 view manifest" % field)
    for component in Path(result).parts:
        normalized_component = _normalized_marker(component)
        if any(marker in normalized_component for marker in _HIDDEN_ROLE_VALUES):
            raise CausalFrontierError("%s exposes an explicit hidden control role" % field)
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    _validate_json_limits(value, label)
    try:
        receipt_io._screen(canonical_bytes(value))
    except RecursionError:
        raise CausalFrontierError("%s exceeds the safe JSON nesting limit" % label) from None
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    return value


def _normalized_marker(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _validate_json_limits(value: Any, field: str) -> None:
    stack = [(value, 0)]
    visited = 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        if visited > MAX_JSON_NODES:
            raise CausalFrontierError("%s exceeds the safe JSON node limit" % field)
        if depth > MAX_JSON_NESTING:
            raise CausalFrontierError("%s exceeds the safe JSON nesting limit" % field)
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _reject_hidden_source_keys(value: Any, field: str) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            hidden = sorted(set(item) & HIDDEN_SOURCE_KEYS)
            if hidden:
                raise CausalFrontierError("%s exposes hidden oracle keys: %s" % (field, hidden))
            for key, child in item.items():
                normalized_key = _normalized_marker(key)
                if any(fragment in normalized_key for fragment in _HIDDEN_KEY_FRAGMENTS):
                    raise CausalFrontierError("%s exposes a normalized hidden oracle key" % field)
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            normalized_value = _normalized_marker(item)
            if normalized_value in _HIDDEN_ROLE_VALUES or any(
                fragment in normalized_value for fragment in _HIDDEN_VALUE_FRAGMENTS
            ):
                raise CausalFrontierError("%s exposes an explicit hidden control-role value" % field)


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


def _require_disjoint_external_zones(root: Path, paths: list[Path]) -> None:
    try:
        root_resolved = root.resolve(strict=True)
        identities: set[tuple[int, int]] = set()
        resolved_paths: set[Path] = set()
        for path in paths:
            resolved = path.resolve(strict=True)
            if resolved == root_resolved or root_resolved in resolved.parents:
                raise CausalFrontierError("V2 external artifacts must be outside the entrant root")
            info = os.stat(resolved, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            if resolved in resolved_paths or identity in identities:
                raise CausalFrontierError("V2 external artifacts must have disjoint paths and file identities")
            resolved_paths.add(resolved)
            identities.add(identity)
    except CausalFrontierError:
        raise
    except OSError:
        raise CausalFrontierError("V2 artifact zones cannot be resolved safely") from None


def _validate_axes(value: Any) -> None:
    if canonical_bytes(value) != canonical_bytes(observation_axes_v2()):
        raise CausalFrontierError("V2 observation axes differ from the fixed finite language")


def observation_axes_v2() -> list[dict[str, Any]]:
    """Return a fresh JSON-safe copy of the immutable observation language."""

    return [{"axis_id": axis_id, "state_ids": list(state_ids)} for axis_id, state_ids in _OBSERVATION_AXIS_SPEC]


def view_content_binding_v2(manifest: dict[str, Any]) -> str:
    """Bind view content without the two commitments, avoiding a hash cycle."""

    if not isinstance(manifest, dict):
        raise CausalFrontierError("V2 view content binding requires a manifest object")
    excluded = {
        "reveal_commitment_scheme",
        "reveal_commitment_sha256",
        "rubric_commitment_scheme",
        "rubric_commitment_sha256",
    }
    if not excluded <= set(manifest):
        raise CausalFrontierError("V2 view content binding is missing commitment fields")
    content = {key: value for key, value in manifest.items() if key not in excluded}
    return sha256_bytes(VIEW_CONTENT_DOMAIN_TAG + canonical_bytes(content))


def _validate_catalog(
    value: Any,
    field: str,
    *,
    id_key: str,
    keys: set[str],
    minimum: int,
    maximum: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise CausalFrontierError("%s has invalid size or type" % field)
    result = []
    identities = []
    for index, raw in enumerate(value):
        item = _shape(raw, keys, "%s[%d]" % (field, index))
        identity = require_id(item[id_key], "%s[%d].%s" % (field, index, id_key))
        identities.append(identity)
        normalized = dict(item)
        for key in keys - {id_key}:
            normalized[key] = require_text(item[key], "%s[%d].%s" % (field, index, key), MAX_TEXT)
        result.append(normalized)
    if identities != sorted(set(identities)):
        raise CausalFrontierError("%s identifiers must be sorted and unique" % field)
    return result


def _validate_toolbox_contract(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(DERIVATION_STAGES):
        raise CausalFrontierError("V2 toolbox contract must contain exactly four stages")
    result = []
    for index, (raw, stage_id) in enumerate(zip(value, DERIVATION_STAGES, strict=True)):
        item = _shape(
            raw,
            {"stage_id", "implementation_version", "source_tree_sha256"},
            "toolbox contract[%d]" % index,
        )
        if item["stage_id"] != stage_id:
            raise CausalFrontierError("V2 toolbox contract order differs")
        result.append(
            {
                "stage_id": stage_id,
                "implementation_version": require_text(
                    item["implementation_version"], "toolbox implementation version", 200
                ),
                "source_tree_sha256": _nonzero_sha256(item["source_tree_sha256"], "toolbox source digest"),
            }
        )
    return result


def _validate_view_manifest(value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _shape(
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
            "role_labels_omitted",
            "required_behaviors_omitted",
            "oracle_material_omitted",
            "reveal_input_accepted",
            "reveal_commitment_scheme",
            "reveal_commitment_sha256",
            "rubric_commitment_scheme",
            "rubric_commitment_sha256",
            "observation_axes",
            "toolbox_contract",
            "controls",
        },
        "V2 role-hidden view manifest",
    )
    if (
        manifest["schema_version"] != VIEW_SCHEMA_VERSION
        or manifest["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(manifest["boundary"]) != BOUNDARY_CANONICAL
        or manifest["known_hindsight"] is not True
        or manifest["prospective"] is not False
        or manifest["model_contamination_unresolved"] is not True
        or manifest["calibration_only"] is not True
        or manifest["primary_performance_eligible"] is not False
        or manifest["scientific_scoring_ready"] is not False
        or manifest["role_labels_omitted"] is not True
        or manifest["required_behaviors_omitted"] is not True
        or manifest["oracle_material_omitted"] is not True
        or manifest["reveal_input_accepted"] is not False
        or manifest["reveal_commitment_scheme"] != REVEAL_COMMITMENT_SCHEME
        or manifest["rubric_commitment_scheme"] != RUBRIC_COMMITMENT_SCHEME
    ):
        raise CausalFrontierError("V2 view manifest overclaims or targets another boundary")
    require_id(manifest["id"], "V2 protocol id")
    _nonzero_sha256(manifest["reveal_commitment_sha256"], "V2 reveal commitment")
    _nonzero_sha256(manifest["rubric_commitment_sha256"], "V2 rubric commitment")
    _validate_axes(manifest["observation_axes"])
    manifest["toolbox_contract"] = _validate_toolbox_contract(manifest["toolbox_contract"])

    raw_controls = manifest["controls"]
    if not isinstance(raw_controls, list) or len(raw_controls) != len(CONTROL_ROLES):
        raise CausalFrontierError("V2 view must contain exactly three opaque controls")
    _reject_hidden_source_keys(raw_controls, "V2 role-hidden controls")
    controls = []
    case_ids = []
    global_source_ids: set[str] = set()
    global_source_paths: set[str] = set()
    for index, raw in enumerate(raw_controls):
        control = _shape(
            raw,
            {
                "opaque_case_id",
                "knowledge_cutoff",
                "decision_question",
                "sources",
                "claim_catalog",
                "information_requirements",
                "feature_catalog",
            },
            "V2 control[%d]" % index,
        )
        case_id = _opaque_case(control["opaque_case_id"], "V2 opaque case id")
        case_ids.append(case_id)
        cutoff = require_utc_timestamp(control["knowledge_cutoff"], "V2 knowledge cutoff")
        question = require_text(control["decision_question"], "V2 decision question", MAX_TEXT)
        raw_sources = control["sources"]
        if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES_PER_CASE:
            raise CausalFrontierError("V2 control sources have invalid size")
        sources = []
        for source_index, raw_source in enumerate(raw_sources):
            source = _shape(
                raw_source,
                {"opaque_source_id", "path", "sha256", "available_at", "data_class", "authority"},
                "V2 source[%d]" % source_index,
            )
            data_class = require_enum(source["data_class"], set(DATA_CLASSES), "V2 source data class")
            authority = require_enum(source["authority"], set(AUTHORITIES), "V2 source authority")
            if authority != ("SYNTHETIC_DATA" if data_class == "SYNTHETIC" else "PUBLIC_DATA"):
                raise CausalFrontierError("V2 source data class and authority differ")
            available_at = require_utc_timestamp(source["available_at"], "V2 source availability")
            if available_at > cutoff:
                raise CausalFrontierError("V2 source was declared available after its knowledge cutoff")
            source_id = _opaque_source(source["opaque_source_id"], "V2 opaque source id")
            source_path = _relative(source["path"], "V2 source path")
            if source_id in global_source_ids or source_path in global_source_paths:
                raise CausalFrontierError("V2 opaque source identifiers and paths must be globally one-to-one")
            global_source_ids.add(source_id)
            global_source_paths.add(source_path)
            sources.append(
                {
                    "opaque_source_id": source_id,
                    "path": source_path,
                    "sha256": _nonzero_sha256(source["sha256"], "V2 source digest"),
                    "available_at": available_at,
                    "data_class": data_class,
                    "authority": authority,
                }
            )
        source_coordinates = [(item["opaque_source_id"], item["path"]) for item in sources]
        if source_coordinates != sorted(set(source_coordinates)):
            raise CausalFrontierError("V2 source identifiers and paths must be uniquely sorted")
        claims = _validate_catalog(
            control["claim_catalog"],
            "V2 claim catalog",
            id_key="claim_id",
            keys={"claim_id", "label", "scope"},
            minimum=2,
            maximum=MAX_CLAIMS_PER_CASE,
        )
        requirements = _validate_catalog(
            control["information_requirements"],
            "V2 information requirements",
            id_key="requirement_id",
            keys={"requirement_id", "description"},
            minimum=1,
            maximum=MAX_INFORMATION_REQUIREMENTS,
        )
        features = _validate_catalog(
            control["feature_catalog"],
            "V2 feature catalog",
            id_key="feature_id",
            keys={"feature_id", "label"},
            minimum=1,
            maximum=MAX_FEATURES_PER_CASE,
        )
        controls.append(
            {
                "opaque_case_id": case_id,
                "knowledge_cutoff": cutoff,
                "decision_question": question,
                "sources": sources,
                "claim_catalog": claims,
                "information_requirements": requirements,
                "feature_catalog": features,
            }
        )
    if case_ids != sorted(set(case_ids)):
        raise CausalFrontierError("V2 opaque controls must be uniquely sorted")
    return manifest, controls


def _load_view(root: Path, expected_manifest_sha256: str) -> dict[str, Any]:
    checkpoint = _nonzero_sha256(expected_manifest_sha256, "V2 view manifest checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, VIEW_MANIFEST)
            if not hmac.compare_digest(sha256_bytes(raw_manifest), checkpoint):
                raise CausalFrontierError("V2 view manifest checkpoint mismatch")
            manifest, controls = _validate_view_manifest(_strict_json(raw_manifest, VIEW_MANIFEST))
            source_by_path: dict[str, dict[str, Any]] = {}
            for control in controls:
                for source in control["sources"]:
                    if source["path"] in source_by_path:
                        raise CausalFrontierError("V2 source path is reused")
                    source_by_path[source["path"]] = source
            paths = sorted(source_by_path)
            if len({path.casefold() for path in paths}) != len(paths):
                raise CausalFrontierError("V2 source paths contain a casefold collision")
            expected_files = {VIEW_MANIFEST, *paths}
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError("V2 entrant root inventory differs")
            snapshots = {}
            total_bytes = len(raw_manifest)
            for path in paths:
                raw = receipt_io._snapshot(descriptor, path)
                snapshots[path] = raw
                total_bytes += len(raw)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("V2 entrant bundle exceeds its byte limit")
                if not hmac.compare_digest(sha256_bytes(raw), source_by_path[path]["sha256"]):
                    raise CausalFrontierError("V2 source digest mismatch")
                parsed = _strict_json(raw, "V2 source")
                _reject_hidden_source_keys(parsed, "V2 source")
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError("V2 entrant root changed while being read")
            if receipt_io._snapshot(descriptor, VIEW_MANIFEST) != raw_manifest:
                raise CausalFrontierError("V2 view manifest changed during preflight")
            for path, raw in snapshots.items():
                if receipt_io._snapshot(descriptor, path) != raw:
                    raise CausalFrontierError("V2 source changed during preflight")
    except OSError:
        raise CausalFrontierError("V2 entrant filesystem cannot be read safely") from None

    bound_controls = []
    for control in controls:
        bound_controls.append(
            {
                "opaque_case_id": control["opaque_case_id"],
                "knowledge_cutoff": control["knowledge_cutoff"],
                "decision_question": control["decision_question"],
                "source_ids": [item["opaque_source_id"] for item in control["sources"]],
                "source_raw_sha256s": [item["sha256"] for item in control["sources"]],
                "source_inventory_sha256": sha256_bytes(canonical_bytes(control["sources"])),
                "claim_ids": [item["claim_id"] for item in control["claim_catalog"]],
                "information_requirement_ids": [item["requirement_id"] for item in control["information_requirements"]],
                "feature_ids": [item["feature_id"] for item in control["feature_catalog"]],
            }
        )
    return {
        "manifest": manifest,
        "manifest_checkpoint_sha256": checkpoint,
        "manifest_canonical_sha256": sha256_bytes(canonical_bytes(manifest)),
        "controls": bound_controls,
        "artifact_files_n": 1 + len(source_by_path),
        "bundle_bytes": total_bytes,
    }


def _build_view_lock(bundle: dict[str, Any]) -> dict[str, Any]:
    manifest = bundle["manifest"]
    core = {
        "schema_version": VIEW_LOCK_SCHEMA_VERSION,
        "status": VIEW_LOCK_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "protocol_id": manifest["id"],
        "view_content_binding_sha256": view_content_binding_v2(manifest),
        "manifest_checkpoint_sha256": bundle["manifest_checkpoint_sha256"],
        "manifest_canonical_sha256": bundle["manifest_canonical_sha256"],
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": manifest["reveal_commitment_sha256"],
        "rubric_commitment_scheme": RUBRIC_COMMITMENT_SCHEME,
        "rubric_commitment_sha256": manifest["rubric_commitment_sha256"],
        "observation_axes": observation_axes_v2(),
        "coordinate_count": COORDINATE_COUNT,
        "toolbox_contract": manifest["toolbox_contract"],
        "controls": bundle["controls"],
        "controls_n": len(bundle["controls"]),
        "artifact_files_n": bundle["artifact_files_n"],
        "bundle_bytes": bundle["bundle_bytes"],
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "registered_hidden_key_denylist_absent_verified": True,
        "explicit_role_values_absent_under_closed_token_screen_verified": True,
        "semantic_role_omission_verified": False,
        "opaque_identifier_syntax_verified": True,
        "opaque_identifier_hmac_verified": False,
        "exact_file_and_nonempty_directory_inventory_verified": True,
        "branch_language_fixed": True,
        "opening_read": False,
        "semantic_blinding_verified": False,
        "temporal_attestation_verified": False,
        "content_outcome_isolation_verified": False,
        "model_training_cleanliness_verified": False,
        "toolbox_execution_replayed": False,
        "privacy_certified": False,
        "independent_custody_verified": False,
        "rollback_resistance_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(VIEW_NONCLAIMS),
    }
    return {**core, "view_lock_sha256": sha256_bytes(VIEW_LOCK_DOMAIN_TAG + canonical_bytes(core))}


def preflight_calibration_v2_view(root: Path, expected_manifest_sha256: str) -> dict[str, Any]:
    """Seal an exact syntactically role-hidden evidence view without reading an opening."""

    return _build_view_lock(_load_view(root, expected_manifest_sha256))


def _validate_view_lock(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    lock = _shape(value, set(expected), "V2 saved view lock")
    core = {key: lock[key] for key in lock if key != "view_lock_sha256"}
    if lock["view_lock_sha256"] != sha256_bytes(VIEW_LOCK_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("V2 view-lock semantic digest differs")
    if canonical_bytes(lock) != canonical_bytes(expected):
        raise CausalFrontierError("V2 saved view lock does not replay from the entrant bundle")
    return lock


def _coordinate_rows() -> list[list[dict[str, str]]]:
    result = []
    state_lists = [state_ids for _axis_id, state_ids in _OBSERVATION_AXIS_SPEC]
    for states in itertools.product(*state_lists):
        result.append(
            [{"axis_id": axis_id, "state_id": state_id} for axis_id, state_id in zip(AXIS_ORDER, states, strict=True)]
        )
    return result


def _coordinate_mapping(coordinate: list[dict[str, str]]) -> dict[str, str]:
    return {item["axis_id"]: item["state_id"] for item in coordinate}


def _expected_branch(coordinate: list[dict[str, str]]) -> str:
    state = _coordinate_mapping(coordinate)
    # Safety dominates recoverability.  Even an internally inconsistent
    # observation that contains a declared harm signal may never route to a
    # repeat recommendation.
    if state["translation_outcome"] == "HARM":
        return "HARM_SIGNAL"
    if state["execution_state"] == "FAILED":
        return "OPERATIONAL_FAILURE"
    if state["target_engagement"] == "NOT_CONFIRMED":
        return "TARGET_ENGAGEMENT_FAILURE"
    if (
        state["target_engagement"] == "UNKNOWN"
        or state["translation_outcome"] == "UNKNOWN"
        or state["evidence_consistency"] == "INSUFFICIENT"
    ):
        return "UNRESOLVED"
    if state["evidence_consistency"] == "DISCORDANT":
        return "CONTRADICTION"
    if state["translation_outcome"] == "BENEFIT":
        return "SUPPORTS_NEXT_FALSIFICATION"
    return "TRANSLATION_FAILURE"


def _successor_for(branch_class: str) -> str:
    return next(value for key, value in _SUCCESSOR_SPEC if key == branch_class)


def _claim_state_for(branch_class: str) -> str:
    return next(value for key, value in _CLAIM_STATE_SPEC if key == branch_class)


def canonical_branch_rows(claim_ids: list[str]) -> list[dict[str, Any]]:
    """Return the fixed total branch rows for a sorted nonempty claim list."""

    normalized = _sorted_ids(claim_ids, "branch claim ids", minimum=1, maximum=MAX_CLAIMS_PER_CASE)
    rows = []
    for coordinate in _coordinate_rows():
        branch_class = _expected_branch(coordinate)
        rows.append(
            {
                "coordinate": coordinate,
                "branch_class": branch_class,
                "claim_states": [
                    {"claim_id": claim_id, "state": _claim_state_for(branch_class)} for claim_id in normalized
                ],
                "successor": _successor_for(branch_class),
            }
        )
    return rows


def _inactive_proposed(value: dict[str, Any]) -> None:
    expected = {
        "status": "NOT_APPLICABLE",
        "question": None,
        "design_class": None,
        "population_or_system": None,
        "intervention_or_exposure": None,
        "comparator": None,
        "primary_endpoint": None,
        "time_horizon": None,
        "falsification_threshold": None,
        "replication_requirement": None,
        "stopping_boundary": None,
        "required_authorities_if_executed": [],
        "execution_authorized": False,
    }
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("inactive proposed falsification is not canonical")


def _inactive_rejection(value: dict[str, Any]) -> None:
    expected = {
        "status": "NOT_APPLICABLE",
        "rejected_claim_ids": [],
        "retained_claim_ids": [],
        "scope_limit": None,
        "reversal_information_ids": [],
    }
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("inactive bounded rejection is not canonical")


def _inactive_information(value: dict[str, Any]) -> None:
    expected = {
        "status": "NOT_APPLICABLE",
        "unresolved_claim_ids": [],
        "competing_claim_sets": [],
        "requested_information_ids": [],
        "resolution_rule": None,
    }
    if canonical_bytes(value) != canonical_bytes(expected):
        raise CausalFrontierError("inactive minimum-information boundary is not canonical")


def _validate_decision(value: Any, control: dict[str, Any]) -> tuple[str, list[str]]:
    decision = _shape(
        value,
        {
            "mode",
            "target_claim_ids",
            "selected_feature_ids",
            "proposed_falsification",
            "bounded_rejection",
            "minimum_information_boundary",
        },
        "V2 structured decision",
    )
    mode = require_enum(decision["mode"], set(DECISION_MODES), "V2 decision mode")
    target_claim_ids = _sorted_ids(
        decision["target_claim_ids"], "V2 target claim ids", minimum=1, maximum=MAX_CLAIMS_PER_CASE
    )
    if not set(target_claim_ids) <= set(control["claim_ids"]):
        raise CausalFrontierError("V2 decision targets an unknown claim")
    selected_features = _sorted_ids(
        decision["selected_feature_ids"], "V2 selected feature ids", minimum=1, maximum=MAX_FEATURES_PER_CASE
    )
    if not set(selected_features) <= set(control["feature_ids"]):
        raise CausalFrontierError("V2 decision selects an unknown feature")

    proposed = _shape(
        decision["proposed_falsification"],
        {
            "status",
            "question",
            "design_class",
            "population_or_system",
            "intervention_or_exposure",
            "comparator",
            "primary_endpoint",
            "time_horizon",
            "falsification_threshold",
            "replication_requirement",
            "stopping_boundary",
            "required_authorities_if_executed",
            "execution_authorized",
        },
        "V2 proposed falsification",
    )
    rejection = _shape(
        decision["bounded_rejection"],
        {"status", "rejected_claim_ids", "retained_claim_ids", "scope_limit", "reversal_information_ids"},
        "V2 bounded rejection",
    )
    information = _shape(
        decision["minimum_information_boundary"],
        {
            "status",
            "unresolved_claim_ids",
            "competing_claim_sets",
            "requested_information_ids",
            "resolution_rule",
        },
        "V2 minimum-information boundary",
    )
    if mode == "PROPOSE_FALSIFICATION":
        if proposed["status"] != "DESCRIPTION_ONLY_NOT_AUTHORIZED" or proposed["execution_authorized"] is not False:
            raise CausalFrontierError("V2 proposed falsification overclaims status or authority")
        for field in {
            "question",
            "design_class",
            "population_or_system",
            "intervention_or_exposure",
            "comparator",
            "primary_endpoint",
            "time_horizon",
            "falsification_threshold",
            "replication_requirement",
            "stopping_boundary",
        }:
            require_text(proposed[field], "V2 proposed %s" % field, MAX_TEXT)
        authorities = _sorted_ids(
            proposed["required_authorities_if_executed"],
            "V2 required external authorities",
            minimum=1,
            maximum=16,
        )
        allowed = {"DOMAIN_AUTHORITY", "ETHICS_IF_APPLICABLE", "EXTERNAL_REVIEW", "RESOURCE_AUTHORITY"}
        if not set(authorities) <= allowed:
            raise CausalFrontierError("V2 proposal names an unregistered execution authority")
        _inactive_rejection(rejection)
        _inactive_information(information)
    elif mode == "BOUNDED_REJECTION":
        _inactive_proposed(proposed)
        if rejection["status"] != "BOUNDED_REVERSIBLE_REJECTION":
            raise CausalFrontierError("V2 rejection is not bounded and reversible")
        rejected = _sorted_ids(
            rejection["rejected_claim_ids"], "V2 rejected claim ids", minimum=1, maximum=MAX_CLAIMS_PER_CASE
        )
        retained = _sorted_ids(rejection["retained_claim_ids"], "V2 retained claim ids", maximum=MAX_CLAIMS_PER_CASE)
        if set(rejected) & set(retained) or sorted(rejected + retained) != target_claim_ids:
            raise CausalFrontierError("V2 bounded rejection must partition every targeted claim")
        require_text(rejection["scope_limit"], "V2 rejection scope limit", MAX_TEXT)
        reversal = _sorted_ids(
            rejection["reversal_information_ids"],
            "V2 rejection reversal requirements",
            minimum=1,
            maximum=MAX_INFORMATION_REQUIREMENTS,
        )
        if not set(reversal) <= set(control["information_requirement_ids"]):
            raise CausalFrontierError("V2 rejection uses an unknown reversal requirement")
        _inactive_information(information)
    else:
        _inactive_proposed(proposed)
        _inactive_rejection(rejection)
        if information["status"] != "ACTIONABLE_MINIMUM_INFORMATION_BOUNDARY":
            raise CausalFrontierError("V2 information request is not actionable")
        unresolved = _sorted_ids(
            information["unresolved_claim_ids"],
            "V2 unresolved claims",
            minimum=1,
            maximum=MAX_CLAIMS_PER_CASE,
        )
        if unresolved != target_claim_ids:
            raise CausalFrontierError("V2 information request must cover every targeted claim")
        competing = information["competing_claim_sets"]
        if not isinstance(competing, list) or not 2 <= len(competing) <= 16:
            raise CausalFrontierError("V2 information request needs at least two competing claim sets")
        normalized_sets = [
            _sorted_ids(item, "V2 competing claim set", minimum=1, maximum=MAX_CLAIMS_PER_CASE) for item in competing
        ]
        if normalized_sets != sorted(normalized_sets) or len({tuple(item) for item in normalized_sets}) != len(
            normalized_sets
        ):
            raise CausalFrontierError("V2 competing claim sets must be sorted and distinct")
        if any(not set(item) <= set(target_claim_ids) for item in normalized_sets):
            raise CausalFrontierError("V2 competing claim set contains an untargeted claim")
        flattened = [claim_id for item in normalized_sets for claim_id in item]
        if len(flattened) != len(set(flattened)) or sorted(flattened) != target_claim_ids:
            raise CausalFrontierError("V2 competing claim sets must be mutually exclusive and collectively complete")
        requested = _sorted_ids(
            information["requested_information_ids"],
            "V2 requested information",
            minimum=1,
            maximum=MAX_INFORMATION_REQUIREMENTS,
        )
        if not set(requested) <= set(control["information_requirement_ids"]):
            raise CausalFrontierError("V2 information request uses an unknown requirement")
        require_text(information["resolution_rule"], "V2 information resolution rule", MAX_TEXT)
    return mode, selected_features


def _validate_evidence_assessments(
    value: Any, control: dict[str, Any], target_claim_ids: list[str]
) -> tuple[str, bool]:
    expected_coordinates = [
        (source_id, claim_id) for source_id in control["source_ids"] for claim_id in target_claim_ids
    ]
    if not isinstance(value, list) or len(value) != len(expected_coordinates):
        raise CausalFrontierError("V2 evidence assessments must cover every source by target-claim coordinate")
    normalized = []
    relation_pattern = []
    for index, (raw, expected) in enumerate(zip(value, expected_coordinates, strict=True)):
        item = _shape(
            raw,
            {"opaque_source_id", "claim_id", "relation", "reason"},
            "V2 evidence assessment[%d]" % index,
        )
        coordinate = (
            _opaque_source(item["opaque_source_id"], "V2 assessment source id"),
            require_id(item["claim_id"], "V2 assessment claim id"),
        )
        if coordinate != expected:
            raise CausalFrontierError("V2 evidence assessment coordinate order differs")
        relation = require_enum(item["relation"], set(EVIDENCE_RELATIONS), "V2 evidence relation")
        require_text(item["reason"], "V2 evidence assessment reason", MAX_TEXT)
        normalized.append({"source": coordinate[0], "claim": coordinate[1], "relation": relation})
        relation_pattern.append(relation)
    decision_relevant = any(item in {"SUPPORTS", "WEAKENS", "LIMITS_TRANSPORT"} for item in relation_pattern)
    return sha256_bytes(canonical_bytes(relation_pattern)), decision_relevant


def _validate_branch_contract(value: Any, target_claim_ids: list[str], decision: dict[str, Any]) -> str:
    contract = _shape(
        value,
        {
            "schema_version",
            "partition",
            "axis_order",
            "coordinate_count",
            "target_claim_ids",
            "decision_sha256",
            "rows",
        },
        "V2 branch contract",
    )
    if (
        contract["schema_version"] != BRANCH_SCHEMA_VERSION
        or contract["partition"] != "CARTESIAN_TOTAL_ENUMERATION_WITH_FAILURE_HARM_CONTRADICTION_AND_RESIDUAL"
        or contract["axis_order"] != list(AXIS_ORDER)
        or contract["coordinate_count"] != COORDINATE_COUNT
        or contract["target_claim_ids"] != target_claim_ids
        or contract["decision_sha256"] != sha256_bytes(canonical_bytes(decision))
    ):
        raise CausalFrontierError("V2 branch contract header or structured-action binding differs")
    rows = contract["rows"]
    if not isinstance(rows, list) or len(rows) != COORDINATE_COUNT:
        raise CausalFrontierError("V2 branch contract is not a complete Cartesian enumeration")
    observed_classes = set()
    expected_coordinates = _coordinate_rows()
    expected_coordinate_bytes = [canonical_bytes(item) for item in expected_coordinates]
    if len(set(expected_coordinate_bytes)) != COORDINATE_COUNT:
        raise CausalFrontierError("V2 internal coordinate specification is not a unique Cartesian partition")
    actual_coordinate_bytes = []
    for index, (raw, expected_coordinate) in enumerate(zip(rows, expected_coordinates, strict=True)):
        row = _shape(
            raw,
            {"coordinate", "branch_class", "claim_states", "successor"},
            "V2 branch row[%d]" % index,
        )
        if canonical_bytes(row["coordinate"]) != canonical_bytes(expected_coordinate):
            raise CausalFrontierError("V2 branch coordinate order, coverage, or uniqueness differs")
        actual_coordinate_bytes.append(canonical_bytes(row["coordinate"]))
        branch_class = require_enum(row["branch_class"], set(BRANCH_CLASSES), "V2 branch class")
        expected_class = _expected_branch(expected_coordinate)
        if branch_class != expected_class or row["successor"] != _successor_for(expected_class):
            raise CausalFrontierError(
                "V2 branch violates the fixed failure, harm, contradiction, or residual semantics"
            )
        claim_states = row["claim_states"]
        if not isinstance(claim_states, list) or len(claim_states) != len(target_claim_ids):
            raise CausalFrontierError("V2 branch row must cover every targeted claim")
        for raw_state, claim_id in zip(claim_states, target_claim_ids, strict=True):
            state = _shape(raw_state, {"claim_id", "state"}, "V2 branch claim state")
            if state["claim_id"] != claim_id or state["state"] != _claim_state_for(expected_class):
                raise CausalFrontierError("V2 branch claim state violates fixed semantics")
        observed_classes.add(branch_class)
    if len(set(actual_coordinate_bytes)) != COORDINATE_COUNT:
        raise CausalFrontierError("V2 branch contract contains a duplicate or missing coordinate")
    if observed_classes != set(BRANCH_CLASSES):
        raise CausalFrontierError("V2 branch contract does not exercise every required branch class")
    return sha256_bytes(canonical_bytes(rows))


def _validate_derivation_trace(value: Any, toolbox_contract: list[dict[str, str]]) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(DERIVATION_STAGES):
        raise CausalFrontierError("V2 derivation trace must contain exactly four stages")
    result = []
    for index, (raw, contract) in enumerate(zip(value, toolbox_contract, strict=True)):
        item = _shape(
            raw,
            {
                "stage_id",
                "status",
                "implementation_version",
                "source_tree_sha256",
                "artifact_sha256",
                "resource_receipt_sha256",
            },
            "V2 derivation trace[%d]" % index,
        )
        if (
            item["stage_id"] != contract["stage_id"]
            or item["status"] != "DECLARED_ARTIFACT_BOUND_NOT_REPLAYED"
            or item["implementation_version"] != contract["implementation_version"]
            or item["source_tree_sha256"] != contract["source_tree_sha256"]
        ):
            raise CausalFrontierError("V2 derivation trace differs from the frozen toolbox contract")
        result.append(
            {
                **item,
                "artifact_sha256": _nonzero_sha256(item["artifact_sha256"], "V2 derivation artifact digest"),
                "resource_receipt_sha256": _nonzero_sha256(
                    item["resource_receipt_sha256"], "V2 derivation resource digest"
                ),
            }
        )
    return result


def _validate_resource_ledger(value: Any, case_id: str) -> dict[str, Any]:
    ledger = _shape(
        value,
        {
            "opaque_case_id",
            "stages",
            "model_input_tokens",
            "model_output_tokens",
            "tool_calls",
            "network_requests",
            "input_bytes",
            "output_bytes",
            "calendar_elapsed_ns",
            "measurement_origin",
            "complete",
            "reveal_accessed",
        },
        "V2 resource ledger",
    )
    if (
        ledger["opaque_case_id"] != case_id
        or ledger["measurement_origin"] != "DECLARED_ONLY"
        or ledger["complete"] is not True
        or ledger["reveal_accessed"] is not False
    ):
        raise CausalFrontierError("V2 resource ledger is incomplete, opened, misbound, or overclaims measurement")
    stages = _shape(ledger["stages"], set(LEDGER_STAGES), "V2 resource ledger stages")
    normalized_stages = {key: _counter(stages[key], "V2 resource stage %s" % key) for key in LEDGER_STAGES}
    counters = {
        key: _counter(ledger[key], "V2 resource %s" % key)
        for key in {
            "model_input_tokens",
            "model_output_tokens",
            "tool_calls",
            "network_requests",
            "input_bytes",
            "output_bytes",
            "calendar_elapsed_ns",
        }
    }
    if counters["network_requests"] != 0:
        raise CausalFrontierError("V2 role-hidden policy run must declare zero network requests")
    if counters["calendar_elapsed_ns"] == 0 or sum(normalized_stages.values()) + sum(counters.values()) == 0:
        raise CausalFrontierError("V2 resource ledger must contain a positive bounded run")
    return {**ledger, "stages": normalized_stages, **counters}


def _validate_submission(value: Any, view_lock: dict[str, Any]) -> dict[str, Any]:
    submission = _shape(
        value,
        {
            "schema_version",
            "protocol_id",
            "run_id",
            "policy_id",
            "view_lock_sha256",
            "fixed_parameter",
            "generated_from_role_hidden_view_only_declared",
            "cases",
            "resource_ledgers",
        },
        "V2 submission",
    )
    if (
        submission["schema_version"] != SUBMISSION_SCHEMA_VERSION
        or submission["protocol_id"] != view_lock["protocol_id"]
        or submission["view_lock_sha256"] != view_lock["view_lock_sha256"]
        or submission["fixed_parameter"] != FIXED_PARAMETER
        or submission["generated_from_role_hidden_view_only_declared"] is not True
    ):
        raise CausalFrontierError("V2 submission targets another run or overclaims its boundary")
    run_id = require_id(submission["run_id"], "V2 run id")
    policy_id = require_id(submission["policy_id"], "V2 policy id")
    cases = submission["cases"]
    ledgers = submission["resource_ledgers"]
    if not isinstance(cases, list) or len(cases) != len(view_lock["controls"]):
        raise CausalFrontierError("V2 submission must retain every intention-to-test case")
    if not isinstance(ledgers, list) or len(ledgers) != len(cases):
        raise CausalFrontierError("V2 submission must retain one resource ledger per case")
    summaries = []
    modes = []
    evidence_patterns = []
    evidence_relevance = []
    for index, (raw_case, control, raw_ledger) in enumerate(zip(cases, view_lock["controls"], ledgers, strict=True)):
        item = _shape(
            raw_case,
            {
                "opaque_case_id",
                "completion_state",
                "failure_code",
                "decision",
                "evidence_assessments",
                "branch_contract",
                "derivation_trace",
            },
            "V2 submission case[%d]" % index,
        )
        case_id = _opaque_case(item["opaque_case_id"], "V2 submission opaque case id")
        if case_id != control["opaque_case_id"]:
            raise CausalFrontierError("V2 submission case order or identity differs")
        completion_state = require_enum(item["completion_state"], set(COMPLETION_STATES), "V2 completion state")
        ledger = _validate_resource_ledger(raw_ledger, case_id)
        if completion_state == "ENTRANT_FAILURE":
            require_enum(item["failure_code"], set(FAILURE_CODES), "V2 entrant failure code")
            if (
                item["decision"] is not None
                or item["evidence_assessments"] != []
                or item["branch_contract"] is not None
                or item["derivation_trace"] != []
            ):
                raise CausalFrontierError("V2 entrant failure row contains a partial scientific output")
            summaries.append(
                {
                    "opaque_case_id": case_id,
                    "completion_state": completion_state,
                    "failure_code": item["failure_code"],
                    "decision_mode": None,
                    "selected_feature_ids": [],
                    "target_claim_ids": [],
                    "evidence_relation_pattern_sha256": None,
                    "decision_relevant_evidence_declared": False,
                    "branch_rows_sha256": None,
                    "resource_ledger_complete": True,
                }
            )
            continue
        if item["failure_code"] is not None:
            raise CausalFrontierError("V2 complete case must not contain a failure code")
        if not isinstance(item["decision"], dict) or not isinstance(item["branch_contract"], dict):
            raise CausalFrontierError("V2 complete case is missing its structured decision or branch contract")
        mode, selected_features = _validate_decision(item["decision"], control)
        target_claim_ids = item["decision"]["target_claim_ids"]
        evidence_pattern, decision_relevant_evidence = _validate_evidence_assessments(
            item["evidence_assessments"], control, target_claim_ids
        )
        rows_sha256 = _validate_branch_contract(item["branch_contract"], target_claim_ids, item["decision"])
        _validate_derivation_trace(item["derivation_trace"], view_lock["toolbox_contract"])
        modes.append(mode)
        evidence_patterns.append(evidence_pattern)
        evidence_relevance.append(decision_relevant_evidence)
        summaries.append(
            {
                "opaque_case_id": case_id,
                "completion_state": completion_state,
                "failure_code": None,
                "decision_mode": mode,
                "selected_feature_ids": selected_features,
                "target_claim_ids": target_claim_ids,
                "evidence_relation_pattern_sha256": evidence_pattern,
                "decision_relevant_evidence_declared": decision_relevant_evidence,
                "branch_rows_sha256": rows_sha256,
                "resource_ledger_complete": ledger["complete"],
            }
        )
    complete_n = sum(item["completion_state"] == "COMPLETE" for item in summaries)
    constant = complete_n == len(summaries) and len(set(modes)) == 1
    always_abstain = complete_n == len(summaries) and set(modes) == {"REQUEST_INFORMATION"}
    evidence_patterns_distinct = complete_n == len(summaries) and len(set(evidence_patterns)) > 1
    all_decision_relevant = complete_n == len(summaries) and all(evidence_relevance)
    return {
        "schema_version": submission["schema_version"],
        "protocol_id": submission["protocol_id"],
        "run_id": run_id,
        "policy_id": policy_id,
        "view_lock_sha256": submission["view_lock_sha256"],
        "cases": summaries,
        "intention_to_test_cases_n": len(summaries),
        "complete_cases_n": complete_n,
        "entrant_failure_cases_n": len(summaries) - complete_n,
        "action_pattern": [item["decision_mode"] for item in summaries],
        "constant_action_pattern": constant,
        "always_abstain_equivalent": always_abstain,
        "evidence_relation_patterns_distinct": evidence_patterns_distinct,
        "all_complete_cases_decision_relevant_evidence_declared": all_decision_relevant,
        "resource_ledgers_n": len(ledgers),
    }


def _build_submission_seal(
    view_lock: dict[str, Any], submission_raw_sha256: str, summary: dict[str, Any]
) -> dict[str, Any]:
    core = {
        "schema_version": SUBMISSION_SEAL_SCHEMA_VERSION,
        "status": SUBMISSION_SEAL_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "protocol_id": summary["protocol_id"],
        "run_id": summary["run_id"],
        "policy_id": summary["policy_id"],
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_raw_sha256": submission_raw_sha256,
        "intention_to_test_cases_n": summary["intention_to_test_cases_n"],
        "complete_cases_n": summary["complete_cases_n"],
        "entrant_failure_cases_n": summary["entrant_failure_cases_n"],
        "resource_ledgers_n": summary["resource_ledgers_n"],
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "cases": summary["cases"],
        "action_pattern": summary["action_pattern"],
        "constant_action_pattern": summary["constant_action_pattern"],
        "always_abstain_equivalent": summary["always_abstain_equivalent"],
        "evidence_relation_patterns_distinct": summary["evidence_relation_patterns_distinct"],
        "all_complete_cases_decision_relevant_evidence_declared": summary[
            "all_complete_cases_decision_relevant_evidence_declared"
        ],
        "complete_intention_to_test_matrix_verified": True,
        "branch_partition_total_and_exclusive_for_complete_cases_verified": True,
        "resource_ledgers_structurally_complete": True,
        "opening_read": False,
        "rubric_read": False,
        "candidate_isolation_verified": False,
        "independent_output_generation_verified": False,
        "real_resource_measurement_verified": False,
        "semantic_action_validity_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(SEAL_NONCLAIMS),
    }
    return {
        **core,
        "submission_seal_sha256": sha256_bytes(SUBMISSION_SEAL_DOMAIN_TAG + canonical_bytes(core)),
    }


def seal_calibration_v2_submission(
    root: Path,
    expected_manifest_sha256: str,
    view_lock_path: Path,
    expected_view_lock_sha256: str,
    submission_path: Path,
    expected_submission_sha256: str,
) -> dict[str, Any]:
    """Seal a complete intention-to-test output without reading rubric or opening material."""

    _require_disjoint_external_zones(root, [view_lock_path, submission_path])
    expected_lock = preflight_calibration_v2_view(root, expected_manifest_sha256)
    _raw_lock, saved_lock = _read_checkpointed_json(view_lock_path, expected_view_lock_sha256, "V2 saved view lock")
    view_lock = _validate_view_lock(saved_lock, expected_lock)
    raw_submission, submission = _read_checkpointed_json(submission_path, expected_submission_sha256, "V2 submission")
    summary = _validate_submission(submission, view_lock)
    return _build_submission_seal(view_lock, sha256_bytes(raw_submission), summary)


def _validate_submission_seal(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    seal = _shape(value, set(expected), "V2 saved submission seal")
    core = {key: seal[key] for key in seal if key != "submission_seal_sha256"}
    if seal["submission_seal_sha256"] != sha256_bytes(SUBMISSION_SEAL_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("V2 submission-seal semantic digest differs")
    if canonical_bytes(seal) != canonical_bytes(expected):
        raise CausalFrontierError("V2 saved submission seal does not replay from the exact submission")
    return seal


def _nonce(value: Any, field: str = "V2 opening nonce") -> bytes:
    if not isinstance(value, str) or NONCE_RE.fullmatch(value) is None:
        raise CausalFrontierError("%s must be exactly 32 lowercase hexadecimal bytes" % field)
    raw = bytes.fromhex(value)
    if not any(raw):
        raise CausalFrontierError("%s must not be all zero" % field)
    return raw


def reveal_commitment_v2(payload: dict[str, Any], nonce_hex: str) -> str:
    return sha256_bytes(REVEAL_DOMAIN_TAG + canonical_bytes(payload) + b"\0" + _nonce(nonce_hex))


def rubric_commitment_v2(rubric: dict[str, Any]) -> str:
    if not isinstance(rubric, dict) or "nonce_hex" not in rubric:
        raise CausalFrontierError("V2 rubric commitment requires a hidden nonce")
    payload = {key: value for key, value in rubric.items() if key != "nonce_hex"}
    nonce = _nonce(rubric["nonce_hex"], "V2 rubric nonce")
    return sha256_bytes(RUBRIC_DOMAIN_TAG + canonical_bytes(payload) + b"\0" + nonce)


def _validate_review_plan(value: Any) -> dict[str, Any]:
    plan = _shape(
        value,
        {
            "plan_id",
            "minimum_reviewers",
            "minimum_organizations",
            "reviewer_assignments",
            "policy_identity_blinded_required",
            "ex_ante_outcome_hidden_required",
            "phase_separation_required",
            "aggregation_rule",
        },
        "V2 review plan",
    )
    if (
        plan["minimum_reviewers"] != 3
        or plan["minimum_organizations"] != 2
        or plan["policy_identity_blinded_required"] is not True
        or plan["ex_ante_outcome_hidden_required"] is not True
        or plan["phase_separation_required"] is not True
        or plan["aggregation_rule"] != "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL"
    ):
        raise CausalFrontierError("V2 review plan weakens the fixed review boundary")
    require_id(plan["plan_id"], "V2 review plan id")
    assignments = plan["reviewer_assignments"]
    if not isinstance(assignments, list) or len(assignments) != 3:
        raise CausalFrontierError("V2 review plan requires exactly three precommitted assignments")
    normalized = []
    reviewer_ids = []
    organization_ids = []
    checkpoints = []
    for index, raw in enumerate(assignments):
        item = _shape(
            raw,
            {"reviewer_id", "organization_id", "assignment_checkpoint_sha256"},
            "V2 review assignment[%d]" % index,
        )
        reviewer_id = require_id(item["reviewer_id"], "V2 planned reviewer id")
        organization_id = require_id(item["organization_id"], "V2 planned reviewer organization id")
        checkpoint = _nonzero_sha256(item["assignment_checkpoint_sha256"], "V2 review assignment checkpoint")
        reviewer_ids.append(reviewer_id)
        organization_ids.append(organization_id)
        checkpoints.append(checkpoint)
        normalized.append(
            {
                "reviewer_id": reviewer_id,
                "organization_id": organization_id,
                "assignment_checkpoint_sha256": checkpoint,
            }
        )
    if (
        reviewer_ids != sorted(set(reviewer_ids))
        or len(set(organization_ids)) < 2
        or len(set(checkpoints)) != len(checkpoints)
    ):
        raise CausalFrontierError("V2 review assignments must be unique, sorted, and span two organizations")
    return {**plan, "reviewer_assignments": normalized}


def _validate_opening(value: Any, view_lock: dict[str, Any], submission_seal: dict[str, Any]) -> dict[str, Any]:
    opening = _shape(
        value,
        {"schema_version", "view_lock_sha256", "submission_seal_sha256", "nonce_hex", "payload"},
        "V2 opening",
    )
    if (
        opening["schema_version"] != OPENING_SCHEMA_VERSION
        or opening["view_lock_sha256"] != view_lock["view_lock_sha256"]
        or opening["submission_seal_sha256"] != submission_seal["submission_seal_sha256"]
    ):
        raise CausalFrontierError("V2 opening targets another sealed run")
    payload = _shape(
        opening["payload"],
        {"schema_version", "protocol_id", "view_content_binding_sha256", "entries"},
        "V2 opening payload",
    )
    if (
        payload["schema_version"] != OPENING_PAYLOAD_SCHEMA_VERSION
        or payload["protocol_id"] != view_lock["protocol_id"]
        or payload["view_content_binding_sha256"] != view_lock["view_content_binding_sha256"]
    ):
        raise CausalFrontierError("V2 opening payload targets another protocol")
    entries = payload["entries"]
    if not isinstance(entries, list) or len(entries) != len(view_lock["controls"]):
        raise CausalFrontierError("V2 opening must contain every opaque control")
    normalized_entries = []
    roles = []
    for index, (raw, control) in enumerate(zip(entries, view_lock["controls"], strict=True)):
        entry = _shape(
            raw,
            {
                "opaque_case_id",
                "control_role",
                "observed_coordinate",
                "reveal_source_sha256",
                "reveal_available_at",
            },
            "V2 opening entry[%d]" % index,
        )
        if entry["opaque_case_id"] != control["opaque_case_id"]:
            raise CausalFrontierError("V2 opening case order or identity differs")
        role = require_enum(entry["control_role"], set(CONTROL_ROLES), "V2 control role")
        roles.append(role)
        coordinate = entry["observed_coordinate"]
        if canonical_bytes(coordinate) not in {canonical_bytes(item) for item in _coordinate_rows()}:
            raise CausalFrontierError("V2 opening observation is outside the fixed coordinate language")
        derived_class = _expected_branch(coordinate)
        reveal_available_at = require_utc_timestamp(entry["reveal_available_at"], "V2 reveal availability")
        if reveal_available_at <= control["knowledge_cutoff"]:
            raise CausalFrontierError("V2 reveal must be declared available after the knowledge cutoff")
        normalized_entries.append(
            {
                "opaque_case_id": entry["opaque_case_id"],
                "control_role": role,
                "observed_coordinate": coordinate,
                "fixed_protocol_outcome_class": derived_class,
                "reveal_source_sha256": _nonzero_sha256(entry["reveal_source_sha256"], "V2 reveal source digest"),
                "reveal_available_at": reveal_available_at,
            }
        )
    if len(roles) != len(set(roles)) or set(roles) != set(CONTROL_ROLES):
        raise CausalFrontierError("V2 opening must contain one positive, failed, and ambiguous role in a hidden order")
    if not hmac.compare_digest(
        reveal_commitment_v2(payload, opening["nonce_hex"]), view_lock["reveal_commitment_sha256"]
    ):
        raise CausalFrontierError("V2 opening does not match the precommitted reveal")
    return {**opening, "payload": {**payload, "entries": normalized_entries}}


def _validate_rubric(value: Any, view_lock: dict[str, Any]) -> dict[str, Any]:
    rubric = _shape(
        value,
        {
            "schema_version",
            "protocol_id",
            "view_content_binding_sha256",
            "nonce_hex",
            "criteria_order",
            "entries",
            "review_plan",
            "aggregation_rule",
        },
        "V2 rubric",
    )
    if (
        rubric["schema_version"] != RUBRIC_SCHEMA_VERSION
        or rubric["protocol_id"] != view_lock["protocol_id"]
        or rubric["view_content_binding_sha256"] != view_lock["view_content_binding_sha256"]
        or rubric["criteria_order"] != list(ADJUDICATION_CRITERIA)
        or rubric["aggregation_rule"] != "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL"
    ):
        raise CausalFrontierError("V2 rubric differs from the fixed protocol")
    _nonce(rubric["nonce_hex"], "V2 rubric nonce")
    review_plan = _validate_review_plan(rubric["review_plan"])
    entries = rubric["entries"]
    if not isinstance(entries, list) or len(entries) != len(view_lock["controls"]):
        raise CausalFrontierError("V2 rubric must cover every opaque control")
    normalized = []
    for index, (raw, control) in enumerate(zip(entries, view_lock["controls"], strict=True)):
        entry = _shape(
            raw,
            {"opaque_case_id", "required_feature_ids", "forbidden_feature_ids", "sentinel_rows", "semantic_criteria"},
            "V2 rubric entry[%d]" % index,
        )
        if entry["opaque_case_id"] != control["opaque_case_id"]:
            raise CausalFrontierError("V2 rubric case order or identity differs")
        required = _sorted_ids(
            entry["required_feature_ids"], "V2 required rubric features", minimum=1, maximum=MAX_FEATURES_PER_CASE
        )
        forbidden = _sorted_ids(
            entry["forbidden_feature_ids"], "V2 forbidden rubric features", maximum=MAX_FEATURES_PER_CASE
        )
        if set(required) & set(forbidden) or not set(required + forbidden) <= set(control["feature_ids"]):
            raise CausalFrontierError("V2 rubric feature sets overlap or contain unknown features")
        sentinel_rows = entry["sentinel_rows"]
        if not isinstance(sentinel_rows, list) or not 1 <= len(sentinel_rows) <= 16:
            raise CausalFrontierError("V2 rubric must contain bounded sentinel rows")
        seen_coordinates = set()
        normalized_sentinels = []
        for row_index, raw_row in enumerate(sentinel_rows):
            row = _shape(
                raw_row,
                {"coordinate", "required_branch_class", "required_successor"},
                "V2 rubric sentinel[%d]" % row_index,
            )
            coordinate_bytes = canonical_bytes(row["coordinate"])
            if coordinate_bytes not in {canonical_bytes(item) for item in _coordinate_rows()}:
                raise CausalFrontierError("V2 rubric sentinel uses an unknown coordinate")
            if coordinate_bytes in seen_coordinates:
                raise CausalFrontierError("V2 rubric sentinel coordinates must be unique")
            seen_coordinates.add(coordinate_bytes)
            expected_class = _expected_branch(row["coordinate"])
            if row["required_branch_class"] != expected_class or row["required_successor"] != _successor_for(
                expected_class
            ):
                raise CausalFrontierError("V2 rubric sentinel contradicts the fixed branch semantics")
            normalized_sentinels.append(row)
        criteria = entry["semantic_criteria"]
        if not isinstance(criteria, list) or len(criteria) != len(ADJUDICATION_CRITERIA):
            raise CausalFrontierError("V2 rubric semantic criteria are incomplete")
        normalized_criteria = []
        for criterion_index, (raw_criterion, criterion_id) in enumerate(
            zip(criteria, ADJUDICATION_CRITERIA, strict=True)
        ):
            criterion = _shape(
                raw_criterion,
                {"criterion_id", "question"},
                "V2 rubric criterion[%d]" % criterion_index,
            )
            if criterion["criterion_id"] != criterion_id:
                raise CausalFrontierError("V2 rubric criterion order differs")
            normalized_criteria.append(
                {"criterion_id": criterion_id, "question": require_text(criterion["question"], "rubric question")}
            )
        normalized.append(
            {
                "opaque_case_id": entry["opaque_case_id"],
                "required_feature_ids": required,
                "forbidden_feature_ids": forbidden,
                "sentinel_rows": normalized_sentinels,
                "semantic_criteria": normalized_criteria,
            }
        )
    if rubric_commitment_v2(rubric) != view_lock["rubric_commitment_sha256"]:
        raise CausalFrontierError("V2 rubric does not match its precommitment")
    return {**rubric, "entries": normalized, "review_plan": review_plan}


def _aggregate_verdicts(verdicts: list[str]) -> str:
    if all(item == "PASS" for item in verdicts):
        return "PASS"
    if any(item == "FAIL" for item in verdicts):
        return "FAIL"
    return "NO_CALL"


def _validate_adjudication(
    value: Any,
    view_lock: dict[str, Any],
    submission_raw_sha256: str,
    submission_seal: dict[str, Any],
    opening_raw_sha256: str,
    rubric: dict[str, Any],
    rubric_raw_sha256: str,
) -> dict[str, Any]:
    adjudication = _shape(
        value,
        {
            "schema_version",
            "protocol_id",
            "run_id",
            "view_lock_sha256",
            "submission_raw_sha256",
            "submission_seal_sha256",
            "opening_raw_sha256",
            "rubric_raw_sha256",
            "criteria_order",
            "entries",
        },
        "V2 adjudication",
    )
    if (
        adjudication["schema_version"] != ADJUDICATION_SCHEMA_VERSION
        or adjudication["protocol_id"] != view_lock["protocol_id"]
        or adjudication["run_id"] != submission_seal["run_id"]
        or adjudication["view_lock_sha256"] != view_lock["view_lock_sha256"]
        or adjudication["submission_raw_sha256"] != submission_raw_sha256
        or adjudication["submission_seal_sha256"] != submission_seal["submission_seal_sha256"]
        or adjudication["opening_raw_sha256"] != opening_raw_sha256
        or adjudication["rubric_raw_sha256"] != rubric_raw_sha256
        or adjudication["criteria_order"] != list(ADJUDICATION_CRITERIA)
    ):
        raise CausalFrontierError("V2 adjudication is incomplete or targets another run")
    entries = adjudication["entries"]
    if not isinstance(entries, list) or len(entries) != len(view_lock["controls"]):
        raise CausalFrontierError("V2 adjudication must cover every opaque control")
    normalized_entries = []
    panel_identity = None
    planned_assignments = rubric["review_plan"]["reviewer_assignments"]
    for index, (raw, control) in enumerate(zip(entries, view_lock["controls"], strict=True)):
        entry = _shape(raw, {"opaque_case_id", "votes"}, "V2 adjudication entry[%d]" % index)
        if entry["opaque_case_id"] != control["opaque_case_id"]:
            raise CausalFrontierError("V2 adjudication case order or identity differs")
        votes = entry["votes"]
        if not isinstance(votes, list) or len(votes) != 3:
            raise CausalFrontierError("V2 adjudication requires exactly three declared reviewers per case")
        reviewer_ids = []
        organization_ids = []
        normalized_votes = []
        for vote_index, (raw_vote, planned) in enumerate(zip(votes, planned_assignments, strict=True)):
            vote = _shape(
                raw_vote,
                {
                    "reviewer_id",
                    "organization_id",
                    "policy_identity_blinded_declared",
                    "outcome_hidden_during_ex_ante_review_declared",
                    "criteria",
                    "review_checkpoint_sha256",
                },
                "V2 adjudication vote[%d]" % vote_index,
            )
            reviewer_id = require_id(vote["reviewer_id"], "V2 reviewer id")
            organization_id = require_id(vote["organization_id"], "V2 reviewer organization id")
            reviewer_ids.append(reviewer_id)
            organization_ids.append(organization_id)
            if (
                reviewer_id != planned["reviewer_id"]
                or organization_id != planned["organization_id"]
                or vote["review_checkpoint_sha256"] != planned["assignment_checkpoint_sha256"]
            ):
                raise CausalFrontierError("V2 adjudication vote differs from the precommitted reviewer assignment")
            if (
                vote["policy_identity_blinded_declared"] is not True
                or vote["outcome_hidden_during_ex_ante_review_declared"] is not True
            ):
                raise CausalFrontierError("V2 adjudication vote declares outcome or policy exposure")
            criteria = vote["criteria"]
            if not isinstance(criteria, list) or len(criteria) != len(ADJUDICATION_CRITERIA):
                raise CausalFrontierError("V2 adjudication vote criteria are incomplete")
            normalized_criteria = []
            for criterion_index, (raw_criterion, criterion_id) in enumerate(
                zip(criteria, ADJUDICATION_CRITERIA, strict=True)
            ):
                criterion = _shape(
                    raw_criterion,
                    {"criterion_id", "verdict", "reason_code"},
                    "V2 adjudication criterion[%d]" % criterion_index,
                )
                if criterion["criterion_id"] != criterion_id:
                    raise CausalFrontierError("V2 adjudication criterion order differs")
                normalized_criteria.append(
                    {
                        "criterion_id": criterion_id,
                        "verdict": require_enum(criterion["verdict"], set(VERDICTS), "V2 criterion verdict"),
                        "reason_code": require_id(criterion["reason_code"], "V2 criterion reason code"),
                    }
                )
            normalized_votes.append(
                {
                    **vote,
                    "reviewer_id": reviewer_id,
                    "organization_id": organization_id,
                    "criteria": normalized_criteria,
                    "review_checkpoint_sha256": _nonzero_sha256(
                        vote["review_checkpoint_sha256"], "V2 review checkpoint"
                    ),
                }
            )
        if reviewer_ids != sorted(set(reviewer_ids)) or len(set(organization_ids)) < 2:
            raise CausalFrontierError("V2 declared panel needs three sorted reviewers from at least two organizations")
        identity = tuple(zip(reviewer_ids, organization_ids, strict=True))
        if panel_identity is None:
            panel_identity = identity
        elif identity != panel_identity:
            raise CausalFrontierError("V2 adjudication panel identity must remain fixed across controls")
        aggregates = []
        for criterion_index, criterion_id in enumerate(ADJUDICATION_CRITERIA):
            verdicts = [vote["criteria"][criterion_index]["verdict"] for vote in normalized_votes]
            aggregates.append({"criterion_id": criterion_id, "verdict": _aggregate_verdicts(verdicts)})
        normalized_entries.append(
            {
                "opaque_case_id": entry["opaque_case_id"],
                "votes": normalized_votes,
                "aggregates": aggregates,
                "all_criteria_unanimous_pass": all(item["verdict"] == "PASS" for item in aggregates),
            }
        )
    return {**adjudication, "entries": normalized_entries}


def _branch_row_for_observation(submission_case: dict[str, Any], coordinate: list[dict[str, str]]) -> dict[str, Any]:
    branch_contract = submission_case["branch_contract"]
    coordinate_bytes = canonical_bytes(coordinate)
    for row in branch_contract["rows"]:
        if canonical_bytes(row["coordinate"]) == coordinate_bytes:
            return row
    raise CausalFrontierError("V2 complete branch table unexpectedly lacks the opened coordinate")


def _rubric_machine_checks(
    summary_case: dict[str, Any], submission_case: dict[str, Any], rubric_entry: dict[str, Any]
) -> tuple[bool, bool]:
    selected = set(summary_case["selected_feature_ids"])
    features_ok = set(rubric_entry["required_feature_ids"]) <= selected and not (
        set(rubric_entry["forbidden_feature_ids"]) & selected
    )
    sentinels_ok = True
    for sentinel in rubric_entry["sentinel_rows"]:
        row = _branch_row_for_observation(submission_case, sentinel["coordinate"])
        if (
            row["branch_class"] != sentinel["required_branch_class"]
            or row["successor"] != sentinel["required_successor"]
        ):
            sentinels_ok = False
    return features_ok, sentinels_ok


def _gates(local_conformance: bool, complete_n: int) -> list[dict[str, str]]:
    return [
        {
            "id": "TEMPORAL_LEAKAGE",
            "status": "NO_CALL",
            "reason": (
                "Cutoff ordering is replayed, but exact historical availability and model contamination are unverified."
            ),
        },
        {
            "id": "PRIVACY",
            "status": "NO_CALL",
            "reason": "Public/synthetic declarations and structural screens are not privacy certification.",
        },
        {
            "id": "AUTHORITY",
            "status": "PASS",
            "reason": "The operation is read-only and every proposed action remains description-only and unauthorized.",
        },
        {
            "id": "BRANCH_TOTALITY",
            "status": "PASS" if complete_n == len(CONTROL_ROLES) else "FAIL",
            "reason": (
                "Every complete output enumerates the fixed 72-coordinate language exactly once; semantic totality is "
                "unverified."
            ),
        },
        {
            "id": "ROLLBACK",
            "status": "NO_CALL",
            "reason": "Caller checkpoints are not independent monotonic witnesses.",
        },
        {
            "id": "INDEPENDENT_ADJUDICATION",
            "status": "NO_CALL",
            "reason": (
                "Three-vote declarations are replayed, but reviewer identity and organizational independence are "
                "external."
            ),
        },
        {
            "id": "LOCAL_PROTOCOL_CONFORMANCE",
            "status": "PASS" if local_conformance else "FAIL",
            "reason": "Exact schemas, commitments, intention-to-test rows, and declared review aggregation replayed.",
        },
        {
            "id": "METHOD_RECOVERY",
            "status": "NO_CALL",
            "reason": (
                "External signed phase-separated semantic review is required; local declarations cannot recover method."
            ),
        },
    ]


def _build_report(
    view_lock: dict[str, Any],
    submission: dict[str, Any],
    submission_raw_sha256: str,
    submission_seal: dict[str, Any],
    opening: dict[str, Any],
    opening_raw_sha256: str,
    rubric: dict[str, Any],
    rubric_raw_sha256: str,
    adjudication: dict[str, Any],
    adjudication_raw_sha256: str,
) -> dict[str, Any]:
    case_results = []
    declared_review_candidate = 0
    structurally_complete = 0
    no_calls = 0
    failed = 0
    for _index, (summary_case, submission_case, opening_entry, rubric_entry, adjudication_entry) in enumerate(
        zip(
            submission_seal["cases"],
            submission["cases"],
            opening["payload"]["entries"],
            rubric["entries"],
            adjudication["entries"],
            strict=True,
        )
    ):
        if summary_case["completion_state"] != "COMPLETE":
            result = {
                "opaque_case_id": summary_case["opaque_case_id"],
                "control_role": opening_entry["control_role"],
                "completion_state": summary_case["completion_state"],
                "decision_mode": None,
                "fixed_protocol_opened_outcome_class": opening_entry["fixed_protocol_outcome_class"],
                "derived_observed_branch_class": None,
                "derived_observed_successor": None,
                "fixed_protocol_branch_replay_matches": False,
                "rubric_feature_check": False,
                "rubric_sentinel_check": False,
                "adjudication_aggregates": adjudication_entry["aggregates"],
                "declared_panel_unanimous_pass": False,
                "case_status": "STRUCTURAL_FAIL",
                "failure_reason": summary_case["failure_code"],
            }
            failed += 1
            case_results.append(result)
            continue
        observed_row = _branch_row_for_observation(submission_case, opening_entry["observed_coordinate"])
        branch_matches = observed_row["branch_class"] == opening_entry["fixed_protocol_outcome_class"]
        feature_ok, sentinel_ok = _rubric_machine_checks(summary_case, submission_case, rubric_entry)
        panel_pass = adjudication_entry["all_criteria_unanimous_pass"]
        aggregate_verdicts = [item["verdict"] for item in adjudication_entry["aggregates"]]
        structurally_complete += 1
        if branch_matches and feature_ok and sentinel_ok and panel_pass:
            status = "DECLARED_REVIEW_CANDIDATE_INDEPENDENCE_UNVERIFIED"
            declared_review_candidate += 1
        elif "FAIL" in aggregate_verdicts or not branch_matches or not feature_ok or not sentinel_ok:
            status = "STRUCTURAL_FAIL"
            failed += 1
        else:
            status = "NO_CALL_DECLARED_REVIEW"
            no_calls += 1
        case_results.append(
            {
                "opaque_case_id": summary_case["opaque_case_id"],
                "control_role": opening_entry["control_role"],
                "completion_state": summary_case["completion_state"],
                "decision_mode": summary_case["decision_mode"],
                "fixed_protocol_opened_outcome_class": opening_entry["fixed_protocol_outcome_class"],
                "derived_observed_branch_class": observed_row["branch_class"],
                "derived_observed_successor": observed_row["successor"],
                "fixed_protocol_branch_replay_matches": branch_matches,
                "rubric_feature_check": feature_ok,
                "rubric_sentinel_check": sentinel_ok,
                "adjudication_aggregates": adjudication_entry["aggregates"],
                "declared_panel_unanimous_pass": panel_pass,
                "case_status": status,
                "failure_reason": None,
            }
        )
    local_conformance = (
        declared_review_candidate == len(CONTROL_ROLES)
        and submission_seal["complete_cases_n"] == len(CONTROL_ROLES)
        and not submission_seal["constant_action_pattern"]
        and not submission_seal["always_abstain_equivalent"]
        and submission_seal["evidence_relation_patterns_distinct"]
        and submission_seal["all_complete_cases_decision_relevant_evidence_declared"]
    )
    promotion_block_reasons = [
        "REVIEWER_CREDENTIALS_UNVERIFIED",
        "VOTE_SIGNATURES_UNVERIFIED",
        "ORGANIZATIONAL_INDEPENDENCE_UNVERIFIED",
        "EX_ANTE_REVIEW_ORDER_UNVERIFIED",
        "CANDIDATE_BRANCH_SEMANTICS_UNVERIFIED",
        "REVEAL_SOURCE_CLASSIFICATION_UNVERIFIED",
    ]
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": REPORT_STRUCTURAL_STATUS if local_conformance else REPORT_BLOCKED_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "protocol_id": view_lock["protocol_id"],
        "run_id": submission_seal["run_id"],
        "policy_id": submission_seal["policy_id"],
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_raw_sha256": submission_raw_sha256,
        "submission_seal_sha256": submission_seal["submission_seal_sha256"],
        "opening_raw_sha256": opening_raw_sha256,
        "rubric_raw_sha256": rubric_raw_sha256,
        "adjudication_raw_sha256": adjudication_raw_sha256,
        "controls_n": len(CONTROL_ROLES),
        "controls_structurally_complete_n": structurally_complete,
        "controls_declared_review_candidate_n": declared_review_candidate,
        "controls_semantically_verified_n": 0,
        "controls_failed_n": failed,
        "controls_no_call_n": no_calls,
        "case_results": case_results,
        "action_pattern": submission_seal["action_pattern"],
        "constant_action_pattern": submission_seal["constant_action_pattern"],
        "always_abstain_equivalent": submission_seal["always_abstain_equivalent"],
        "evidence_relation_patterns_distinct": submission_seal["evidence_relation_patterns_distinct"],
        "all_complete_cases_decision_relevant_evidence_declared": submission_seal[
            "all_complete_cases_decision_relevant_evidence_declared"
        ],
        "complete_intention_to_test_matrix_verified": True,
        "machine_branch_partition_total_and_exclusive_verified": submission_seal["complete_cases_n"]
        == len(CONTROL_ROLES),
        "fixed_protocol_safety_table_replayed": submission_seal["complete_cases_n"] == len(CONTROL_ROLES),
        "candidate_branch_semantics_evaluated": False,
        "action_branch_semantics_verified": False,
        "opened_coordinates_structurally_validated": True,
        "reveal_source_bytes_classified": False,
        "precutoff_action_and_successor_outcome_orthogonalized": False,
        "declared_panel_aggregation_replayed": True,
        "reviewer_plan_precommitted_verified": True,
        "reviewer_credentials_verified": False,
        "vote_signatures_verified": False,
        "ex_ante_review_order_verified": False,
        "positional_role_mapping_absent_verified": True,
        "alias_generation_independence_verified": False,
        "local_protocol_conformance_pass": local_conformance,
        "declared_review_candidate_pass": declared_review_candidate == len(CONTROL_ROLES),
        "method_recovery_status": "NO_CALL_EXTERNAL_REVIEW_REQUIRED",
        "method_recovery_pass": False,
        "promotion_block_reasons": promotion_block_reasons,
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "semantic_blinding_verified": False,
        "temporal_attestation_verified": False,
        "content_outcome_isolation_verified": False,
        "independent_output_generation_verified": False,
        "independent_semantic_adjudication_verified": False,
        "control_semantic_validity_verified": False,
        "real_resource_measurement_verified": False,
        "privacy_certified": False,
        "independent_custody_verified": False,
        "rollback_resistance_verified": False,
        "calibrated_abstention_verified": False,
        "cross_domain_generality_verified": False,
        "primary_scoring_ready": False,
        "scientific_scoring_ready": False,
        "scientific_claim_ready": False,
        "winner": None,
        "ranking": [],
        "acceleration_ratio": None,
        "gates": _gates(local_conformance, submission_seal["complete_cases_n"]),
        "nonclaims": list(REPORT_NONCLAIMS),
    }
    return {**core, "report_sha256": sha256_bytes(REPORT_DOMAIN_TAG + canonical_bytes(core))}


def finalize_calibration_v2(
    root: Path,
    expected_manifest_sha256: str,
    view_lock_path: Path,
    expected_view_lock_sha256: str,
    submission_path: Path,
    expected_submission_sha256: str,
    submission_seal_path: Path,
    expected_submission_seal_sha256: str,
    opening_path: Path,
    expected_opening_sha256: str,
    rubric_path: Path,
    expected_rubric_sha256: str,
    adjudication_path: Path,
    expected_adjudication_sha256: str,
) -> dict[str, Any]:
    """Replay every V2 zone and produce a calibration-only structural report."""

    external_paths = [
        view_lock_path,
        submission_path,
        submission_seal_path,
        opening_path,
        rubric_path,
        adjudication_path,
    ]
    _require_disjoint_external_zones(root, external_paths)
    expected_view_lock = preflight_calibration_v2_view(root, expected_manifest_sha256)
    _raw_view_lock, saved_view_lock = _read_checkpointed_json(
        view_lock_path, expected_view_lock_sha256, "V2 saved view lock"
    )
    view_lock = _validate_view_lock(saved_view_lock, expected_view_lock)
    raw_submission, submission = _read_checkpointed_json(submission_path, expected_submission_sha256, "V2 submission")
    submission_summary = _validate_submission(submission, view_lock)
    expected_submission_seal = _build_submission_seal(view_lock, sha256_bytes(raw_submission), submission_summary)
    _raw_seal, saved_seal = _read_checkpointed_json(
        submission_seal_path, expected_submission_seal_sha256, "V2 saved submission seal"
    )
    submission_seal = _validate_submission_seal(saved_seal, expected_submission_seal)

    raw_opening, opening_value = _read_checkpointed_json(opening_path, expected_opening_sha256, "V2 opening")
    opening = _validate_opening(opening_value, view_lock, submission_seal)
    raw_rubric, rubric_value = _read_checkpointed_json(rubric_path, expected_rubric_sha256, "V2 rubric")
    rubric = _validate_rubric(rubric_value, view_lock)
    raw_adjudication, adjudication_value = _read_checkpointed_json(
        adjudication_path, expected_adjudication_sha256, "V2 adjudication"
    )
    adjudication = _validate_adjudication(
        adjudication_value,
        view_lock,
        sha256_bytes(raw_submission),
        submission_seal,
        sha256_bytes(raw_opening),
        rubric,
        sha256_bytes(raw_rubric),
    )
    return _build_report(
        view_lock,
        submission,
        sha256_bytes(raw_submission),
        submission_seal,
        opening,
        sha256_bytes(raw_opening),
        rubric,
        sha256_bytes(raw_rubric),
        adjudication,
        sha256_bytes(raw_adjudication),
    )


def verify_calibration_v2_report(
    root: Path,
    expected_manifest_sha256: str,
    view_lock_path: Path,
    expected_view_lock_sha256: str,
    submission_path: Path,
    expected_submission_sha256: str,
    submission_seal_path: Path,
    expected_submission_seal_sha256: str,
    opening_path: Path,
    expected_opening_sha256: str,
    rubric_path: Path,
    expected_rubric_sha256: str,
    adjudication_path: Path,
    expected_adjudication_sha256: str,
    report_path: Path,
    expected_report_sha256: str,
) -> dict[str, Any]:
    """Verify a saved report only by replaying every upstream artifact."""

    _require_disjoint_external_zones(
        root,
        [
            view_lock_path,
            submission_path,
            submission_seal_path,
            opening_path,
            rubric_path,
            adjudication_path,
            report_path,
        ],
    )
    expected = finalize_calibration_v2(
        root,
        expected_manifest_sha256,
        view_lock_path,
        expected_view_lock_sha256,
        submission_path,
        expected_submission_sha256,
        submission_seal_path,
        expected_submission_seal_sha256,
        opening_path,
        expected_opening_sha256,
        rubric_path,
        expected_rubric_sha256,
        adjudication_path,
        expected_adjudication_sha256,
    )
    _raw_report, saved = _read_checkpointed_json(report_path, expected_report_sha256, "V2 saved report")
    report = _shape(saved, set(expected), "V2 saved report")
    core = {key: report[key] for key in report if key != "report_sha256"}
    if report["report_sha256"] != sha256_bytes(REPORT_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("V2 report semantic digest differs")
    if canonical_bytes(report) != canonical_bytes(expected):
        raise CausalFrontierError("V2 report does not replay from every upstream checkpoint")
    return report


__all__ = [
    "canonical_branch_rows",
    "finalize_calibration_v2",
    "observation_axes_v2",
    "preflight_calibration_v2_view",
    "reveal_commitment_v2",
    "rubric_commitment_v2",
    "seal_calibration_v2_submission",
    "verify_calibration_v2_report",
    "view_content_binding_v2",
]
