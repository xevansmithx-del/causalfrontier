"""Fail-closed preflight for a model-neutral scientific-decision challenge.

The challenge contract is deliberately narrower than a benchmark scorer.  It
binds exact bytes for independently authored CausalFrontier cases, source
receipt preflights, baseline specifications, and a hidden reveal commitment.
It never treats declarations as independent attestations and never emits a
scientific score.
"""

from __future__ import annotations

from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    require_text,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary, validate_case

SCHEMA_VERSION = "causalfrontier.challenge-lock.v1"
PREFLIGHT_VERSION = "causalfrontier.challenge-preflight.v1"
BASELINE_SCHEMA_VERSION = "causalfrontier.baseline-specification.v1"
MANIFEST = "challenge.json"
REVEAL_COMMITMENT_SCHEME = "SHA256_DOMAIN_SEPARATED_CANONICAL_REVEAL_PLUS_32_BYTE_RANDOM_NONCE"
GENESIS = "0" * 64
MAX_CASES = 7
MAX_ENCODINGS = 14
MAX_ARTIFACTS = 80
MAX_CHALLENGE_BYTES = 32 * 1024 * 1024
MAX_FROZEN_SOURCE_BYTES = 1024 * 1024

SCOPES = frozenset({"SYNTHETIC_PROTOCOL_TEST", "HISTORICAL_REPLAY_DRAFT"})
CONTROL_CLASSES = frozenset({"POSITIVE", "FAILED_TRANSLATION", "AMBIGUOUS"})
SELECTION_ORIGINS = frozenset({"KNOWN_HINDSIGHT", "UNASSESSED", "SYNTHETIC_FIXTURE"})
ARTIFACT_ROLES = frozenset(
    {
        "FROZEN_CASE",
        "FROZEN_CASE_SOURCE",
        "RECEIPT_PREFLIGHT",
        "RECEIPT_SET_FILE",
        "BASELINE_SPECIFICATION",
    }
)
MEDIA_TYPES = frozenset({"application/json", "text/plain", "text/csv", "text/tab-separated-values"})
BASELINE_FAMILIES = frozenset(
    {
        "LAB_ACTUAL_CHOICE",
        "CURRENT_STANDARDIZED_WORKFLOW",
        "INDEPENDENT_EXPERT",
        "HUMAN_PLUS_AGENT",
        "FRONTIER_GENERAL_AGENT",
        "POPPER_SEQUENTIAL_FALSIFICATION",
        "RETRIEVAL_ONLY",
        "GRAPH_ONLY",
        "RANDOM",
        "DO_NOTHING_OR_ABSTAIN",
        "BLIND_OFAT",
        "INFORMED_OFAT",
        "BAYESIAN_DESIGN",
        "COST_AWARE_EXPECTED_INFORMATION_GAIN",
        "ORACLE_REPLAY_ONLY",
    }
)

_METRIC_CONTRACT_TEMPLATE = {
    "primary_endpoint": "FIRST_CORRECT_PREDECLARED_DECISION_STATE_TRANSITION_SUSTAINED_ON_REQUIRED_REPLICATION",
    "primary_comparator": "CURRENT_STANDARDIZED_WORKFLOW",
    "secondary_comparator": "STRONGEST_APPLICABLE_COMPUTATIONAL_BASELINE",
    "execution_design": "PARALLEL_RANDOMIZED_OR_COMPLETE_REPLAY_ORACLE_ONLY",
    "analysis_population": "INTENTION_TO_TREAT",
    "primary_resource_estimand": "PREDECLARED_PER_DOMAIN_NO_POSTHOC_TIME_OR_COST_CHOICE",
    "success_threshold_numerator": 10,
    "success_threshold_denominator": 1,
    "comparison": "PAIRED_WITHIN_CASE_WHEN_COUNTERFACTUAL_OUTCOMES_ARE_IDENTIFIABLE",
    "success_rule": "TENFOLD_ON_PREDECLARED_PRIMARY_RESOURCE_VERSUS_CURRENT_WORKFLOW_AND_NONINFERIOR_OTHERWISE",
    "uncertainty_rule": "INTERVAL_MUST_EXCLUDE_MATERIALLY_SMALLER_GAIN",
    "resource_vector": [
        "calendar_minutes",
        "human_minutes",
        "compute_units",
        "direct_cost_minor_units_same_currency_and_date_basis",
    ],
    "epistemic_vector": [
        "correct_predeclared_decision_state_transition",
        "predeclared_decision_equivalence_classes_excluded",
        "correct_abstention",
        "selective_risk_basis_points",
        "coverage_basis_points",
        "replication_state",
        "authority_violations",
    ],
    "reporting": "PARETO_VECTOR_NO_COMPOSITE_SCORE",
    "unreached_endpoint": "CENSORED_NOT_IMPUTED",
    "authority_violation": "INVALIDATE_RUN",
}
METRIC_CONTRACT_CANONICAL = canonical_bytes(_METRIC_CONTRACT_TEMPLATE)
# Compatibility view only. Validation uses the immutable canonical bytes.
METRIC_CONTRACT = read_json_bytes(METRIC_CONTRACT_CANONICAL, "fixed metric contract")


def fixed_metric_contract() -> dict[str, Any]:
    return read_json_bytes(METRIC_CONTRACT_CANONICAL, "fixed metric contract")


def challenge_registration_sha256(document: dict[str, Any]) -> str:
    """Bind the complete challenge registration without its commitment value.

    Excluding only ``reveal_commitment_sha256`` avoids a hash cycle while still
    binding the reveal scheme, artifacts, cohort, controls, and all contracts.
    """

    if not isinstance(document, dict) or "reveal_commitment_sha256" not in document:
        raise CausalFrontierError("challenge registration lacks its reveal commitment")
    core = {key: value for key, value in document.items() if key != "reveal_commitment_sha256"}
    return sha256_bytes(canonical_bytes(core))


NONCLAIMS = (
    "This preflight is not scientific, biological, clinical, or prospective validation.",
    "A digest proves byte identity, not truth, independence, availability time, or authorship.",
    "Receipt bundles are replayed structurally; their source dates remain independently unattested.",
    "Receipt-to-dossier binding proves direct byte identity only; derived transforms are unsupported in v1.",
    "Pattern screening is not privacy certification.",
    "Bound baseline specifications have not been executed or shown adequate.",
    "The caller-supplied sequence and digest are not proof of an independently stored checkpoint.",
    "No challenge outcome is revealed, adjudicated, or scored.",
    "No patient, human-decision, material-execution, or clinical authority is granted.",
)


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _bounded_list(value: Any, field: str, minimum: int, maximum: int) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= maximum
        or any(not isinstance(item, dict) for item in value)
    ):
        raise CausalFrontierError("%s must contain %d..%d objects" % (field, minimum, maximum))
    return value


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or not 1 <= value <= 1_000_000_000:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _strict_json(raw: bytes, label: str) -> Any:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    receipt_io._screen(canonical_bytes(value))
    return value


def _validate_receipt_preflight(value: Any, selection_origin: str) -> dict[str, Any]:
    report = _shape(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "receipt_set_sha256",
            "canonical_receipt_set_sha256",
            "fixed_parameter",
            "boundary",
            "selection_origin",
            "historical_scoring",
            "historically_eligible_receipts_n",
            "privacy_status",
            "control_trio_status",
            "files_sha256",
            "receipt_results",
        },
        "receipt preflight",
    )
    if (
        report["schema_version"] != "causalfrontier.receipt-preflight.v1"
        or report["status"] != "STRUCTURALLY_BOUND_NOT_HISTORICALLY_ADMISSIBLE"
        or report["implementation_status"] != "LOCAL_UNRELEASED_RECEIPT_PREFLIGHT"
        or report["base_compiler_version"] != COMPILER_VERSION
        or report["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(report["boundary"]) != BOUNDARY_CANONICAL
        or report["selection_origin"] != selection_origin
        or report["historical_scoring"] != "DISABLED"
        or type(report["historically_eligible_receipts_n"]) is not int
        or report["historically_eligible_receipts_n"] != 0
        or report["privacy_status"] != "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"
        or report["control_trio_status"] != "NOT_EVALUATED_NO_SCORING_PATH"
    ):
        raise CausalFrontierError("receipt preflight is incompatible or claims unsupported admission")
    require_sha256(report["receipt_set_sha256"], "receipt-set digest")
    require_sha256(report["canonical_receipt_set_sha256"], "canonical receipt-set digest")
    files = report["files_sha256"]
    if not isinstance(files, dict) or not files:
        raise CausalFrontierError("receipt preflight must bind its files")
    for path, digest in files.items():
        receipt_io._relative(path)
        require_sha256(digest, "receipt file digest")
    results = report["receipt_results"]
    if not isinstance(results, list) or not results:
        raise CausalFrontierError("receipt preflight must retain receipt results")
    receipt_ids: set[str] = set()
    for result in results:
        _shape(
            result,
            {
                "receipt_id",
                "outcome_class",
                "reason_codes",
                "historical_eligible",
                "temporal_state",
                "submitted_arguments_sha256",
                "raw_response_sha256",
            },
            "receipt result",
        )
        receipt_id = require_id(result["receipt_id"], "receipt result id")
        if receipt_id in receipt_ids:
            raise CausalFrontierError("receipt preflight contains duplicate result ids")
        receipt_ids.add(receipt_id)
        require_enum(result["outcome_class"], {"FAILURE", "NO_CALL"}, "receipt result outcome")
        if result["historical_eligible"] is not False:
            raise CausalFrontierError("receipt result cannot claim historical eligibility in v1")
        reasons = result["reason_codes"]
        if not isinstance(reasons, list) or not reasons:
            raise CausalFrontierError("receipt result must preserve reason codes")
        normalized_reasons = []
        for reason in reasons:
            require_id(reason, "receipt reason code")
            normalized_reasons.append(reason)
        if len(normalized_reasons) != len(set(normalized_reasons)):
            raise CausalFrontierError("receipt result must preserve reason codes")
        require_sha256(result["submitted_arguments_sha256"], "submitted-arguments digest")
        require_sha256(result["raw_response_sha256"], "raw-response digest")
        if result["temporal_state"] != "DECLARED_TEMPORAL_METADATA_UNATTESTED":
            raise CausalFrontierError("receipt result has an unsupported temporal state")
    return report


def _validate_baseline_spec(value: Any, baseline_id: str, family: str) -> None:
    specification = _shape(
        value,
        {
            "schema_version",
            "id",
            "family",
            "version",
            "case_scope",
            "input_contract",
            "output_contract",
            "strategy_description",
            "stopping_rule",
            "budget_rule",
            "resource_accounting",
            "execution_state",
            "implementation_sha256",
            "entrypoint",
        },
        "baseline specification",
    )
    if (
        specification["schema_version"] != BASELINE_SCHEMA_VERSION
        or specification["id"] != baseline_id
        or specification["family"] != family
        or specification["case_scope"] != "ALL_CHALLENGE_CASES"
        or specification["input_contract"] != "FROZEN_CASE_AND_RECEIPT_BUNDLE"
        or specification["output_contract"] != "DECISION_STATE_TRANSITION_AND_AUDITED_RESOURCE_LEDGER"
        or specification["budget_rule"] != "SAME_PREDECLARED_CASE_SPECIFIC_BUDGET_AS_ENTRANTS"
        or specification["resource_accounting"] != "FULLY_LOADED_AUDIT_REQUIRED_BEFORE_EXECUTION"
        or specification["execution_state"] != "SPECIFICATION_ONLY_NOT_EXECUTED"
        or specification["implementation_sha256"] is not None
        or specification["entrypoint"] is not None
    ):
        raise CausalFrontierError("baseline specification is incompatible or claims execution")
    require_id(specification["id"], "baseline specification id")
    require_enum(specification["family"], BASELINE_FAMILIES, "baseline specification family")
    require_text(specification["version"], "baseline version", 200)
    require_text(specification["strategy_description"], "baseline strategy", 2000)
    require_text(specification["stopping_rule"], "baseline stopping rule", 2000)


def _artifact_table(value: Any) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    artifacts = _bounded_list(value, "artifacts", 1, MAX_ARTIFACTS)
    by_id: dict[str, dict[str, Any]] = {}
    by_path: dict[str, str] = {}
    for index, item in enumerate(artifacts):
        artifact = _shape(item, {"id", "path", "sha256", "role", "media_type"}, "artifact[%d]" % index)
        identity = require_id(artifact["id"], "artifact id")
        if identity in by_id:
            raise CausalFrontierError("duplicate artifact id: %s" % identity)
        path = receipt_io._relative(artifact["path"])
        if path == MANIFEST or path in by_path:
            raise CausalFrontierError("challenge artifact path conflicts")
        artifact["sha256"] = require_sha256(artifact["sha256"], "artifact digest")
        artifact["role"] = require_enum(artifact["role"], ARTIFACT_ROLES, "artifact role")
        artifact["media_type"] = require_enum(artifact["media_type"], MEDIA_TYPES, "artifact media type")
        if artifact["role"] in {"FROZEN_CASE", "RECEIPT_PREFLIGHT", "BASELINE_SPECIFICATION"} and (
            artifact["media_type"] != "application/json"
        ):
            raise CausalFrontierError("challenge artifact role and media type differ")
        if (
            artifact["role"] == "RECEIPT_SET_FILE"
            and PurePosixPath(path).name == receipt_io.MANIFEST
            and artifact["media_type"] != "application/json"
        ):
            raise CausalFrontierError("receipt-set manifest media type must be application/json")
        by_id[identity] = artifact
        by_path[path] = identity
    return by_id, by_path


def _require_artifact(
    artifact_id: Any,
    role: str,
    artifacts: dict[str, dict[str, Any]],
    referenced: set[str],
    field: str,
) -> str:
    identity = require_id(artifact_id, field)
    artifact = artifacts.get(identity)
    if artifact is None or artifact["role"] != role:
        raise CausalFrontierError("%s does not reference a %s artifact" % (field, role))
    if identity in referenced:
        raise CausalFrontierError("artifact is reused across incompatible challenge roles: %s" % identity)
    referenced.add(identity)
    return identity


def _under_prefix(path: str, prefix: str) -> bool:
    parts = PurePosixPath(path).parts
    prefix_parts = PurePosixPath(prefix).parts
    return len(parts) > len(prefix_parts) and parts[: len(prefix_parts)] == prefix_parts


def _bind_receipt_bundle(
    root: Path,
    prefix_value: Any,
    report: dict[str, Any],
    evidence_cutoff: str,
    challenge_frozen_at: str,
    scope: str,
    artifacts: dict[str, dict[str, Any]],
    artifact_paths: dict[str, str],
    raw_artifacts: dict[str, bytes],
    referenced: set[str],
) -> dict[str, Any]:
    prefix = receipt_io._relative(prefix_value)
    expected_paths: set[str] = set()
    for relative, digest in report["files_sha256"].items():
        relative = receipt_io._relative(relative)
        path = (PurePosixPath(prefix) / relative).as_posix()
        identity = artifact_paths.get(path)
        artifact = artifacts.get(identity or "")
        if artifact is None or artifact["role"] != "RECEIPT_SET_FILE" or artifact["sha256"] != digest:
            raise CausalFrontierError("receipt preflight file binding is absent or differs")
        if identity in referenced:
            raise CausalFrontierError("receipt-set artifact is reused across challenge cases")
        referenced.add(identity)
        expected_paths.add(path)
    actual_paths = {path for path in artifact_paths if _under_prefix(path, prefix)}
    if actual_paths != expected_paths:
        raise CausalFrontierError(
            "receipt bundle inventory differs from its replay report",
            reason_code="INVENTORY_MISMATCH",
            operation="challenge._bind_receipt_bundle",
        )
    manifest_path = (PurePosixPath(prefix) / receipt_io.MANIFEST).as_posix()
    manifest_identity = artifact_paths.get(manifest_path)
    if manifest_identity is None:
        raise CausalFrontierError("receipt bundle is missing its manifest")
    receipt_set = _strict_json(raw_artifacts[manifest_identity], "receipt-set manifest")
    if not isinstance(receipt_set, dict) or receipt_set.get("evidence_cutoff") != evidence_cutoff:
        raise CausalFrontierError("receipt bundle evidence cutoff differs from challenge case")
    replay = receipt_io.preflight_receipts(root / Path(prefix), report["receipt_set_sha256"])
    if canonical_bytes(replay) != canonical_bytes(report):
        raise CausalFrontierError("receipt preflight report is not reproducible from bound bytes")
    receipt_frozen_at = require_utc_timestamp(receipt_set["frozen_at"], "receipt-set freeze")
    if receipt_frozen_at > challenge_frozen_at:
        raise CausalFrontierError("receipt bundle was frozen after the challenge lock")
    receipt_items = receipt_set["receipts"]
    if scope == "SYNTHETIC_PROTOCOL_TEST" and any(
        item["data_class"] != "SYNTHETIC" or item["authority"] != "SYNTHETIC_DATA" for item in receipt_items
    ):
        raise CausalFrontierError("synthetic challenge receipt bundle is not synthetic-only")
    raw_response_bindings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in receipt_items:
        raw_response_bindings[item["raw_response"]["sha256"]].append(
            {
                "data_class": item["data_class"],
                "authority": item["authority"],
                "retrieved_at": item["retrieved_at"],
                "retrieval_state": item["retrieval_state"],
                "semantic_state": item["semantic_state"],
                "coverage_complete": item["coverage"]["state"] == "COMPLETE",
            }
        )
    return {
        "receipt_set_sha256": report["receipt_set_sha256"],
        "raw_response_bindings": dict(raw_response_bindings),
    }


def _receipt_supports_source(source: dict[str, Any], receipt: dict[str, Any]) -> bool:
    """Require the same bytes to retain compatible acquisition semantics."""

    semantic_map = {
        "SYNTHETIC_FIXTURE_ONLY": {"SYNTHETIC_FIXTURE_ONLY"},
        "USABLE_FOR_DECLARED_SCOPE": {"USABLE_FOR_DECLARED_SCOPE"},
        "CONTEXT_ONLY_PARTIAL": {"CONTEXT_ONLY", "METADATA_ONLY"},
        "QUERY_FAILURE_NOT_EVIDENCE": {"UNUSABLE"},
        "NO_RESULT_NOT_ABSENCE": {"UNUSABLE"},
    }
    retrieval_map = {
        "COMPLETE": {"COMPLETE"},
        "PARTIAL": {"PARTIAL"},
        "FAILED": {"FAILED", "TIMEOUT"},
        "NOT_RUN": {"NOT_RUN"},
    }
    return (
        receipt["data_class"] == source["data_class"]
        and receipt["authority"] == source["authority"]
        and receipt["retrieved_at"] == source["retrieved_at"]
        and receipt["retrieval_state"] in retrieval_map[source["retrieval_state"]]
        and receipt["semantic_state"] in semantic_map[source["semantic_state"]]
        and receipt["coverage_complete"] is source["coverage_complete"]
    )


def _shared_action_input_core(frozen_case: dict[str, Any]) -> dict[str, Any]:
    """Return exact dossier, gates, and actions shared across encoder strata.

    Worlds and prediction relations intentionally remain encoder-specific and
    must be evaluated as separate sensitivity strata until agreement is judged.
    """

    return {
        "evidence_cutoff": frozen_case["evidence_cutoff"],
        "provenance": frozen_case["provenance"],
        "decision": frozen_case["decision"],
        "gates": frozen_case["gates"],
        "experiments": [
            {
                "id": experiment["id"],
                "protocol": experiment["protocol"],
                "execution_class": experiment["execution_class"],
                "required_gate_ids": experiment["required_gate_ids"],
                "required_authorities": experiment["required_authorities"],
                "resources": experiment["resources"],
                "outcome_partition": experiment["outcome_partition"],
                "outcomes": experiment["outcomes"],
                "classifier": experiment["classifier"],
                "classifier_sha256": experiment["classifier_sha256"],
            }
            for experiment in frozen_case["experiments"]
        ],
    }


def _bind_case_sources(
    artifact_id: str,
    artifacts: dict[str, dict[str, Any]],
    artifact_paths: dict[str, str],
    raw_artifacts: dict[str, bytes],
    referenced: set[str],
) -> dict[str, Any]:
    artifact = artifacts[artifact_id]
    case_path = PurePosixPath(artifact["path"])
    if case_path.name != "case.json" or case_path.parent == PurePosixPath("."):
        raise CausalFrontierError("frozen case artifact must be a nested case.json")
    frozen_case = validate_case(_strict_json(raw_artifacts[artifact_id], "frozen case artifact"))
    expected_paths = {artifact["path"]}
    for source in frozen_case["provenance"]:
        path = (case_path.parent / receipt_io._relative(source["path"])).as_posix()
        identity = artifact_paths.get(path)
        source_artifact = artifacts.get(identity or "")
        if (
            source_artifact is None
            or source_artifact["role"] != "FROZEN_CASE_SOURCE"
            or source_artifact["sha256"] != source["sha256"]
        ):
            raise CausalFrontierError("frozen case source bytes are absent or differ")
        if len(raw_artifacts[identity]) > MAX_FROZEN_SOURCE_BYTES:
            raise CausalFrontierError("frozen case source exceeds the standalone case-loader limit")
        if identity in referenced:
            raise CausalFrontierError("frozen case source artifact is reused")
        referenced.add(identity)
        expected_paths.add(path)
    actual_paths = {path for path in artifact_paths if _under_prefix(path, case_path.parent.as_posix())}
    if actual_paths != expected_paths:
        raise CausalFrontierError(
            "frozen case inventory differs from declared provenance",
            reason_code="INVENTORY_MISMATCH",
            operation="challenge._bind_case_sources",
        )
    return frozen_case


def _verify_unchanged(
    root: Path,
    raw_manifest: bytes,
    expected_files: set[str],
    artifacts: dict[str, dict[str, Any]],
    artifact_paths: dict[str, str],
    raw_artifacts: dict[str, bytes],
) -> None:
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            if receipt_io._snapshot(descriptor, MANIFEST) != raw_manifest:
                raise CausalFrontierError(
                    "challenge manifest changed during preflight",
                    reason_code="INPUT_CHANGED",
                    operation="challenge._verify_unchanged",
                )
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError(
                    "challenge inventory changed during preflight",
                    reason_code="INPUT_CHANGED",
                    operation="challenge._verify_unchanged",
                )
            for path, identity in sorted(artifact_paths.items()):
                if receipt_io._snapshot(descriptor, path) != raw_artifacts[identity]:
                    raise CausalFrontierError(
                        "challenge artifact changed during preflight",
                        reason_code="INPUT_CHANGED",
                        operation="challenge._verify_unchanged",
                    )
                if sha256_bytes(raw_artifacts[identity]) != artifacts[identity]["sha256"]:
                    raise CausalFrontierError(
                        "challenge artifact digest changed during preflight",
                        reason_code="INPUT_CHANGED",
                        operation="challenge._verify_unchanged",
                    )
    except OSError as exc:
        raise io_error(
            exc, "challenge filesystem cannot be reverified safely", operation="challenge._verify_unchanged"
        ) from None


def _gate(identity: str, status: str, reason: str) -> dict[str, str]:
    return {"id": identity, "status": status, "reason": reason}


def preflight_challenge(root: Path, expected_manifest_sha256: str, expected_sequence: int) -> dict[str, Any]:
    """Verify a complete challenge bundle and preserve every scientific blocker.

    The expected digest must be stored outside ``root``.  This function performs
    read-only byte binding and structural validation; it never scores a case.
    """

    require_sha256(expected_manifest_sha256, "external challenge checkpoint")
    expected_sequence = _positive_integer(expected_sequence, "external challenge sequence")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, MANIFEST)
            if sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("external challenge checkpoint mismatch")
            document = _strict_json(raw_manifest, MANIFEST)
            manifest = _shape(
                document,
                {
                    "schema_version",
                    "id",
                    "fixed_parameter",
                    "boundary",
                    "sequence",
                    "predecessor_manifest_sha256",
                    "frozen_at",
                    "scope",
                    "metric_contract",
                    "reveal_commitment_sha256",
                    "reveal_commitment_scheme",
                    "artifacts",
                    "cases",
                    "encoders",
                    "encodings",
                    "baselines",
                },
                "challenge",
            )
            if manifest["schema_version"] != SCHEMA_VERSION or manifest["fixed_parameter"] != FIXED_PARAMETER:
                raise CausalFrontierError("challenge schema or fixed parameter differs")
            challenge_id = require_id(manifest["id"], "challenge id")
            if canonical_bytes(manifest["boundary"]) != BOUNDARY_CANONICAL:
                raise CausalFrontierError("challenge boundary is immutable with exact value types")
            sequence = _positive_integer(manifest["sequence"], "challenge sequence")
            if sequence != expected_sequence:
                raise CausalFrontierError("external challenge sequence mismatch")
            predecessor = require_sha256(manifest["predecessor_manifest_sha256"], "predecessor challenge digest")
            if (sequence == 1 and predecessor != GENESIS) or (sequence > 1 and predecessor == GENESIS):
                raise CausalFrontierError("challenge predecessor lineage is discontinuous")
            if predecessor == expected_manifest_sha256:
                raise CausalFrontierError("challenge cannot name itself as predecessor")
            frozen_at = require_utc_timestamp(manifest["frozen_at"], "challenge freeze")
            scope = require_enum(manifest["scope"], SCOPES, "challenge scope")
            if canonical_bytes(manifest["metric_contract"]) != METRIC_CONTRACT_CANONICAL:
                raise CausalFrontierError("challenge metric contract differs from provisional v1")
            reveal_commitment = require_sha256(manifest["reveal_commitment_sha256"], "hidden reveal commitment")
            if manifest["reveal_commitment_scheme"] != REVEAL_COMMITMENT_SCHEME:
                raise CausalFrontierError("challenge reveal commitment scheme differs")
            artifacts, artifact_paths = _artifact_table(manifest["artifacts"])
            expected_files = {MANIFEST, *artifact_paths}
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError(
                    "challenge file inventory differs",
                    reason_code="INVENTORY_MISMATCH",
                    operation="challenge.preflight_challenge",
                )
            raw_artifacts: dict[str, bytes] = {}
            total_size = len(raw_manifest)
            for path, identity in sorted(artifact_paths.items()):
                raw = receipt_io._snapshot(descriptor, path)
                total_size += len(raw)
                if total_size > MAX_CHALLENGE_BYTES:
                    raise CausalFrontierError("challenge total byte limit exceeded")
                if sha256_bytes(raw) != artifacts[identity]["sha256"]:
                    raise CausalFrontierError("challenge artifact digest mismatch")
                receipt_io._screen(raw)
                raw_artifacts[identity] = raw
            if receipt_io._inventory(descriptor) != expected_files:
                raise CausalFrontierError(
                    "challenge inventory changed during preflight",
                    reason_code="INPUT_CHANGED",
                    operation="challenge.preflight_challenge",
                )
    except OSError as exc:
        raise io_error(
            exc, "challenge filesystem cannot be read safely", operation="challenge.preflight_challenge"
        ) from None

    referenced: set[str] = set()
    cases = _bounded_list(manifest["cases"], "cases", 3, MAX_CASES)
    case_table: dict[str, dict[str, Any]] = {}
    receipt_set_digests: dict[str, str] = {}
    receipt_bindings: dict[str, dict[str, Any]] = {}
    controls: set[str] = set()
    domains: set[str] = set()
    for index, item in enumerate(cases):
        case = _shape(
            item,
            {
                "id",
                "control_class",
                "domain",
                "evidence_cutoff",
                "receipt_preflight_artifact_id",
                "receipt_bundle_path",
                "selection_origin",
            },
            "case[%d]" % index,
        )
        case_id = require_id(case["id"], "case id")
        if case_id in case_table:
            raise CausalFrontierError("duplicate challenge case id: %s" % case_id)
        control = require_enum(case["control_class"], CONTROL_CLASSES, "control class")
        controls.add(control)
        domains.add(require_id(case["domain"], "case domain"))
        cutoff = require_utc_timestamp(case["evidence_cutoff"], "case evidence cutoff")
        if cutoff > frozen_at:
            raise CausalFrontierError("case evidence cutoff follows challenge freeze")
        origin = require_enum(case["selection_origin"], SELECTION_ORIGINS, "selection origin")
        if scope == "SYNTHETIC_PROTOCOL_TEST" and origin != "SYNTHETIC_FIXTURE":
            raise CausalFrontierError("synthetic challenge must contain only synthetic fixtures")
        receipt_artifact = _require_artifact(
            case["receipt_preflight_artifact_id"],
            "RECEIPT_PREFLIGHT",
            artifacts,
            referenced,
            "receipt preflight artifact",
        )
        receipt_report = _validate_receipt_preflight(
            _strict_json(raw_artifacts[receipt_artifact], "receipt preflight artifact"), origin
        )
        receipt_binding = _bind_receipt_bundle(
            root,
            case["receipt_bundle_path"],
            receipt_report,
            cutoff,
            frozen_at,
            scope,
            artifacts,
            artifact_paths,
            raw_artifacts,
            referenced,
        )
        receipt_bindings[case_id] = receipt_binding
        receipt_set_digests[case_id] = receipt_binding["receipt_set_sha256"]
        case_table[case_id] = case
    if len(set(receipt_set_digests.values())) != len(receipt_set_digests):
        raise CausalFrontierError("challenge cases must bind distinct receipt sets")
    if controls != CONTROL_CLASSES:
        raise CausalFrontierError("challenge requires positive, failed-translation, and ambiguous controls")

    encoders = _bounded_list(manifest["encoders"], "encoders", 2, 2)
    encoder_table: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(encoders):
        encoder = _shape(item, {"id", "organization_id", "independence_state"}, "encoder[%d]" % index)
        encoder_id = require_id(encoder["id"], "encoder id")
        if encoder_id in encoder_table:
            raise CausalFrontierError("duplicate encoder id: %s" % encoder_id)
        require_id(encoder["organization_id"], "encoder organization id")
        require_enum(
            encoder["independence_state"],
            {"SELF_DECLARED_UNVERIFIED"},
            "encoder independence state",
        )
        encoder_table[encoder_id] = encoder

    expected_encodings = len(cases) * len(encoders)
    encodings = _bounded_list(manifest["encodings"], "encodings", expected_encodings, expected_encodings)
    by_case: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    shared_dossiers: dict[str, str] = {}
    shared_action_inputs: dict[str, set[str]] = defaultdict(set)
    encoding_ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for index, item in enumerate(encodings):
        encoding = _shape(
            item,
            {"id", "case_id", "encoder_id", "frozen_case_artifact_id"},
            "encoding[%d]" % index,
        )
        encoding_id = require_id(encoding["id"], "encoding id")
        if encoding_id in encoding_ids:
            raise CausalFrontierError("duplicate encoding id: %s" % encoding_id)
        encoding_ids.add(encoding_id)
        case_id = require_id(encoding["case_id"], "encoding case id")
        encoder_id = require_id(encoding["encoder_id"], "encoding encoder id")
        if case_id not in case_table or encoder_id not in encoder_table:
            raise CausalFrontierError("encoding references an unknown case or encoder")
        if (case_id, encoder_id) in pairs:
            raise CausalFrontierError("encoder submitted more than one encoding for a case")
        pairs.add((case_id, encoder_id))
        artifact_id = _require_artifact(
            encoding["frozen_case_artifact_id"],
            "FROZEN_CASE",
            artifacts,
            referenced,
            "frozen case artifact",
        )
        frozen_case = _bind_case_sources(artifact_id, artifacts, artifact_paths, raw_artifacts, referenced)
        if (
            frozen_case["case_id"] != case_id
            or frozen_case["evidence_cutoff"] != case_table[case_id]["evidence_cutoff"]
            or frozen_case["frozen_at"] > frozen_at
        ):
            raise CausalFrontierError("frozen case artifact differs from challenge case binding")
        if scope == "SYNTHETIC_PROTOCOL_TEST" and any(
            source["data_class"] != "SYNTHETIC" or source["authority"] != "SYNTHETIC_DATA"
            for source in frozen_case["provenance"]
        ):
            raise CausalFrontierError("synthetic challenge frozen case is not synthetic-only")
        for source in frozen_case["provenance"]:
            candidates = receipt_bindings[case_id]["raw_response_bindings"].get(source["sha256"], [])
            if not candidates:
                raise CausalFrontierError("frozen case evidence is not directly bound to replayed receipt bytes")
            if not any(_receipt_supports_source(source, receipt) for receipt in candidates):
                raise CausalFrontierError("receipt and frozen case acquisition semantics differ")
        dossier_sha256 = sha256_bytes(
            canonical_bytes(
                {
                    "evidence_cutoff": frozen_case["evidence_cutoff"],
                    "provenance": frozen_case["provenance"],
                    "decision": frozen_case["decision"],
                }
            )
        )
        prior_dossier = shared_dossiers.setdefault(case_id, dossier_sha256)
        if prior_dossier != dossier_sha256:
            raise CausalFrontierError("independent encodings do not share one evidence and decision dossier")
        shared_action_inputs[case_id].add(sha256_bytes(canonical_bytes(_shared_action_input_core(frozen_case))))
        organization = encoder_table[encoder_id]["organization_id"]
        by_case[case_id].append((encoder_id, organization, artifacts[artifact_id]["sha256"]))
    for case_id, case_encodings in by_case.items():
        if (
            len(case_encodings) != len(encoders)
            or {item[0] for item in case_encodings} != set(encoder_table)
            or len({item[1] for item in case_encodings}) != len(encoders)
        ):
            raise CausalFrontierError("case %s needs encodings from two organizations" % case_id)
    if set(by_case) != set(case_table):
        raise CausalFrontierError("every challenge case needs independent encodings")
    execution_aligned = all(len(digests) == 1 for digests in shared_action_inputs.values())

    baselines = _bounded_list(manifest["baselines"], "baselines", len(BASELINE_FAMILIES), 32)
    baseline_ids: set[str] = set()
    families: set[str] = set()
    for index, item in enumerate(baselines):
        baseline = _shape(item, {"id", "family", "artifact_id"}, "baseline[%d]" % index)
        baseline_id = require_id(baseline["id"], "baseline id")
        if baseline_id in baseline_ids:
            raise CausalFrontierError("duplicate baseline id: %s" % baseline_id)
        baseline_ids.add(baseline_id)
        family = require_enum(baseline["family"], BASELINE_FAMILIES, "baseline family")
        if family in families:
            raise CausalFrontierError("baseline family is duplicated")
        families.add(family)
        artifact_id = _require_artifact(
            baseline["artifact_id"],
            "BASELINE_SPECIFICATION",
            artifacts,
            referenced,
            "baseline artifact",
        )
        if artifacts[artifact_id]["media_type"] != "application/json":
            raise CausalFrontierError("baseline specification must be JSON")
        _validate_baseline_spec(_strict_json(raw_artifacts[artifact_id], "baseline specification"), baseline_id, family)
    if families != BASELINE_FAMILIES:
        raise CausalFrontierError("challenge is missing one or more required baseline families")
    if referenced != set(artifacts):
        raise CausalFrontierError("challenge contains unreferenced artifacts")
    _verify_unchanged(root, raw_manifest, expected_files, artifacts, artifact_paths, raw_artifacts)

    hindsight_n = sum(case["selection_origin"] == "KNOWN_HINDSIGHT" for case in cases)
    gates = [
        _gate("artifact_integrity", "PASS", "CASE_EVIDENCE_RECEIPTS_AND_SPECS_REPLAYED_FROM_EXACT_BYTES"),
        _gate(
            "receipt_to_dossier",
            "PASS",
            "EVERY_DOSSIER_SOURCE_MATCHES_REPLAYED_BYTES_AND_ACQUISITION_SEMANTICS",
        ),
        _gate("control_trio", "PASS", "THREE_REQUIRED_DECLARED_CONTROL_ROLE_LABELS_PRESENT"),
        _gate("control_validity", "NO_CALL", "CONTROL_LABELS_DECLARED_NOT_INDEPENDENTLY_ADJUDICATED"),
        _gate("branch_totality", "PASS", "EVERY_ENCODING_PASSES_FROZEN_CASE_VALIDATION"),
        _gate("authority", "PASS", "IMMUTABLE_ALPHA_BOUNDARY"),
        _gate(
            "domain_diversity",
            "NO_CALL",
            "THREE_DECLARED_DOMAINS_NOT_INDEPENDENTLY_VERIFIED" if len(domains) >= 3 else "CROSS_DOMAIN_GATE_UNMET",
        ),
        _gate("privacy", "NO_CALL", "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION"),
        _gate("encoder_independence", "NO_CALL", "SELF_DECLARED_NOT_INDEPENDENTLY_VERIFIED"),
        _gate("encoding_agreement", "NO_CALL", "BLINDED_AGREEMENT_SCORER_NOT_IMPLEMENTED"),
        _gate(
            "execution_alignment",
            "PASS" if execution_aligned else "NO_CALL",
            "EXACT_SHARED_DOSSIER_GATES_AND_ACTION_CONTRACT_ENCODER_WORLDS_REMAIN_SEPARATE"
            if execution_aligned
            else "ENCODER_ACTION_OR_MEASUREMENT_CONTRACTS_DIFFER",
        ),
        _gate("temporal_leakage", "NO_CALL", "RECEIPT_V1_HAS_NO_INDEPENDENT_TEMPORAL_VERIFIER"),
        _gate("receipt_replay", "PASS", "REPORT_RECOMPUTED_FROM_BOUND_RECEIPT_SET_AND_PAYLOAD_BYTES"),
        _gate(
            "scope_integrity",
            "PASS" if scope == "SYNTHETIC_PROTOCOL_TEST" else "NO_CALL",
            "SYNTHETIC_DATA_CLASSES_ENFORCED"
            if scope == "SYNTHETIC_PROTOCOL_TEST"
            else "HISTORICAL_SCOPE_HAS_NO_INDEPENDENT_PROVENANCE_ADJUDICATION",
        ),
        _gate("baseline_specifications", "PASS", "ALL_REQUIRED_V1_SPECIFICATIONS_SCHEMA_BOUND"),
        _gate("baseline_execution", "NO_CALL", "SPECIFICATIONS_BOUND_BUT_NOT_EXECUTED"),
        _gate("rollback", "NO_CALL", "CALLER_CHECKPOINT_NOT_PROVEN_INDEPENDENTLY_STORED_OR_MONOTONIC"),
        _gate("reveal_commitment", "NO_CALL", "SCHEME_BOUND_BUT_OPENING_AND_EXTERNAL_TIMESTAMP_UNVERIFIED"),
        _gate("scientific_scoring", "NO_CALL", "ALL_SCIENTIFIC_SCORING_DISABLED"),
    ]
    if hindsight_n:
        gates.append(_gate("historical_blinding", "NO_CALL", "KNOWN_HINDSIGHT_CASES_PRESENT"))
    else:
        gates.append(_gate("historical_blinding", "NO_CALL", "LATENT_MODEL_CONTAMINATION_NOT_EXCLUDED"))
    return {
        "schema_version": PREFLIGHT_VERSION,
        "status": "STRUCTURALLY_BOUND_AND_REPLAYED_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_CHALLENGE_PREFLIGHT",
        "base_compiler_version": COMPILER_VERSION,
        "challenge_id": challenge_id,
        "challenge_sequence": sequence,
        "predecessor_manifest_sha256": predecessor,
        "challenge_manifest_sha256": expected_manifest_sha256,
        "canonical_challenge_sha256": sha256_bytes(canonical_bytes(document)),
        "challenge_registration_sha256": challenge_registration_sha256(document),
        "scope": scope,
        "reveal_commitment_sha256": reveal_commitment,
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "metric_contract": fixed_metric_contract(),
        "control_classes": sorted(controls),
        "domains": sorted(domains),
        "cases_n": len(cases),
        "encodings_n": len(encodings),
        "required_baseline_families": sorted(families),
        "known_hindsight_cases_n": hindsight_n,
        "protocol_exercise_ready": execution_aligned,
        "scientific_scoring_ready": False,
        "gates": sorted(gates, key=lambda gate: gate["id"]),
        "case_encoding_sha256": {
            case_id: sorted(item[2] for item in case_encodings) for case_id, case_encodings in sorted(by_case.items())
        },
        "case_shared_dossier_sha256": dict(sorted(shared_dossiers.items())),
        "case_shared_action_input_sha256": {
            case_id: next(iter(digests))
            for case_id, digests in sorted(shared_action_inputs.items())
            if len(digests) == 1
        },
        "case_receipt_set_sha256": dict(sorted(receipt_set_digests.items())),
        "files_sha256": {
            MANIFEST: expected_manifest_sha256,
            **{artifact["path"]: artifact["sha256"] for artifact in artifacts.values()},
        },
        "nonclaims": list(NONCLAIMS),
    }


def load_protocol_cases(
    root: Path, expected_manifest_sha256: str, expected_sequence: int
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Load exact frozen encodings only after complete challenge preflight.

    This helper is for local protocol exercises. It deliberately returns both
    encoder strata and never reconciles their causal worlds or predictions.
    """

    before = preflight_challenge(root, expected_manifest_sha256, expected_sequence)
    if not before["protocol_exercise_ready"]:
        raise CausalFrontierError("challenge encodings do not share an executable action contract")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(descriptor, MANIFEST)
            if sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("external challenge checkpoint mismatch")
            manifest = _strict_json(raw_manifest, MANIFEST)
            artifacts, _paths = _artifact_table(manifest["artifacts"])
            by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for encoding in sorted(manifest["encodings"], key=lambda item: item["id"]):
                artifact = artifacts[encoding["frozen_case_artifact_id"]]
                raw_case = receipt_io._snapshot(descriptor, artifact["path"])
                if sha256_bytes(raw_case) != artifact["sha256"]:
                    raise CausalFrontierError("frozen case artifact digest changed")
                frozen_case = validate_case(_strict_json(raw_case, "frozen case artifact"))
                by_case[encoding["case_id"]].append(
                    {
                        "encoding_id": encoding["id"],
                        "encoder_id": encoding["encoder_id"],
                        "frozen_case_sha256": artifact["sha256"],
                        "case": frozen_case,
                    }
                )
    except OSError as exc:
        raise io_error(
            exc, "challenge protocol cases cannot be read safely", operation="challenge.load_protocol_cases"
        ) from None
    after = preflight_challenge(root, expected_manifest_sha256, expected_sequence)
    if canonical_bytes(before) != canonical_bytes(after):
        raise CausalFrontierError(
            "challenge changed while protocol cases were loaded",
            reason_code="INPUT_CHANGED",
            operation="challenge.load_protocol_cases",
        )
    return before, dict(sorted(by_case.items()))
