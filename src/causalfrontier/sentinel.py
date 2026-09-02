"""Artifact-closed sentinel cohort admission preflight.

This module closes the missing preimage behind the goal claim plan's cohort
checkpoint.  It validates a pre-generation assignment plan, an exact bounded
artifact bundle, and the existing immutable goal claim plan as one read-only
composition.  It deliberately cannot admit a cohort or enable scoring: semantic
validity, public availability at a cutoff, generator independence, privacy, and
prospective custody require external evidence and authority.
"""

from __future__ import annotations

import os
import stat
from collections import Counter
from contextlib import ExitStack
from itertools import combinations
from pathlib import Path
from typing import Any

from . import claim
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

GENERATION_PLAN_SCHEMA_VERSION = "causalfrontier.sentinel-generation-plan.v1"
GENERATION_PLAN_STATUS = "PREGENERATION_ASSIGNMENT_LOCK_SCORING_DISABLED"
GENERATION_PLAN_DOMAIN_TAG = b"causalfrontier.sentinel-generation-plan.v1\x00"
MANIFEST_SCHEMA_VERSION = "causalfrontier.sentinel-admission-manifest.v1"
PHASE_BOUND_MANIFEST_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-admission-manifest.v1"
PHASE_BOUND_PAYLOAD_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-case-payload.v1"
PHASE_BOUND_PROVENANCE_SCHEMA_VERSION = "causalfrontier.sentinel-phase-bound-case-provenance.v1"
GENERATION_PHASE_CONTEXT_SCHEMA_VERSION = "causalfrontier.sentinel-generation-phase-context.v1"
PREFLIGHT_SCHEMA_VERSION = "causalfrontier.sentinel-admission-preflight.v1"
PREFLIGHT_STATUS = "SENTINEL_ADMISSION_ASSESSED_NOT_ADMITTED"
PREFLIGHT_DOMAIN_TAG = b"causalfrontier.sentinel-admission-preflight.v1\x00"
MANIFEST = "sentinel-admission.json"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_ARTIFACT_CLOSURE_PREFLIGHT"
SCOPE = "PUBLIC_OR_SYNTHETIC_NON_PATIENT_READ_ONLY"
AUDIENCE = "STEWARD_ONLY_AGGREGATES"

EXACT_DOMAINS = 3
EXACT_GENERATOR_FAMILIES = 3
PRIMARY_CASES_PER_DOMAIN = 10
LABORATORIES_PER_DOMAIN = 2
CONTROL_ROLES = claim.CONTROL_ROLES
CONTROL_BEHAVIORS = dict(zip(claim.CONTROL_ROLES, claim.CONTROL_REQUIRED_BEHAVIORS, strict=True))
CASE_ROLES = frozenset({"PRIMARY", *CONTROL_ROLES})
PRIMARY_ORIGIN = "UNASSESSED_PROSPECTIVE_CANDIDATE"
CONTROL_ORIGIN = "KNOWN_HINDSIGHT_CALIBRATION_ONLY"
MAX_ARTIFACTS = 512
MAX_FILES = MAX_ARTIFACTS + 1
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MEDIA_TYPES = frozenset({"application/json", "text/plain", "text/x-python", "text/markdown", "text/csv"})
DATA_CLASSES = frozenset({"PUBLIC_AGGREGATE", "PUBLIC_METADATA", "SYNTHETIC", "OPEN_SOURCE_TEXT"})

ARTIFACT_ROLES = frozenset(
    {
        "ADMISSION_POLICY",
        "SEMANTIC_REVIEW_PROTOCOL",
        "GENERATOR_AUDIT_PROTOCOL",
        "CUTOFF_AUDIT_PROTOCOL",
        "PROVENANCE_PROTOCOL",
        "PRIVACY_REVIEW_PROTOCOL",
        "CONTROL_SCORING_PROTOCOL",
        "CONTROL_SCORING_IMPLEMENTATION",
        "GENERATOR_SOURCE_MANIFEST",
        "GENERATOR_SOURCE_FILE",
        "GENERATOR_DEPENDENCY_LOCK",
        "GENERATOR_BUILD_RECIPE",
        "GENERATOR_ENVIRONMENT",
        "GENERATOR_TOOL_MODEL_INVENTORY",
        "GENERATOR_INPUT_INVENTORY",
        "GENERATOR_CONTROLLER_DISCLOSURE",
        "GENERATOR_ANCESTRY",
        "GENERATOR_EXECUTION_PROTOCOL",
        "GENERATOR_PAIR_AUDIT",
        "DOMAIN_SEMANTICS",
        "DOMAIN_REVIEW",
        "DOMAIN_PAIR_REVIEW",
        "CONTROL_METHODOLOGY_REVIEW",
        "CASE_PAYLOAD",
        "CASE_ROLE_PACKET",
        "CASE_SOURCE_INVENTORY",
        "CASE_CUTOFF_AUDIT",
        "CASE_PROVENANCE",
        "SOURCE_EVIDENCE",
        "AVAILABILITY_EVIDENCE",
        "TRANSFORM_INTERMEDIATE",
    }
)

ORGANIZATION_ROLES = frozenset(
    {
        "STEWARD",
        "GENERATOR_AUTHOR",
        "GENERATOR_CONTROLLER",
        "GENERATOR_AUDITOR",
        "DOMAIN_REVIEWER",
        "CONTROL_REVIEWER",
        "LABORATORY",
        "OUTCOME_PROVIDER",
        "ADJUDICATOR",
    }
)

GENERATOR_FAMILY_RULE = (
    "MAXIMAL_CLUSTER_SHARING_CONTROLLER_SOURCE_ANCESTRY_TEMPLATE_SCAFFOLD_PROMPT_PROGRAM_"
    "GENERATOR_IMPLEMENTATION_OR_HIDDEN_SELECTION_PROCESS"
)
CONTROL_ASSIGNMENT_RULE = "EXACT_THREE_BY_THREE_LATIN_SQUARE_EACH_FAMILY_ONCE_PER_DOMAIN_AND_CONTROL_ROLE"
PRIMARY_BALANCE_RULE = (
    "EVERY_DOMAIN_USES_ALL_THREE_GENERATOR_FAMILIES_NONE_CONTRIBUTES_A_MAJORITY_"
    "EACH_FAMILY_OCCURS_IN_BOTH_LABS_WITH_CELL_DIFFERENCE_AT_MOST_ONE"
)
CASE_SELECTION_RULE = "ALL_CASE_IDS_ROLES_GENERATORS_CUTOFFS_AND_INCLUSION_RULES_LOCKED_BEFORE_GENERATION"
ORACLE_BOUNDARY_RULE = "ONLY_DOMAIN_SEPARATED_EXTERNAL_COMMITMENTS_OPENINGS_EXCLUDED"
SOURCE_ELIGIBILITY_RULE = (
    "ONLY_EXACT_PUBLIC_AGGREGATE_OR_SYNTHETIC_SOURCE_BYTES_DECLARED_AVAILABLE_NO_LATER_THAN_CASE_CUTOFF"
)
CUTOFF_RULE = "CASE_SOURCE_AND_TOOL_ACCESS_MUST_NOT_EXCEED_THE_PRECOMMITTED_WHOLE_SECOND_UTC_CUTOFF"

REJECTION_REASON_ORDER = (
    "DECLARED_SOURCE_AFTER_CASE_CUTOFF",
    "DECLARED_GENERATOR_KNOWLEDGE_AFTER_CASE_CUTOFF",
    "EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION",
    "DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION",
    "DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION",
    "NORMALIZED_DOMAIN_SEMANTICS_COLLISION",
    "NORMALIZED_CASE_DECISION_CORE_COLLISION",
)

NONCLAIMS = (
    "Artifact closure and exact replay do not establish scientific correctness, authorship, or semantic validity.",
    "Different source bytes and declared organization identifiers do not establish generator or governance "
    "independence.",
    "The three-domain Latin square removes declared role confounding only; it does not prove domain diversity.",
    "Self-declared dates and availability packets do not prove that exact source bytes were public before a cutoff.",
    "The API accepts no designated opening, outcome, result, winner, or score input, but arbitrary content may "
    "encode them.",
    "Seed and oracle SHA-256 values are caller-supplied digest declarations; local uniqueness and alias checks do "
    "not verify commitment preimages, entropy, hiding, binding, custody, or timely publication.",
    "Exact normalized text collision checks exclude oracle commitments but cannot establish semantic diversity or "
    "detect paraphrased duplicates.",
    "Public or synthetic labels and bounded pattern screens are not privacy certification or proof of "
    "patient-data absence.",
    "The pre-generation checkpoint is caller supplied and does not prove independent time, monotonic custody, "
    "or currentness.",
    "Known-hindsight controls are calibration only and can never count as prospective primary performance.",
    "A complete review packet is not admission, registration, comparator execution, acceleration, or a "
    "scientific claim.",
    "No biological, clinical, patient, wet-lab, material, publication, release, or scoring authority is granted.",
)

FIXED_FALSE_FIELDS = frozenset(
    {
        "cohort_admitted",
        "externally_registered",
        "scientific_scoring_ready",
        "scientific_claim_ready",
        "prospective_primary_eligible",
        "domain_semantic_validity_verified",
        "control_semantic_validity_verified",
        "generator_independence_verified",
        "governance_independence_verified",
        "content_outcome_isolation_verified",
        "independent_cutoff_admissibility_verified",
        "privacy_certified",
        "provenance_truth_verified",
        "rollback_currentness_verified",
        "publication_claim_authorized",
    }
)

PROTOCOL_FIELDS = {
    "admission_policy_artifact_id": "ADMISSION_POLICY",
    "semantic_review_protocol_artifact_id": "SEMANTIC_REVIEW_PROTOCOL",
    "generator_audit_protocol_artifact_id": "GENERATOR_AUDIT_PROTOCOL",
    "cutoff_audit_protocol_artifact_id": "CUTOFF_AUDIT_PROTOCOL",
    "provenance_protocol_artifact_id": "PROVENANCE_PROTOCOL",
    "privacy_review_protocol_artifact_id": "PRIVACY_REVIEW_PROTOCOL",
    "control_scoring_protocol_artifact_id": "CONTROL_SCORING_PROTOCOL",
    "control_scoring_implementation_artifact_id": "CONTROL_SCORING_IMPLEMENTATION",
}

GENERATOR_ARTIFACT_FIELDS = {
    "source_manifest_artifact_id": "GENERATOR_SOURCE_MANIFEST",
    "dependency_lock_artifact_id": "GENERATOR_DEPENDENCY_LOCK",
    "build_recipe_artifact_id": "GENERATOR_BUILD_RECIPE",
    "environment_artifact_id": "GENERATOR_ENVIRONMENT",
    "tool_model_inventory_artifact_id": "GENERATOR_TOOL_MODEL_INVENTORY",
    "input_inventory_artifact_id": "GENERATOR_INPUT_INVENTORY",
    "controller_disclosure_artifact_id": "GENERATOR_CONTROLLER_DISCLOSURE",
    "ancestry_artifact_id": "GENERATOR_ANCESTRY",
    "execution_protocol_artifact_id": "GENERATOR_EXECUTION_PROTOCOL",
}

GENERATOR_PRECOMMITMENT_DIGEST_FIELDS = {
    "dependency_lock_sha256": "dependency_lock_artifact_id",
    "build_recipe_sha256": "build_recipe_artifact_id",
    "environment_sha256": "environment_artifact_id",
    "tool_model_inventory_sha256": "tool_model_inventory_artifact_id",
    "input_inventory_sha256": "input_inventory_artifact_id",
    "controller_disclosure_sha256": "controller_disclosure_artifact_id",
    "ancestry_sha256": "ancestry_artifact_id",
    "execution_protocol_sha256": "execution_protocol_artifact_id",
}

GENERATION_PHASE_CONTEXT_KEYS = {
    "schema_version",
    "lock_id",
    "sequence",
    "generation_plan_checkpoint_sha256",
    "generation_plan_sha256",
    "generation_lock_preflight_sha256",
    "generation_epoch_sha256",
}


def _shape(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    return require_exact_keys(value, keys, field)


def _positive_integer(value: Any, field: str, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded positive integer" % field)
    return value


def _nonnegative_integer(value: Any, field: str, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded nonnegative integer" % field)
    return value


def _sorted_ids(value: Any, field: str, *, exact: int | None = None, minimum: int = 1) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum or (exact is not None and len(value) != exact):
        raise CausalFrontierError("%s has invalid cardinality" % field)
    result = [require_id(item, "%s item" % field) for item in value]
    if result != sorted(set(result)) or len({item.casefold() for item in result}) != len(result):
        raise CausalFrontierError("%s must contain case-insensitively unique sorted identifiers" % field)
    return result


def _strict_json(raw: bytes, label: str) -> Any:
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    receipt_io._screen(canonical_bytes(value))
    return value


def _artifact_digest(value: Any, field: str) -> str:
    digest = require_sha256(value, field)
    if digest == "0" * 64:
        raise CausalFrontierError("%s must not be an all-zero placeholder" % field)
    return digest


def _validate_generation_phase_context(
    value: Any,
    expected: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the exact non-null phase-1 successor context.

    This context is deliberately separate from the phase-1 target's nullable
    predecessor field.  It names the current, freshly replayed dual-witness
    preflight and generation epoch that successor bytes must embed.
    """

    context = _shape(value, set(GENERATION_PHASE_CONTEXT_KEYS), "sentinel generation phase context")
    if context["schema_version"] != GENERATION_PHASE_CONTEXT_SCHEMA_VERSION:
        raise CausalFrontierError("sentinel generation phase context schema differs")
    require_id(context["lock_id"], "sentinel generation phase lock id")
    _positive_integer(context["sequence"], "sentinel generation phase sequence")
    for field in sorted(GENERATION_PHASE_CONTEXT_KEYS - {"schema_version", "lock_id", "sequence"}):
        _artifact_digest(context[field], "sentinel generation phase %s" % field)
    if expected is not None and canonical_bytes(context) != canonical_bytes(expected):
        raise CausalFrontierError("sentinel generation phase context differs from fresh phase-1 replay")
    return context


def _validate_fixed_header(value: dict[str, Any], *, schema: str, status: str | None = None) -> None:
    if value["schema_version"] != schema or value["fixed_parameter"] != FIXED_PARAMETER:
        raise CausalFrontierError("sentinel schema or fixed parameter differs")
    if status is not None and value["status"] != status:
        raise CausalFrontierError("sentinel status differs")
    if canonical_bytes(value["boundary"]) != BOUNDARY_CANONICAL:
        raise CausalFrontierError("sentinel authority boundary differs")


def _read_checkpointed_json(path: Path, expected_sha256: str, label: str) -> tuple[bytes, dict[str, Any]]:
    _artifact_digest(expected_sha256, "%s external checkpoint" % label)
    if path.name in {"", ".", ".."}:
        raise CausalFrontierError("%s path must name one file" % label)
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError:
        raise CausalFrontierError("%s cannot be read safely" % label) from None
    if len(raw) > MAX_FILE_BYTES or sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("%s external checkpoint mismatch or size limit exceeded" % label)
    value = _strict_json(raw, label)
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    return raw, value


def _validate_generation_case_assignment(value: Any, index: int) -> dict[str, Any]:
    item = _shape(
        value,
        {
            "case_id",
            "domain_id",
            "case_role",
            "control_role",
            "required_behavior",
            "generator_family_id",
            "outcome_provider_organization_id",
            "role_packet_sha256",
            "source_inventory_sha256",
            "laboratory_id",
            "selection_origin",
            "knowledge_cutoff",
        },
        "generation case assignment[%d]" % index,
    )
    require_id(item["case_id"], "generation case id")
    require_id(item["domain_id"], "generation case domain id")
    role = require_enum(item["case_role"], set(CASE_ROLES), "generation case role")
    require_id(item["generator_family_id"], "generation case family id")
    require_id(item["outcome_provider_organization_id"], "generation outcome provider or adjudicator id")
    _artifact_digest(item["role_packet_sha256"], "precommitted role packet")
    _artifact_digest(item["source_inventory_sha256"], "precommitted source inventory")
    require_utc_timestamp(item["knowledge_cutoff"], "generation case cutoff")
    if role == "PRIMARY":
        if (
            item["control_role"] is not None
            or item["required_behavior"] is not None
            or item["selection_origin"] != PRIMARY_ORIGIN
        ):
            raise CausalFrontierError("primary generation assignment has calibration semantics")
        require_id(item["laboratory_id"], "primary generation laboratory")
    else:
        if (
            item["control_role"] != role
            or item["required_behavior"] != CONTROL_BEHAVIORS[role]
            or item["laboratory_id"] is not None
            or item["selection_origin"] != CONTROL_ORIGIN
        ):
            raise CausalFrontierError("calibration generation assignment violates its fixed role")
    return item


def _validate_generation_plan(value: Any) -> dict[str, Any]:
    plan = _shape(
        value,
        {
            "schema_version",
            "status",
            "plan_id",
            "sequence",
            "fixed_parameter",
            "boundary",
            "goal_claim_contract_sha256",
            "frozen_at",
            "scope",
            "organization_registry_sha256",
            "domain_ids",
            "generator_family_ids",
            "domain_contracts",
            "case_assignments",
            "generator_precommitments",
            "protocol_precommitments",
            "rules",
            "designated_outcome_input_absent",
            "case_selection_after_generation_allowed",
            "oracle_opening_input_allowed",
            "scoring_disabled",
            "plan_sha256",
        },
        "sentinel generation plan",
    )
    _validate_fixed_header(plan, schema=GENERATION_PLAN_SCHEMA_VERSION, status=GENERATION_PLAN_STATUS)
    require_id(plan["plan_id"], "sentinel generation plan id")
    _positive_integer(plan["sequence"], "sentinel generation sequence")
    if plan["goal_claim_contract_sha256"] != claim.goal_claim_contract_sha256():
        raise CausalFrontierError("generation plan binds a different goal claim contract")
    frozen_at = require_utc_timestamp(plan["frozen_at"], "sentinel generation freeze")
    if plan["scope"] != SCOPE:
        raise CausalFrontierError("sentinel generation scope differs")
    _artifact_digest(plan["organization_registry_sha256"], "precommitted organization registry")
    domain_ids = _sorted_ids(plan["domain_ids"], "generation domain ids", exact=EXACT_DOMAINS)
    family_ids = _sorted_ids(plan["generator_family_ids"], "generation family ids", exact=EXACT_GENERATOR_FAMILIES)

    rules = _shape(
        plan["rules"],
        {
            "generator_family_definition",
            "control_assignment_rule",
            "primary_balance_rule",
            "case_selection_rule",
            "oracle_boundary_rule",
            "source_eligibility_rule",
            "cutoff_rule",
            "exact_domains_n",
            "exact_generator_families_n",
            "primary_cases_per_domain",
            "laboratories_per_domain",
        },
        "sentinel generation rules",
    )
    if rules != {
        "generator_family_definition": GENERATOR_FAMILY_RULE,
        "control_assignment_rule": CONTROL_ASSIGNMENT_RULE,
        "primary_balance_rule": PRIMARY_BALANCE_RULE,
        "case_selection_rule": CASE_SELECTION_RULE,
        "oracle_boundary_rule": ORACLE_BOUNDARY_RULE,
        "source_eligibility_rule": SOURCE_ELIGIBILITY_RULE,
        "cutoff_rule": CUTOFF_RULE,
        "exact_domains_n": EXACT_DOMAINS,
        "exact_generator_families_n": EXACT_GENERATOR_FAMILIES,
        "primary_cases_per_domain": PRIMARY_CASES_PER_DOMAIN,
        "laboratories_per_domain": LABORATORIES_PER_DOMAIN,
    }:
        raise CausalFrontierError("sentinel generation rules differ from v1")
    if not (
        plan["designated_outcome_input_absent"] is True
        and plan["case_selection_after_generation_allowed"] is False
        and plan["oracle_opening_input_allowed"] is False
        and plan["scoring_disabled"] is True
    ):
        raise CausalFrontierError("generation plan opens a post-outcome or scoring path")

    contracts = plan["domain_contracts"]
    if not isinstance(contracts, list) or len(contracts) != EXACT_DOMAINS:
        raise CausalFrontierError("generation plan must bind exactly three domain contracts")
    by_domain: dict[str, dict[str, Any]] = {}
    all_labs: set[str] = set()
    all_cases: set[str] = set()
    for index, raw_contract in enumerate(contracts):
        contract = _shape(
            raw_contract,
            {
                "domain_id",
                "knowledge_cutoff",
                "domain_semantics_sha256",
                "laboratory_ids",
                "primary_case_ids",
                "calibration_cases",
            },
            "generation domain contract[%d]" % index,
        )
        domain_id = require_id(contract["domain_id"], "generation domain id")
        if domain_id in by_domain:
            raise CausalFrontierError("duplicate generation domain contract")
        cutoff = require_utc_timestamp(contract["knowledge_cutoff"], "%s generation cutoff" % domain_id)
        _artifact_digest(contract["domain_semantics_sha256"], "%s precommitted domain semantics" % domain_id)
        if cutoff > frozen_at:
            raise CausalFrontierError("generation cutoff follows its freeze")
        labs = _sorted_ids(contract["laboratory_ids"], "%s laboratory ids" % domain_id, exact=LABORATORIES_PER_DOMAIN)
        primary_ids = _sorted_ids(
            contract["primary_case_ids"], "%s primary case ids" % domain_id, exact=PRIMARY_CASES_PER_DOMAIN
        )
        calibration = contract["calibration_cases"]
        if not isinstance(calibration, list) or len(calibration) != len(CONTROL_ROLES):
            raise CausalFrontierError("each generation domain needs the complete control trio")
        calibration_ids: list[str] = []
        for role_index, raw_control in enumerate(calibration):
            control = _shape(raw_control, {"case_id", "control_role"}, "generation calibration case")
            if control["control_role"] != CONTROL_ROLES[role_index]:
                raise CausalFrontierError("generation calibration controls must use canonical role order")
            calibration_ids.append(require_id(control["case_id"], "generation calibration case id"))
        if len(set(calibration_ids)) != len(calibration_ids) or len(
            {item.casefold() for item in calibration_ids}
        ) != len(calibration_ids):
            raise CausalFrontierError("generation calibration case ids must be case-insensitively unique")
        submitted = set(primary_ids) | set(calibration_ids)
        if len(submitted) != len(primary_ids) + len(calibration_ids) or submitted & all_cases:
            raise CausalFrontierError("generation case ids must be globally disjoint")
        if set(labs) & all_labs:
            raise CausalFrontierError("generation laboratory ids must be domain-disjoint")
        all_cases.update(submitted)
        all_labs.update(labs)
        by_domain[domain_id] = contract
    if list(by_domain) != domain_ids:
        raise CausalFrontierError("generation domain contracts must follow the locked sorted domain ids")

    assignments_raw = plan["case_assignments"]
    expected_assignments = EXACT_DOMAINS * (PRIMARY_CASES_PER_DOMAIN + len(CONTROL_ROLES))
    if not isinstance(assignments_raw, list) or len(assignments_raw) != expected_assignments:
        raise CausalFrontierError("generation case assignment matrix is incomplete")
    assignments = [_validate_generation_case_assignment(item, index) for index, item in enumerate(assignments_raw)]
    assignment_ids = [item["case_id"] for item in assignments]
    if (
        assignment_ids != sorted(set(assignment_ids))
        or len({item.casefold() for item in assignment_ids}) != len(assignment_ids)
        or set(assignment_ids) != all_cases
    ):
        raise CausalFrontierError(
            "generation assignments must case-insensitively uniquely cover the sorted closed case set"
        )

    role_family_counts: dict[str, Counter[str]] = {role: Counter() for role in CONTROL_ROLES}
    for domain_id, contract in by_domain.items():
        domain_items = [item for item in assignments if item["domain_id"] == domain_id]
        if len(domain_items) != PRIMARY_CASES_PER_DOMAIN + len(CONTROL_ROLES):
            raise CausalFrontierError("generation assignment domain geometry differs")
        if any(item["knowledge_cutoff"] != contract["knowledge_cutoff"] for item in domain_items):
            raise CausalFrontierError("generation assignment cutoff differs from its domain")
        primary = [item for item in domain_items if item["case_role"] == "PRIMARY"]
        controls = [item for item in domain_items if item["case_role"] != "PRIMARY"]
        if {item["case_id"] for item in primary} != set(contract["primary_case_ids"]):
            raise CausalFrontierError("generation primary assignments differ from their domain contract")
        if {item["laboratory_id"] for item in primary} != set(contract["laboratory_ids"]):
            raise CausalFrontierError("generation primary assignments must use both laboratories")
        primary_family_counts = Counter(item["generator_family_id"] for item in primary)
        if set(primary_family_counts) != set(family_ids) or max(primary_family_counts.values()) * 2 >= len(primary):
            raise CausalFrontierError("generation primary cases violate the three-family no-majority rule")
        laboratory_counts = Counter(item["laboratory_id"] for item in primary)
        if laboratory_counts != Counter(dict.fromkeys(contract["laboratory_ids"], PRIMARY_CASES_PER_DOMAIN // 2)):
            raise CausalFrontierError("generation primary laboratories must be exactly balanced within each domain")
        for family_id in family_ids:
            family_laboratory_counts = Counter(
                item["laboratory_id"] for item in primary if item["generator_family_id"] == family_id
            )
            if set(family_laboratory_counts) != set(contract["laboratory_ids"]):
                raise CausalFrontierError("every primary generator family must occur in both domain laboratories")
            if max(family_laboratory_counts.values()) - min(family_laboratory_counts.values()) > 1:
                raise CausalFrontierError("primary generator by laboratory cells must be balanced within one case")
        controls_by_role = {item["case_role"]: item for item in controls}
        if set(controls_by_role) != set(CONTROL_ROLES):
            raise CausalFrontierError("generation control roles are incomplete within a domain")
        control_families = [controls_by_role[role]["generator_family_id"] for role in CONTROL_ROLES]
        if set(control_families) != set(family_ids):
            raise CausalFrontierError("each generation domain control trio must use all three families")
        expected_controls = {control["control_role"]: control["case_id"] for control in contract["calibration_cases"]}
        if any(controls_by_role[role]["case_id"] != expected_controls[role] for role in CONTROL_ROLES):
            raise CausalFrontierError("generation control assignments differ from their domain contract")
        for role in CONTROL_ROLES:
            role_family_counts[role][controls_by_role[role]["generator_family_id"]] += 1
    if any(counts != Counter(dict.fromkeys(family_ids, 1)) for counts in role_family_counts.values()):
        raise CausalFrontierError("generation controls do not form the locked three-by-three Latin square")
    if any(item["generator_family_id"] not in family_ids for item in assignments):
        raise CausalFrontierError("generation assignment references an undeclared family")
    if any(item["domain_id"] not in domain_ids for item in assignments):
        raise CausalFrontierError("generation assignment references an undeclared domain")

    precommitments = plan["generator_precommitments"]
    if not isinstance(precommitments, list) or len(precommitments) != EXACT_GENERATOR_FAMILIES:
        raise CausalFrontierError("generation plan must bind three generator precommitments")
    seen_families: list[str] = []
    seed_commitments: list[str] = []
    for index, raw_precommitment in enumerate(precommitments):
        precommitment = _shape(
            raw_precommitment,
            {
                "generator_family_id",
                "mechanism_family_id",
                "governance_family_id",
                "author_organization_id",
                "controller_organization_id",
                "source_content_multiset_sha256",
                "source_path_sensitive_sha256",
                *GENERATOR_PRECOMMITMENT_DIGEST_FIELDS,
                "seed_external_commitment_sha256",
            },
            "generator precommitment[%d]" % index,
        )
        seen_families.append(require_id(precommitment["generator_family_id"], "precommitted family id"))
        for key in {
            "generator_family_id",
            "mechanism_family_id",
            "governance_family_id",
            "author_organization_id",
            "controller_organization_id",
        }:
            require_id(precommitment[key], "generator precommitment %s" % key)
        for key in set(precommitment) - {
            "generator_family_id",
            "mechanism_family_id",
            "governance_family_id",
            "author_organization_id",
            "controller_organization_id",
        }:
            _artifact_digest(precommitment[key], "generator precommitment %s" % key)
        seed_commitments.append(precommitment["seed_external_commitment_sha256"])
    if seen_families != family_ids:
        raise CausalFrontierError("generator precommitments must follow the locked family order")
    if len(set(seed_commitments)) != len(seed_commitments):
        raise CausalFrontierError("generator seed commitments must be unique across families")

    protocol_precommitments = _shape(
        plan["protocol_precommitments"], set(PROTOCOL_FIELDS), "generation protocol precommitments"
    )
    for field, digest in protocol_precommitments.items():
        _artifact_digest(digest, "generation %s" % field)

    core = {key: plan[key] for key in plan if key != "plan_sha256"}
    if plan["plan_sha256"] != sha256_bytes(GENERATION_PLAN_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("sentinel generation semantic digest differs")
    return plan


def preflight_sentinel_generation_plan(path: Path, expected_plan_checkpoint_sha256: str) -> dict[str, Any]:
    """Replay an exact pre-generation lock; never attest that it was timely."""

    raw, value = _read_checkpointed_json(path, expected_plan_checkpoint_sha256, "sentinel generation plan")
    plan = _validate_generation_plan(value)
    second_raw, second_value = _read_checkpointed_json(
        path, expected_plan_checkpoint_sha256, "sentinel generation plan"
    )
    if raw != second_raw or canonical_bytes(plan) != canonical_bytes(_validate_generation_plan(second_value)):
        raise CausalFrontierError("sentinel generation plan changed during preflight")
    return plan


def _inventory(
    root_fd: int,
    prefix: str = "",
    entries: set[str] | None = None,
    visited: list[int] | None = None,
) -> set[str]:
    entries = set() if entries is None else entries
    visited = [0] if visited is None else visited
    names: list[str] = []
    with os.scandir(root_fd) as directory:
        for entry in directory:
            visited[0] += 1
            if visited[0] > MAX_FILES:
                raise CausalFrontierError("sentinel inventory exceeds its fixed file limit")
            names.append(entry.name)
    for name in sorted(names):
        relative = receipt_io._relative(prefix + name)
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            with ExitStack() as stack:
                child = receipt_io._open_directory(stack, name, root_fd)
                _inventory(child, relative + "/", entries, visited)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entries.add(relative)
        else:
            raise CausalFrontierError("sentinel inventory contains an unsafe filesystem object")
    return entries


def _validate_artifact_descriptors(value: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARTIFACTS:
        raise CausalFrontierError("sentinel artifact inventory has invalid size")
    artifacts: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    paths: list[str] = []
    for index, raw_item in enumerate(value):
        item = _shape(
            raw_item,
            {"artifact_id", "path", "sha256", "role", "media_type", "data_class"},
            "sentinel artifact[%d]" % index,
        )
        artifact_id = require_id(item["artifact_id"], "sentinel artifact id")
        if artifact_id in by_id:
            raise CausalFrontierError("duplicate sentinel artifact id")
        relative = receipt_io._relative(item["path"])
        if relative == MANIFEST:
            raise CausalFrontierError("sentinel manifest cannot list itself as an artifact")
        _artifact_digest(item["sha256"], "sentinel artifact digest")
        require_enum(item["role"], set(ARTIFACT_ROLES), "sentinel artifact role")
        require_enum(item["media_type"], set(MEDIA_TYPES), "sentinel artifact media type")
        require_enum(item["data_class"], set(DATA_CLASSES), "sentinel artifact data class")
        if item["role"] in {"CASE_PAYLOAD", "SOURCE_EVIDENCE", "TRANSFORM_INTERMEDIATE"}:
            allowed_data_classes = {"PUBLIC_AGGREGATE", "SYNTHETIC"}
        elif item["role"] == "AVAILABILITY_EVIDENCE":
            allowed_data_classes = {"PUBLIC_METADATA", "OPEN_SOURCE_TEXT"}
        else:
            allowed_data_classes = {"OPEN_SOURCE_TEXT"}
        if item["data_class"] not in allowed_data_classes:
            raise CausalFrontierError("sentinel artifact role uses an ineligible data class")
        artifacts.append(item)
        by_id[artifact_id] = item
        paths.append(relative)
    artifact_ids = [item["artifact_id"] for item in artifacts]
    if artifact_ids != sorted(artifact_ids):
        raise CausalFrontierError("sentinel artifacts must use sorted identifiers")
    if len(set(paths)) != len(paths) or len({path.casefold() for path in paths}) != len(paths):
        raise CausalFrontierError("sentinel artifact paths must be case-insensitively unique")
    if len({artifact_id.casefold() for artifact_id in artifact_ids}) != len(artifact_ids):
        raise CausalFrontierError("sentinel artifact ids must be case-insensitively unique")
    return artifacts, by_id


def _snapshot_bundle(
    root: Path, expected_manifest_sha256: str
) -> tuple[bytes, dict[str, Any], dict[str, dict[str, Any]], dict[str, bytes]]:
    _artifact_digest(expected_manifest_sha256, "sentinel manifest external checkpoint")
    try:
        with ExitStack() as stack:
            root_fd = receipt_io._root_descriptor(stack, root)
            raw_manifest = receipt_io._snapshot(root_fd, MANIFEST)
            if len(raw_manifest) > MAX_FILE_BYTES or sha256_bytes(raw_manifest) != expected_manifest_sha256:
                raise CausalFrontierError("sentinel manifest checkpoint mismatch or size limit exceeded")
            document = _strict_json(raw_manifest, "sentinel admission manifest")
            if not isinstance(document, dict):
                raise CausalFrontierError("sentinel admission manifest must be an object")
            artifacts, by_id = _validate_artifact_descriptors(document.get("artifacts"))
            expected_files = {MANIFEST, *(item["path"] for item in artifacts)}
            if _inventory(root_fd) != expected_files:
                raise CausalFrontierError("sentinel bundle inventory differs from its manifest")
            snapshots: dict[str, bytes] = {}
            total = len(raw_manifest)
            for item in artifacts:
                raw = receipt_io._snapshot(root_fd, item["path"])
                total += len(raw)
                if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("sentinel bundle exceeds its fixed byte limits")
                if sha256_bytes(raw) != item["sha256"]:
                    raise CausalFrontierError("sentinel artifact digest mismatch")
                receipt_io._screen(raw)
                if item["media_type"] == "application/json":
                    _strict_json(raw, item["artifact_id"])
                snapshots[item["artifact_id"]] = raw
            if _inventory(root_fd) != expected_files:
                raise CausalFrontierError("sentinel bundle inventory changed while being read")
    except OSError:
        raise CausalFrontierError("sentinel bundle cannot be read safely") from None
    return raw_manifest, document, by_id, snapshots


def _artifact(
    artifact_id: Any,
    expected_role: str,
    by_id: dict[str, dict[str, Any]],
    used: set[str],
    field: str,
) -> dict[str, Any]:
    identity = require_id(artifact_id, field)
    item = by_id.get(identity)
    if item is None or item["role"] != expected_role:
        raise CausalFrontierError("%s does not reference a %s artifact" % (field, expected_role))
    used.add(identity)
    return item


def _json_artifact(
    artifact_id: Any,
    expected_role: str,
    by_id: dict[str, dict[str, Any]],
    snapshots: dict[str, bytes],
    used: set[str],
    field: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    descriptor = _artifact(artifact_id, expected_role, by_id, used, field)
    if descriptor["media_type"] != "application/json":
        raise CausalFrontierError("%s must reference a strict JSON artifact" % field)
    value = _strict_json(snapshots[descriptor["artifact_id"]], field)
    if not isinstance(value, dict):
        raise CausalFrontierError("%s artifact must be an object" % field)
    return descriptor, value


def _source_tree_signatures(
    generator: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    snapshots: dict[str, bytes],
    used: set[str],
) -> tuple[str, str]:
    descriptor, value = _json_artifact(
        generator["source_manifest_artifact_id"],
        "GENERATOR_SOURCE_MANIFEST",
        by_id,
        snapshots,
        used,
        "%s source manifest" % generator["generator_family_id"],
    )
    _shape(value, {"schema_version", "generator_family_id", "files"}, "generator source manifest")
    if (
        value["schema_version"] != "causalfrontier.generator-source-manifest.v1"
        or value["generator_family_id"] != generator["generator_family_id"]
    ):
        raise CausalFrontierError("generator source manifest identity differs")
    files = value["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 128:
        raise CausalFrontierError("generator source manifest file list has invalid size")
    normalized: list[dict[str, str]] = []
    logical_paths: list[str] = []
    content_hashes: list[str] = []
    for index, raw_file in enumerate(files):
        source_file = _shape(
            raw_file,
            {"logical_path", "artifact_id", "sha256"},
            "generator source file[%d]" % index,
        )
        logical_path = receipt_io._relative(source_file["logical_path"])
        source_descriptor = _artifact(
            source_file["artifact_id"],
            "GENERATOR_SOURCE_FILE",
            by_id,
            used,
            "generator source file artifact",
        )
        digest = _artifact_digest(source_file["sha256"], "generator source file digest")
        if source_descriptor["sha256"] != digest:
            raise CausalFrontierError("generator source manifest digest differs from artifact bytes")
        logical_paths.append(logical_path)
        content_hashes.append(digest)
        normalized.append({"logical_path": logical_path, "sha256": digest})
    if logical_paths != sorted(set(logical_paths)) or len({path.casefold() for path in logical_paths}) != len(
        logical_paths
    ):
        raise CausalFrontierError("generator logical source paths must be case-insensitively unique and sorted")
    if descriptor["data_class"] != "OPEN_SOURCE_TEXT":
        raise CausalFrontierError("generator source manifest must be declared open-source text")
    return (
        sha256_bytes(canonical_bytes(sorted(content_hashes))),
        sha256_bytes(canonical_bytes(normalized)),
    )


def _validate_generator_ancestry(value: dict[str, Any], family_id: str) -> set[str]:
    _shape(
        value,
        {
            "schema_version",
            "generator_family_id",
            "declared_shared_source_ancestry_family_ids",
            "declared_shared_template_family_ids",
            "declared_shared_prompt_family_ids",
            "declared_shared_hidden_selection_family_ids",
            "external_truth_verified",
        },
        "%s generator ancestry" % family_id,
    )
    if not (
        value["schema_version"] == "causalfrontier.generator-ancestry.v1"
        and value["generator_family_id"] == family_id
        and value["external_truth_verified"] is False
    ):
        raise CausalFrontierError("generator ancestry identity differs or overclaims external verification")
    related: set[str] = set()
    for field in {
        "declared_shared_source_ancestry_family_ids",
        "declared_shared_template_family_ids",
        "declared_shared_prompt_family_ids",
        "declared_shared_hidden_selection_family_ids",
    }:
        raw_ids = value[field]
        if not isinstance(raw_ids, list):
            raise CausalFrontierError("generator ancestry family list must be a list")
        ids = [require_id(item, "declared related generator family") for item in raw_ids]
        if ids != sorted(set(ids)) or len({item.casefold() for item in ids}) != len(ids):
            raise CausalFrontierError("generator ancestry family ids must be case-insensitively unique and sorted")
        if family_id in ids:
            raise CausalFrontierError("generator ancestry cannot list its own family")
        related.update(ids)
    return related


def _validate_generator_tool_model_inventory(value: dict[str, Any], family_id: str, earliest_case_cutoff: str) -> bool:
    _shape(
        value,
        {
            "schema_version",
            "generator_family_id",
            "tool_model_ids",
            "declared_maximum_knowledge_timestamp",
            "network_access_during_generation_allowed",
            "post_cutoff_retrieval_allowed",
            "independent_temporal_attestation_verified",
        },
        "%s tool/model inventory" % family_id,
    )
    tool_model_ids = _sorted_ids(value["tool_model_ids"], "%s tool/model ids" % family_id)
    del tool_model_ids
    maximum_knowledge_timestamp = require_utc_timestamp(
        value["declared_maximum_knowledge_timestamp"], "%s maximum knowledge timestamp" % family_id
    )
    if not (
        value["schema_version"] == "causalfrontier.generator-tool-model-inventory.v1"
        and value["generator_family_id"] == family_id
        and value["network_access_during_generation_allowed"] is False
        and value["post_cutoff_retrieval_allowed"] is False
        and value["independent_temporal_attestation_verified"] is False
    ):
        raise CausalFrontierError("generator tool/model inventory opens access or overclaims independent time")
    return maximum_knowledge_timestamp > earliest_case_cutoff


def _validate_organizations(value: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not isinstance(value, list) or not 8 <= len(value) <= 128:
        raise CausalFrontierError("sentinel organization declarations have invalid size")
    organizations: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw_item in enumerate(value):
        item = _shape(
            raw_item,
            {"organization_id", "roles", "controller_group_id", "store_group_id"},
            "sentinel organization[%d]" % index,
        )
        organization_id = require_id(item["organization_id"], "sentinel organization id")
        roles = _sorted_ids(item["roles"], "%s roles" % organization_id)
        if not set(roles) <= ORGANIZATION_ROLES:
            raise CausalFrontierError("organization has an unsupported role")
        require_id(item["controller_group_id"], "organization controller group")
        require_id(item["store_group_id"], "organization store group")
        if organization_id in by_id:
            raise CausalFrontierError("duplicate sentinel organization id")
        organizations.append(item)
        by_id[organization_id] = item
    ids = [item["organization_id"] for item in organizations]
    if ids != sorted(ids) or len({item.casefold() for item in ids}) != len(ids):
        raise CausalFrontierError("sentinel organizations must be case-insensitively unique and sorted")
    if not any("STEWARD" in item["roles"] for item in organizations):
        raise CausalFrontierError("sentinel bundle must name a steward declaration")
    return organizations, by_id


def _require_org_role(
    organization_id: Any,
    role: str,
    organizations: dict[str, dict[str, Any]],
    field: str,
) -> dict[str, Any]:
    identity = require_id(organization_id, field)
    item = organizations.get(identity)
    if item is None or role not in item["roles"]:
        raise CausalFrontierError("%s lacks the declared %s role" % (field, role))
    return item


def _validate_domain_semantics(value: dict[str, Any], domain_id: str) -> str:
    _shape(
        value,
        {
            "schema_version",
            "domain_id",
            "ontology_namespace",
            "ontology_identifier",
            "decision_unit",
            "evidence_modalities",
            "permissible_action_class",
            "terminal_observation_interface",
            "decision_loss_semantics",
            "resource_basis",
            "common_horizon",
            "inclusion_criteria",
            "exclusion_criteria",
            "semantic_validity_review_state",
        },
        "%s domain semantics" % domain_id,
    )
    if (
        value["schema_version"] != "causalfrontier.domain-semantics.v1"
        or value["domain_id"] != domain_id
        or value["semantic_validity_review_state"] != "EXTERNAL_REVIEW_REQUIRED_NOT_VERIFIED"
    ):
        raise CausalFrontierError("domain semantics identity or no-call state differs")
    for key in {
        "ontology_namespace",
        "ontology_identifier",
        "decision_unit",
        "permissible_action_class",
        "terminal_observation_interface",
        "decision_loss_semantics",
        "resource_basis",
        "common_horizon",
        "inclusion_criteria",
        "exclusion_criteria",
    }:
        require_text(value[key], "%s %s" % (domain_id, key), 4000)
    modalities = value["evidence_modalities"]
    if not isinstance(modalities, list) or not 1 <= len(modalities) <= 32:
        raise CausalFrontierError("domain evidence modalities have invalid size")
    normalized = [require_text(item, "domain evidence modality", 1000) for item in modalities]
    if normalized != sorted(set(normalized)):
        raise CausalFrontierError("domain evidence modalities must be sorted and unique")
    decision_geometry = {
        key: value[key]
        for key in {
            "decision_unit",
            "evidence_modalities",
            "permissible_action_class",
            "terminal_observation_interface",
            "decision_loss_semantics",
            "resource_basis",
            "common_horizon",
            "inclusion_criteria",
            "exclusion_criteria",
        }
    }
    return sha256_bytes(canonical_bytes(decision_geometry))


def _validate_domain_review(
    value: dict[str, Any],
    domain_id: str,
    semantics_sha256: str,
    organizations: dict[str, dict[str, Any]],
    forbidden_org_ids: set[str],
) -> list[str]:
    _shape(
        value,
        {
            "schema_version",
            "domain_id",
            "semantics_sha256",
            "reviewer_organization_ids",
            "review_protocol_state",
            "critical_disagreement_rule",
            "domain_semantic_validity_verified",
        },
        "%s domain review" % domain_id,
    )
    reviewers = _sorted_ids(value["reviewer_organization_ids"], "domain reviewers", exact=2)
    if (
        value["schema_version"] != "causalfrontier.domain-review.v1"
        or value["domain_id"] != domain_id
        or value["semantics_sha256"] != semantics_sha256
        or value["review_protocol_state"] != "PACKET_BOUND_REVIEW_NOT_EXECUTED"
        or value["critical_disagreement_rule"] != "ANY_DECISION_CRITICAL_DISAGREEMENT_YIELDS_NO_CALL"
        or value["domain_semantic_validity_verified"] is not False
    ):
        raise CausalFrontierError("domain review packet overclaims or differs")
    for reviewer_id in reviewers:
        _require_org_role(reviewer_id, "DOMAIN_REVIEWER", organizations, "domain reviewer")
        if reviewer_id in forbidden_org_ids:
            raise CausalFrontierError("domain reviewer overlaps a generator author or controller")
    return reviewers


def _validate_case_payload(
    value: dict[str, Any],
    case_id: str,
    domain_id: str,
    expected_generation_phase_context: dict[str, Any] | None = None,
) -> tuple[str, str, str, dict[str, str]]:
    required_keys = {"schema_version", "case_id", "domain_id", "decision_core", "presentation"}
    if expected_generation_phase_context is not None:
        required_keys.add("generation_phase_context")
    _shape(
        value,
        required_keys,
        "%s case payload" % case_id,
    )
    expected_schema = (
        PHASE_BOUND_PAYLOAD_SCHEMA_VERSION
        if expected_generation_phase_context is not None
        else "causalfrontier.sentinel-case-payload.v1"
    )
    if value["schema_version"] != expected_schema:
        raise CausalFrontierError("case payload schema differs")
    if value["case_id"] != case_id or value["domain_id"] != domain_id:
        raise CausalFrontierError("case payload identity differs")
    if expected_generation_phase_context is not None:
        _validate_generation_phase_context(
            value["generation_phase_context"],
            expected_generation_phase_context,
        )
    core = _shape(
        value["decision_core"],
        {
            "question",
            "evidence_interface",
            "action_interface",
            "falsification_contract",
            "branch_contract",
            "terminal_oracle_external_commitment_sha256",
        },
        "%s decision core" % case_id,
    )
    for key in {"question", "evidence_interface", "action_interface", "falsification_contract"}:
        require_text(core[key], "%s %s" % (case_id, key), 4000)
    branch_contract = _shape(
        core["branch_contract"],
        {
            "schema_version",
            "observation_state_ids",
            "mappings",
            "unknown_observation_state",
            "complete_over_declared_states",
            "semantic_exhaustiveness_verified",
        },
        "%s branch contract" % case_id,
    )
    observation_state_ids = _sorted_ids(
        branch_contract["observation_state_ids"], "%s observation state ids" % case_id, minimum=2
    )
    mappings = branch_contract["mappings"]
    if not isinstance(mappings, list) or len(mappings) != len(observation_state_ids):
        raise CausalFrontierError("branch contract must map every declared observation state exactly once")
    mapped_ids: list[str] = []
    branch_decision_mapping: dict[str, str] = {}
    for index, raw_mapping in enumerate(mappings):
        mapping = _shape(
            raw_mapping,
            {"observation_state_id", "decision_state"},
            "%s branch mapping[%d]" % (case_id, index),
        )
        observation_state_id = require_id(mapping["observation_state_id"], "mapped observation state id")
        mapped_ids.append(observation_state_id)
        branch_decision_mapping[observation_state_id] = require_enum(
            mapping["decision_state"],
            {"NEXT_FALSIFICATION", "REJECT_TRANSLATION", "REPLICATE", "NO_CALL"},
            "branch decision state",
        )
    if not (
        branch_contract["schema_version"] == "causalfrontier.declared-branch-contract.v1"
        and mapped_ids == observation_state_ids
        and branch_contract["unknown_observation_state"] == "NO_CALL"
        and branch_contract["complete_over_declared_states"] is True
        and branch_contract["semantic_exhaustiveness_verified"] is False
    ):
        raise CausalFrontierError("branch contract is incomplete, unsorted, or overclaims semantic exhaustiveness")
    oracle_commitment_sha256 = _artifact_digest(
        core["terminal_oracle_external_commitment_sha256"], "terminal oracle commitment"
    )
    if not isinstance(value["presentation"], dict):
        raise CausalFrontierError("case presentation must be an object")

    def normalize_identity_only_text(item: Any) -> Any:
        if isinstance(item, str):
            return item.replace(case_id, "<CASE_ID>").replace(domain_id, "<DOMAIN_ID>")
        if isinstance(item, list):
            return [normalize_identity_only_text(value) for value in item]
        if isinstance(item, dict):
            return {key: normalize_identity_only_text(value) for key, value in item.items()}
        return item

    normalized_core = normalize_identity_only_text(
        {key: item for key, item in core.items() if key != "terminal_oracle_external_commitment_sha256"}
    )
    return (
        sha256_bytes(canonical_bytes(normalized_core)),
        sha256_bytes(canonical_bytes(branch_contract)),
        oracle_commitment_sha256,
        branch_decision_mapping,
    )


def _validate_role_packet(
    value: dict[str, Any],
    case: dict[str, Any],
    expected_branch_contract_sha256: str,
    expected_oracle_commitment_sha256: str,
    branch_decision_mapping: dict[str, str],
    organizations: dict[str, dict[str, Any]],
) -> None:
    common = {
        "schema_version",
        "case_id",
        "case_role",
        "selection_origin",
        "declared_branch_contract_sha256",
    }
    role = case["case_role"]
    if role == "PRIMARY":
        packet = _shape(
            value,
            common
            | {
                "outcome_unresolved_at_lock_declared",
                "laboratory_id",
                "outcome_provider_organization_id",
                "observation_protocol",
                "replication_rule",
                "stopping_rule",
                "terminal_adjudication_mapping",
                "next_falsification_observation_state_ids",
                "no_call_observation_state_ids",
                "reveal_external_commitment_sha256",
                "external_registration_receipt_present",
            },
            "%s primary role packet" % case["case_id"],
        )
        if not (
            packet["outcome_unresolved_at_lock_declared"] is True
            and packet["laboratory_id"] == case["laboratory_id"]
            and packet["outcome_provider_organization_id"] == case["outcome_provider_organization_id"]
            and packet["external_registration_receipt_present"] is False
            and packet["reveal_external_commitment_sha256"] == expected_oracle_commitment_sha256
        ):
            raise CausalFrontierError("primary role packet differs or invents registration")
        _require_org_role(packet["laboratory_id"], "LABORATORY", organizations, "primary laboratory")
        _require_org_role(
            packet["outcome_provider_organization_id"],
            "OUTCOME_PROVIDER",
            organizations,
            "primary outcome provider",
        )
        for key in {"observation_protocol", "replication_rule", "stopping_rule", "terminal_adjudication_mapping"}:
            require_text(packet[key], "primary %s" % key, 4000)
        _artifact_digest(packet["reveal_external_commitment_sha256"], "primary reveal commitment")
    elif role == "POSITIVE":
        packet = _shape(
            value,
            common
            | {
                "method_recovery_criterion",
                "decision_transition_rule",
                "replication_rule",
                "required_behavior_observation_state_ids",
                "sealed_opening_external_commitment_sha256",
                "independent_adjudication_state",
            },
            "%s positive role packet" % case["case_id"],
        )
        for key in {"method_recovery_criterion", "decision_transition_rule", "replication_rule"}:
            require_text(packet[key], "positive %s" % key, 4000)
        _artifact_digest(packet["sealed_opening_external_commitment_sha256"], "positive opening commitment")
        if packet["independent_adjudication_state"] != "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED":
            raise CausalFrontierError("positive control packet invents adjudication")
    elif role == "FAILED_TRANSLATION":
        packet = _shape(
            value,
            common
            | {
                "precutoff_translated_expectation",
                "terminal_failure_definition",
                "rejection_stop_criterion",
                "operational_failure_exclusion_rule",
                "required_behavior_observation_state_ids",
                "sealed_opening_external_commitment_sha256",
                "independent_adjudication_state",
            },
            "%s failed-translation role packet" % case["case_id"],
        )
        for key in {
            "precutoff_translated_expectation",
            "terminal_failure_definition",
            "rejection_stop_criterion",
            "operational_failure_exclusion_rule",
        }:
            require_text(packet[key], "failed translation %s" % key, 4000)
        _artifact_digest(packet["sealed_opening_external_commitment_sha256"], "failed opening commitment")
        if packet["independent_adjudication_state"] != "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED":
            raise CausalFrontierError("failed-translation packet invents adjudication")
    else:
        packet = _shape(
            value,
            common
            | {
                "ambiguity_set",
                "competing_interpretations",
                "correct_abstention_rule",
                "minimum_information_boundary",
                "required_behavior_observation_state_ids",
                "sealed_opening_external_commitment_sha256",
                "independent_adjudication_state",
            },
            "%s ambiguous role packet" % case["case_id"],
        )
        require_text(packet["ambiguity_set"], "ambiguous control set", 4000)
        interpretations = packet["competing_interpretations"]
        if not isinstance(interpretations, list) or not 2 <= len(interpretations) <= 16:
            raise CausalFrontierError("ambiguous control must bind at least two interpretations")
        normalized = [require_text(item, "ambiguous interpretation", 4000) for item in interpretations]
        if normalized != sorted(set(normalized)):
            raise CausalFrontierError("ambiguous interpretations must be sorted and unique")
        for key in {"correct_abstention_rule", "minimum_information_boundary"}:
            require_text(packet[key], "ambiguous %s" % key, 4000)
        _artifact_digest(packet["sealed_opening_external_commitment_sha256"], "ambiguous opening commitment")
        if packet["independent_adjudication_state"] != "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED":
            raise CausalFrontierError("ambiguous packet invents adjudication")
    if role != "PRIMARY" and packet["sealed_opening_external_commitment_sha256"] != expected_oracle_commitment_sha256:
        raise CausalFrontierError("control role packet opening differs from its case oracle commitment")
    if role == "PRIMARY":
        behavior_links = {
            "next_falsification_observation_state_ids": "NEXT_FALSIFICATION",
            "no_call_observation_state_ids": "NO_CALL",
        }
    else:
        behavior_links = {
            "required_behavior_observation_state_ids": {
                "POSITIVE": "NEXT_FALSIFICATION",
                "FAILED_TRANSLATION": "REJECT_TRANSLATION",
                "AMBIGUOUS": "NO_CALL",
            }[role]
        }
    for field, expected_decision_state in behavior_links.items():
        linked_state_ids = _sorted_ids(packet[field], "%s %s" % (case["case_id"], field))
        if any(branch_decision_mapping.get(state_id) != expected_decision_state for state_id in linked_state_ids):
            raise CausalFrontierError("case role behavior observation states do not map to the required decision state")
    if not (
        packet["schema_version"] == "causalfrontier.case-role-packet.v1"
        and packet["case_id"] == case["case_id"]
        and packet["case_role"] == role
        and packet["selection_origin"] == case["selection_origin"]
        and packet["declared_branch_contract_sha256"] == expected_branch_contract_sha256
    ):
        raise CausalFrontierError("case role packet identity differs")


def _validate_source_inventory(
    value: dict[str, Any],
    case: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    snapshots: dict[str, bytes],
    used: set[str],
) -> tuple[list[dict[str, Any]], bool]:
    _shape(
        value,
        {"schema_version", "case_id", "knowledge_cutoff", "sources"},
        "%s source inventory" % case["case_id"],
    )
    if (
        value["schema_version"] != "causalfrontier.case-source-inventory.v1"
        or value["case_id"] != case["case_id"]
        or value["knowledge_cutoff"] != case["knowledge_cutoff"]
    ):
        raise CausalFrontierError("case source inventory identity or cutoff differs")
    sources = value["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 64:
        raise CausalFrontierError("case source inventory has invalid size")
    source_ids: list[str] = []
    late = False
    for index, raw_source in enumerate(sources):
        source = _shape(
            raw_source,
            {
                "source_id",
                "evidence_artifact_id",
                "evidence_sha256",
                "availability_evidence_artifact_id",
                "availability_evidence_sha256",
                "claimed_available_at",
                "data_class",
                "semantic_state",
            },
            "%s source[%d]" % (case["case_id"], index),
        )
        source_ids.append(require_id(source["source_id"], "case source id"))
        evidence = _artifact(source["evidence_artifact_id"], "SOURCE_EVIDENCE", by_id, used, "case source evidence")
        availability, availability_value = _json_artifact(
            source["availability_evidence_artifact_id"],
            "AVAILABILITY_EVIDENCE",
            by_id,
            snapshots,
            used,
            "case availability evidence",
        )
        available_at = require_utc_timestamp(source["claimed_available_at"], "claimed source availability")
        _shape(
            availability_value,
            {
                "schema_version",
                "source_id",
                "claimed_available_at",
                "state",
                "independent_temporal_attestation_verified",
            },
            "case availability evidence declaration",
        )
        if not (
            availability_value["schema_version"] == "causalfrontier.source-availability-declaration.v1"
            and availability_value["source_id"] == source["source_id"]
            and require_utc_timestamp(
                availability_value["claimed_available_at"], "availability evidence claimed timestamp"
            )
            == available_at
            and availability_value["state"] == "DECLARED_ONLY_NOT_INDEPENDENTLY_ATTESTED"
            and availability_value["independent_temporal_attestation_verified"] is False
        ):
            raise CausalFrontierError("availability evidence identity or declared date differs from source inventory")
        late = late or available_at > case["knowledge_cutoff"]
        require_enum(source["data_class"], {"PUBLIC_AGGREGATE", "SYNTHETIC"}, "source data class")
        if not (
            evidence["data_class"] == source["data_class"]
            and evidence["sha256"] == _artifact_digest(source["evidence_sha256"], "source evidence digest")
            and availability["sha256"]
            == _artifact_digest(source["availability_evidence_sha256"], "source availability evidence digest")
        ):
            raise CausalFrontierError("source inventory bytes or data class differ from exact evidence artifacts")
        if source["semantic_state"] != "DECISION_CRITICAL_DECLARED_NOT_EXTERNALLY_ADJUDICATED":
            raise CausalFrontierError("source inventory invents semantic adjudication")
    if source_ids != sorted(set(source_ids)) or len({item.casefold() for item in source_ids}) != len(source_ids):
        raise CausalFrontierError("case source ids must be case-insensitively unique and sorted")
    return sources, late


def _validate_cutoff_audit(
    value: dict[str, Any],
    case: dict[str, Any],
    source_inventory_descriptor: dict[str, Any],
    sources: list[dict[str, Any]],
    cutoff_protocol_sha256: str,
    by_id: dict[str, dict[str, Any]],
) -> None:
    _shape(
        value,
        {
            "schema_version",
            "case_id",
            "knowledge_cutoff",
            "source_inventory_sha256",
            "cutoff_audit_protocol_sha256",
            "source_checks",
            "independent_temporal_attestation_verified",
            "public_availability_verified",
            "post_cutoff_access_verified_absent",
        },
        "%s cutoff audit" % case["case_id"],
    )
    checks = value["source_checks"]
    if not isinstance(checks, list) or len(checks) != len(sources):
        raise CausalFrontierError("case cutoff audit must cover every source")
    expected_checks = []
    for source in sources:
        availability = by_id[source["availability_evidence_artifact_id"]]
        expected_checks.append(
            {
                "source_id": source["source_id"],
                "claimed_available_at": source["claimed_available_at"],
                "before_or_at_cutoff": source["claimed_available_at"] <= case["knowledge_cutoff"],
                "availability_evidence_sha256": availability["sha256"],
            }
        )
    if not (
        value["schema_version"] == "causalfrontier.case-cutoff-audit.v1"
        and value["case_id"] == case["case_id"]
        and value["knowledge_cutoff"] == case["knowledge_cutoff"]
        and value["source_inventory_sha256"] == source_inventory_descriptor["sha256"]
        and value["cutoff_audit_protocol_sha256"] == cutoff_protocol_sha256
        and checks == expected_checks
        and value["independent_temporal_attestation_verified"] is False
        and value["public_availability_verified"] is False
        and value["post_cutoff_access_verified_absent"] is False
    ):
        raise CausalFrontierError("case cutoff audit differs or overclaims independent time")


def _validate_provenance(
    value: dict[str, Any],
    case: dict[str, Any],
    source_inventory_descriptor: dict[str, Any],
    sources: list[dict[str, Any]],
    generator_source_manifest: dict[str, Any],
    source_content_sha256: str,
    by_id: dict[str, dict[str, Any]],
    used: set[str],
    expected_generation_phase_context: dict[str, Any] | None = None,
) -> None:
    required_keys = {
        "schema_version",
        "case_id",
        "generator_family_id",
        "source_inventory_sha256",
        "generator_source_content_sha256",
        "transformations",
        "final_artifact_ids",
        "provenance_truth_externally_verified",
    }
    if expected_generation_phase_context is not None:
        required_keys.add("generation_phase_context")
    _shape(
        value,
        required_keys,
        "%s provenance" % case["case_id"],
    )
    expected_schema = (
        PHASE_BOUND_PROVENANCE_SCHEMA_VERSION
        if expected_generation_phase_context is not None
        else "causalfrontier.case-provenance.v1"
    )
    if not (
        value["schema_version"] == expected_schema
        and value["case_id"] == case["case_id"]
        and value["generator_family_id"] == case["generator_family_id"]
        and value["source_inventory_sha256"] == source_inventory_descriptor["sha256"]
        and value["generator_source_content_sha256"] == source_content_sha256
        and value["provenance_truth_externally_verified"] is False
    ):
        raise CausalFrontierError("case provenance identity or no-call boundary differs")
    if expected_generation_phase_context is not None:
        _validate_generation_phase_context(
            value["generation_phase_context"],
            expected_generation_phase_context,
        )
    source_artifact_ids = {source["evidence_artifact_id"] for source in sources}
    available = set(source_artifact_ids)
    required_implementations = set()
    # Implementation ids are derived from the already validated source manifest.
    required_implementations.update(item["artifact_id"] for item in generator_source_manifest["files"])
    transformations = value["transformations"]
    if not isinstance(transformations, list) or not 1 <= len(transformations) <= 128:
        raise CausalFrontierError("case provenance transformation list has invalid size")
    step_ids: list[str] = []
    outputs: set[str] = set()
    parents: dict[str, set[str]] = {}
    consumed_sources: set[str] = set()
    for index, raw_step in enumerate(transformations):
        step = _shape(
            raw_step,
            {"step_id", "implementation_artifact_id", "input_artifact_ids", "output_artifact_id"},
            "%s provenance step[%d]" % (case["case_id"], index),
        )
        step_ids.append(require_id(step["step_id"], "provenance step id"))
        implementation_id = require_id(step["implementation_artifact_id"], "provenance implementation id")
        if implementation_id not in required_implementations:
            raise CausalFrontierError("case provenance uses code outside its generator source tree")
        used.add(implementation_id)
        inputs = _sorted_ids(step["input_artifact_ids"], "provenance inputs")
        if any(item not in available for item in inputs):
            raise CausalFrontierError("case provenance is cyclic, forward-referencing, or has an unknown input")
        consumed_sources.update(set(inputs) & source_artifact_ids)
        output_id = require_id(step["output_artifact_id"], "provenance output id")
        if output_id in available or output_id not in by_id:
            raise CausalFrontierError("case provenance output is duplicate or undeclared")
        if by_id[output_id]["role"] not in {"TRANSFORM_INTERMEDIATE", "CASE_PAYLOAD"}:
            raise CausalFrontierError("case provenance output uses an invalid artifact role")
        used.add(output_id)
        outputs.add(output_id)
        parents[output_id] = set(inputs)
        available.add(output_id)
    if step_ids != sorted(set(step_ids)) or len({item.casefold() for item in step_ids}) != len(step_ids):
        raise CausalFrontierError("case provenance steps must be case-insensitively unique and sorted")
    final_ids = _sorted_ids(value["final_artifact_ids"], "provenance final artifacts", exact=1)
    expected_finals = [case["case_payload_artifact_id"]]
    if final_ids != expected_finals or not set(final_ids) <= outputs or consumed_sources != source_artifact_ids:
        raise CausalFrontierError("case provenance must consume every source and produce the generated payload")
    if any(output not in set(final_ids) and by_id[output]["role"] != "TRANSFORM_INTERMEDIATE" for output in outputs):
        raise CausalFrontierError("non-final provenance output must be an explicit intermediate")
    ancestor_closure = set(final_ids)
    pending = list(final_ids)
    while pending:
        current = pending.pop()
        for parent in parents.get(current, set()):
            if parent not in ancestor_closure:
                ancestor_closure.add(parent)
                pending.append(parent)
    if not outputs <= ancestor_closure or not source_artifact_ids <= ancestor_closure:
        raise CausalFrontierError("case provenance contains a branch disconnected from every final artifact")


def _report_gate(gate_id: str, state: str, reason: str) -> dict[str, str]:
    return {"gate_id": gate_id, "state": state, "reason": reason}


def _expected_report_gates(
    *,
    generator_component_collision_pairs: int,
    generator_role_collision_pairs: int,
    cross_role_group_collision_pairs: int,
    domain_collision_pairs: int,
    case_collision_pairs: int,
    late_cases: int,
    late_generator_inventories: int,
) -> list[dict[str, str]]:
    return [
        _report_gate(
            "ARTIFACT_CLOSURE",
            "PASS",
            "Every bounded artifact byte and the complete inventory replayed twice.",
        ),
        _report_gate(
            "GOAL_PLAN_COHORT_PREIMAGE",
            "PASS",
            "The raw sentinel manifest digest equals the validated goal plan cohort checkpoint.",
        ),
        _report_gate(
            "PREGENERATION_ASSIGNMENT",
            "NO_CALL",
            "The exact predecessor replayed, but independent prospective time and custody are unverified.",
        ),
        _report_gate(
            "DOMAIN_SEMANTICS",
            "REJECT" if domain_collision_pairs else "NO_CALL",
            "Exact semantics and pair-review packets are bound; scientific validity requires external review.",
        ),
        _report_gate(
            "GENERATOR_INDEPENDENCE",
            "REJECT"
            if generator_component_collision_pairs or generator_role_collision_pairs or cross_role_group_collision_pairs
            else "NO_CALL",
            "Exact collisions are rejected; unequal bytes and declared groups do not prove independence.",
        ),
        _report_gate(
            "CASE_DISTINCTNESS",
            "REJECT" if case_collision_pairs else "NO_CALL",
            "Normalized exact duplicates are rejected; semantic diversity and paraphrase detection remain unverified.",
        ),
        _report_gate(
            "BRANCH_TOTALITY",
            "PASS",
            "Every declared observation state maps once and unknown observations map to NO_CALL; semantic "
            "exhaustiveness remains unverified.",
        ),
        _report_gate(
            "CONTROL_VALIDITY",
            "NO_CALL",
            "Role-specific packets are bound but not independently adjudicated.",
        ),
        _report_gate(
            "CUTOFF_ADMISSIBILITY",
            "REJECT" if late_cases or late_generator_inventories else "NO_CALL",
            "Declared date consistency is checked; exact public availability and post-cutoff isolation are unverified.",
        ),
        _report_gate(
            "CONTENT_OUTCOME_ISOLATION",
            "NO_CALL",
            "No designated outcome channel is accepted, but arbitrary admitted bytes can encode hindsight.",
        ),
        _report_gate(
            "PRIVACY",
            "NO_CALL",
            "Public/synthetic declarations and bounded pattern screens are not privacy certification.",
        ),
        _report_gate(
            "AUTHORITY",
            "PASS",
            "The operation was read-only software validation and grants no scientific or material authority.",
        ),
        _report_gate(
            "ROLLBACK_AND_CURRENTNESS",
            "NO_CALL",
            "Caller checkpoints are not independently stored monotonic witnesses.",
        ),
        _report_gate(
            "SCIENTIFIC_SCORING",
            "NO_CALL",
            "No outcome, comparator execution, resource, winner, or score was accepted.",
        ),
    ]


def _report_shape(value: Any) -> dict[str, Any]:
    core_keys = {
        "schema_version",
        "status",
        "implementation_status",
        "audience",
        "base_compiler_version",
        "fixed_parameter",
        "boundary",
        "scope",
        "goal_claim_contract_sha256",
        "goal_claim_plan_checkpoint_sha256",
        "goal_claim_plan_sha256",
        "generation_plan_checkpoint_sha256",
        "generation_plan_sha256",
        "manifest_checkpoint_sha256",
        "manifest_canonical_sha256",
        "manifest_sequence",
        "bundle_inventory_sha256",
        "declared_domains_n",
        "declared_generator_families_n",
        "primary_cases_n",
        "calibration_cases_n",
        "declared_laboratories_n",
        "artifact_files_n",
        "generator_pair_audits_n",
        "domain_pair_reviews_n",
        "generator_component_identity_or_content_collision_pairs_n",
        "declared_generator_role_collision_pairs_n",
        "declared_cross_role_group_collision_pairs_n",
        "normalized_domain_semantics_collision_pairs_n",
        "normalized_case_decision_core_collision_pairs_n",
        "declared_post_cutoff_cases_n",
        "declared_post_cutoff_generator_inventories_n",
        "artifact_closure_verified",
        "goal_plan_cohort_preimage_verified",
        "generation_plan_replayed",
        "case_geometry_replayed",
        "latin_square_verified",
        "primary_generator_laboratory_assignment_balance_verified",
        "declared_case_provenance_graph_structure_verified",
        "declared_branch_totality_verified",
        "oracle_commitments_unique_verified",
        "generator_seed_and_case_oracle_commitments_disjoint_verified",
        "generator_seed_or_case_oracle_enumerated_bundle_digest_alias_absent_verified",
        "declared_cutoff_consistency_verified",
        "generator_pair_audit_packets_bound",
        "domain_review_packets_bound",
        "control_role_packets_bound",
        "admission_state",
        "rejection_reasons",
        *FIXED_FALSE_FIELDS,
        "gates",
        "nonclaims",
    }
    report = _shape(value, core_keys | {"preflight_sha256"}, "sentinel admission preflight")
    core = {key: report[key] for key in core_keys}
    if report["preflight_sha256"] != sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core)):
        raise CausalFrontierError("sentinel admission preflight digest differs")
    if not (
        report["schema_version"] == PREFLIGHT_SCHEMA_VERSION
        and report["status"] == PREFLIGHT_STATUS
        and report["implementation_status"] == IMPLEMENTATION_STATUS
        and report["audience"] == AUDIENCE
        and report["base_compiler_version"] == COMPILER_VERSION
        and report["fixed_parameter"] == FIXED_PARAMETER
        and canonical_bytes(report["boundary"]) == BOUNDARY_CANONICAL
        and report["scope"] == SCOPE
        and report["goal_claim_contract_sha256"] == claim.goal_claim_contract_sha256()
        and report["nonclaims"] == list(NONCLAIMS)
        and all(report[field] is False for field in FIXED_FALSE_FIELDS)
    ):
        raise CausalFrontierError("sentinel admission preflight violated its fixed no-authority boundary")
    for field in {
        "goal_claim_plan_checkpoint_sha256",
        "goal_claim_plan_sha256",
        "generation_plan_checkpoint_sha256",
        "generation_plan_sha256",
        "manifest_checkpoint_sha256",
        "manifest_canonical_sha256",
        "bundle_inventory_sha256",
        "preflight_sha256",
    }:
        _artifact_digest(report[field], "sentinel report %s" % field)
    _positive_integer(report["manifest_sequence"], "sentinel report manifest sequence")
    expected_exact_counts = {
        "declared_domains_n": EXACT_DOMAINS,
        "declared_generator_families_n": EXACT_GENERATOR_FAMILIES,
        "primary_cases_n": EXACT_DOMAINS * PRIMARY_CASES_PER_DOMAIN,
        "calibration_cases_n": EXACT_DOMAINS * len(CONTROL_ROLES),
        "declared_laboratories_n": EXACT_DOMAINS * LABORATORIES_PER_DOMAIN,
        "generator_pair_audits_n": EXACT_GENERATOR_FAMILIES * (EXACT_GENERATOR_FAMILIES - 1) // 2,
        "domain_pair_reviews_n": EXACT_DOMAINS * (EXACT_DOMAINS - 1) // 2,
    }
    if any(report[field] != expected for field, expected in expected_exact_counts.items()):
        raise CausalFrontierError("sentinel report fixed geometry counts differ")
    _positive_integer(report["artifact_files_n"], "sentinel report artifact count", MAX_ARTIFACTS)
    bounded_counts = {
        "generator_component_identity_or_content_collision_pairs_n": 3,
        "declared_generator_role_collision_pairs_n": 3,
        "declared_cross_role_group_collision_pairs_n": 8128,
        "normalized_domain_semantics_collision_pairs_n": 3,
        "normalized_case_decision_core_collision_pairs_n": 741,
        "declared_post_cutoff_cases_n": 39,
        "declared_post_cutoff_generator_inventories_n": 3,
    }
    for field, maximum in bounded_counts.items():
        _nonnegative_integer(report[field], "sentinel report %s" % field, maximum)
    required_true_fields = {
        "artifact_closure_verified",
        "goal_plan_cohort_preimage_verified",
        "generation_plan_replayed",
        "case_geometry_replayed",
        "latin_square_verified",
        "primary_generator_laboratory_assignment_balance_verified",
        "declared_case_provenance_graph_structure_verified",
        "declared_branch_totality_verified",
        "oracle_commitments_unique_verified",
        "generator_seed_and_case_oracle_commitments_disjoint_verified",
        "generator_seed_or_case_oracle_enumerated_bundle_digest_alias_absent_verified",
        "generator_pair_audit_packets_bound",
        "domain_review_packets_bound",
        "control_role_packets_bound",
    }
    if any(report[field] is not True for field in required_true_fields):
        raise CausalFrontierError("sentinel report structural verification booleans differ")
    late_cases = report["declared_post_cutoff_cases_n"]
    late_generator_inventories = report["declared_post_cutoff_generator_inventories_n"]
    if report["declared_cutoff_consistency_verified"] is not (late_cases == 0 and late_generator_inventories == 0):
        raise CausalFrontierError("sentinel report cutoff boolean differs from its count")
    expected_reasons = []
    if late_cases:
        expected_reasons.append(REJECTION_REASON_ORDER[0])
    if late_generator_inventories:
        expected_reasons.append(REJECTION_REASON_ORDER[1])
    if report["generator_component_identity_or_content_collision_pairs_n"]:
        expected_reasons.append(REJECTION_REASON_ORDER[2])
    if report["declared_generator_role_collision_pairs_n"]:
        expected_reasons.append(REJECTION_REASON_ORDER[3])
    if report["declared_cross_role_group_collision_pairs_n"]:
        expected_reasons.append(REJECTION_REASON_ORDER[4])
    if report["normalized_domain_semantics_collision_pairs_n"]:
        expected_reasons.append(REJECTION_REASON_ORDER[5])
    if report["normalized_case_decision_core_collision_pairs_n"]:
        expected_reasons.append(REJECTION_REASON_ORDER[6])
    expected_state = (
        "REJECTED_STRUCTURAL_ADMISSION_GATES_NOT_ADMITTED"
        if expected_reasons
        else "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"
    )
    if report["rejection_reasons"] != expected_reasons or report["admission_state"] != expected_state:
        raise CausalFrontierError("sentinel report rejection state differs from its computed counts")
    expected_gates = _expected_report_gates(
        generator_component_collision_pairs=report["generator_component_identity_or_content_collision_pairs_n"],
        generator_role_collision_pairs=report["declared_generator_role_collision_pairs_n"],
        cross_role_group_collision_pairs=report["declared_cross_role_group_collision_pairs_n"],
        domain_collision_pairs=report["normalized_domain_semantics_collision_pairs_n"],
        case_collision_pairs=report["normalized_case_decision_core_collision_pairs_n"],
        late_cases=late_cases,
        late_generator_inventories=late_generator_inventories,
    )
    if report["gates"] != expected_gates:
        raise CausalFrontierError("sentinel report gates differ from computed counts or canonical order")
    return report


def _preflight_sentinel_admission_core(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    goal_claim_plan_path: Path,
    expected_goal_claim_plan_sha256: str,
    expected_generation_phase_context: dict[str, Any] | None,
    additional_supplied_preimage_digests: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Close sentinel artifacts under an exact v1 or phase-bound policy."""

    expected_sequence = _positive_integer(expected_sequence, "sentinel external sequence")
    generation_plan = preflight_sentinel_generation_plan(generation_plan_path, expected_generation_plan_sha256)
    goal_raw, goal_value = claim._read_checkpointed_plan(goal_claim_plan_path, expected_goal_claim_plan_sha256)
    goal_plan = claim.validate_goal_claim_plan(goal_value)
    goal_preflight = claim.preflight_goal_claim_plan(goal_claim_plan_path, expected_goal_claim_plan_sha256)
    raw_manifest, manifest, by_id, snapshots = _snapshot_bundle(root, expected_manifest_sha256)
    manifest_keys = {
        "schema_version",
        "manifest_id",
        "sequence",
        "generation_plan_checkpoint_sha256",
        "generation_plan_sha256",
        "fixed_parameter",
        "boundary",
        "goal_claim_contract_sha256",
        "scope",
        "frozen_at",
        "protocol_artifact_ids",
        "organizations",
        "generators",
        "domains",
        "generator_pair_audits",
        "domain_pair_reviews",
        "artifacts",
        "designated_outcome_input_absent",
        "oracle_opening_input_absent",
        "scoring_disabled",
    }
    if expected_generation_phase_context is not None:
        manifest_keys.add("generation_phase_context")
    manifest = _shape(
        manifest,
        manifest_keys,
        "sentinel admission manifest",
    )
    _validate_fixed_header(
        manifest,
        schema=(
            PHASE_BOUND_MANIFEST_SCHEMA_VERSION
            if expected_generation_phase_context is not None
            else MANIFEST_SCHEMA_VERSION
        ),
    )
    if expected_generation_phase_context is not None:
        _validate_generation_phase_context(
            manifest["generation_phase_context"],
            expected_generation_phase_context,
        )
    require_id(manifest["manifest_id"], "sentinel manifest id")
    if manifest["sequence"] != expected_sequence or generation_plan["sequence"] != expected_sequence:
        raise CausalFrontierError("sentinel manifest, generation plan, and external sequence differ")
    if not (
        manifest["generation_plan_checkpoint_sha256"] == expected_generation_plan_sha256
        and manifest["generation_plan_sha256"] == generation_plan["plan_sha256"]
        and manifest["goal_claim_contract_sha256"] == claim.goal_claim_contract_sha256()
        and manifest["scope"] == SCOPE
        and manifest["designated_outcome_input_absent"] is True
        and manifest["oracle_opening_input_absent"] is True
        and manifest["scoring_disabled"] is True
    ):
        raise CausalFrontierError("sentinel manifest predecessor or no-outcome boundary differs")
    manifest_frozen_at = require_utc_timestamp(manifest["frozen_at"], "sentinel manifest freeze")
    if manifest_frozen_at < generation_plan["frozen_at"]:
        raise CausalFrontierError("sentinel manifest predates its generation plan declaration")
    if goal_plan["goal_claim_contract_sha256"] != manifest["goal_claim_contract_sha256"]:
        raise CausalFrontierError("goal claim plan and sentinel bind different goal contracts")
    if goal_plan["cohort_checkpoint_sha256"] != expected_manifest_sha256:
        raise CausalFrontierError("sentinel manifest is not the preimage of the goal plan cohort checkpoint")
    if goal_plan["sequence"] != expected_sequence:
        raise CausalFrontierError("goal claim plan sequence differs from the sentinel lock")

    used: set[str] = set()
    protocols = _shape(manifest["protocol_artifact_ids"], set(PROTOCOL_FIELDS), "sentinel protocols")
    protocol_digests: dict[str, str] = {}
    for field, role in PROTOCOL_FIELDS.items():
        descriptor = _artifact(protocols[field], role, by_id, used, field)
        protocol_digests[field] = descriptor["sha256"]
        if descriptor["data_class"] != "OPEN_SOURCE_TEXT":
            raise CausalFrontierError("sentinel protocol artifacts must be open-source text")
        if not snapshots[descriptor["artifact_id"]]:
            raise CausalFrontierError("sentinel protocol artifacts must be nonempty")
        if generation_plan["protocol_precommitments"][field] != descriptor["sha256"]:
            raise CausalFrontierError("sentinel protocol bytes differ from their pre-generation commitment")

    organization_values, organizations = _validate_organizations(manifest["organizations"])
    if generation_plan["organization_registry_sha256"] != sha256_bytes(canonical_bytes(organization_values)):
        raise CausalFrontierError("organization registry differs from its pre-generation commitment")
    steward_ids = [item["organization_id"] for item in organization_values if "STEWARD" in item["roles"]]
    if len(steward_ids) != 1:
        raise CausalFrontierError("sentinel bundle must name exactly one steward")
    used_org_ids = set(steward_ids)
    organization_contexts: dict[str, set[str]] = {steward_ids[0]: {"STEWARD"}}
    generator_values = manifest["generators"]
    if not isinstance(generator_values, list) or len(generator_values) != EXACT_GENERATOR_FAMILIES:
        raise CausalFrontierError("sentinel manifest must bind exactly three generator families")
    generators: dict[str, dict[str, Any]] = {}
    generator_source_signatures: dict[str, tuple[str, str]] = {}
    generator_source_manifests: dict[str, dict[str, Any]] = {}
    generator_ancestry: dict[str, set[str]] = {}
    generator_org_ids: set[str] = set()
    late_generator_inventories = 0
    for index, raw_generator in enumerate(generator_values):
        generator = _shape(
            raw_generator,
            {
                "generator_family_id",
                "mechanism_family_id",
                "governance_family_id",
                "author_organization_id",
                "controller_organization_id",
                *GENERATOR_ARTIFACT_FIELDS,
            },
            "sentinel generator[%d]" % index,
        )
        family_id = require_id(generator["generator_family_id"], "sentinel generator family id")
        require_id(generator["mechanism_family_id"], "sentinel mechanism family id")
        require_id(generator["governance_family_id"], "sentinel governance family id")
        author = _require_org_role(
            generator["author_organization_id"], "GENERATOR_AUTHOR", organizations, "generator author"
        )
        controller = _require_org_role(
            generator["controller_organization_id"],
            "GENERATOR_CONTROLLER",
            organizations,
            "generator controller",
        )
        generator_org_ids.update({author["organization_id"], controller["organization_id"]})
        used_org_ids.update({author["organization_id"], controller["organization_id"]})
        for organization_id in {author["organization_id"], controller["organization_id"]}:
            organization_contexts.setdefault(organization_id, set()).add("GENERATOR")
        if author["controller_group_id"] == controller["controller_group_id"] and author != controller:
            # This is allowed within one family; the family is the maximal governance cluster.
            pass
        for field, role in GENERATOR_ARTIFACT_FIELDS.items():
            descriptor = _artifact(generator[field], role, by_id, used, "%s %s" % (family_id, field))
            if descriptor["data_class"] != "OPEN_SOURCE_TEXT":
                raise CausalFrontierError("generator contracts and source must be open-source text")
        content_signature, path_signature = _source_tree_signatures(generator, by_id, snapshots, used)
        source_descriptor, source_manifest_value = _json_artifact(
            generator["source_manifest_artifact_id"],
            "GENERATOR_SOURCE_MANIFEST",
            by_id,
            snapshots,
            used,
            "%s source manifest replay" % family_id,
        )
        del source_descriptor
        generator_source_manifests[family_id] = source_manifest_value
        generator_source_signatures[family_id] = (content_signature, path_signature)
        _, ancestry_value = _json_artifact(
            generator["ancestry_artifact_id"],
            "GENERATOR_ANCESTRY",
            by_id,
            snapshots,
            used,
            "%s ancestry replay" % family_id,
        )
        generator_ancestry[family_id] = _validate_generator_ancestry(ancestry_value, family_id)
        _, tool_model_inventory = _json_artifact(
            generator["tool_model_inventory_artifact_id"],
            "GENERATOR_TOOL_MODEL_INVENTORY",
            by_id,
            snapshots,
            used,
            "%s tool/model inventory replay" % family_id,
        )
        earliest_case_cutoff = min(
            item["knowledge_cutoff"]
            for item in generation_plan["case_assignments"]
            if item["generator_family_id"] == family_id
        )
        late_generator_inventories += int(
            _validate_generator_tool_model_inventory(tool_model_inventory, family_id, earliest_case_cutoff)
        )
        if family_id in generators:
            raise CausalFrontierError("duplicate sentinel generator family")
        generators[family_id] = generator
    if list(generators) != generation_plan["generator_family_ids"]:
        raise CausalFrontierError("sentinel generators differ from the pre-generation family order")
    if any(
        related_family not in generators
        for related_families in generator_ancestry.values()
        for related_family in related_families
    ):
        raise CausalFrontierError("generator ancestry references an undeclared family")
    precommitments = {item["generator_family_id"]: item for item in generation_plan["generator_precommitments"]}
    for family_id, generator in generators.items():
        precommitment = precommitments[family_id]
        content_signature, path_signature = generator_source_signatures[family_id]
        if not (
            precommitment["mechanism_family_id"] == generator["mechanism_family_id"]
            and precommitment["governance_family_id"] == generator["governance_family_id"]
            and precommitment["author_organization_id"] == generator["author_organization_id"]
            and precommitment["controller_organization_id"] == generator["controller_organization_id"]
            and precommitment["source_content_multiset_sha256"] == content_signature
            and precommitment["source_path_sensitive_sha256"] == path_signature
        ):
            raise CausalFrontierError("generator identity or source tree differs from its pre-generation commitment")
        for digest_field, artifact_field in GENERATOR_PRECOMMITMENT_DIGEST_FIELDS.items():
            if precommitment[digest_field] != by_id[generator[artifact_field]]["sha256"]:
                raise CausalFrontierError("generator artifact differs from its pre-generation commitment")

    generator_pairs = list(combinations(generation_plan["generator_family_ids"], 2))
    generator_component_collision_pairs = 0
    role_collision_pairs = 0
    for left_id, right_id in generator_pairs:
        left = generators[left_id]
        right = generators[right_id]
        left_source_ids = {item["artifact_id"] for item in generator_source_manifests[left_id]["files"]}
        right_source_ids = {item["artifact_id"] for item in generator_source_manifests[right_id]["files"]}
        left_component_ids = {left[field] for field in GENERATOR_ARTIFACT_FIELDS} | left_source_ids
        right_component_ids = {right[field] for field in GENERATOR_ARTIFACT_FIELDS} | right_source_ids
        left_component_digests = {by_id[artifact_id]["sha256"] for artifact_id in left_component_ids}
        right_component_digests = {by_id[artifact_id]["sha256"] for artifact_id in right_component_ids}
        if (
            generator_source_signatures[left_id][0] == generator_source_signatures[right_id][0]
            or left_component_ids & right_component_ids
            or left_component_digests & right_component_digests
        ):
            generator_component_collision_pairs += 1
        left_author = organizations[left["author_organization_id"]]
        left_controller = organizations[left["controller_organization_id"]]
        right_author = organizations[right["author_organization_id"]]
        right_controller = organizations[right["controller_organization_id"]]
        left_group_ids = {
            left_author["controller_group_id"].casefold(),
            left_author["store_group_id"].casefold(),
            left_controller["controller_group_id"].casefold(),
            left_controller["store_group_id"].casefold(),
        }
        right_group_ids = {
            right_author["controller_group_id"].casefold(),
            right_author["store_group_id"].casefold(),
            right_controller["controller_group_id"].casefold(),
            right_controller["store_group_id"].casefold(),
        }
        if (
            left["mechanism_family_id"].casefold() == right["mechanism_family_id"].casefold()
            or left["governance_family_id"].casefold() == right["governance_family_id"].casefold()
            or right_id in generator_ancestry[left_id]
            or left_id in generator_ancestry[right_id]
            or left_group_ids & right_group_ids
        ):
            role_collision_pairs += 1

    pair_audits_raw = manifest["generator_pair_audits"]
    if not isinstance(pair_audits_raw, list) or len(pair_audits_raw) != len(generator_pairs):
        raise CausalFrontierError("generator pair audit matrix is incomplete")
    observed_pairs: list[tuple[str, str]] = []
    for index, raw_pair_audit in enumerate(pair_audits_raw):
        pair_audit = _shape(
            raw_pair_audit,
            {"left_generator_family_id", "right_generator_family_id", "audit_artifact_id"},
            "generator pair audit[%d]" % index,
        )
        left_id = require_id(pair_audit["left_generator_family_id"], "left generator audit family")
        right_id = require_id(pair_audit["right_generator_family_id"], "right generator audit family")
        pair = (left_id, right_id)
        observed_pairs.append(pair)
        if pair not in generator_pairs:
            raise CausalFrontierError("generator pair audit references an unordered or undeclared pair")
        _, audit = _json_artifact(
            pair_audit["audit_artifact_id"],
            "GENERATOR_PAIR_AUDIT",
            by_id,
            snapshots,
            used,
            "generator pair audit packet",
        )
        _shape(
            audit,
            {
                "schema_version",
                "left_generator_family_id",
                "right_generator_family_id",
                "reviewer_organization_ids",
                "generator_audit_protocol_sha256",
                "left_source_content_multiset_sha256",
                "right_source_content_multiset_sha256",
                "exact_source_content_collision",
                "shared_source_artifact_id_collision",
                "shared_source_content_sha256_collision",
                "shared_generator_component_artifact_id_collision",
                "shared_generator_component_content_sha256_collision",
                "declared_mechanism_family_collision",
                "declared_governance_family_collision",
                "declared_ancestry_collision",
                "declared_controller_group_collision",
                "declared_store_group_collision",
                "declared_cross_dimension_group_collision",
                "semantic_independence_verified",
                "governance_independence_verified",
                "audit_state",
            },
            "generator pair audit packet",
        )
        reviewers = _sorted_ids(audit["reviewer_organization_ids"], "generator pair reviewers", exact=2)
        forbidden = {
            generators[left_id]["author_organization_id"],
            generators[left_id]["controller_organization_id"],
            generators[right_id]["author_organization_id"],
            generators[right_id]["controller_organization_id"],
        }
        for reviewer_id in reviewers:
            _require_org_role(reviewer_id, "GENERATOR_AUDITOR", organizations, "generator auditor")
            used_org_ids.add(reviewer_id)
            organization_contexts.setdefault(reviewer_id, set()).add("GENERATOR_AUDITOR")
            if reviewer_id in forbidden:
                raise CausalFrontierError("generator auditor overlaps a compared family")
        left = generators[left_id]
        right = generators[right_id]
        controller_collision = bool(
            {
                organizations[left["author_organization_id"]]["controller_group_id"].casefold(),
                organizations[left["controller_organization_id"]]["controller_group_id"].casefold(),
            }
            & {
                organizations[right["author_organization_id"]]["controller_group_id"].casefold(),
                organizations[right["controller_organization_id"]]["controller_group_id"].casefold(),
            }
        )
        store_collision = bool(
            {
                organizations[left["author_organization_id"]]["store_group_id"].casefold(),
                organizations[left["controller_organization_id"]]["store_group_id"].casefold(),
            }
            & {
                organizations[right["author_organization_id"]]["store_group_id"].casefold(),
                organizations[right["controller_organization_id"]]["store_group_id"].casefold(),
            }
        )
        cross_dimension_group_collision = bool(
            {
                organizations[left["author_organization_id"]]["controller_group_id"].casefold(),
                organizations[left["controller_organization_id"]]["controller_group_id"].casefold(),
            }
            & {
                organizations[right["author_organization_id"]]["store_group_id"].casefold(),
                organizations[right["controller_organization_id"]]["store_group_id"].casefold(),
            }
            or {
                organizations[left["author_organization_id"]]["store_group_id"].casefold(),
                organizations[left["controller_organization_id"]]["store_group_id"].casefold(),
            }
            & {
                organizations[right["author_organization_id"]]["controller_group_id"].casefold(),
                organizations[right["controller_organization_id"]]["controller_group_id"].casefold(),
            }
        )
        left_component_ids = {left[field] for field in GENERATOR_ARTIFACT_FIELDS} | {
            item["artifact_id"] for item in generator_source_manifests[left_id]["files"]
        }
        right_component_ids = {right[field] for field in GENERATOR_ARTIFACT_FIELDS} | {
            item["artifact_id"] for item in generator_source_manifests[right_id]["files"]
        }
        left_component_digests = {by_id[artifact_id]["sha256"] for artifact_id in left_component_ids}
        right_component_digests = {by_id[artifact_id]["sha256"] for artifact_id in right_component_ids}
        ancestry_collision = right_id in generator_ancestry[left_id] or left_id in generator_ancestry[right_id]
        if not (
            audit["schema_version"] == "causalfrontier.generator-pair-audit.v1"
            and audit["left_generator_family_id"] == left_id
            and audit["right_generator_family_id"] == right_id
            and audit["generator_audit_protocol_sha256"] == protocol_digests["generator_audit_protocol_artifact_id"]
            and audit["left_source_content_multiset_sha256"] == generator_source_signatures[left_id][0]
            and audit["right_source_content_multiset_sha256"] == generator_source_signatures[right_id][0]
            and audit["exact_source_content_collision"]
            is (generator_source_signatures[left_id][0] == generator_source_signatures[right_id][0])
            and audit["shared_source_artifact_id_collision"]
            is bool(
                {item["artifact_id"] for item in generator_source_manifests[left_id]["files"]}
                & {item["artifact_id"] for item in generator_source_manifests[right_id]["files"]}
            )
            and audit["shared_source_content_sha256_collision"]
            is bool(
                {item["sha256"] for item in generator_source_manifests[left_id]["files"]}
                & {item["sha256"] for item in generator_source_manifests[right_id]["files"]}
            )
            and audit["shared_generator_component_artifact_id_collision"]
            is bool(left_component_ids & right_component_ids)
            and audit["shared_generator_component_content_sha256_collision"]
            is bool(left_component_digests & right_component_digests)
            and audit["declared_mechanism_family_collision"]
            is (left["mechanism_family_id"].casefold() == right["mechanism_family_id"].casefold())
            and audit["declared_governance_family_collision"]
            is (left["governance_family_id"].casefold() == right["governance_family_id"].casefold())
            and audit["declared_ancestry_collision"] is ancestry_collision
            and audit["declared_controller_group_collision"] is controller_collision
            and audit["declared_store_group_collision"] is store_collision
            and audit["declared_cross_dimension_group_collision"] is cross_dimension_group_collision
            and audit["semantic_independence_verified"] is False
            and audit["governance_independence_verified"] is False
            and audit["audit_state"] == "EXACT_BYTE_COMPARISON_BOUND_EXTERNAL_INDEPENDENCE_UNVERIFIED"
        ):
            raise CausalFrontierError("generator pair audit differs from computed bytes or overclaims independence")
    if observed_pairs != generator_pairs:
        raise CausalFrontierError("generator pair audits must use canonical exhaustive pair order")

    goal_domains = {item["domain_id"]: item for item in goal_plan["domains"]}
    generation_domains = {item["domain_id"]: item for item in generation_plan["domain_contracts"]}
    domain_values = manifest["domains"]
    if not isinstance(domain_values, list) or len(domain_values) != EXACT_DOMAINS:
        raise CausalFrontierError("sentinel manifest must bind exactly three domains")
    domains: dict[str, dict[str, Any]] = {}
    semantics_digests: dict[str, str] = {}
    semantics_core_digests: dict[str, str] = {}
    semantics_values: dict[str, dict[str, Any]] = {}
    domain_registry_digests: dict[str, str] = {}
    decision_core_digests: list[str] = []
    late_cases = 0
    primary_cases_n = 0
    calibration_cases_n = 0
    phase_bound_payload_counts: Counter[str] = Counter()
    phase_bound_provenance_counts: Counter[str] = Counter()
    laboratories: set[str] = set()
    control_opening_commitments: list[dict[str, str]] = []
    oracle_commitments: list[str] = []
    case_artifact_fields = {
        "case_payload_artifact_id": "CASE_PAYLOAD",
        "role_packet_artifact_id": "CASE_ROLE_PACKET",
        "source_inventory_artifact_id": "CASE_SOURCE_INVENTORY",
        "cutoff_audit_artifact_id": "CASE_CUTOFF_AUDIT",
        "provenance_artifact_id": "CASE_PROVENANCE",
    }
    generation_assignments = {item["case_id"]: item for item in generation_plan["case_assignments"]}
    seen_case_specific_artifacts: set[str] = set()
    for index, raw_domain in enumerate(domain_values):
        domain = _shape(
            raw_domain,
            {
                "domain_id",
                "knowledge_cutoff",
                "laboratory_ids",
                "semantics_artifact_id",
                "domain_review_artifact_id",
                "control_review_artifact_id",
                "cases",
            },
            "sentinel domain[%d]" % index,
        )
        domain_id = require_id(domain["domain_id"], "sentinel domain id")
        if domain_id in domains or domain_id not in generation_domains or domain_id not in goal_domains:
            raise CausalFrontierError("sentinel domain is duplicate or absent from a predecessor plan")
        generation_domain = generation_domains[domain_id]
        goal_domain = goal_domains[domain_id]
        if not (
            domain["knowledge_cutoff"] == generation_domain["knowledge_cutoff"] == goal_domain["knowledge_cutoff"]
            and domain["laboratory_ids"] == generation_domain["laboratory_ids"] == goal_domain["laboratory_ids"]
        ):
            raise CausalFrontierError("sentinel domain cutoff or laboratory geometry differs from a predecessor")
        require_utc_timestamp(domain["knowledge_cutoff"], "sentinel domain cutoff")
        labs = _sorted_ids(domain["laboratory_ids"], "sentinel domain laboratories", exact=LABORATORIES_PER_DOMAIN)
        laboratories.update(labs)
        for lab_id in labs:
            _require_org_role(lab_id, "LABORATORY", organizations, "sentinel laboratory")
            used_org_ids.add(lab_id)
            organization_contexts.setdefault(lab_id, set()).add("LABORATORY")
        semantics_descriptor, semantics = _json_artifact(
            domain["semantics_artifact_id"],
            "DOMAIN_SEMANTICS",
            by_id,
            snapshots,
            used,
            "%s semantics" % domain_id,
        )
        semantics_core_digests[domain_id] = _validate_domain_semantics(semantics, domain_id)
        semantics_values[domain_id] = semantics
        semantics_digests[domain_id] = semantics_descriptor["sha256"]
        if semantics_descriptor["sha256"] != generation_domain["domain_semantics_sha256"]:
            raise CausalFrontierError("domain semantics differ from their pre-generation commitment")
        _, domain_review = _json_artifact(
            domain["domain_review_artifact_id"],
            "DOMAIN_REVIEW",
            by_id,
            snapshots,
            used,
            "%s domain review" % domain_id,
        )
        domain_reviewers = _validate_domain_review(
            domain_review, domain_id, semantics_descriptor["sha256"], organizations, generator_org_ids
        )
        used_org_ids.update(domain_reviewers)
        for reviewer_id in domain_reviewers:
            organization_contexts.setdefault(reviewer_id, set()).add("DOMAIN_REVIEWER")
        control_review_descriptor, control_review = _json_artifact(
            domain["control_review_artifact_id"],
            "CONTROL_METHODOLOGY_REVIEW",
            by_id,
            snapshots,
            used,
            "%s control review" % domain_id,
        )

        cases_raw = domain["cases"]
        if not isinstance(cases_raw, list) or len(cases_raw) != PRIMARY_CASES_PER_DOMAIN + len(CONTROL_ROLES):
            raise CausalFrontierError("sentinel domain case geometry is incomplete")
        case_ids: list[str] = []
        case_registry_records: list[dict[str, Any]] = []
        control_packet_hashes: dict[str, str] = {}
        for case_index, raw_case in enumerate(cases_raw):
            case = _shape(
                raw_case,
                {
                    "case_id",
                    "case_role",
                    "control_role",
                    "required_behavior",
                    "generator_family_id",
                    "laboratory_id",
                    "outcome_provider_organization_id",
                    "selection_origin",
                    "knowledge_cutoff",
                    *case_artifact_fields,
                },
                "%s case[%d]" % (domain_id, case_index),
            )
            case_id = require_id(case["case_id"], "sentinel case id")
            case_ids.append(case_id)
            if case_id not in generation_assignments:
                raise CausalFrontierError("sentinel case was not precommitted for generation")
            assignment = generation_assignments[case_id]
            for field in {
                "case_id",
                "case_role",
                "control_role",
                "required_behavior",
                "generator_family_id",
                "laboratory_id",
                "outcome_provider_organization_id",
                "selection_origin",
                "knowledge_cutoff",
            }:
                if case[field] != assignment[field]:
                    raise CausalFrontierError("sentinel case assignment differs from its pre-generation lock")
            if assignment["domain_id"] != domain_id or case["knowledge_cutoff"] != domain["knowledge_cutoff"]:
                raise CausalFrontierError("sentinel case domain or cutoff differs")
            if case["generator_family_id"] not in generators:
                raise CausalFrontierError("sentinel case references an undeclared generator")
            role = case["case_role"]
            if role == "PRIMARY":
                primary_cases_n += 1
                _require_org_role(case["laboratory_id"], "LABORATORY", organizations, "case laboratory")
                if case["laboratory_id"] not in labs:
                    raise CausalFrontierError("primary case laboratory is outside its domain")
            else:
                calibration_cases_n += 1
                if case["laboratory_id"] is not None:
                    raise CausalFrontierError("calibration case cannot enter the primary laboratory geometry")
            _require_org_role(
                case["outcome_provider_organization_id"],
                "OUTCOME_PROVIDER" if role == "PRIMARY" else "ADJUDICATOR",
                organizations,
                "case outcome provider or adjudicator",
            )
            used_org_ids.add(case["outcome_provider_organization_id"])
            organization_contexts.setdefault(case["outcome_provider_organization_id"], set()).add(
                "PRIMARY_OUTCOME_PROVIDER" if role == "PRIMARY" else "CONTROL_ADJUDICATOR"
            )
            if case["outcome_provider_organization_id"] in generator_org_ids:
                raise CausalFrontierError("case outcome provider overlaps a generator author or controller")
            descriptors: dict[str, dict[str, Any]] = {}
            for field, artifact_role in case_artifact_fields.items():
                descriptor = _artifact(case[field], artifact_role, by_id, used, "%s %s" % (case_id, field))
                if descriptor["media_type"] != "application/json":
                    raise CausalFrontierError("sentinel case structured artifacts must use application/json")
                if descriptor["artifact_id"] in seen_case_specific_artifacts:
                    raise CausalFrontierError("case-specific artifact is reused across cases")
                seen_case_specific_artifacts.add(descriptor["artifact_id"])
                descriptors[field] = descriptor
            if not (
                assignment["role_packet_sha256"] == descriptors["role_packet_artifact_id"]["sha256"]
                and assignment["source_inventory_sha256"] == descriptors["source_inventory_artifact_id"]["sha256"]
            ):
                raise CausalFrontierError("case role or exact source inventory differs from its pre-generation lock")
            payload = _strict_json(snapshots[case["case_payload_artifact_id"]], "%s payload" % case_id)
            if not isinstance(payload, dict):
                raise CausalFrontierError("case payload must be an object")
            (
                decision_core_digest,
                branch_contract_sha256,
                oracle_commitment_sha256,
                branch_decision_mapping,
            ) = _validate_case_payload(
                payload,
                case_id,
                domain_id,
                expected_generation_phase_context,
            )
            if expected_generation_phase_context is not None:
                phase_bound_payload_counts[role] += 1
            decision_core_digests.append(decision_core_digest)
            oracle_commitments.append(oracle_commitment_sha256)
            role_packet = _strict_json(snapshots[case["role_packet_artifact_id"]], "%s role packet" % case_id)
            if not isinstance(role_packet, dict):
                raise CausalFrontierError("case role packet must be an object")
            _validate_role_packet(
                role_packet,
                case,
                branch_contract_sha256,
                oracle_commitment_sha256,
                branch_decision_mapping,
                organizations,
            )
            if role != "PRIMARY":
                control_packet_hashes[role] = descriptors["role_packet_artifact_id"]["sha256"]
                control_opening_commitments.append(
                    {
                        "case_id": case_id,
                        "control_role": role,
                        "opening_commitment_sha256": role_packet["sealed_opening_external_commitment_sha256"],
                    }
                )
            source_inventory = _strict_json(
                snapshots[case["source_inventory_artifact_id"]], "%s source inventory" % case_id
            )
            if not isinstance(source_inventory, dict):
                raise CausalFrontierError("case source inventory must be an object")
            sources, late = _validate_source_inventory(source_inventory, case, by_id, snapshots, used)
            late_cases += int(late)
            cutoff_audit = _strict_json(snapshots[case["cutoff_audit_artifact_id"]], "%s cutoff audit" % case_id)
            if not isinstance(cutoff_audit, dict):
                raise CausalFrontierError("case cutoff audit must be an object")
            _validate_cutoff_audit(
                cutoff_audit,
                case,
                descriptors["source_inventory_artifact_id"],
                sources,
                protocol_digests["cutoff_audit_protocol_artifact_id"],
                by_id,
            )
            provenance = _strict_json(snapshots[case["provenance_artifact_id"]], "%s provenance" % case_id)
            if not isinstance(provenance, dict):
                raise CausalFrontierError("case provenance must be an object")
            _validate_provenance(
                provenance,
                case,
                descriptors["source_inventory_artifact_id"],
                sources,
                generator_source_manifests[case["generator_family_id"]],
                generator_source_signatures[case["generator_family_id"]][0],
                by_id,
                used,
                expected_generation_phase_context,
            )
            if expected_generation_phase_context is not None:
                phase_bound_provenance_counts[role] += 1
            case_registry_records.append(
                {
                    "case_id": case_id,
                    "case_role": role,
                    "control_role": case["control_role"],
                    "required_behavior": case["required_behavior"],
                    "generator_family_id": case["generator_family_id"],
                    "laboratory_id": case["laboratory_id"],
                    "outcome_provider_organization_id": case["outcome_provider_organization_id"],
                    "selection_origin": case["selection_origin"],
                    "knowledge_cutoff": case["knowledge_cutoff"],
                    "case_payload_sha256": descriptors["case_payload_artifact_id"]["sha256"],
                    "role_packet_sha256": descriptors["role_packet_artifact_id"]["sha256"],
                    "source_inventory_sha256": descriptors["source_inventory_artifact_id"]["sha256"],
                    "cutoff_audit_sha256": descriptors["cutoff_audit_artifact_id"]["sha256"],
                    "provenance_sha256": descriptors["provenance_artifact_id"]["sha256"],
                }
            )
        if case_ids != sorted(set(case_ids)) or len({item.casefold() for item in case_ids}) != len(case_ids):
            raise CausalFrontierError("sentinel domain cases must be case-insensitively unique and sorted")
        _shape(
            control_review,
            {
                "schema_version",
                "domain_id",
                "reviewer_organization_ids",
                "control_scoring_rule",
                "control_role_packet_sha256",
                "review_state",
                "control_semantic_validity_verified",
            },
            "%s control methodology review" % domain_id,
        )
        control_reviewers = _sorted_ids(control_review["reviewer_organization_ids"], "control reviewers", exact=2)
        for reviewer_id in control_reviewers:
            _require_org_role(reviewer_id, "CONTROL_REVIEWER", organizations, "control reviewer")
            used_org_ids.add(reviewer_id)
            organization_contexts.setdefault(reviewer_id, set()).add("CONTROL_REVIEWER")
            if reviewer_id in generator_org_ids:
                raise CausalFrontierError("control reviewer overlaps a generator author or controller")
        if not (
            control_review["schema_version"] == "causalfrontier.control-methodology-review.v1"
            and control_review["domain_id"] == domain_id
            and control_review["control_scoring_rule"] == claim.CONTROL_FAILURE_RULE
            and control_review["control_role_packet_sha256"]
            == [{"control_role": role, "sha256": control_packet_hashes[role]} for role in CONTROL_ROLES]
            and control_review["review_state"] == "PACKETS_BOUND_REVIEW_NOT_EXECUTED"
            and control_review["control_semantic_validity_verified"] is False
        ):
            raise CausalFrontierError("control methodology review differs or overclaims validity")
        domain_core = {
            "schema_version": "causalfrontier.sentinel-domain-registry.v1",
            "domain_id": domain_id,
            "knowledge_cutoff": domain["knowledge_cutoff"],
            "laboratory_ids": labs,
            "semantics_sha256": semantics_descriptor["sha256"],
            "domain_review_sha256": by_id[domain["domain_review_artifact_id"]]["sha256"],
            "control_review_sha256": control_review_descriptor["sha256"],
            "cases": case_registry_records,
        }
        domain_registry_digest = sha256_bytes(canonical_bytes(domain_core))
        domain_registry_digests[domain_id] = domain_registry_digest
        if goal_domain["case_registry_checkpoint_sha256"] != domain_registry_digest:
            raise CausalFrontierError("sentinel domain registry is not the goal plan checkpoint preimage")
        if goal_domain["primary_case_ids"] != generation_domain["primary_case_ids"]:
            raise CausalFrontierError("goal and generation primary case geometry differs")
        if goal_domain["calibration_cases"] != generation_domain["calibration_cases"]:
            raise CausalFrontierError("goal and generation calibration geometry differs")
        assignment_projection = [
            {"case_id": item["case_id"], "laboratory_id": item["laboratory_id"]}
            for item in generation_plan["case_assignments"]
            if item["domain_id"] == domain_id and item["case_role"] == "PRIMARY"
        ]
        if goal_domain["primary_case_laboratory_assignments"] != assignment_projection:
            raise CausalFrontierError("goal and generation laboratory assignments differ")
        domains[domain_id] = domain
    if list(domains) != generation_plan["domain_ids"] or set(goal_domains) != set(domains):
        raise CausalFrontierError("sentinel, generation, and goal domain sets differ")
    if expected_generation_phase_context is not None:
        expected_phase_counts = Counter(
            {
                "PRIMARY": EXACT_DOMAINS * PRIMARY_CASES_PER_DOMAIN,
                **dict.fromkeys(CONTROL_ROLES, EXACT_DOMAINS),
            }
        )
        if (
            phase_bound_payload_counts != expected_phase_counts
            or phase_bound_provenance_counts != expected_phase_counts
        ):
            raise CausalFrontierError("phase-bound payload or provenance role geometry is incomplete")
    if len(set(oracle_commitments)) != len(oracle_commitments):
        raise CausalFrontierError("case oracle commitments must be globally unique")
    generator_seed_commitments = {
        item["seed_external_commitment_sha256"] for item in generation_plan["generator_precommitments"]
    }
    if generator_seed_commitments & set(oracle_commitments):
        raise CausalFrontierError("generator seed and case oracle commitment classes must be disjoint")
    inventory_core = [
        {
            "artifact_id": item["artifact_id"],
            "path": item["path"],
            "sha256": item["sha256"],
            "role": item["role"],
        }
        for item in manifest["artifacts"]
    ]
    bundle_inventory_sha256 = sha256_bytes(canonical_bytes(inventory_core))
    supplied_preimage_digests = {
        *(descriptor["sha256"] for descriptor in by_id.values()),
        expected_manifest_sha256,
        sha256_bytes(canonical_bytes(manifest)),
        expected_generation_plan_sha256,
        generation_plan["plan_sha256"],
        expected_goal_claim_plan_sha256,
        goal_plan["plan_sha256"],
        claim.goal_claim_contract_sha256(),
        generation_plan["organization_registry_sha256"],
        bundle_inventory_sha256,
        sha256_bytes(canonical_bytes(control_opening_commitments)),
        *domain_registry_digests.values(),
        *(digest for signatures in generator_source_signatures.values() for digest in signatures),
    }
    if expected_generation_phase_context is not None:
        supplied_preimage_digests.update(
            value for key, value in expected_generation_phase_context.items() if key.endswith("_sha256")
        )
        supplied_preimage_digests.add(sha256_bytes(canonical_bytes(expected_generation_phase_context)))
    for index, digest in enumerate(sorted(additional_supplied_preimage_digests or ())):
        supplied_preimage_digests.add(_artifact_digest(digest, "additional supplied preimage digest[%d]" % index))
    if (generator_seed_commitments | set(oracle_commitments)) & supplied_preimage_digests:
        raise CausalFrontierError("commitment digest has a supplied input preimage")

    domain_pairs = list(combinations(generation_plan["domain_ids"], 2))
    domain_pair_values = manifest["domain_pair_reviews"]
    if not isinstance(domain_pair_values, list) or len(domain_pair_values) != len(domain_pairs):
        raise CausalFrontierError("domain pair review matrix is incomplete")
    observed_domain_pairs: list[tuple[str, str]] = []
    for index, raw_pair in enumerate(domain_pair_values):
        pair = _shape(
            raw_pair,
            {"left_domain_id", "right_domain_id", "review_artifact_id"},
            "domain pair review[%d]" % index,
        )
        left_id = require_id(pair["left_domain_id"], "left reviewed domain")
        right_id = require_id(pair["right_domain_id"], "right reviewed domain")
        observed_domain_pairs.append((left_id, right_id))
        if (left_id, right_id) not in domain_pairs:
            raise CausalFrontierError("domain pair review references an unordered or undeclared pair")
        _, review = _json_artifact(
            pair["review_artifact_id"],
            "DOMAIN_PAIR_REVIEW",
            by_id,
            snapshots,
            used,
            "domain pair review packet",
        )
        _shape(
            review,
            {
                "schema_version",
                "left_domain_id",
                "right_domain_id",
                "left_semantics_sha256",
                "right_semantics_sha256",
                "reviewer_organization_ids",
                "decision_critical_axes_declared_different",
                "semantic_independence_verified",
                "review_state",
            },
            "domain pair review packet",
        )
        reviewers = _sorted_ids(review["reviewer_organization_ids"], "domain pair reviewers", exact=2)
        for reviewer_id in reviewers:
            _require_org_role(reviewer_id, "DOMAIN_REVIEWER", organizations, "domain pair reviewer")
            used_org_ids.add(reviewer_id)
            organization_contexts.setdefault(reviewer_id, set()).add("DOMAIN_REVIEWER")
            if reviewer_id in generator_org_ids:
                raise CausalFrontierError("domain pair reviewer overlaps a generator author or controller")
        axes = review["decision_critical_axes_declared_different"]
        allowed_axes = {
            "decision_unit",
            "evidence_modalities",
            "permissible_action_class",
            "terminal_observation_interface",
            "decision_loss_semantics",
            "resource_basis",
            "common_horizon",
            "inclusion_criteria",
            "exclusion_criteria",
        }
        if not isinstance(axes, list):
            raise CausalFrontierError("domain pair review difference axes must be a list")
        normalized_axes = [require_enum(item, allowed_axes, "domain difference axis") for item in axes]
        if normalized_axes != sorted(set(normalized_axes)):
            raise CausalFrontierError("domain difference axes must be sorted and unique")
        if not normalized_axes and semantics_core_digests[left_id] != semantics_core_digests[right_id]:
            raise CausalFrontierError("noncolliding domain pair must declare an exact decision-critical difference")
        if any(semantics_values[left_id][axis] == semantics_values[right_id][axis] for axis in normalized_axes):
            raise CausalFrontierError("domain pair review declares a difference absent from exact semantics")
        if not (
            review["schema_version"] == "causalfrontier.domain-pair-review.v1"
            and review["left_domain_id"] == left_id
            and review["right_domain_id"] == right_id
            and review["left_semantics_sha256"] == semantics_digests[left_id]
            and review["right_semantics_sha256"] == semantics_digests[right_id]
            and review["semantic_independence_verified"] is False
            and review["review_state"] == "PAIR_DIFFERENCE_DECLARATION_BOUND_EXTERNAL_REVIEW_NOT_EXECUTED"
        ):
            raise CausalFrontierError("domain pair review differs or overclaims semantic independence")
    if observed_domain_pairs != domain_pairs:
        raise CausalFrontierError("domain pair reviews must use canonical exhaustive pair order")

    calibration = goal_plan["calibration"]
    expected_control_oracle_commitment = sha256_bytes(canonical_bytes(control_opening_commitments))
    if not (
        calibration["control_oracle_commitment_sha256"] == expected_control_oracle_commitment
        and calibration["control_scoring_protocol_sha256"] == protocol_digests["control_scoring_protocol_artifact_id"]
        and calibration["control_scoring_implementation_sha256"]
        == protocol_digests["control_scoring_implementation_artifact_id"]
        and calibration["semantic_validity_review_protocol_sha256"]
        == protocol_digests["semantic_review_protocol_artifact_id"]
    ):
        raise CausalFrontierError("goal calibration commitments are not preimages of the sentinel control artifacts")

    if used_org_ids != set(organizations):
        raise CausalFrontierError("sentinel bundle contains an unused organization declaration")
    cross_role_group_collision_pairs = 0
    for contexts in organization_contexts.values():
        cross_role_group_collision_pairs += len(contexts) * (len(contexts) - 1) // 2
    for left_id, right_id in combinations(sorted(used_org_ids), 2):
        left_org = organizations[left_id]
        right_org = organizations[right_id]
        left_group_ids = {
            left_org["controller_group_id"].casefold(),
            left_org["store_group_id"].casefold(),
        }
        right_group_ids = {
            right_org["controller_group_id"].casefold(),
            right_org["store_group_id"].casefold(),
        }
        if not left_group_ids & right_group_ids:
            continue
        generator_only_pair = bool(
            organization_contexts[left_id] == {"GENERATOR"} and organization_contexts[right_id] == {"GENERATOR"}
        )
        if not generator_only_pair:
            cross_role_group_collision_pairs += 1

    if used != set(by_id):
        raise CausalFrontierError("sentinel bundle contains orphan or unreferenced artifacts")
    semantic_counts = Counter(semantics_core_digests.values())
    domain_collision_pairs = sum(count * (count - 1) // 2 for count in semantic_counts.values())
    case_counts = Counter(decision_core_digests)
    case_collision_pairs = sum(count * (count - 1) // 2 for count in case_counts.values())
    rejection_reasons = []
    if late_cases:
        rejection_reasons.append("DECLARED_SOURCE_AFTER_CASE_CUTOFF")
    if late_generator_inventories:
        rejection_reasons.append("DECLARED_GENERATOR_KNOWLEDGE_AFTER_CASE_CUTOFF")
    if generator_component_collision_pairs:
        rejection_reasons.append("EXACT_GENERATOR_COMPONENT_IDENTITY_OR_CONTENT_COLLISION")
    if role_collision_pairs:
        rejection_reasons.append("DECLARED_GENERATOR_MECHANISM_GOVERNANCE_ANCESTRY_OR_GROUP_COLLISION")
    if cross_role_group_collision_pairs:
        rejection_reasons.append("DECLARED_CROSS_ROLE_CONTROLLER_OR_STORE_COLLISION")
    if domain_collision_pairs:
        rejection_reasons.append("NORMALIZED_DOMAIN_SEMANTICS_COLLISION")
    if case_collision_pairs:
        rejection_reasons.append("NORMALIZED_CASE_DECISION_CORE_COLLISION")

    second_manifest, second_value, second_by_id, second_snapshots = _snapshot_bundle(root, expected_manifest_sha256)
    if not (
        raw_manifest == second_manifest
        and canonical_bytes(manifest) == canonical_bytes(second_value)
        and canonical_bytes(by_id) == canonical_bytes(second_by_id)
        and snapshots == second_snapshots
    ):
        raise CausalFrontierError("sentinel bundle changed during preflight")
    second_generation = preflight_sentinel_generation_plan(generation_plan_path, expected_generation_plan_sha256)
    second_goal_raw, second_goal_value = claim._read_checkpointed_plan(
        goal_claim_plan_path, expected_goal_claim_plan_sha256
    )
    if not (
        canonical_bytes(generation_plan) == canonical_bytes(second_generation)
        and goal_raw == second_goal_raw
        and canonical_bytes(goal_plan) == canonical_bytes(claim.validate_goal_claim_plan(second_goal_value))
        and goal_preflight == claim.preflight_goal_claim_plan(goal_claim_plan_path, expected_goal_claim_plan_sha256)
    ):
        raise CausalFrontierError("a predecessor plan changed during sentinel preflight")

    gates = _expected_report_gates(
        generator_component_collision_pairs=generator_component_collision_pairs,
        generator_role_collision_pairs=role_collision_pairs,
        cross_role_group_collision_pairs=cross_role_group_collision_pairs,
        domain_collision_pairs=domain_collision_pairs,
        case_collision_pairs=case_collision_pairs,
        late_cases=late_cases,
        late_generator_inventories=late_generator_inventories,
    )
    core = {
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "status": PREFLIGHT_STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "audience": AUDIENCE,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scope": SCOPE,
        "goal_claim_contract_sha256": claim.goal_claim_contract_sha256(),
        "goal_claim_plan_checkpoint_sha256": expected_goal_claim_plan_sha256,
        "goal_claim_plan_sha256": goal_plan["plan_sha256"],
        "generation_plan_checkpoint_sha256": expected_generation_plan_sha256,
        "generation_plan_sha256": generation_plan["plan_sha256"],
        "manifest_checkpoint_sha256": expected_manifest_sha256,
        "manifest_canonical_sha256": sha256_bytes(canonical_bytes(manifest)),
        "manifest_sequence": expected_sequence,
        "bundle_inventory_sha256": bundle_inventory_sha256,
        "declared_domains_n": len(domains),
        "declared_generator_families_n": len(generators),
        "primary_cases_n": primary_cases_n,
        "calibration_cases_n": calibration_cases_n,
        "declared_laboratories_n": len(laboratories),
        "artifact_files_n": len(by_id),
        "generator_pair_audits_n": len(generator_pairs),
        "domain_pair_reviews_n": len(domain_pairs),
        "generator_component_identity_or_content_collision_pairs_n": generator_component_collision_pairs,
        "declared_generator_role_collision_pairs_n": role_collision_pairs,
        "declared_cross_role_group_collision_pairs_n": cross_role_group_collision_pairs,
        "normalized_domain_semantics_collision_pairs_n": domain_collision_pairs,
        "normalized_case_decision_core_collision_pairs_n": case_collision_pairs,
        "declared_post_cutoff_cases_n": late_cases,
        "declared_post_cutoff_generator_inventories_n": late_generator_inventories,
        "artifact_closure_verified": True,
        "goal_plan_cohort_preimage_verified": True,
        "generation_plan_replayed": True,
        "case_geometry_replayed": True,
        "latin_square_verified": True,
        "primary_generator_laboratory_assignment_balance_verified": True,
        "declared_case_provenance_graph_structure_verified": True,
        "declared_branch_totality_verified": True,
        "oracle_commitments_unique_verified": True,
        "generator_seed_and_case_oracle_commitments_disjoint_verified": True,
        "generator_seed_or_case_oracle_enumerated_bundle_digest_alias_absent_verified": True,
        "declared_cutoff_consistency_verified": late_cases == 0 and late_generator_inventories == 0,
        "generator_pair_audit_packets_bound": True,
        "domain_review_packets_bound": True,
        "control_role_packets_bound": True,
        "admission_state": (
            "REJECTED_STRUCTURAL_ADMISSION_GATES_NOT_ADMITTED"
            if rejection_reasons
            else "REVIEW_PACKET_COMPLETE_NOT_ADMITTED"
        ),
        "rejection_reasons": rejection_reasons,
        **dict.fromkeys(FIXED_FALSE_FIELDS, False),
        "gates": gates,
        "nonclaims": list(NONCLAIMS),
    }
    report = dict(core)
    report["preflight_sha256"] = sha256_bytes(PREFLIGHT_DOMAIN_TAG + canonical_bytes(core))
    return _report_shape(report)


def preflight_sentinel_admission(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    goal_claim_plan_path: Path,
    expected_goal_claim_plan_sha256: str,
) -> dict[str, Any]:
    """Close legacy sentinel-v1 artifacts without admission or scoring."""

    return _preflight_sentinel_admission_core(
        root,
        expected_manifest_sha256,
        expected_sequence,
        generation_plan_path,
        expected_generation_plan_sha256,
        goal_claim_plan_path,
        expected_goal_claim_plan_sha256,
        None,
    )


def _preflight_sentinel_phase_bound_admission(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    goal_claim_plan_path: Path,
    expected_goal_claim_plan_sha256: str,
    expected_generation_phase_context: dict[str, Any],
    additional_supplied_preimage_digests: frozenset[str],
) -> dict[str, Any]:
    """Internal successor path; callers must derive context from raw witness replay."""

    context = _validate_generation_phase_context(expected_generation_phase_context)
    return _preflight_sentinel_admission_core(
        root,
        expected_manifest_sha256,
        expected_sequence,
        generation_plan_path,
        expected_generation_plan_sha256,
        goal_claim_plan_path,
        expected_goal_claim_plan_sha256,
        context,
        additional_supplied_preimage_digests,
    )


def verify_sentinel_admission_preflight(
    value: Any,
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    generation_plan_path: Path,
    expected_generation_plan_sha256: str,
    goal_claim_plan_path: Path,
    expected_goal_claim_plan_sha256: str,
) -> dict[str, Any]:
    """Deterministically rebuild a report and reject coherent projection forgery."""

    report = _report_shape(value)
    expected = preflight_sentinel_admission(
        root,
        expected_manifest_sha256,
        expected_sequence,
        generation_plan_path,
        expected_generation_plan_sha256,
        goal_claim_plan_path,
        expected_goal_claim_plan_sha256,
    )
    if canonical_bytes(report) != canonical_bytes(expected):
        raise CausalFrontierError("sentinel admission report differs from exact deterministic replay")
    return report
