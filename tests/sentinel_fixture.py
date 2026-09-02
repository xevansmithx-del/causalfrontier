"""Deterministic artifact-closed sentinel fixtures for hostile tests and probes."""

from __future__ import annotations

from itertools import combinations
from pathlib import Path
from typing import Any

from test_claim import _plan as goal_plan_fixture
from test_claim import _reseal as reseal_goal_plan

from causalfrontier import claim, sentinel
from causalfrontier.canonical import canonical_bytes, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


class _Artifacts:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.items: dict[str, dict[str, Any]] = {}
        self.raw: dict[str, bytes] = {}

    @staticmethod
    def _filename(artifact_id: str, extension: str) -> str:
        stem = artifact_id.replace(":", "_").replace(".", "_")
        return "artifacts/%s.%s" % (stem, extension)

    def add_raw(
        self,
        artifact_id: str,
        role: str,
        raw: bytes,
        *,
        media_type: str = "text/plain",
        data_class: str = "OPEN_SOURCE_TEXT",
    ) -> dict[str, Any]:
        if artifact_id in self.items:
            raise AssertionError("duplicate fixture artifact")
        extension = "json" if media_type == "application/json" else "txt"
        relative = self._filename(artifact_id, extension)
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        descriptor = {
            "artifact_id": artifact_id,
            "path": relative,
            "sha256": sha256_bytes(raw),
            "role": role,
            "media_type": media_type,
            "data_class": data_class,
        }
        self.items[artifact_id] = descriptor
        self.raw[artifact_id] = raw
        return descriptor

    def add_json(
        self,
        artifact_id: str,
        role: str,
        value: dict[str, Any],
        *,
        data_class: str = "OPEN_SOURCE_TEXT",
    ) -> dict[str, Any]:
        return self.add_raw(
            artifact_id,
            role,
            canonical_bytes(value) + b"\n",
            media_type="application/json",
            data_class=data_class,
        )

    def descriptor(self, artifact_id: str) -> dict[str, Any]:
        return self.items[artifact_id]

    def descriptors(self) -> list[dict[str, Any]]:
        return [self.items[key] for key in sorted(self.items)]


def _organization(
    organization_id: str,
    roles: list[str],
    controller_group_id: str,
    store_group_id: str,
) -> dict[str, Any]:
    return {
        "organization_id": organization_id,
        "roles": sorted(roles),
        "controller_group_id": controller_group_id,
        "store_group_id": store_group_id,
    }


def _organizations(
    *,
    generator_role_collision: bool,
    generator_group_casefold_collision: bool,
    generator_cross_dimension_group_collision: bool,
    cross_role_group_collision: bool,
    cross_role_group_casefold_collision: bool,
    cross_role_cross_dimension_group_collision: bool,
    unused_organization: bool,
    outcome_role_collision: bool,
) -> list[dict[str, Any]]:
    items = [
        _organization("organization:steward", ["STEWARD"], "controller:steward", "store:steward"),
        _organization(
            "organization:generator-auditor:1",
            ["GENERATOR_AUDITOR"],
            "controller:generator-auditor:1",
            "store:generator-auditor:1",
        ),
        _organization(
            "organization:generator-auditor:2",
            ["GENERATOR_AUDITOR"],
            "controller:generator-auditor:2",
            "store:generator-auditor:2",
        ),
        _organization(
            "organization:domain-reviewer:1",
            ["DOMAIN_REVIEWER"],
            "controller:domain-reviewer:1",
            "store:domain-reviewer:1",
        ),
        _organization(
            "organization:domain-reviewer:2",
            ["DOMAIN_REVIEWER"],
            "controller:domain-reviewer:2",
            "store:domain-reviewer:2",
        ),
        _organization(
            "organization:control-reviewer:1",
            ["CONTROL_REVIEWER"],
            "controller:control-reviewer:1",
            "store:control-reviewer:1",
        ),
        _organization(
            "organization:control-reviewer:2",
            ["CONTROL_REVIEWER"],
            "controller:control-reviewer:2",
            "store:control-reviewer:2",
        ),
    ]
    for generator_index in range(1, 4):
        controller_group = "controller:generator:%d" % generator_index
        if generator_role_collision and generator_index == 2:
            controller_group = "controller:generator:1"
        if generator_group_casefold_collision and generator_index == 2:
            controller_group = "CONTROLLER:GENERATOR:1"
        if generator_cross_dimension_group_collision and generator_index == 2:
            controller_group = "store:generator-author:1"
        items.extend(
            [
                _organization(
                    "organization:generator-author:%d" % generator_index,
                    ["GENERATOR_AUTHOR"],
                    controller_group,
                    "store:generator-author:%d" % generator_index,
                ),
                _organization(
                    "organization:generator-controller:%d" % generator_index,
                    ["GENERATOR_CONTROLLER"],
                    controller_group,
                    "store:generator-controller:%d" % generator_index,
                ),
            ]
        )
    for domain_index in range(1, 4):
        domain_organizations = [
            _organization(
                "laboratory:%d:1" % domain_index,
                ["LABORATORY"],
                "controller:laboratory:%d:1" % domain_index,
                "store:laboratory:%d:1" % domain_index,
            ),
            _organization(
                "laboratory:%d:2" % domain_index,
                ["LABORATORY"],
                "controller:laboratory:%d:2" % domain_index,
                "store:laboratory:%d:2" % domain_index,
            ),
        ]
        if outcome_role_collision:
            domain_organizations.append(
                _organization(
                    "organization:outcome-custodian:%d" % domain_index,
                    ["OUTCOME_PROVIDER", "ADJUDICATOR"],
                    "controller:outcome-custodian:%d" % domain_index,
                    "store:outcome-custodian:%d" % domain_index,
                )
            )
        else:
            domain_organizations.extend(
                [
                    _organization(
                        "organization:outcome-provider:%d" % domain_index,
                        ["OUTCOME_PROVIDER"],
                        "controller:outcome-provider:%d" % domain_index,
                        "store:outcome-provider:%d" % domain_index,
                    ),
                    _organization(
                        "organization:adjudicator:%d" % domain_index,
                        ["ADJUDICATOR"],
                        "controller:adjudicator:%d" % domain_index,
                        "store:adjudicator:%d" % domain_index,
                    ),
                ]
            )
        items.extend(domain_organizations)
    if cross_role_group_collision:
        auditor = next(item for item in items if item["organization_id"] == "organization:generator-auditor:1")
        auditor["controller_group_id"] = "controller:generator:1"
        auditor["store_group_id"] = "store:generator-author:1"
    if cross_role_group_casefold_collision:
        auditor = next(item for item in items if item["organization_id"] == "organization:generator-auditor:1")
        auditor["controller_group_id"] = "CONTROLLER:GENERATOR:1"
        auditor["store_group_id"] = "STORE:GENERATOR-AUTHOR:1"
    if cross_role_cross_dimension_group_collision:
        auditor = next(item for item in items if item["organization_id"] == "organization:generator-auditor:1")
        auditor["controller_group_id"] = "store:generator-author:1"
    if unused_organization:
        items.append(
            _organization(
                "organization:unused-reviewer",
                ["DOMAIN_REVIEWER"],
                "controller:unused-reviewer",
                "store:unused-reviewer",
            )
        )
    return sorted(items, key=lambda item: item["organization_id"])


def _role_packet(
    case: dict[str, Any],
    domain_index: int,
    branch_contract_sha256: str,
    oracle_commitment_sha256: str,
    *,
    required_behavior_observation_mismatch: bool,
) -> dict[str, Any]:
    common = {
        "schema_version": "causalfrontier.case-role-packet.v1",
        "case_id": case["case_id"],
        "case_role": case["case_role"],
        "selection_origin": case["selection_origin"],
        "declared_branch_contract_sha256": branch_contract_sha256,
    }
    if case["case_role"] == "PRIMARY":
        return {
            **common,
            "outcome_unresolved_at_lock_declared": True,
            "laboratory_id": case["laboratory_id"],
            "outcome_provider_organization_id": case["outcome_provider_organization_id"],
            "observation_protocol": "Observe the predeclared terminal interface without material execution.",
            "replication_rule": "Require the frozen replication state before adjudication.",
            "stopping_rule": "Stop only at a predeclared terminal state or common horizon.",
            "terminal_adjudication_mapping": "Map the terminal observation to the frozen decision classes.",
            "next_falsification_observation_state_ids": ["observation:support"],
            "no_call_observation_state_ids": ["observation:unresolved"],
            "reveal_external_commitment_sha256": oracle_commitment_sha256,
            "external_registration_receipt_present": False,
        }
    if case["case_role"] == "POSITIVE":
        return {
            **common,
            "method_recovery_criterion": "Recover the predeclared historical method-level transition.",
            "decision_transition_rule": "The locked decision class changes only under the recovery criterion.",
            "replication_rule": "The recovery must persist under the frozen replication rule.",
            "required_behavior_observation_state_ids": ["observation:support"],
            "sealed_opening_external_commitment_sha256": oracle_commitment_sha256,
            "independent_adjudication_state": "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED",
        }
    if case["case_role"] == "FAILED_TRANSLATION":
        return {
            **common,
            "precutoff_translated_expectation": "The pre-cutoff surrogate supports the translated expectation.",
            "terminal_failure_definition": "The downstream terminal criterion fails despite the surrogate.",
            "rejection_stop_criterion": "Reject translation after the predeclared replicated terminal failure.",
            "operational_failure_exclusion_rule": "Operational acquisition failure is not translation failure.",
            "required_behavior_observation_state_ids": [
                "observation:support" if required_behavior_observation_mismatch else "observation:refute"
            ],
            "sealed_opening_external_commitment_sha256": oracle_commitment_sha256,
            "independent_adjudication_state": "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED",
        }
    return {
        **common,
        "ambiguity_set": "Two live decision classes remain observationally compatible at the boundary.",
        "competing_interpretations": ["interpretation:a", "interpretation:b"],
        "correct_abstention_rule": "Return NO_CALL while both frozen interpretations remain live.",
        "minimum_information_boundary": (
            "At least two explicit live classes and one resolving observation are required."
        ),
        "required_behavior_observation_state_ids": ["observation:unresolved"],
        "sealed_opening_external_commitment_sha256": oracle_commitment_sha256,
        "independent_adjudication_state": "NOT_EXECUTED_EXTERNAL_REVIEW_REQUIRED",
    }


def _domain_semantics(
    domain_id: str,
    domain_index: int,
    *,
    collision: bool,
    false_axis_declaration: bool,
) -> dict[str, Any]:
    semantic_index = 1 if collision and domain_index == 2 else domain_index
    return {
        "schema_version": "causalfrontier.domain-semantics.v1",
        "domain_id": domain_id,
        "ontology_namespace": "synthetic-domain-ontology",
        "ontology_identifier": "SDO:%04d" % semantic_index,
        "decision_unit": (
            "decision unit 1" if false_axis_declaration and domain_index == 2 else "decision unit %d" % semantic_index
        ),
        "evidence_modalities": ["aggregate modality %d" % semantic_index],
        "permissible_action_class": "read-only action class %d" % semantic_index,
        "terminal_observation_interface": "terminal observation interface %d" % semantic_index,
        "decision_loss_semantics": "decision loss semantics %d" % semantic_index,
        "resource_basis": "resource basis %d" % semantic_index,
        "common_horizon": "common horizon %d" % semantic_index,
        "inclusion_criteria": "public or synthetic aggregate cases in domain %d" % semantic_index,
        "exclusion_criteria": "patient-level or outcome-open cases in domain %d" % semantic_index,
        "semantic_validity_review_state": "EXTERNAL_REVIEW_REQUIRED_NOT_VERIFIED",
    }


def build_sentinel_fixture(
    base: Path,
    *,
    generator_source_collision: bool = False,
    generator_role_collision: bool = False,
    generator_group_casefold_collision: bool = False,
    generator_cross_dimension_group_collision: bool = False,
    generator_mechanism_casefold_collision: bool = False,
    generator_ancestry_collision: bool = False,
    cross_role_group_collision: bool = False,
    cross_role_group_casefold_collision: bool = False,
    cross_role_cross_dimension_group_collision: bool = False,
    domain_semantics_collision: bool = False,
    case_core_collision: bool = False,
    late_source: bool = False,
    late_generator_inventory: bool = False,
    oracle_commitment_collision: bool = False,
    seed_oracle_commitment_collision: bool = False,
    oracle_artifact_digest_collision: bool = False,
    seed_artifact_digest_collision: bool = False,
    seed_bundle_inventory_digest_collision: bool = False,
    seed_outer_registry_digest_collision: bool = False,
    false_domain_axis_declaration: bool = False,
    unused_organization: bool = False,
    public_metadata_source: bool = False,
    outcome_role_collision: bool = False,
    shared_generator_source_identity: bool = False,
    shared_generator_source_content_with_distinct_identity: bool = False,
    shared_generator_component_content_with_distinct_identity: bool = False,
    branch_role_mismatch: bool = False,
    branch_role_observation_mismatch: bool = False,
    primary_branch_all_no_call: bool = False,
    availability_evidence_mismatch: bool = False,
    empty_protocol_artifact: bool = False,
    wrong_case_artifact_media_type: bool = False,
    generation_phase_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bundle_root = base / "sentinel-bundle"
    bundle_root.mkdir(parents=True)
    artifacts = _Artifacts(bundle_root)

    protocols = {}
    protocol_precommitments = {}
    for protocol_index, (field, role) in enumerate(sentinel.PROTOCOL_FIELDS.items()):
        artifact_id = "artifact:protocol:%s" % field.removesuffix("_artifact_id").replace("_", "-")
        descriptor = artifacts.add_raw(
            artifact_id,
            role,
            b""
            if empty_protocol_artifact and protocol_index == 0
            else ("%s exact open protocol bytes\n" % role).encode("utf-8"),
        )
        protocols[field] = artifact_id
        protocol_precommitments[field] = descriptor["sha256"]

    organizations = _organizations(
        generator_role_collision=generator_role_collision,
        generator_group_casefold_collision=generator_group_casefold_collision,
        generator_cross_dimension_group_collision=generator_cross_dimension_group_collision,
        cross_role_group_collision=cross_role_group_collision,
        cross_role_group_casefold_collision=cross_role_group_casefold_collision,
        cross_role_cross_dimension_group_collision=cross_role_cross_dimension_group_collision,
        unused_organization=unused_organization,
        outcome_role_collision=outcome_role_collision,
    )
    organization_map = {item["organization_id"]: item for item in organizations}
    generators = []
    generator_precommitments = []
    generator_signatures: dict[str, tuple[str, str]] = {}
    generator_source_file_ids: dict[str, str] = {}
    generator_source_artifact_ids: dict[str, set[str]] = {}
    generator_source_content_digests: dict[str, set[str]] = {}
    for generator_index in range(1, 4):
        family_id = "generator:%d" % generator_index
        source_label = 1 if generator_source_collision and generator_index == 2 else generator_index
        source_id = "artifact:generator:%d:source:main" % generator_index
        source = artifacts.add_raw(
            source_id,
            "GENERATOR_SOURCE_FILE",
            ("def generate():\n    return 'family-%d'\n" % source_label).encode("utf-8"),
            media_type="text/x-python",
        )
        generator_source_file_ids[family_id] = source_id
        source_manifest_id = "artifact:generator:%d:source-manifest" % generator_index
        source_files = [{"logical_path": "main.py", "artifact_id": source_id, "sha256": source["sha256"]}]
        if shared_generator_source_identity and generator_index == 2:
            shared_source_id = generator_source_file_ids["generator:1"]
            source_files.append(
                {
                    "logical_path": "shared.py",
                    "artifact_id": shared_source_id,
                    "sha256": artifacts.descriptor(shared_source_id)["sha256"],
                }
            )
        if shared_generator_source_content_with_distinct_identity and generator_index == 2:
            copied_source_id = "artifact:generator:2:source:shared-copy"
            copied_source = artifacts.add_raw(
                copied_source_id,
                "GENERATOR_SOURCE_FILE",
                b"def generate():\n    return 'family-1'\n",
                media_type="text/x-python",
            )
            source_files.append(
                {
                    "logical_path": "shared-copy.py",
                    "artifact_id": copied_source_id,
                    "sha256": copied_source["sha256"],
                }
            )
        artifacts.add_json(
            source_manifest_id,
            "GENERATOR_SOURCE_MANIFEST",
            {
                "schema_version": "causalfrontier.generator-source-manifest.v1",
                "generator_family_id": family_id,
                "files": source_files,
            },
        )
        content_signature = sha256_bytes(canonical_bytes(sorted(item["sha256"] for item in source_files)))
        path_signature = sha256_bytes(
            canonical_bytes([{"logical_path": item["logical_path"], "sha256": item["sha256"]} for item in source_files])
        )
        generator_signatures[family_id] = (content_signature, path_signature)
        generator_source_artifact_ids[family_id] = {item["artifact_id"] for item in source_files}
        generator_source_content_digests[family_id] = {item["sha256"] for item in source_files}
        field_artifacts = {"source_manifest_artifact_id": source_manifest_id}
        for field, role in sentinel.GENERATOR_ARTIFACT_FIELDS.items():
            if field == "source_manifest_artifact_id":
                continue
            artifact_id = "artifact:generator:%d:%s" % (
                generator_index,
                field.removesuffix("_artifact_id").replace("_", "-"),
            )
            if field == "ancestry_artifact_id":
                related_family_ids = []
                if generator_ancestry_collision and generator_index in {1, 2}:
                    related_family_ids = ["generator:%d" % (3 - generator_index)]
                artifacts.add_json(
                    artifact_id,
                    role,
                    {
                        "schema_version": "causalfrontier.generator-ancestry.v1",
                        "generator_family_id": family_id,
                        "declared_shared_source_ancestry_family_ids": related_family_ids,
                        "declared_shared_template_family_ids": [],
                        "declared_shared_prompt_family_ids": [],
                        "declared_shared_hidden_selection_family_ids": [],
                        "external_truth_verified": False,
                    },
                )
            elif field == "tool_model_inventory_artifact_id":
                artifacts.add_json(
                    artifact_id,
                    role,
                    {
                        "schema_version": "causalfrontier.generator-tool-model-inventory.v1",
                        "generator_family_id": family_id,
                        "tool_model_ids": ["tool-model:synthetic:%d" % generator_index],
                        "declared_maximum_knowledge_timestamp": (
                            "2026-12-01T00:00:00Z"
                            if late_generator_inventory and generator_index == 1
                            else "2025-11-01T00:00:00Z"
                        ),
                        "network_access_during_generation_allowed": False,
                        "post_cutoff_retrieval_allowed": False,
                        "independent_temporal_attestation_verified": False,
                    },
                )
            else:
                component_label = (
                    1
                    if shared_generator_component_content_with_distinct_identity
                    and generator_index == 2
                    and field == "execution_protocol_artifact_id"
                    else generator_index
                )
                artifacts.add_raw(
                    artifact_id,
                    role,
                    ("%s family %d exact bytes\n" % (role, component_label)).encode("utf-8"),
                )
            field_artifacts[field] = artifact_id
        generator = {
            "generator_family_id": family_id,
            "mechanism_family_id": (
                "MECHANISM:1"
                if generator_mechanism_casefold_collision and generator_index == 2
                else "mechanism:%d" % generator_index
            ),
            "governance_family_id": "governance:%d" % generator_index,
            "author_organization_id": "organization:generator-author:%d" % generator_index,
            "controller_organization_id": "organization:generator-controller:%d" % generator_index,
            **field_artifacts,
        }
        generators.append(generator)
        precommitment = {
            "generator_family_id": family_id,
            "mechanism_family_id": generator["mechanism_family_id"],
            "governance_family_id": generator["governance_family_id"],
            "author_organization_id": generator["author_organization_id"],
            "controller_organization_id": generator["controller_organization_id"],
            "source_content_multiset_sha256": content_signature,
            "source_path_sensitive_sha256": path_signature,
            "seed_external_commitment_sha256": _digest("generator-seed:%d" % generator_index),
        }
        for digest_field, artifact_field in sentinel.GENERATOR_PRECOMMITMENT_DIGEST_FIELDS.items():
            precommitment[digest_field] = artifacts.descriptor(generator[artifact_field])["sha256"]
        generator_precommitments.append(precommitment)

    if seed_artifact_digest_collision:
        generator_precommitments[0]["seed_external_commitment_sha256"] = artifacts.descriptor(
            generator_source_file_ids["generator:1"]
        )["sha256"]

    generator_pair_audits = []
    for left_id, right_id in combinations(["generator:1", "generator:2", "generator:3"], 2):
        left = generators[int(left_id[-1]) - 1]
        right = generators[int(right_id[-1]) - 1]
        left_groups = {
            organization_map[left["author_organization_id"]]["controller_group_id"].casefold(),
            organization_map[left["controller_organization_id"]]["controller_group_id"].casefold(),
        }
        right_groups = {
            organization_map[right["author_organization_id"]]["controller_group_id"].casefold(),
            organization_map[right["controller_organization_id"]]["controller_group_id"].casefold(),
        }
        left_stores = {
            organization_map[left["author_organization_id"]]["store_group_id"].casefold(),
            organization_map[left["controller_organization_id"]]["store_group_id"].casefold(),
        }
        right_stores = {
            organization_map[right["author_organization_id"]]["store_group_id"].casefold(),
            organization_map[right["controller_organization_id"]]["store_group_id"].casefold(),
        }
        left_component_ids = {
            left[field] for field in sentinel.GENERATOR_ARTIFACT_FIELDS
        } | generator_source_artifact_ids[left_id]
        right_component_ids = {
            right[field] for field in sentinel.GENERATOR_ARTIFACT_FIELDS
        } | generator_source_artifact_ids[right_id]
        left_component_digests = {artifacts.descriptor(artifact_id)["sha256"] for artifact_id in left_component_ids}
        right_component_digests = {artifacts.descriptor(artifact_id)["sha256"] for artifact_id in right_component_ids}
        audit_id = "artifact:generator-audit:%s:%s" % (left_id[-1], right_id[-1])
        artifacts.add_json(
            audit_id,
            "GENERATOR_PAIR_AUDIT",
            {
                "schema_version": "causalfrontier.generator-pair-audit.v1",
                "left_generator_family_id": left_id,
                "right_generator_family_id": right_id,
                "reviewer_organization_ids": [
                    "organization:generator-auditor:1",
                    "organization:generator-auditor:2",
                ],
                "generator_audit_protocol_sha256": protocol_precommitments["generator_audit_protocol_artifact_id"],
                "left_source_content_multiset_sha256": generator_signatures[left_id][0],
                "right_source_content_multiset_sha256": generator_signatures[right_id][0],
                "exact_source_content_collision": generator_signatures[left_id][0] == generator_signatures[right_id][0],
                "shared_source_artifact_id_collision": bool(
                    generator_source_artifact_ids[left_id] & generator_source_artifact_ids[right_id]
                ),
                "shared_source_content_sha256_collision": bool(
                    generator_source_content_digests[left_id] & generator_source_content_digests[right_id]
                ),
                "shared_generator_component_artifact_id_collision": bool(left_component_ids & right_component_ids),
                "shared_generator_component_content_sha256_collision": bool(
                    left_component_digests & right_component_digests
                ),
                "declared_mechanism_family_collision": left["mechanism_family_id"].casefold()
                == right["mechanism_family_id"].casefold(),
                "declared_governance_family_collision": left["governance_family_id"].casefold()
                == right["governance_family_id"].casefold(),
                "declared_ancestry_collision": (
                    generator_ancestry_collision and (left_id, right_id) == ("generator:1", "generator:2")
                ),
                "declared_controller_group_collision": bool(left_groups & right_groups),
                "declared_store_group_collision": bool(left_stores & right_stores),
                "declared_cross_dimension_group_collision": bool(
                    left_groups & right_stores or left_stores & right_groups
                ),
                "semantic_independence_verified": False,
                "governance_independence_verified": False,
                "audit_state": "EXACT_BYTE_COMPARISON_BOUND_EXTERNAL_INDEPENDENCE_UNVERIFIED",
            },
        )
        generator_pair_audits.append(
            {
                "left_generator_family_id": left_id,
                "right_generator_family_id": right_id,
                "audit_artifact_id": audit_id,
            }
        )

    goal_template = goal_plan_fixture()
    generation_domain_contracts = []
    case_assignments = []
    domains = []
    domain_registry_digests: dict[str, str] = {}
    semantics_descriptors: dict[str, dict[str, Any]] = {}
    duplicate_core: dict[str, Any] | None = None
    first_oracle_commitment: str | None = None
    control_opening_commitments: list[dict[str, str]] = []
    for domain_index, goal_domain in enumerate(goal_template["domains"], start=1):
        domain_id = goal_domain["domain_id"]
        semantic_value = _domain_semantics(
            domain_id,
            domain_index,
            collision=domain_semantics_collision,
            false_axis_declaration=false_domain_axis_declaration,
        )
        semantics_id = "artifact:domain:%d:semantics" % domain_index
        semantics_descriptor = artifacts.add_json(semantics_id, "DOMAIN_SEMANTICS", semantic_value)
        semantics_descriptors[domain_id] = semantics_descriptor
        generation_domain_contracts.append(
            {
                "domain_id": domain_id,
                "knowledge_cutoff": goal_domain["knowledge_cutoff"],
                "domain_semantics_sha256": semantics_descriptor["sha256"],
                "laboratory_ids": goal_domain["laboratory_ids"],
                "primary_case_ids": goal_domain["primary_case_ids"],
                "calibration_cases": goal_domain["calibration_cases"],
            }
        )
        domain_review_id = "artifact:domain:%d:review" % domain_index
        artifacts.add_json(
            domain_review_id,
            "DOMAIN_REVIEW",
            {
                "schema_version": "causalfrontier.domain-review.v1",
                "domain_id": domain_id,
                "semantics_sha256": semantics_descriptor["sha256"],
                "reviewer_organization_ids": [
                    "organization:domain-reviewer:1",
                    "organization:domain-reviewer:2",
                ],
                "review_protocol_state": "PACKET_BOUND_REVIEW_NOT_EXECUTED",
                "critical_disagreement_rule": "ANY_DECISION_CRITICAL_DISAGREEMENT_YIELDS_NO_CALL",
                "domain_semantic_validity_verified": False,
            },
        )

        raw_assignments = []
        for case_index, case_id in enumerate(goal_domain["primary_case_ids"]):
            raw_assignments.append(
                {
                    "case_id": case_id,
                    "domain_id": domain_id,
                    "case_role": "PRIMARY",
                    "control_role": None,
                    "required_behavior": None,
                    "generator_family_id": "generator:%d" % ((case_index % 3) + 1),
                    "laboratory_id": goal_domain["laboratory_ids"][case_index % 2],
                    "outcome_provider_organization_id": (
                        "organization:outcome-custodian:%d" % domain_index
                        if outcome_role_collision
                        else "organization:outcome-provider:%d" % domain_index
                    ),
                    "selection_origin": sentinel.PRIMARY_ORIGIN,
                    "knowledge_cutoff": goal_domain["knowledge_cutoff"],
                }
            )
        for role_index, control in enumerate(goal_domain["calibration_cases"]):
            raw_assignments.append(
                {
                    "case_id": control["case_id"],
                    "domain_id": domain_id,
                    "case_role": control["control_role"],
                    "control_role": control["control_role"],
                    "required_behavior": sentinel.CONTROL_BEHAVIORS[control["control_role"]],
                    "generator_family_id": "generator:%d" % (((domain_index - 1 + role_index) % 3) + 1),
                    "laboratory_id": None,
                    "outcome_provider_organization_id": (
                        "organization:outcome-custodian:%d" % domain_index
                        if outcome_role_collision
                        else "organization:adjudicator:%d" % domain_index
                    ),
                    "selection_origin": sentinel.CONTROL_ORIGIN,
                    "knowledge_cutoff": goal_domain["knowledge_cutoff"],
                }
            )
        raw_assignments.sort(key=lambda item: item["case_id"])
        case_assignments.extend(raw_assignments)

        domain_cases = []
        registry_records = []
        control_packet_hashes = {}
        for local_index, assignment in enumerate(raw_assignments):
            case_id = assignment["case_id"]
            safe = case_id.replace(":", "-")
            outcome_provider_id = assignment["outcome_provider_organization_id"]
            source_id = "artifact:case:%s:source" % safe
            source_data_class = (
                "PUBLIC_METADATA" if public_metadata_source and domain_index == 1 and local_index == 0 else "SYNTHETIC"
            )
            source_descriptor = artifacts.add_raw(
                source_id,
                "SOURCE_EVIDENCE",
                ("synthetic source evidence for %s\n" % case_id).encode("utf-8"),
                data_class=source_data_class,
            )
            available_at = "2025-12-01T00:00:00Z"
            if late_source and domain_index == 1 and local_index == 0:
                available_at = "2026-12-01T00:00:00Z"
            availability_id = "artifact:case:%s:availability" % safe
            availability_descriptor = artifacts.add_json(
                availability_id,
                "AVAILABILITY_EVIDENCE",
                {
                    "schema_version": "causalfrontier.source-availability-declaration.v1",
                    "source_id": (
                        "source:deliberate-mismatch"
                        if availability_evidence_mismatch and domain_index == 1 and local_index == 0
                        else "source:%s" % safe
                    ),
                    "claimed_available_at": available_at,
                    "state": "DECLARED_ONLY_NOT_INDEPENDENTLY_ATTESTED",
                    "independent_temporal_attestation_verified": False,
                },
            )
            source_inventory_id = "artifact:case:%s:source-inventory" % safe
            source_inventory_descriptor = artifacts.add_json(
                source_inventory_id,
                "CASE_SOURCE_INVENTORY",
                {
                    "schema_version": "causalfrontier.case-source-inventory.v1",
                    "case_id": case_id,
                    "knowledge_cutoff": assignment["knowledge_cutoff"],
                    "sources": [
                        {
                            "source_id": "source:%s" % safe,
                            "evidence_artifact_id": source_id,
                            "evidence_sha256": source_descriptor["sha256"],
                            "availability_evidence_artifact_id": availability_id,
                            "availability_evidence_sha256": availability_descriptor["sha256"],
                            "claimed_available_at": available_at,
                            "data_class": source_data_class,
                            "semantic_state": "DECISION_CRITICAL_DECLARED_NOT_EXTERNALLY_ADJUDICATED",
                        }
                    ],
                },
            )
            payload_id = "artifact:case:%s:payload" % safe
            branch_contract = {
                "schema_version": "causalfrontier.declared-branch-contract.v1",
                "observation_state_ids": ["observation:refute", "observation:support", "observation:unresolved"],
                "mappings": [
                    {"observation_state_id": "observation:refute", "decision_state": "REJECT_TRANSLATION"},
                    {"observation_state_id": "observation:support", "decision_state": "NEXT_FALSIFICATION"},
                    {"observation_state_id": "observation:unresolved", "decision_state": "NO_CALL"},
                ],
                "unknown_observation_state": "NO_CALL",
                "complete_over_declared_states": True,
                "semantic_exhaustiveness_verified": False,
            }
            if branch_role_mismatch and domain_index == 1 and assignment["case_role"] == "FAILED_TRANSLATION":
                branch_contract["mappings"][0]["decision_state"] = "REPLICATE"
            if primary_branch_all_no_call and domain_index == 1 and assignment["case_role"] == "PRIMARY":
                for mapping in branch_contract["mappings"]:
                    mapping["decision_state"] = "NO_CALL"
            oracle_commitment_sha256 = _digest("oracle:%s" % case_id)
            if oracle_artifact_digest_collision and domain_index == 1 and local_index == 0:
                oracle_commitment_sha256 = source_descriptor["sha256"]
            if first_oracle_commitment is None:
                first_oracle_commitment = oracle_commitment_sha256
            elif oracle_commitment_collision and domain_index == 1 and local_index == 1:
                oracle_commitment_sha256 = first_oracle_commitment
            decision_core = {
                "question": "Which predeclared decision class is falsified for synthetic hypothesis %d-%d?"
                % (domain_index, local_index + 1),
                "evidence_interface": "Read the exact synthetic aggregate source packet.",
                "action_interface": "Choose a read-only falsification action from the frozen interface.",
                "falsification_contract": "Exclude at least one live decision class under replication.",
                "branch_contract": branch_contract,
                "terminal_oracle_external_commitment_sha256": oracle_commitment_sha256,
            }
            if duplicate_core is None:
                duplicate_core = dict(decision_core)
            elif case_core_collision and domain_index == 1 and local_index == 1:
                decision_core = dict(duplicate_core)
                decision_core["terminal_oracle_external_commitment_sha256"] = oracle_commitment_sha256
            payload_value = {
                "schema_version": (
                    sentinel.PHASE_BOUND_PAYLOAD_SCHEMA_VERSION
                    if generation_phase_context is not None
                    else "causalfrontier.sentinel-case-payload.v1"
                ),
                "case_id": case_id,
                "domain_id": domain_id,
                "decision_core": decision_core,
                "presentation": {"title": "Synthetic sentinel %s" % case_id},
            }
            if generation_phase_context is not None:
                payload_value["generation_phase_context"] = generation_phase_context
            payload_descriptor = artifacts.add_json(
                payload_id,
                "CASE_PAYLOAD",
                payload_value,
                data_class="SYNTHETIC",
            )
            if wrong_case_artifact_media_type and domain_index == 1 and local_index == 0:
                payload_descriptor["media_type"] = "text/x-python"
            case_stub = {
                **assignment,
                "outcome_provider_organization_id": outcome_provider_id,
            }
            role_packet_id = "artifact:case:%s:role-packet" % safe
            role_packet_descriptor = artifacts.add_json(
                role_packet_id,
                "CASE_ROLE_PACKET",
                _role_packet(
                    case_stub,
                    domain_index,
                    sha256_bytes(canonical_bytes(branch_contract)),
                    decision_core["terminal_oracle_external_commitment_sha256"],
                    required_behavior_observation_mismatch=(
                        branch_role_observation_mismatch
                        and domain_index == 1
                        and assignment["case_role"] == "FAILED_TRANSLATION"
                    ),
                ),
            )
            assignment["source_inventory_sha256"] = source_inventory_descriptor["sha256"]
            assignment["role_packet_sha256"] = role_packet_descriptor["sha256"]
            if assignment["case_role"] != "PRIMARY":
                control_packet_hashes[assignment["case_role"]] = role_packet_descriptor["sha256"]
                control_opening_commitments.append(
                    {
                        "case_id": case_id,
                        "control_role": assignment["case_role"],
                        "opening_commitment_sha256": decision_core["terminal_oracle_external_commitment_sha256"],
                    }
                )
            cutoff_id = "artifact:case:%s:cutoff-audit" % safe
            cutoff_descriptor = artifacts.add_json(
                cutoff_id,
                "CASE_CUTOFF_AUDIT",
                {
                    "schema_version": "causalfrontier.case-cutoff-audit.v1",
                    "case_id": case_id,
                    "knowledge_cutoff": assignment["knowledge_cutoff"],
                    "source_inventory_sha256": source_inventory_descriptor["sha256"],
                    "cutoff_audit_protocol_sha256": protocol_precommitments["cutoff_audit_protocol_artifact_id"],
                    "source_checks": [
                        {
                            "source_id": "source:%s" % safe,
                            "claimed_available_at": available_at,
                            "before_or_at_cutoff": available_at <= assignment["knowledge_cutoff"],
                            "availability_evidence_sha256": availability_descriptor["sha256"],
                        }
                    ],
                    "independent_temporal_attestation_verified": False,
                    "public_availability_verified": False,
                    "post_cutoff_access_verified_absent": False,
                },
            )
            provenance_id = "artifact:case:%s:provenance" % safe
            implementation_id = generator_source_file_ids[assignment["generator_family_id"]]
            payload_step_id = "step:%s:payload" % safe
            transformations = [
                {
                    "step_id": payload_step_id,
                    "implementation_artifact_id": implementation_id,
                    "input_artifact_ids": [source_id],
                    "output_artifact_id": payload_id,
                }
            ]
            provenance_value = {
                "schema_version": (
                    sentinel.PHASE_BOUND_PROVENANCE_SCHEMA_VERSION
                    if generation_phase_context is not None
                    else "causalfrontier.case-provenance.v1"
                ),
                "case_id": case_id,
                "generator_family_id": assignment["generator_family_id"],
                "source_inventory_sha256": source_inventory_descriptor["sha256"],
                "generator_source_content_sha256": generator_signatures[assignment["generator_family_id"]][0],
                "transformations": transformations,
                "final_artifact_ids": [payload_id],
                "provenance_truth_externally_verified": False,
            }
            if generation_phase_context is not None:
                provenance_value["generation_phase_context"] = generation_phase_context
            provenance_descriptor = artifacts.add_json(
                provenance_id,
                "CASE_PROVENANCE",
                provenance_value,
            )
            case = {
                "case_id": case_id,
                "case_role": assignment["case_role"],
                "control_role": assignment["control_role"],
                "required_behavior": assignment["required_behavior"],
                "generator_family_id": assignment["generator_family_id"],
                "laboratory_id": assignment["laboratory_id"],
                "outcome_provider_organization_id": outcome_provider_id,
                "selection_origin": assignment["selection_origin"],
                "knowledge_cutoff": assignment["knowledge_cutoff"],
                "case_payload_artifact_id": payload_id,
                "role_packet_artifact_id": role_packet_id,
                "source_inventory_artifact_id": source_inventory_id,
                "cutoff_audit_artifact_id": cutoff_id,
                "provenance_artifact_id": provenance_id,
            }
            domain_cases.append(case)
            registry_records.append(
                {
                    "case_id": case_id,
                    "case_role": assignment["case_role"],
                    "control_role": assignment["control_role"],
                    "required_behavior": assignment["required_behavior"],
                    "generator_family_id": assignment["generator_family_id"],
                    "laboratory_id": assignment["laboratory_id"],
                    "outcome_provider_organization_id": outcome_provider_id,
                    "selection_origin": assignment["selection_origin"],
                    "knowledge_cutoff": assignment["knowledge_cutoff"],
                    "case_payload_sha256": payload_descriptor["sha256"],
                    "role_packet_sha256": role_packet_descriptor["sha256"],
                    "source_inventory_sha256": source_inventory_descriptor["sha256"],
                    "cutoff_audit_sha256": cutoff_descriptor["sha256"],
                    "provenance_sha256": provenance_descriptor["sha256"],
                }
            )
        control_review_id = "artifact:domain:%d:control-review" % domain_index
        control_review_descriptor = artifacts.add_json(
            control_review_id,
            "CONTROL_METHODOLOGY_REVIEW",
            {
                "schema_version": "causalfrontier.control-methodology-review.v1",
                "domain_id": domain_id,
                "reviewer_organization_ids": [
                    "organization:control-reviewer:1",
                    "organization:control-reviewer:2",
                ],
                "control_scoring_rule": claim.CONTROL_FAILURE_RULE,
                "control_role_packet_sha256": [
                    {"control_role": role, "sha256": control_packet_hashes[role]} for role in sentinel.CONTROL_ROLES
                ],
                "review_state": "PACKETS_BOUND_REVIEW_NOT_EXECUTED",
                "control_semantic_validity_verified": False,
            },
        )
        domain_review_descriptor = artifacts.descriptor(domain_review_id)
        domain_core = {
            "schema_version": "causalfrontier.sentinel-domain-registry.v1",
            "domain_id": domain_id,
            "knowledge_cutoff": goal_domain["knowledge_cutoff"],
            "laboratory_ids": goal_domain["laboratory_ids"],
            "semantics_sha256": semantics_descriptor["sha256"],
            "domain_review_sha256": domain_review_descriptor["sha256"],
            "control_review_sha256": control_review_descriptor["sha256"],
            "cases": registry_records,
        }
        domain_registry_digests[domain_id] = sha256_bytes(canonical_bytes(domain_core))
        domains.append(
            {
                "domain_id": domain_id,
                "knowledge_cutoff": goal_domain["knowledge_cutoff"],
                "laboratory_ids": goal_domain["laboratory_ids"],
                "semantics_artifact_id": semantics_id,
                "domain_review_artifact_id": domain_review_id,
                "control_review_artifact_id": control_review_id,
                "cases": domain_cases,
            }
        )

    case_assignments.sort(key=lambda item: item["case_id"])
    if seed_oracle_commitment_collision:
        if first_oracle_commitment is None:
            raise AssertionError("fixture must produce at least one oracle commitment")
        generator_precommitments[0]["seed_external_commitment_sha256"] = first_oracle_commitment
    domain_pair_reviews = []
    for left_id, right_id in combinations(["domain:1", "domain:2", "domain:3"], 2):
        review_id = "artifact:domain-pair:%s:%s" % (left_id[-1], right_id[-1])
        artifacts.add_json(
            review_id,
            "DOMAIN_PAIR_REVIEW",
            {
                "schema_version": "causalfrontier.domain-pair-review.v1",
                "left_domain_id": left_id,
                "right_domain_id": right_id,
                "left_semantics_sha256": semantics_descriptors[left_id]["sha256"],
                "right_semantics_sha256": semantics_descriptors[right_id]["sha256"],
                "reviewer_organization_ids": [
                    "organization:domain-reviewer:1",
                    "organization:domain-reviewer:2",
                ],
                "decision_critical_axes_declared_different": (
                    []
                    if domain_semantics_collision and (left_id, right_id) == ("domain:1", "domain:2")
                    else ["decision_unit"]
                    if false_domain_axis_declaration and (left_id, right_id) == ("domain:1", "domain:2")
                    else ["decision_unit", "resource_basis"]
                ),
                "semantic_independence_verified": False,
                "review_state": "PAIR_DIFFERENCE_DECLARATION_BOUND_EXTERNAL_REVIEW_NOT_EXECUTED",
            },
        )
        domain_pair_reviews.append(
            {"left_domain_id": left_id, "right_domain_id": right_id, "review_artifact_id": review_id}
        )

    if seed_bundle_inventory_digest_collision:
        inventory_core = [
            {
                "artifact_id": item["artifact_id"],
                "path": item["path"],
                "sha256": item["sha256"],
                "role": item["role"],
            }
            for item in artifacts.descriptors()
        ]
        generator_precommitments[0]["seed_external_commitment_sha256"] = sha256_bytes(canonical_bytes(inventory_core))
    if seed_outer_registry_digest_collision:
        generator_precommitments[0]["seed_external_commitment_sha256"] = sha256_bytes(
            canonical_bytes(organizations) + b"\n"
        )

    generation_plan = {
        "schema_version": sentinel.GENERATION_PLAN_SCHEMA_VERSION,
        "status": sentinel.GENERATION_PLAN_STATUS,
        "plan_id": "plan:sentinel-generation:1",
        "sequence": 1,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "goal_claim_contract_sha256": claim.goal_claim_contract_sha256(),
        "frozen_at": "2026-02-01T00:00:00Z",
        "scope": sentinel.SCOPE,
        "organization_registry_sha256": sha256_bytes(canonical_bytes(organizations)),
        "domain_ids": ["domain:1", "domain:2", "domain:3"],
        "generator_family_ids": ["generator:1", "generator:2", "generator:3"],
        "domain_contracts": generation_domain_contracts,
        "case_assignments": case_assignments,
        "generator_precommitments": generator_precommitments,
        "protocol_precommitments": protocol_precommitments,
        "rules": {
            "generator_family_definition": sentinel.GENERATOR_FAMILY_RULE,
            "control_assignment_rule": sentinel.CONTROL_ASSIGNMENT_RULE,
            "primary_balance_rule": sentinel.PRIMARY_BALANCE_RULE,
            "case_selection_rule": sentinel.CASE_SELECTION_RULE,
            "oracle_boundary_rule": sentinel.ORACLE_BOUNDARY_RULE,
            "source_eligibility_rule": sentinel.SOURCE_ELIGIBILITY_RULE,
            "cutoff_rule": sentinel.CUTOFF_RULE,
            "exact_domains_n": sentinel.EXACT_DOMAINS,
            "exact_generator_families_n": sentinel.EXACT_GENERATOR_FAMILIES,
            "primary_cases_per_domain": sentinel.PRIMARY_CASES_PER_DOMAIN,
            "laboratories_per_domain": sentinel.LABORATORIES_PER_DOMAIN,
        },
        "designated_outcome_input_absent": True,
        "case_selection_after_generation_allowed": False,
        "oracle_opening_input_allowed": False,
        "scoring_disabled": True,
    }
    generation_plan["plan_sha256"] = sha256_bytes(
        sentinel.GENERATION_PLAN_DOMAIN_TAG + canonical_bytes(generation_plan)
    )
    generation_plan_path = base / "sentinel-generation-plan.json"
    generation_plan_raw = canonical_bytes(generation_plan) + b"\n"
    generation_plan_path.write_bytes(generation_plan_raw)
    generation_plan_checkpoint = sha256_bytes(generation_plan_raw)

    manifest = {
        "schema_version": (
            sentinel.PHASE_BOUND_MANIFEST_SCHEMA_VERSION
            if generation_phase_context is not None
            else sentinel.MANIFEST_SCHEMA_VERSION
        ),
        "manifest_id": "manifest:sentinel-admission:1",
        "sequence": 1,
        "generation_plan_checkpoint_sha256": generation_plan_checkpoint,
        "generation_plan_sha256": generation_plan["plan_sha256"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "goal_claim_contract_sha256": claim.goal_claim_contract_sha256(),
        "scope": sentinel.SCOPE,
        "frozen_at": "2026-02-02T00:00:00Z",
        "protocol_artifact_ids": protocols,
        "organizations": organizations,
        "generators": generators,
        "domains": domains,
        "generator_pair_audits": generator_pair_audits,
        "domain_pair_reviews": domain_pair_reviews,
        "artifacts": artifacts.descriptors(),
        "designated_outcome_input_absent": True,
        "oracle_opening_input_absent": True,
        "scoring_disabled": True,
    }
    if generation_phase_context is not None:
        manifest["generation_phase_context"] = generation_phase_context
    manifest_path = bundle_root / sentinel.MANIFEST
    manifest_raw = canonical_bytes(manifest) + b"\n"
    manifest_path.write_bytes(manifest_raw)
    manifest_checkpoint = sha256_bytes(manifest_raw)

    goal_plan = goal_template
    goal_plan["cohort_checkpoint_sha256"] = manifest_checkpoint
    goal_plan["calibration"]["control_oracle_commitment_sha256"] = sha256_bytes(
        canonical_bytes(control_opening_commitments)
    )
    goal_plan["calibration"]["control_scoring_protocol_sha256"] = protocol_precommitments[
        "control_scoring_protocol_artifact_id"
    ]
    goal_plan["calibration"]["control_scoring_implementation_sha256"] = protocol_precommitments[
        "control_scoring_implementation_artifact_id"
    ]
    goal_plan["calibration"]["semantic_validity_review_protocol_sha256"] = protocol_precommitments[
        "semantic_review_protocol_artifact_id"
    ]
    for goal_domain in goal_plan["domains"]:
        goal_domain["case_registry_checkpoint_sha256"] = domain_registry_digests[goal_domain["domain_id"]]
    reseal_goal_plan(goal_plan)
    goal_plan_path = base / "goal-claim-plan.json"
    goal_plan_raw = canonical_bytes(goal_plan) + b"\n"
    goal_plan_path.write_bytes(goal_plan_raw)
    goal_plan_checkpoint = sha256_bytes(goal_plan_raw)

    return {
        "root": bundle_root,
        "manifest_path": manifest_path,
        "manifest": manifest,
        "manifest_sha256": manifest_checkpoint,
        "generation_plan_path": generation_plan_path,
        "generation_plan": generation_plan,
        "generation_plan_sha256": generation_plan_checkpoint,
        "goal_plan_path": goal_plan_path,
        "goal_plan": goal_plan,
        "goal_plan_sha256": goal_plan_checkpoint,
        "artifact_descriptors": artifacts.items,
    }


def reseal_generation_plan(fixture: dict[str, Any]) -> None:
    plan = fixture["generation_plan"]
    core = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan["plan_sha256"] = sha256_bytes(sentinel.GENERATION_PLAN_DOMAIN_TAG + canonical_bytes(core))
    raw = canonical_bytes(plan) + b"\n"
    fixture["generation_plan_path"].write_bytes(raw)
    fixture["generation_plan_sha256"] = sha256_bytes(raw)


def reseal_manifest_and_goal(fixture: dict[str, Any]) -> None:
    manifest_raw = canonical_bytes(fixture["manifest"]) + b"\n"
    fixture["manifest_path"].write_bytes(manifest_raw)
    fixture["manifest_sha256"] = sha256_bytes(manifest_raw)
    fixture["goal_plan"]["cohort_checkpoint_sha256"] = fixture["manifest_sha256"]
    reseal_goal_plan(fixture["goal_plan"])
    goal_raw = canonical_bytes(fixture["goal_plan"]) + b"\n"
    fixture["goal_plan_path"].write_bytes(goal_raw)
    fixture["goal_plan_sha256"] = sha256_bytes(goal_raw)
