#!/usr/bin/env python3
"""Generate the deterministic, calibration-only V2 public-metadata rehearsal.

The generator performs no network or material operation.  It writes steward-
prepared metadata reconstructions, seals each protocol phase with the public V2
API, finalizes the local structural report, and then replays its verifier.
"""

from __future__ import annotations

import argparse
import errno
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from causalfrontier import calibration_v2 as v2
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, io_error, sha256_bytes
from causalfrontier.model import FIXED_PARAMETER, fixed_boundary

SCHEMA = "causalfrontier.calibration-v2-public-metadata-example.v1"
PROTOCOL_ID = "calibration.v2.public-metadata-therapeutic-translation"
RUN_ID = "run.calibration-v2.public-metadata-rehearsal"
POLICY_ID = "policy.causalfrontier.v2.public-metadata-rehearsal"
GENESIS = "0" * 64

PUBLIC_METADATA_LIMITS = {
    "status": "CURRENT_METADATA_RECONSTRUCTION_NOT_HISTORICAL_BYTES",
    "metadata_only": True,
    "full_text_included": False,
    "historical_byte_custody_verified": False,
    "original_representation_verified": False,
    "independent_temporal_attestation_verified": False,
    "clinical_or_patient_decision_authority": False,
    "wet_lab_or_material_authority": False,
}

CASE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "pcsk9-pre-fourier": {
        "role": "POSITIVE",
        "cutoff": "2012-12-31T23:59:59Z",
        "mode": "PROPOSE_FALSIFICATION",
        "question": (
            "What aggregate outcome study would distinguish cardiovascular net benefit from LDL target engagement "
            "alone under this cutoff?"
        ),
        "sources": [
            {
                "key": "pubmed-16554528",
                "available_at": "2006-03-24T09:00:00Z",
                "availability_basis": "PUBMED_INGESTION_METADATA",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:16554528",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/16554528/",
                "reported_date": "2006-03-23",
                "metadata_note": "Human PCSK9 genetic-association record including coronary-event metadata.",
                "relations": ("SUPPORTS", "LIMITS_TRANSPORT"),
            },
            {
                "key": "pubmed-23113833",
                "available_at": "2012-11-02T06:00:00Z",
                "availability_basis": "PUBMED_INGESTION_METADATA",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:23113833",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/23113833/",
                "reported_date": "2012",
                "metadata_note": "Early pharmacologic PCSK9-inhibition bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "pubmed-23141813",
                "available_at": "2012-11-13T06:00:00Z",
                "availability_basis": "PUBMED_INGESTION_METADATA",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:23141813",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/23141813/",
                "reported_date": "2012",
                "metadata_note": "Phase-two LDL target-engagement bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
        ],
        "opening_available_at": "2017-03-17T00:00:00Z",
        "opening_coordinate": ("COMPLETE", "CONFIRMED", "BENEFIT", "CONSISTENT"),
        "opening_citations": [
            {
                "stable_identifier": "PMID:28304224",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/28304224/",
            }
        ],
        "tooluniverse_raw_response_sha256": "d328ee5725a28165ce95879a66dda49af58c3c3524c17ed3ee9302451c496e0d",
    },
    "verubecestat-pre-epoch-readout": {
        "role": "FAILED_TRANSLATION",
        "cutoff": "2016-11-03T23:59:59Z",
        "mode": "REQUEST_INFORMATION",
        "question": (
            "Which aggregate clinical, safety, target-engagement, and retention observations are still needed to "
            "separate net benefit from no net benefit under this cutoff?"
        ),
        "sources": [
            {
                "key": "pubmed-22801501",
                "available_at": "2012-08-02T23:59:59Z",
                "availability_basis": "REPORTED_PUBLICATION_DATE_END_OF_DAY_UTC",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:22801501",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/22801501/",
                "reported_date": "2012-08-02",
                "metadata_note": "Human APP genetic-protection bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "crossref-aad9704",
                "available_at": "2016-11-02T14:15:50Z",
                "availability_basis": "CROSSREF_BIBLIOGRAPHIC_CREATED_TIMESTAMP",
                "source_type": "CROSSREF_BIBLIOGRAPHIC",
                "stable_identifier": "DOI:10.1126/scitranslmed.aad9704",
                "public_locator": "https://doi.org/10.1126/scitranslmed.aad9704",
                "reported_date": "2016-11-02",
                "metadata_note": "Bibliographic metadata for preclinical and human CNS target-engagement work.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "clinicaltrials-nct01739348-v47",
                "available_at": "2016-10-07T23:59:59Z",
                "availability_basis": "OFFICIAL_REGISTRY_VERSION_DATE_END_OF_DAY_UTC",
                "source_type": "CLINICALTRIALS_HISTORY_METADATA",
                "stable_identifier": "NCT01739348:VERSION_47",
                "public_locator": "https://clinicaltrials.gov/study/NCT01739348",
                "reported_date": "2016-10-07",
                "metadata_note": "Reconstructed registry-history metadata for the declared version and study design.",
                "relations": ("CONTEXT_ONLY", "CONTEXT_ONLY"),
            },
            {
                "key": "clinicaltrials-nct01953601-v42",
                "available_at": "2016-10-04T23:59:59Z",
                "availability_basis": "OFFICIAL_REGISTRY_VERSION_DATE_END_OF_DAY_UTC",
                "source_type": "CLINICALTRIALS_HISTORY_METADATA",
                "stable_identifier": "NCT01953601:VERSION_42",
                "public_locator": "https://clinicaltrials.gov/study/NCT01953601",
                "reported_date": "2016-10-04",
                "metadata_note": "Reconstructed registry-history metadata for the declared version and study design.",
                "relations": ("CONTEXT_ONLY", "CONTEXT_ONLY"),
            },
        ],
        "opening_available_at": "2018-05-03T00:00:00Z",
        "opening_coordinate": ("COMPLETE", "CONFIRMED", "HARM", "CONSISTENT"),
        "opening_citations": [
            {
                "stable_identifier": "PMID:29719179",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/29719179/",
            }
        ],
        "tooluniverse_raw_response_sha256": "47faf86615b118e1687e5cf8b42b001fe7ad28aefcd0f7628a511a982d0bbf38",
    },
    "remdesivir-pre-actt": {
        "role": "AMBIGUOUS",
        "cutoff": "2020-02-20T23:59:59Z",
        "mode": "REQUEST_INFORMATION",
        "question": (
            "Which aggregate clinical, safety, timing, and target-engagement observations are still needed to "
            "separate net benefit from no net benefit under this cutoff?"
        ),
        "sources": [
            {
                "key": "pubmed-28659436",
                "available_at": "2017-07-01T00:00:00Z",
                "availability_basis": "CONSERVATIVE_POST_PUBLICATION_METADATA_DATE",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:28659436",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/28659436/",
                "reported_date": "2017",
                "metadata_note": "Preclinical coronavirus antiviral-activity bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "pubmed-32020029",
                "available_at": "2020-02-06T06:00:00Z",
                "availability_basis": "PUBMED_INGESTION_METADATA",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:32020029",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/32020029/",
                "reported_date": "2020-02-04",
                "metadata_note": "SARS-CoV-2 cell-culture activity bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "pubmed-32054787",
                "available_at": "2020-02-15T06:00:00Z",
                "availability_basis": "PUBMED_INGESTION_METADATA",
                "source_type": "PUBMED_BIBLIOGRAPHIC",
                "stable_identifier": "PMID:32054787",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/32054787/",
                "reported_date": "2020-02-13",
                "metadata_note": "MERS-CoV nonhuman-primate activity bibliographic record.",
                "relations": ("LIMITS_TRANSPORT", "UNKNOWN"),
            },
            {
                "key": "clinicaltrials-nct04252664-v1",
                "available_at": "2020-02-05T23:59:59Z",
                "availability_basis": "OFFICIAL_REGISTRY_FIRST_POST_DATE_END_OF_DAY_UTC",
                "source_type": "CLINICALTRIALS_HISTORY_METADATA",
                "stable_identifier": "NCT04252664:VERSION_1",
                "public_locator": "https://clinicaltrials.gov/study/NCT04252664",
                "reported_date": "2020-02-05",
                "metadata_note": "Reconstructed first-posted registry metadata for a randomized study design.",
                "relations": ("CONTEXT_ONLY", "CONTEXT_ONLY"),
            },
            {
                "key": "clinicaltrials-nct04257656-v1",
                "available_at": "2020-02-06T23:59:59Z",
                "availability_basis": "OFFICIAL_REGISTRY_FIRST_POST_DATE_END_OF_DAY_UTC",
                "source_type": "CLINICALTRIALS_HISTORY_METADATA",
                "stable_identifier": "NCT04257656:VERSION_1",
                "public_locator": "https://clinicaltrials.gov/study/NCT04257656",
                "reported_date": "2020-02-06",
                "metadata_note": "Reconstructed first-posted registry metadata for a randomized study design.",
                "relations": ("CONTEXT_ONLY", "CONTEXT_ONLY"),
            },
        ],
        "opening_available_at": "2020-05-22T00:00:00Z",
        "opening_coordinate": ("COMPLETE", "UNKNOWN", "UNKNOWN", "INSUFFICIENT"),
        "opening_citations": [
            {
                "stable_identifier": "PMID:32445440",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/32445440/",
            },
            {
                "stable_identifier": "PMID:32423584",
                "public_locator": "https://pubmed.ncbi.nlm.nih.gov/32423584/",
            },
        ],
        "tooluniverse_raw_response_sha256": "7ae6f4bc801e4b1d3ba114dd88d47759a6bbae5c9214807bc17f44d06184a170",
    },
}

TOOLBOX_CONTRACT = (
    (
        "TOOLUNIVERSE_CAPTURE",
        "tooluniverse-1.4.1-local-installation-snapshot",
        "e5577dc0fd407a2c57cf3773c53d28b2a16badca436bca26e6a108c600b039b7",
    ),
    (
        "GRACEGRAPH_CAPSULE",
        "gracegraph-local-source-manifest",
        "9ae37c6270d9a66a77e4948aff87f86c56574413b474aede3a7dc37b2b3e0152",
    ),
    (
        "GRACELOOP_FRONTIER",
        "graceloop-0.1.0a1-local-source-snapshot",
        "abe7078cfe7269728926e587c51d64d1dd7652f1cc655dbb8e5c3f2a024c566f",
    ),
)

CLAIMS = [
    {
        "claim_id": "claim.net-benefit",
        "label": "The intervention has aggregate net clinical benefit in the bounded population and horizon",
        "scope": "Prespecified population, intervention version, comparator, endpoints, safety, and horizon only",
    },
    {
        "claim_id": "claim.no-net-benefit",
        "label": "The intervention does not have aggregate net clinical benefit in that same bounded scope",
        "scope": "Prespecified population, intervention version, comparator, endpoints, safety, and horizon only",
    },
]

INFORMATION_REQUIREMENTS = [
    {
        "requirement_id": "information.adherence-retention",
        "description": "Aggregate adherence, discontinuation, loss-to-follow-up, and retention accounting",
    },
    {
        "requirement_id": "information.clinical-endpoints",
        "description": "Prespecified aggregate clinical endpoint estimates with uncertainty",
    },
    {
        "requirement_id": "information.safety",
        "description": "Prespecified aggregate serious-harm and tolerability estimates",
    },
    {
        "requirement_id": "information.target-engagement",
        "description": "Prespecified target-engagement evidence kept distinct from clinical outcomes",
    },
]

FEATURES = [
    {"feature_id": "feature.endpoint-specificity", "label": "Endpoint-specific interpretation"},
    {
        "feature_id": "feature.no-surrogate-substitution",
        "label": "Target engagement is kept distinct from clinical outcomes",
    },
    {
        "feature_id": "feature.population-stage-specificity",
        "label": "Population and disease-stage bounds are explicit",
    },
    {"feature_id": "feature.safety-boundary", "label": "Harm routes to a safety stop"},
    {"feature_id": "feature.surrogate-substitution", "label": "Clinical outcomes are replaced by a surrogate"},
    {
        "feature_id": "feature.target-engagement-distinct",
        "label": "Target engagement is represented on its own observation axis",
    },
]

SELECTED_FEATURES = [
    "feature.endpoint-specificity",
    "feature.no-surrogate-substitution",
    "feature.population-stage-specificity",
    "feature.safety-boundary",
    "feature.target-engagement-distinct",
]

PANEL = (
    ("reviewer.example-a", "organization.example-a"),
    ("reviewer.example-b", "organization.example-b"),
    ("reviewer.example-c", "organization.example-b"),
)


def _opaque(kind: str, label: str) -> str:
    return f"entrant:{kind}:" + sha256(f"{kind}:{label}".encode()).hexdigest()


def _coordinate(states: tuple[str, str, str, str]) -> list[dict[str, str]]:
    return [{"axis_id": axis_id, "state_id": state_id} for axis_id, state_id in zip(v2.AXIS_ORDER, states, strict=True)]


def _write_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(value) + b"\n"
    path.write_bytes(raw)
    return sha256_bytes(raw)


def _inactive_proposed() -> dict[str, Any]:
    return {
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


def _inactive_rejection() -> dict[str, Any]:
    return {
        "status": "NOT_APPLICABLE",
        "rejected_claim_ids": [],
        "retained_claim_ids": [],
        "scope_limit": None,
        "reversal_information_ids": [],
    }


def _inactive_information() -> dict[str, Any]:
    return {
        "status": "NOT_APPLICABLE",
        "unresolved_claim_ids": [],
        "competing_claim_sets": [],
        "requested_information_ids": [],
        "resolution_rule": None,
    }


def _decision(case_key: str) -> dict[str, Any]:
    definition = CASE_DEFINITIONS[case_key]
    proposed = _inactive_proposed()
    information = _inactive_information()
    if definition["mode"] == "PROPOSE_FALSIFICATION":
        proposed = {
            "status": "DESCRIPTION_ONLY_NOT_AUTHORIZED",
            "question": (
                "Does randomized pharmacologic PCSK9 inhibition reduce the prespecified aggregate major "
                "cardiovascular-event endpoint without an offsetting serious-harm signal?"
            ),
            "design_class": "RANDOMIZED_CONTROLLED_AGGREGATE_OUTCOME_STUDY_DESCRIPTION",
            "population_or_system": (
                "A prespecified aggregate high-cardiovascular-risk population receiving background standard care"
            ),
            "intervention_or_exposure": "A frozen PCSK9-inhibitor regimen added to background standard care",
            "comparator": "A concurrently randomized matching control under the same measurement protocol",
            "primary_endpoint": "A frozen aggregate major cardiovascular-event endpoint with serious harms reported",
            "time_horizon": "The prespecified clinical follow-up interval",
            "falsification_threshold": (
                "The prespecified interval estimate must exclude the null in the beneficial direction while the "
                "serious-harm boundary remains untriggered"
            ),
            "replication_requirement": (
                "One prespecified independent replication or a coherent held-out aggregate validation cohort"
            ),
            "stopping_boundary": "Stop for harm, integrity failure, or the prespecified futility boundary",
            "required_authorities_if_executed": [
                "DOMAIN_AUTHORITY",
                "ETHICS_IF_APPLICABLE",
                "EXTERNAL_REVIEW",
                "RESOURCE_AUTHORITY",
            ],
            "execution_authorized": False,
        }
    else:
        information = {
            "status": "ACTIONABLE_MINIMUM_INFORMATION_BOUNDARY",
            "unresolved_claim_ids": ["claim.net-benefit", "claim.no-net-benefit"],
            "competing_claim_sets": [["claim.net-benefit"], ["claim.no-net-benefit"]],
            "requested_information_ids": [
                "information.adherence-retention",
                "information.clinical-endpoints",
                "information.safety",
                "information.target-engagement",
            ],
            "resolution_rule": (
                "Retain both claims until prespecified aggregate clinical endpoints, safety, target engagement, and "
                "adherence-retention jointly identify a fixed branch; stop for any harm signal"
            ),
        }
    return {
        "mode": definition["mode"],
        "target_claim_ids": ["claim.net-benefit", "claim.no-net-benefit"],
        "selected_feature_ids": SELECTED_FEATURES,
        "proposed_falsification": proposed,
        "bounded_rejection": _inactive_rejection(),
        "minimum_information_boundary": information,
    }


def _branch_contract(decision: dict[str, Any]) -> dict[str, Any]:
    claim_ids = decision["target_claim_ids"]
    return {
        "schema_version": v2.BRANCH_SCHEMA_VERSION,
        "partition": "CARTESIAN_TOTAL_ENUMERATION_WITH_FAILURE_HARM_CONTRADICTION_AND_RESIDUAL",
        "axis_order": list(v2.AXIS_ORDER),
        "coordinate_count": v2.COORDINATE_COUNT,
        "target_claim_ids": claim_ids,
        "decision_sha256": sha256_bytes(canonical_bytes(decision)),
        "rows": v2.canonical_branch_rows(claim_ids),
    }


def _branch_for(coordinate: list[dict[str, str]]) -> tuple[str, str]:
    coordinate_bytes = canonical_bytes(coordinate)
    for row in v2.canonical_branch_rows(["claim.net-benefit", "claim.no-net-benefit"]):
        if canonical_bytes(row["coordinate"]) == coordinate_bytes:
            return row["branch_class"], row["successor"]
    raise RuntimeError("fixed coordinate was not present in the V2 branch table")


def _source_card(source: dict[str, Any], cutoff: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        **PUBLIC_METADATA_LIMITS,
        "source_type": source["source_type"],
        "stable_identifier": source["stable_identifier"],
        "public_locator": source["public_locator"],
        "reported_date": source["reported_date"],
        "declared_available_at": source["available_at"],
        "availability_basis": source["availability_basis"],
        "knowledge_cutoff": cutoff,
        "metadata_note": source["metadata_note"],
        "preparation_limits": [
            "The cited public record is represented by a steward-authored 2026 metadata card.",
            "The declared date is ordering metadata, not custody of the cited record's historical bytes.",
            "This card contains no abstract, full text, participant row, or treatment recommendation.",
        ],
    }


def _opening_card(case_key: str, case_id: str) -> dict[str, Any]:
    definition = CASE_DEFINITIONS[case_key]
    return {
        "schema_version": SCHEMA,
        **PUBLIC_METADATA_LIMITS,
        "opaque_case_id": case_id,
        "declared_available_at": definition["opening_available_at"],
        "citations": definition["opening_citations"],
        "committed_coordinate": _coordinate(definition["opening_coordinate"]),
        "preparation_limits": [
            "This opening card is a steward-authored metadata reconstruction, not an independently classified source.",
            "The coordinate is a protocol input and is not validator-established biomedical truth.",
            "No patient, clinical, publication, wet-lab, material, or execution authority is conveyed.",
        ],
    }


def _toolbox_contract() -> list[dict[str, str]]:
    # Bind the module actually executing the protocol, including when this
    # script is run against an installed package instead of an editable tree.
    # The legacy protocol field is named source_tree_sha256; this declaration
    # has always covered calibration_v2.py alone, not a complete source tree.
    causalfrontier_module = Path(v2.__file__).resolve(strict=True)
    entries = [
        {
            "stage_id": stage_id,
            "implementation_version": version,
            "source_tree_sha256": source_digest,
        }
        for stage_id, version, source_digest in TOOLBOX_CONTRACT
    ]
    entries.append(
        {
            "stage_id": "CAUSALFRONTIER_STRUCTURED_ACTION",
            "implementation_version": "causalfrontier-calibration-v2-local-unreleased",
            "source_tree_sha256": sha256_bytes(causalfrontier_module.read_bytes()),
        }
    )
    return entries


def _toolbox_detail(stage_id: str, definition: dict[str, Any]) -> dict[str, Any]:
    if stage_id == "TOOLUNIVERSE_CAPTURE":
        return {
            "tool_version": "tu 1.4.1",
            "current_query_response_sha256": definition["tooluniverse_raw_response_sha256"],
            "source_installation_snapshot_sha256": TOOLBOX_CONTRACT[0][2],
            "current_query_is_not_historical_source_bytes": True,
        }
    if stage_id == "GRACEGRAPH_CAPSULE":
        return {
            "source_manifest_sha256": TOOLBOX_CONTRACT[1][2],
            "sealed_capsule_manifest_sha256": "190dc097e057f15883b9f38edf7b18ffa20db27e8e485cf0d2f824259ae1772f",
            "static_status": "SELF_CONSISTENT_UNAUTHENTICATED",
            "live_replay_status": "FAILED_CLOSED_PROJECT_DRIFT",
        }
    if stage_id == "GRACELOOP_FRONTIER":
        return {
            "source_snapshot_sha256": TOOLBOX_CONTRACT[2][2],
            "capsule_manifest_raw_sha256": "644a0cb3d2f27cf6afab57c518005176a484cecbe0416fae1fe5ff6703e4f291",
            "frontier_raw_sha256": "91a2ee166e6e60f061f1c5c29d98a7af4ba698b8dc57fdd22291b8aba9ec8988",
            "status": "PLAN_ONLY_NO_EMPIRICAL_EVIDENCE",
            "empirical_n": 0,
            "authorized": False,
        }
    return {
        "coordinate_count": v2.COORDINATE_COUNT,
        "structured_action_schema_version": v2.SUBMISSION_SCHEMA_VERSION,
        "execution_authorized": False,
    }


def _toolbox_trace(
    output: Path,
    case_key: str,
    case_id: str,
    source_ids: list[str],
    contract: list[dict[str, str]],
) -> list[dict[str, str]]:
    trace = []
    suffix = case_id.rsplit(":", 1)[1][:16]
    for index, stage in enumerate(contract):
        stage_slug = f"{index + 1:02d}-{stage['stage_id'].casefold().replace('_', '-')}"
        artifact_path = output / "toolbox" / suffix / f"{stage_slug}.artifact.json"
        receipt_path = output / "toolbox" / suffix / f"{stage_slug}.resource.json"
        artifact_sha256 = _write_json(
            artifact_path,
            {
                "schema_version": "causalfrontier.calibration-v2-toolbox-artifact.v1",
                "status": "DECLARED_ARTIFACT_BOUND_NOT_REPLAYED",
                "opaque_case_id": case_id,
                "stage_id": stage["stage_id"],
                "implementation_version": stage["implementation_version"],
                "source_tree_sha256": stage["source_tree_sha256"],
                "input_source_ids": source_ids,
                "diagnostic_detail": _toolbox_detail(stage["stage_id"], CASE_DEFINITIONS[case_key]),
                "nonclaims": [
                    "This record binds a local diagnostic declaration; the V2 validator does not replay this stage.",
                    (
                        "No historical custody, independent execution, scientific validity, or execution authority "
                        "is proven."
                    ),
                ],
            },
        )
        resource_sha256 = _write_json(
            receipt_path,
            {
                "schema_version": "causalfrontier.calibration-v2-toolbox-resource-declaration.v1",
                "status": "DECLARED_ONLY_NOT_INDEPENDENTLY_METERED",
                "opaque_case_id": case_id,
                "stage_id": stage["stage_id"],
                "network_requests_during_role_hidden_run": 0,
                "patient_rows": 0,
                "wet_lab_operations": 0,
                "material_operations": 0,
                "execution_authorized": False,
            },
        )
        trace.append(
            {
                **stage,
                "status": "DECLARED_ARTIFACT_BOUND_NOT_REPLAYED",
                "artifact_sha256": artifact_sha256,
                "resource_receipt_sha256": resource_sha256,
            }
        )
    return trace


def _evidence_assessments(case_key: str, source_rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    definition = CASE_DEFINITIONS[case_key]
    source_by_key = {source["key"]: source for source in definition["sources"]}
    result = []
    claim_ids = ["claim.net-benefit", "claim.no-net-benefit"]
    for source_row in source_rows:
        source = source_by_key[source_row["key"]]
        for claim_id, relation in zip(claim_ids, source["relations"], strict=True):
            result.append(
                {
                    "opaque_source_id": source_row["opaque_source_id"],
                    "claim_id": claim_id,
                    "relation": relation,
                    "reason": (
                        "The cutoff-bounded metadata is classified only for its relation to this claim; mechanistic, "
                        "genetic, target-engagement, and registry-design metadata do not substitute for aggregate "
                        "clinical outcomes or safety."
                    ),
                }
            )
    return result


def _rubric(case_rows: list[dict[str, Any]], view_binding: str) -> dict[str, Any]:
    sentinels = {
        "remdesivir-pre-actt": _coordinate(("FAILED", "UNKNOWN", "UNKNOWN", "INSUFFICIENT")),
        "pcsk9-pre-fourier": _coordinate(("COMPLETE", "CONFIRMED", "BENEFIT", "CONSISTENT")),
        "verubecestat-pre-epoch-readout": _coordinate(("COMPLETE", "CONFIRMED", "HARM", "CONSISTENT")),
    }
    entries = []
    for case in case_rows:
        coordinate = sentinels[case["case_key"]]
        branch_class, successor = _branch_for(coordinate)
        entries.append(
            {
                "opaque_case_id": case["opaque_case_id"],
                "required_feature_ids": SELECTED_FEATURES,
                "forbidden_feature_ids": ["feature.surrogate-substitution"],
                "sentinel_rows": [
                    {
                        "coordinate": coordinate,
                        "required_branch_class": branch_class,
                        "required_successor": successor,
                    }
                ],
                "semantic_criteria": [
                    {
                        "criterion_id": criterion_id,
                        "question": (
                            "Does the anonymous submission satisfy this criterion within the explicit "
                            "calibration-only, "
                            "aggregate, non-authorizing boundary?"
                        ),
                    }
                    for criterion_id in v2.ADJUDICATION_CRITERIA
                ],
            }
        )
    return {
        "schema_version": v2.RUBRIC_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "view_content_binding_sha256": view_binding,
        "nonce_hex": "7d" * 32,
        "criteria_order": list(v2.ADJUDICATION_CRITERIA),
        "entries": entries,
        "review_plan": {
            "plan_id": "review.plan.calibration-v2.public-example",
            "minimum_reviewers": 3,
            "minimum_organizations": 2,
            "reviewer_assignments": [
                {
                    "reviewer_id": reviewer_id,
                    "organization_id": organization_id,
                    "assignment_checkpoint_sha256": sha256_bytes(
                        f"declared-example-assignment:{reviewer_id}:{organization_id}".encode()
                    ),
                }
                for reviewer_id, organization_id in PANEL
            ],
            "policy_identity_blinded_required": True,
            "ex_ante_outcome_hidden_required": True,
            "phase_separation_required": True,
            "aggregation_rule": "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL",
        },
        "aggregation_rule": "UNANIMOUS_PASS_ANY_FAIL_FAIL_OTHERWISE_NO_CALL",
    }


def _votes() -> list[dict[str, Any]]:
    return [
        {
            "reviewer_id": reviewer_id,
            "organization_id": organization_id,
            "policy_identity_blinded_declared": True,
            "outcome_hidden_during_ex_ante_review_declared": True,
            "criteria": [
                {
                    "criterion_id": criterion_id,
                    "verdict": "PASS",
                    "reason_code": "DECLARED_EXAMPLE_REVIEW_PASS_NOT_INDEPENDENTLY_VERIFIED",
                }
                for criterion_id in v2.ADJUDICATION_CRITERIA
            ],
            "review_checkpoint_sha256": sha256_bytes(
                f"declared-example-assignment:{reviewer_id}:{organization_id}".encode()
            ),
        }
        for reviewer_id, organization_id in PANEL
    ]


def generate(output: Path) -> dict[str, Any]:
    """Generate a deterministic current-module rehearsal in a new directory.

    Historical artifacts remain immutable. A changed module digest propagates
    through the declared toolbox trace and all dependent protocol commitments.
    """

    if output.is_symlink():
        raise CausalFrontierError(
            "output must be a new directory; historical snapshots are never overwritten",
            reason_code="SAFE_PATH_REJECTED",
            operation="example_generate",
        )
    try:
        output = output.resolve()
    except RuntimeError:
        # Python 3.10-3.12 can report a symlink loop as RuntimeError.
        raise CausalFrontierError(
            "output path cannot be resolved safely", reason_code="SAFE_PATH_REJECTED", operation="example_generate"
        ) from None
    output.mkdir(parents=True, exist_ok=False)
    entrant_root = output / "entrant-root"
    external = output / "external-zones"
    toolbox_contract = _toolbox_contract()

    case_rows = []
    for case_key, definition in CASE_DEFINITIONS.items():
        case_id = _opaque("case", case_key)
        source_rows = []
        for source in definition["sources"]:
            source_rows.append(
                {
                    "key": source["key"],
                    "opaque_source_id": _opaque("source", f"{case_key}:{source['key']}"),
                    "source": source,
                }
            )
        source_rows.sort(key=lambda item: item["opaque_source_id"])
        manifest_sources = []
        for source_row in source_rows:
            source_id = source_row["opaque_source_id"]
            relative_path = f"sources/{source_id.rsplit(':', 1)[1][:24]}.json"
            source_sha256 = _write_json(
                entrant_root / relative_path,
                _source_card(source_row["source"], definition["cutoff"]),
            )
            manifest_sources.append(
                {
                    "opaque_source_id": source_id,
                    "path": relative_path,
                    "sha256": source_sha256,
                    "available_at": source_row["source"]["available_at"],
                    "data_class": "PUBLIC_METADATA",
                    "authority": "PUBLIC_DATA",
                }
            )
        opening_path = output / "opening-sources" / f"{case_id.rsplit(':', 1)[1][:24]}.json"
        opening_source_sha256 = _write_json(opening_path, _opening_card(case_key, case_id))
        case_rows.append(
            {
                "case_key": case_key,
                "opaque_case_id": case_id,
                "source_rows": source_rows,
                "manifest_sources": manifest_sources,
                "opening_source_sha256": opening_source_sha256,
            }
        )
    case_rows.sort(key=lambda item: item["opaque_case_id"])

    controls = [
        {
            "opaque_case_id": case["opaque_case_id"],
            "knowledge_cutoff": CASE_DEFINITIONS[case["case_key"]]["cutoff"],
            "decision_question": CASE_DEFINITIONS[case["case_key"]]["question"],
            "sources": case["manifest_sources"],
            "claim_catalog": CLAIMS,
            "information_requirements": INFORMATION_REQUIREMENTS,
            "feature_catalog": FEATURES,
        }
        for case in case_rows
    ]
    manifest = {
        "schema_version": v2.VIEW_SCHEMA_VERSION,
        "id": PROTOCOL_ID,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "known_hindsight": True,
        "prospective": False,
        "model_contamination_unresolved": True,
        "calibration_only": True,
        "primary_performance_eligible": False,
        "scientific_scoring_ready": False,
        "role_labels_omitted": True,
        "required_behaviors_omitted": True,
        "oracle_material_omitted": True,
        "reveal_input_accepted": False,
        "reveal_commitment_scheme": v2.REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": sha256_bytes(b"temporary reveal commitment"),
        "rubric_commitment_scheme": v2.RUBRIC_COMMITMENT_SCHEME,
        "rubric_commitment_sha256": sha256_bytes(b"temporary rubric commitment"),
        "observation_axes": v2.observation_axes_v2(),
        "toolbox_contract": toolbox_contract,
        "controls": controls,
    }
    view_binding = v2.view_content_binding_v2(manifest)
    opening_payload = {
        "schema_version": v2.OPENING_PAYLOAD_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "view_content_binding_sha256": view_binding,
        "entries": [
            {
                "opaque_case_id": case["opaque_case_id"],
                "control_role": CASE_DEFINITIONS[case["case_key"]]["role"],
                "observed_coordinate": _coordinate(CASE_DEFINITIONS[case["case_key"]]["opening_coordinate"]),
                "reveal_source_sha256": case["opening_source_sha256"],
                "reveal_available_at": CASE_DEFINITIONS[case["case_key"]]["opening_available_at"],
            }
            for case in case_rows
        ],
    }
    rubric = _rubric(case_rows, view_binding)
    reveal_nonce = "4b" * 32
    manifest["reveal_commitment_sha256"] = v2.reveal_commitment_v2(opening_payload, reveal_nonce)
    manifest["rubric_commitment_sha256"] = v2.rubric_commitment_v2(rubric)

    manifest_path = entrant_root / v2.VIEW_MANIFEST
    manifest_raw_sha256 = _write_json(manifest_path, manifest)
    view_lock = v2.preflight_calibration_v2_view(entrant_root, manifest_raw_sha256)
    view_lock_path = external / "view-lock.json"
    view_lock_raw_sha256 = _write_json(view_lock_path, view_lock)

    submission_cases = []
    ledgers = []
    for case in case_rows:
        case_key = case["case_key"]
        decision = _decision(case_key)
        source_ids = [row["opaque_source_id"] for row in case["source_rows"]]
        derivation_trace = _toolbox_trace(output, case_key, case["opaque_case_id"], source_ids, toolbox_contract)
        evidence_assessments = _evidence_assessments(case_key, case["source_rows"])
        branch_contract = _branch_contract(decision)
        submission_cases.append(
            {
                "opaque_case_id": case["opaque_case_id"],
                "completion_state": "COMPLETE",
                "failure_code": None,
                "decision": decision,
                "evidence_assessments": evidence_assessments,
                "branch_contract": branch_contract,
                "derivation_trace": derivation_trace,
            }
        )
        input_bytes = sum(len((entrant_root / source["path"]).read_bytes()) for source in case["manifest_sources"])
        output_bytes = len(canonical_bytes({"decision": decision, "branch_contract": branch_contract}))
        ledgers.append(
            {
                "opaque_case_id": case["opaque_case_id"],
                "stages": {
                    "preprocessing": 1,
                    "retrieval": 0,
                    "model_tool_calls": 0,
                    "retries": 0,
                    "human": 0,
                    "compute": 1,
                    "calendar": 0,
                    "direct_cost": 0,
                },
                "model_input_tokens": 0,
                "model_output_tokens": 0,
                "tool_calls": 0,
                "network_requests": 0,
                "input_bytes": input_bytes,
                "output_bytes": output_bytes,
                "calendar_elapsed_ns": 1,
                "measurement_origin": "DECLARED_ONLY",
                "complete": True,
                "reveal_accessed": False,
            }
        )
    submission = {
        "schema_version": v2.SUBMISSION_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "run_id": RUN_ID,
        "policy_id": POLICY_ID,
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "fixed_parameter": FIXED_PARAMETER,
        "generated_from_role_hidden_view_only_declared": True,
        "cases": submission_cases,
        "resource_ledgers": ledgers,
    }
    submission_path = external / "submission.json"
    submission_raw_sha256 = _write_json(submission_path, submission)
    submission_seal = v2.seal_calibration_v2_submission(
        entrant_root,
        manifest_raw_sha256,
        view_lock_path,
        view_lock_raw_sha256,
        submission_path,
        submission_raw_sha256,
    )
    submission_seal_path = external / "submission-seal.json"
    submission_seal_raw_sha256 = _write_json(submission_seal_path, submission_seal)

    opening = {
        "schema_version": v2.OPENING_SCHEMA_VERSION,
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_seal_sha256": submission_seal["submission_seal_sha256"],
        "nonce_hex": reveal_nonce,
        "payload": opening_payload,
    }
    opening_path = external / "opening.json"
    opening_raw_sha256 = _write_json(opening_path, opening)
    rubric_path = external / "rubric.json"
    rubric_raw_sha256 = _write_json(rubric_path, rubric)
    adjudication = {
        "schema_version": v2.ADJUDICATION_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "run_id": RUN_ID,
        "view_lock_sha256": view_lock["view_lock_sha256"],
        "submission_raw_sha256": submission_raw_sha256,
        "submission_seal_sha256": submission_seal["submission_seal_sha256"],
        "opening_raw_sha256": opening_raw_sha256,
        "rubric_raw_sha256": rubric_raw_sha256,
        "criteria_order": list(v2.ADJUDICATION_CRITERIA),
        "entries": [{"opaque_case_id": case["opaque_case_id"], "votes": _votes()} for case in case_rows],
    }
    adjudication_path = external / "adjudication.json"
    adjudication_raw_sha256 = _write_json(adjudication_path, adjudication)
    report = v2.finalize_calibration_v2(
        entrant_root,
        manifest_raw_sha256,
        view_lock_path,
        view_lock_raw_sha256,
        submission_path,
        submission_raw_sha256,
        submission_seal_path,
        submission_seal_raw_sha256,
        opening_path,
        opening_raw_sha256,
        rubric_path,
        rubric_raw_sha256,
        adjudication_path,
        adjudication_raw_sha256,
    )
    report_path = external / "report.json"
    report_raw_sha256 = _write_json(report_path, report)
    verified = v2.verify_calibration_v2_report(
        entrant_root,
        manifest_raw_sha256,
        view_lock_path,
        view_lock_raw_sha256,
        submission_path,
        submission_raw_sha256,
        submission_seal_path,
        submission_seal_raw_sha256,
        opening_path,
        opening_raw_sha256,
        rubric_path,
        rubric_raw_sha256,
        adjudication_path,
        adjudication_raw_sha256,
        report_path,
        report_raw_sha256,
    )
    if canonical_bytes(verified) != canonical_bytes(report):
        raise RuntimeError("saved V2 report did not replay")

    protocol_checkpoints = {
        "manifest_raw_sha256": manifest_raw_sha256,
        "view_lock_raw_sha256": view_lock_raw_sha256,
        "submission_raw_sha256": submission_raw_sha256,
        "submission_seal_raw_sha256": submission_seal_raw_sha256,
        "opening_raw_sha256": opening_raw_sha256,
        "rubric_raw_sha256": rubric_raw_sha256,
        "adjudication_raw_sha256": adjudication_raw_sha256,
        "report_raw_sha256": report_raw_sha256,
    }
    generated_roots = ("entrant-root", "external-zones", "opening-sources", "toolbox")
    artifact_rows = []
    for root_name in generated_roots:
        for path in sorted((output / root_name).rglob("*")):
            if path.is_file():
                artifact_rows.append(
                    {
                        "path": path.relative_to(output).as_posix(),
                        "sha256": sha256_bytes(path.read_bytes()),
                    }
                )
    checkpoints = {
        "schema_version": "causalfrontier.calibration-v2-example-checkpoints.v1",
        "status": "LOCAL_EXAMPLE_CHECKPOINT_NOT_INDEPENDENT_CUSTODY",
        "fixed_parameter": FIXED_PARAMETER,
        "protocol_id": PROTOCOL_ID,
        "protocol_checkpoints": protocol_checkpoints,
        "report_semantic_sha256": report["report_sha256"],
        "artifact_files_n": len(artifact_rows),
        "artifacts": artifact_rows,
        "calibration_only": True,
        "method_recovery_pass": False,
        "scientific_claim_ready": False,
        "nonclaims": [
            "This local checkpoint is not an independent timestamp, custody witness, or rollback-resistant log.",
            "The source and opening cards are current metadata reconstructions, not preserved historical bytes.",
            "Declared reviews are not signed, credentialed, independent, or externally phase-attested.",
            "No patient, clinical, publication, wet-lab, material, scoring, or execution authority is granted.",
        ],
    }
    _write_json(output / "checkpoints.json", checkpoints)
    return checkpoints


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new directory for a rehearsal bound to the executing module; existing directories are refused",
    )
    args = parser.parse_args()
    try:
        checkpoints = generate(args.output)
        print(canonical_bytes(checkpoints).decode("utf-8"))
    except (OSError, CausalFrontierError) as exc:
        if isinstance(exc, CausalFrontierError):
            diagnostic = exc.diagnostic()
        elif exc.errno == errno.EEXIST:
            diagnostic = CausalFrontierError(
                "output already exists", reason_code="OUTPUT_EXISTS", operation="example_generate", errno=exc.errno
            ).diagnostic()
        else:
            diagnostic = io_error(exc, "example generation failed", operation="example_generate").diagnostic()
        print(
            canonical_bytes({"schema_version": "causalfrontier.error.v1", **diagnostic}).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
