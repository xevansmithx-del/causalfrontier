"""Conservative, no-write assessment of synthetic registry candidates.

The registry boundary exists to detect one dangerous failure mode before a
scientific challenge can be mistaken for evidence: several differently named
cases may be the same decision problem.  This module replays exact challenge,
race, entrant-view, and nonce checkpoints and compares label-invariant typed
graphs.  It never registers a candidate, accepts a separately designated
outcome channel, or emits a score.  Because it necessarily reads frozen case
text and source bytes, it does not claim that those arbitrary contents cannot
encode outcome information.

Graph refinement is used only to prune an exact, bounded isomorphism search.
Equality is reported only after an attribute-, direction-, edge-label-, and
multiplicity-preserving bijection is found.  Search exhaustion is a NO_CALL,
never evidence that two cases differ.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations, permutations
from pathlib import Path
from typing import Any

from . import blind
from .canonical import CausalFrontierError, canonical_bytes, require_sha256, sha256_bytes
from .challenge import load_protocol_cases
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

SCHEMA_VERSION = "causalfrontier.registry-candidate-steward-assessment.v1"
STATUS = "REGISTRY_CANDIDATE_ASSESSED_SCIENTIFIC_SCORING_DISABLED"
IMPLEMENTATION_STATUS = "LOCAL_UNRELEASED_NO_WRITE_REGISTRY_CANDIDATE_ASSESSMENT"
AUDIENCE = "STEWARD_ONLY"
ASSESSMENT_STATES = frozenset(
    {
        "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED",
        "NO_CALL_CANONICALIZATION_LIMIT",
        "NO_CALL_STRUCTURAL_SIMILARITY",
        "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED",
    }
)

MAX_GRAPH_NODES = 512
MAX_GRAPH_EDGES = 16384
MAX_ISOMORPHISM_SEARCH_STATES = 200_000
MAX_ISOMORPHISM_WORK_UNITS = 2_000_000
MAX_ASSESSMENT_ISOMORPHISM_WORK_UNITS = 8_000_000


class _GraphLimitExceeded(CausalFrontierError):
    """Internal signal that a valid case exceeded the bounded comparison surface."""


GRAPH_LAYERS = (
    "STEWARD_FULL",
    "CAUSAL_TOPOLOGY",
    "EXECUTION_CONTRACT",
    "ENTRANT_GEOMETRY",
)
EVIDENCE_LAYERS = ("DECISION_CRITICAL_EVIDENCE", "ALL_EVIDENCE")
ALL_LAYERS = (*GRAPH_LAYERS[:3], *EVIDENCE_LAYERS, GRAPH_LAYERS[3])

NONCLAIMS = (
    "This steward-only assessment is not a registry write, prospective registration, or admission decision.",
    "An exact structural match is evidence of a duplicate representation, not proof of shared authorship or intent.",
    "No detected v1 structural match is not proof of semantic, domain, encoder, store, or scientific independence.",
    "Exact source-byte identity is not semantic identity, and different bytes are not evidence of different science.",
    "Declared domain, control, organization, and store labels do not establish independent governance or custody.",
    "Opaque entrant identifiers are replayed for binding; the report is not a public unlinkable projection.",
    "Caller-supplied digests are checked exactly but do not prove independent storage, time, currentness, or "
    "rollback resistance.",
    "No separately designated oracle, opening, or outcome input is accepted; arbitrary frozen text and source "
    "bytes are read, so content-level outcome isolation is not verified.",
    "Patient-level data and material action are prohibited and outside the declared scope; synthetic labels and "
    "pattern screens do not verify content-level absence.",
    "No scientific baseline or score is accepted or evaluated.",
    "No clinical, human-decision, material-execution, prospective, publication, or release authority is granted.",
)

REPORT_CORE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "implementation_status",
        "audience",
        "base_compiler_version",
        "fixed_parameter",
        "boundary",
        "scope",
        "challenge_manifest_sha256",
        "challenge_sequence",
        "race_spec_sha256",
        "entrant_view_checkpoint_sha256",
        "nonce_checkpoint_sha256",
        "graph_contract",
        "graph_contract_sha256",
        "cases_n",
        "declared_domains_n",
        "declared_control_classes_n",
        "layer_equivalence",
        "pair_collision_patterns",
        "structural_collision_pairs_n",
        "structural_collision_group_sizes",
        "unresolved_similarity_pairs_n",
        "canonicalization_no_call_pairs_n",
        "assessment_state",
        "candidate_registered",
        "registration_write_performed",
        "designated_outcome_input_accepted",
        "content_outcome_isolation_verified",
        "semantic_cohort_uniqueness_verified",
        "domain_independence_verified",
        "encoder_independence_verified",
        "store_independence_verified",
        "temporal_admissibility_verified",
        "prospective_registration_verified",
        "privacy_certified",
        "scientific_scoring_ready",
        "gates",
        "nonclaims",
    }
)
REPORT_KEYS = REPORT_CORE_KEYS | {"assessment_sha256"}
FIXED_FALSE_FIELDS = frozenset(
    {
        "candidate_registered",
        "registration_write_performed",
        "designated_outcome_input_accepted",
        "content_outcome_isolation_verified",
        "semantic_cohort_uniqueness_verified",
        "domain_independence_verified",
        "encoder_independence_verified",
        "store_independence_verified",
        "temporal_admissibility_verified",
        "prospective_registration_verified",
        "privacy_certified",
        "scientific_scoring_ready",
    }
)
FIXED_GATES = {
    "ARTIFACT_INTEGRITY": ("PASS", "Exact challenge artifacts and total branch matrices replayed."),
    "AUTHORITY_BOUNDARY": ("PASS", "Assessment performed read-only synthetic/software computation only."),
    "BRANCH_TOTALITY": ("PASS", "Existing frozen-case validation replayed every total branch matrix."),
    "CONTENT_OUTCOME_ISOLATION": (
        "NO_CALL",
        "Arbitrary frozen text and source bytes may encode outcome information.",
    ),
    "CONTROL_VALIDITY": ("NO_CALL", "Declared control labels were not scientifically adjudicated."),
    "DECLARED_DOMAIN_VALIDITY": (
        "NO_CALL",
        "Submitted domain labels do not establish scientific diversity.",
    ),
    "ENCODER_INDEPENDENCE": ("NO_CALL", "Organization strings do not prove independent controllers."),
    "EXPLICIT_OUTCOME_CHANNEL_ABSENCE": (
        "PASS",
        "The API accepts no separately designated oracle, opening, reveal, outcome, or score input.",
    ),
    "GOVERNANCE": ("NO_CALL", "No reviewed admission authority or policy was supplied."),
    "PRIVACY_CERTIFICATION": (
        "NO_CALL",
        "Synthetic-only scope and pattern screens are not certification.",
    ),
    "RACE_VIEW_NONCE_REPLAY": ("PASS", "The exact entrant view replayed from all bound checkpoints."),
    "ROLLBACK_RESISTANCE": (
        "NO_CALL",
        "Caller checkpoints are not independently stored monotonic witnesses.",
    ),
    "SCIENTIFIC_SCORING": ("NO_CALL", "No scientific baseline, outcome, resource, or score was evaluated."),
    "STORE_INDEPENDENCE": ("NO_CALL", "No independently governed storage witnesses were supplied."),
    "TEMPORAL_ORDER_AND_CURRENTNESS": (
        "NO_CALL",
        "No independent prospective time or currentness proof was supplied.",
    ),
}
STRUCTURAL_GATE_BY_STATE = {
    "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED": (
        "REJECT",
        "Exact v1 normalized steward collisions were verified; excluded prose still requires semantic review.",
    ),
    "NO_CALL_CANONICALIZATION_LIMIT": (
        "NO_CALL",
        "At least one bounded graph construction or exact comparison exceeded its limit.",
    ),
    "NO_CALL_STRUCTURAL_SIMILARITY": (
        "NO_CALL",
        "At least one non-decisive structural layer matched; independence cannot be inferred.",
    ),
    "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED": (
        "PASS_NO_V1_COLLISION_DETECTED_NOT_INDEPENDENCE",
        "The bounded v1 screen found no exact steward duplicate; this is not an independence claim.",
    ),
}


def graph_contract() -> dict[str, Any]:
    """Return the frozen v1 comparison contract."""

    return {
        "schema_version": "causalfrontier.registry-graph-contract.v1",
        "comparison": "BOUNDED_EXACT_COLORED_DIRECTED_MULTIGRAPH_ISOMORPHISM",
        "refinement_role": "PRUNING_ONLY_NOT_IDENTITY_PROOF",
        "case_aggregation": "UNORDERED_MULTISET_OF_ENCODER_LANES",
        "steward_full": {
            "sources": "DECISION_CRITICAL_WITH_EXACT_BYTE_SHA256_AND_SEMANTIC_STATE",
            "causal_incidence": True,
            "classifier_scalar_contract": True,
            "experiment_resources": True,
        },
        "causal_topology": {
            "sources": "DECISION_CRITICAL_WITHOUT_BYTE_SHA256",
            "causal_incidence": True,
            "classifier_scalar_contract": True,
            "experiment_resources": False,
        },
        "execution_contract": {
            "sources": "DECISION_CRITICAL_WITHOUT_BYTE_SHA256",
            "causal_incidence": True,
            "classifier_scalar_contract": True,
            "experiment_resources": True,
        },
        "entrant_geometry": {
            "case_budget": True,
            "action_tariffs": True,
            "eligible_and_co_minimax_incidence": True,
            "nonce_derived_aliases": False,
            "selection_projection_sha256": False,
        },
        "excluded_presentation_fields": [
            "opaque_entity_ids_but_not_operational_classifier_schema_or_selectors",
            "case_domain_control_and_organization_labels",
            "descriptions_labels_nonclaims_protocols_purposes_questions_titles",
            "paths_queries_source_locators_and_licenses",
            "timestamps",
            "id_sensitive_classifier_and_branch_digests",
            "nonce_derived_aliases_and_opaque_bindings",
        ],
        "limits": {
            "max_graph_nodes": MAX_GRAPH_NODES,
            "max_graph_edges": MAX_GRAPH_EDGES,
            "max_isomorphism_search_states_per_graph_pair": MAX_ISOMORPHISM_SEARCH_STATES,
            "max_isomorphism_work_units_per_graph_pair": MAX_ISOMORPHISM_WORK_UNITS,
            "max_isomorphism_work_units_per_assessment": MAX_ASSESSMENT_ISOMORPHISM_WORK_UNITS,
        },
        "bounded_search_presentation_dependence": (
            "OPAQUE_ID_TIE_BREAKING_MAY_DEGRADE_AN_ISOMORPHIC_RESULT_FROM_TRUE_TO_NO_CALL_NEVER_FALSE"
        ),
        "outcome_boundary": {
            "separately_designated_outcome_channel": "ABSENT",
            "arbitrary_bound_content_outcome_isolation": "NO_CALL",
        },
        "different_graph_meaning": "NO_V1_EXACT_MATCH_NOT_SEMANTIC_INDEPENDENCE",
        "search_exhaustion": "NO_CALL",
    }


def graph_contract_sha256() -> str:
    return sha256_bytes(canonical_bytes(graph_contract()))


def validate_assessment_report(
    value: Any,
    *,
    expected_manifest_sha256: str,
    expected_sequence: int,
    expected_race_spec_sha256: str,
    expected_view_checkpoint_sha256: str,
    expected_nonce_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Reject any report that could expand the fixed no-authority boundary."""

    message = "registry assessment violated fixed no-authority postconditions"
    try:
        if not isinstance(value, dict) or set(value) != REPORT_KEYS:
            raise ValueError
        core = {key: value[key] for key in REPORT_CORE_KEYS}
        if value["assessment_sha256"] != sha256_bytes(canonical_bytes(core)):
            raise ValueError
        if not (
            value["schema_version"] == SCHEMA_VERSION
            and value["status"] == STATUS
            and value["implementation_status"] == IMPLEMENTATION_STATUS
            and value["audience"] == AUDIENCE
            and value["base_compiler_version"] == COMPILER_VERSION
            and value["fixed_parameter"] == FIXED_PARAMETER
            and value["boundary"] == fixed_boundary()
            and value["scope"] == "SYNTHETIC_PROTOCOL_TEST"
            and value["challenge_manifest_sha256"] == expected_manifest_sha256
            and value["challenge_sequence"] == expected_sequence
            and value["race_spec_sha256"] == expected_race_spec_sha256
            and value["entrant_view_checkpoint_sha256"] == expected_view_checkpoint_sha256
            and value["nonce_checkpoint_sha256"] == expected_nonce_checkpoint_sha256
            and value["assessment_state"] in ASSESSMENT_STATES
            and value["graph_contract"] == graph_contract()
            and value["graph_contract_sha256"] == graph_contract_sha256()
            and value["nonclaims"] == list(NONCLAIMS)
            and all(value[field] is False for field in FIXED_FALSE_FIELDS)
        ):
            raise ValueError
        digest_fields = (
            "assessment_sha256",
            "challenge_manifest_sha256",
            "race_spec_sha256",
            "entrant_view_checkpoint_sha256",
            "nonce_checkpoint_sha256",
            "graph_contract_sha256",
        )
        if any(
            not isinstance(value[field], str)
            or len(value[field]) != 64
            or any(character not in "0123456789abcdef" for character in value[field])
            for field in digest_fields
        ):
            raise ValueError
        integer_fields = (
            "cases_n",
            "declared_domains_n",
            "declared_control_classes_n",
            "structural_collision_pairs_n",
            "unresolved_similarity_pairs_n",
            "canonicalization_no_call_pairs_n",
        )
        if any(type(value[field]) is not int or value[field] < 0 for field in integer_fields):
            raise ValueError
        cases_n = value["cases_n"]
        pairs_n = cases_n * (cases_n - 1) // 2
        if not (
            cases_n >= 3
            and 1 <= value["declared_domains_n"] <= cases_n
            and 1 <= value["declared_control_classes_n"] <= cases_n
            and value["structural_collision_pairs_n"] <= pairs_n
            and value["unresolved_similarity_pairs_n"] <= pairs_n
            and value["canonicalization_no_call_pairs_n"] <= pairs_n
            and value["structural_collision_pairs_n"] + value["unresolved_similarity_pairs_n"] <= pairs_n
        ):
            raise ValueError
        layer_reports = value["layer_equivalence"]
        if not isinstance(layer_reports, list) or len(layer_reports) != len(ALL_LAYERS):
            raise ValueError
        layer_equal_counts: dict[str, int] = {}
        layer_class_sizes: dict[str, list[int]] = {}
        graph_no_call_counts: list[int] = []
        for expected_layer, report in zip(ALL_LAYERS, layer_reports, strict=True):
            if not isinstance(report, dict) or set(report) != {
                "layer",
                "verified_equivalence_class_sizes",
                "equal_pairs_n",
                "unequal_pairs_n",
                "no_call_pairs_n",
            }:
                raise ValueError
            counts = (report["equal_pairs_n"], report["unequal_pairs_n"], report["no_call_pairs_n"])
            class_sizes = report["verified_equivalence_class_sizes"]
            if not (
                report["layer"] == expected_layer
                and all(type(count) is int and count >= 0 for count in counts)
                and sum(counts) == pairs_n
                and isinstance(class_sizes, list)
                and all(type(size) is int and size >= 1 for size in class_sizes)
                and sum(class_sizes) == cases_n
                and class_sizes == sorted(class_sizes, reverse=True)
                and sum(size - 1 for size in class_sizes) <= report["equal_pairs_n"]
                and report["equal_pairs_n"] <= sum(size * (size - 1) // 2 for size in class_sizes)
                and (expected_layer not in EVIDENCE_LAYERS or report["no_call_pairs_n"] == 0)
            ):
                raise ValueError
            layer_equal_counts[expected_layer] = report["equal_pairs_n"]
            layer_class_sizes[expected_layer] = class_sizes
            if expected_layer in GRAPH_LAYERS:
                graph_no_call_counts.append(report["no_call_pairs_n"])
        patterns = value["pair_collision_patterns"]
        if not isinstance(patterns, list):
            raise ValueError
        pattern_total = 0
        pattern_equal_counts = Counter()
        expected_unresolved_n = 0
        prior_pattern: tuple[str, ...] | None = None
        for pattern in patterns:
            if not isinstance(pattern, dict) or set(pattern) != {"matched_layers", "pairs_n"}:
                raise ValueError
            matched = pattern["matched_layers"]
            count = pattern["pairs_n"]
            if not isinstance(matched, list) or any(not isinstance(layer, str) for layer in matched):
                raise ValueError
            matched_tuple = tuple(matched)
            if (
                matched != [layer for layer in ALL_LAYERS if layer in set(matched)]
                or type(count) is not int
                or count <= 0
                or (prior_pattern is not None and matched_tuple <= prior_pattern)
            ):
                raise ValueError
            prior_pattern = matched_tuple
            pattern_total += count
            pattern_equal_counts.update(dict.fromkeys(matched, count))
            if "STEWARD_FULL" not in matched and any(
                layer in matched
                for layer in (
                    "CAUSAL_TOPOLOGY",
                    "EXECUTION_CONTRACT",
                    "DECISION_CRITICAL_EVIDENCE",
                    "ALL_EVIDENCE",
                )
            ):
                expected_unresolved_n += count
        if pattern_total != pairs_n or any(
            pattern_equal_counts[layer] != layer_equal_counts[layer] for layer in ALL_LAYERS
        ):
            raise ValueError
        canonicalization_n = value["canonicalization_no_call_pairs_n"]
        if not (
            max(graph_no_call_counts) <= canonicalization_n <= min(pairs_n, sum(graph_no_call_counts))
            and value["unresolved_similarity_pairs_n"] == expected_unresolved_n
        ):
            raise ValueError
        group_sizes = value["structural_collision_group_sizes"]
        if not (
            isinstance(group_sizes, list)
            and all(type(size) is int and 2 <= size <= cases_n for size in group_sizes)
            and group_sizes == sorted(group_sizes, reverse=True)
            and sum(group_sizes) <= cases_n
            and bool(group_sizes) == bool(value["structural_collision_pairs_n"])
            and layer_equal_counts["STEWARD_FULL"] == value["structural_collision_pairs_n"]
            and group_sizes == [size for size in layer_class_sizes["STEWARD_FULL"] if size > 1]
        ):
            raise ValueError
        expected_state = (
            "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED"
            if value["structural_collision_pairs_n"]
            else "NO_CALL_CANONICALIZATION_LIMIT"
            if value["canonicalization_no_call_pairs_n"]
            else "NO_CALL_STRUCTURAL_SIMILARITY"
            if value["unresolved_similarity_pairs_n"]
            else "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED"
        )
        if value["assessment_state"] != expected_state:
            raise ValueError
        structural_state, structural_reason = STRUCTURAL_GATE_BY_STATE[expected_state]
        expected_gates = [
            *(_gate(gate_id, state, reason) for gate_id, (state, reason) in FIXED_GATES.items()),
            _gate("STRUCTURAL_CLONE_DETECTION", structural_state, structural_reason),
        ]
        if value["gates"] != sorted(expected_gates, key=lambda gate: gate["id"]):
            raise ValueError
    except Exception:
        raise CausalFrontierError(message) from None
    return value


def _graph() -> dict[str, Any]:
    return {"nodes": {}, "edges": []}


def _key(kind: str, *parts: str) -> str:
    """Encode an internal node tuple injectively without exposing it in output."""

    return canonical_bytes([kind, *parts]).decode("utf-8")


def _node(graph: dict[str, Any], key: str, kind: str, features: dict[str, Any]) -> None:
    if key in graph["nodes"]:
        raise CausalFrontierError("registry graph contains a duplicate internal node")
    if len(graph["nodes"]) >= MAX_GRAPH_NODES:
        raise _GraphLimitExceeded("registry graph exceeds the bounded v1 node contract")
    graph["nodes"][key] = {"kind": kind, "features": features}


def _edge(graph: dict[str, Any], source: str, label: str, target: str) -> None:
    if source not in graph["nodes"] or target not in graph["nodes"]:
        raise CausalFrontierError("registry graph edge references an unknown internal node")
    if len(graph["edges"]) >= MAX_GRAPH_EDGES:
        raise _GraphLimitExceeded("registry graph exceeds the bounded v1 edge contract")
    graph["edges"].append((source, label, target))


def _finish_graph(graph: dict[str, Any]) -> dict[str, Any]:
    if len(graph["nodes"]) > MAX_GRAPH_NODES or len(graph["edges"]) > MAX_GRAPH_EDGES:
        raise _GraphLimitExceeded("registry graph exceeds the bounded v1 comparison contract")
    graph["edges"] = sorted(graph["edges"])
    return graph


def _critical_source_ids(case: dict[str, Any]) -> set[str]:
    result = {source_id for world in case["worlds"] for source_id in world["source_ids"]}
    for experiment in case["experiments"]:
        result.add(experiment["classifier"]["source_id"])
        result.update(source_id for prediction in experiment["predictions"] for source_id in prediction["source_ids"])
    return result


def _source_features(source: dict[str, Any], *, include_bytes: bool) -> dict[str, Any]:
    features = {
        "data_class": source["data_class"],
        "authority": source["authority"],
        "temporal_basis": source["temporal_basis"],
        "retrieval_state": source["retrieval_state"],
        "semantic_state": source["semantic_state"],
        "coverage_complete": source["coverage_complete"],
    }
    if include_bytes:
        features["sha256"] = source["sha256"]
    return features


def _classifier_features(classifier: dict[str, Any], *, normalize_operational_tokens: bool) -> dict[str, Any]:
    rule = classifier["rule"]
    result: dict[str, Any] = {
        "schema_version": classifier["schema_version"],
        "engine": classifier["engine"],
        "rule_kind": rule["kind"],
    }
    if normalize_operational_tokens:
        result.update(
            {
                "role_columns": ["GROUP", "INTERVENTION", "VALUE"],
                "intervention_roles": ["CANDIDATE", "COMPARATOR"],
            }
        )
    else:
        result.update(
            {
                "input_columns": list(classifier["input_columns"]),
                "group_column": rule["group_column"],
                "intervention_column": rule["intervention_column"],
                "value_column": rule["value_column"],
                "candidate_value": rule["candidate_value"],
                "comparator_value": rule["comparator_value"],
            }
        )
    if rule["kind"] in {"GROUPED_CONTRAST_RANGE_V1", "GROUPED_SHARED_VALUE_RANGE_V1"}:
        result.update(
            {
                "minimum_groups": rule["minimum_groups"],
                "low_max": rule["low_max"],
                "high_min": rule["high_min"],
            }
        )
    else:
        result.update(
            {
                "training_groups_n": len(rule["training_groups"]),
                "outside_margin_min": rule["outside_margin_min"],
            }
        )
        if not normalize_operational_tokens:
            result.update(
                {
                    "training_groups": sorted(rule["training_groups"]),
                    "heldout_group": rule["heldout_group"],
                }
            )
    return result


def _steward_lane_graph(case: dict[str, Any], *, include_bytes: bool, include_resources: bool) -> dict[str, Any]:
    graph = _graph()
    critical_sources = _critical_source_ids(case)
    sources = {source["id"]: source for source in case["provenance"] if source["id"] in critical_sources}
    if set(sources) != critical_sources:
        raise CausalFrontierError("registry graph cannot resolve every decision-critical source")

    decision_key = _key("decision")
    _node(graph, decision_key, "DECISION", {})
    defer_id = case["decision"]["defer_option_id"]
    for option in case["decision"]["options"]:
        key = _key("option", option["id"])
        _node(graph, key, "OPTION", {"role": "DEFER" if option["id"] == defer_id else "SUBSTANTIVE"})
        _edge(graph, decision_key, "HAS_OPTION", key)

    for source_id, source in sources.items():
        _node(graph, _key("source", source_id), "SOURCE", _source_features(source, include_bytes=include_bytes))

    for gate in case["gates"]:
        _node(
            graph,
            _key("gate", gate["id"]),
            "GATE",
            {"state": gate["state"], "authority": gate["authority"]},
        )

    for world in case["worlds"]:
        world_key = _key("world", world["id"])
        _node(graph, world_key, "WORLD", {"is_residual": world["is_residual"]})
        _edge(graph, decision_key, "HAS_WORLD", world_key)
        for option_id in world["admissible_option_ids"]:
            _edge(graph, world_key, "ADMITS_OPTION", _key("option", option_id))
        for source_id in world["source_ids"]:
            _edge(graph, world_key, "SUPPORTED_BY_SOURCE", _key("source", source_id))

    for experiment in case["experiments"]:
        experiment_key = _key("experiment", experiment["id"])
        features: dict[str, Any] = {
            "execution_class": experiment["execution_class"],
            "required_authorities": sorted(experiment["required_authorities"]),
            "outcome_partition": experiment["outcome_partition"],
            "classifier": _classifier_features(
                experiment["classifier"],
                normalize_operational_tokens=not include_bytes and not include_resources,
            ),
        }
        if include_resources:
            features["resources"] = experiment["resources"]
        _node(graph, experiment_key, "EXPERIMENT", features)
        _edge(graph, decision_key, "HAS_EXPERIMENT", experiment_key)
        for gate_id in experiment["required_gate_ids"]:
            _edge(graph, experiment_key, "REQUIRES_GATE", _key("gate", gate_id))
        _edge(
            graph,
            experiment_key,
            "CLASSIFIER_USES_SOURCE",
            _key("source", experiment["classifier"]["source_id"]),
        )

        outcome_map = experiment["classifier"]["outcome_map"]
        token_by_outcome = {outcome_id: token for token, outcome_id in outcome_map.items()}
        for outcome in experiment["outcomes"]:
            outcome_key = _key("outcome", experiment["id"], outcome["id"])
            _node(
                graph,
                outcome_key,
                "OUTCOME",
                {"class": outcome["class"], "classifier_token": token_by_outcome[outcome["id"]]},
            )
            _edge(graph, experiment_key, "HAS_OUTCOME", outcome_key)
            _edge(graph, experiment_key, "CLASSIFIER_TOKEN_" + token_by_outcome[outcome["id"]], outcome_key)

        for prediction in experiment["predictions"]:
            prediction_key = _key(
                "prediction",
                experiment["id"],
                prediction["world_id"],
                prediction["outcome_id"],
            )
            _node(graph, prediction_key, "PREDICTION", {"relation": prediction["relation"]})
            _edge(graph, experiment_key, "HAS_PREDICTION", prediction_key)
            _edge(graph, prediction_key, "PREDICTS_WORLD", _key("world", prediction["world_id"]))
            _edge(
                graph,
                prediction_key,
                "PREDICTS_OUTCOME",
                _key("outcome", experiment["id"], prediction["outcome_id"]),
            )
            for source_id in prediction["source_ids"]:
                _edge(graph, prediction_key, "SUPPORTED_BY_SOURCE", _key("source", source_id))
    return _finish_graph(graph)


def _entrant_case_graph(view: dict[str, Any], entrant_case: dict[str, Any]) -> dict[str, Any]:
    graph = _graph()
    _node(
        graph,
        _key("entrant-case"),
        "ENTRANT_CASE",
        {
            "budget": entrant_case["budget"],
            "required_replicates": view["required_replicates"],
            "resource_accounting_mode": view["resource_accounting_mode"],
            "resource_dimensions": view["resource_dimensions"],
            "policy_contract_sha256": view["policy_contract_sha256"],
        },
    )
    for tariff in entrant_case["action_batch_tariffs"]:
        action_key = _key("entrant-action", tariff["entrant_action_id"])
        _node(graph, action_key, "ACTION", {"resources": tariff["resources"]})
        _edge(graph, _key("entrant-case"), "HAS_ACTION", action_key)
    for lane in entrant_case["lanes"]:
        lane_key = _key("entrant-lane", lane["entrant_lane_id"])
        _node(graph, lane_key, "LANE", {})
        _edge(graph, _key("entrant-case"), "HAS_LANE", lane_key)
        for action_id in lane["eligible_action_ids"]:
            _edge(graph, lane_key, "ELIGIBLE", _key("entrant-action", action_id))
        for action_id in lane["co_minimax_action_ids"]:
            _edge(graph, lane_key, "CO_MINIMAX", _key("entrant-action", action_id))
    return _finish_graph(graph)


def _evidence_fingerprint(case: dict[str, Any], *, critical_only: bool) -> str:
    allowed = _critical_source_ids(case) if critical_only else {source["id"] for source in case["provenance"]}
    records = [_source_features(source, include_bytes=True) for source in case["provenance"] if source["id"] in allowed]
    domain = (
        "causalfrontier.registry-decision-critical-evidence.v1"
        if critical_only
        else "causalfrontier.registry-all-evidence.v1"
    )
    return sha256_bytes(canonical_bytes({"domain": domain, "records": sorted(records, key=canonical_bytes)}))


def _joint_refinement(
    left: dict[str, Any], right: dict[str, Any], consume_work: Any = None
) -> tuple[dict[str, int], dict[str, int]] | None:
    graphs = (left, right)
    base: dict[tuple[int, str], bytes] = {}
    for graph_index, graph in enumerate(graphs):
        for node_id, attributes in graph["nodes"].items():
            base[(graph_index, node_id)] = canonical_bytes(attributes)
    initial_tokens = sorted(set(base.values()))
    token_colors = {token: index for index, token in enumerate(initial_tokens)}
    colors = {node: token_colors[token] for node, token in base.items()}
    prior_classes = len(set(colors.values()))

    incoming: dict[tuple[int, str], list[tuple[str, str]]] = defaultdict(list)
    outgoing: dict[tuple[int, str], list[tuple[str, str]]] = defaultdict(list)
    for graph_index, graph in enumerate(graphs):
        for source, label, target in graph["edges"]:
            outgoing[(graph_index, source)].append((label, target))
            incoming[(graph_index, target)].append((label, source))

    for _round in range(len(colors) + 1):
        if consume_work is not None:
            consume_work(len(colors) + 2 * (len(left["edges"]) + len(right["edges"])))
        signatures: dict[tuple[int, str], bytes] = {}
        for node in colors:
            graph_index, _node_id = node
            signatures[node] = canonical_bytes(
                {
                    "base_sha256": sha256_bytes(base[node]),
                    "prior_color": colors[node],
                    "incoming": sorted([label, colors[(graph_index, neighbor)]] for label, neighbor in incoming[node]),
                    "outgoing": sorted([label, colors[(graph_index, neighbor)]] for label, neighbor in outgoing[node]),
                }
            )
        unique = sorted(set(signatures.values()))
        signature_colors = {signature: index for index, signature in enumerate(unique)}
        refined = {node: signature_colors[signature] for node, signature in signatures.items()}
        refined_classes = len(unique)
        colors = refined
        if refined_classes == prior_classes:
            return (
                {node_id: color for (graph_index, node_id), color in colors.items() if graph_index == 0},
                {node_id: color for (graph_index, node_id), color in colors.items() if graph_index == 1},
            )
        prior_classes = refined_classes
    return None


def _graphs_isomorphic(
    left: dict[str, Any],
    right: dict[str, Any],
    assessment_work_budget: list[int] | None = None,
) -> bool | None:
    if left == right:
        return True
    if len(left["nodes"]) != len(right["nodes"]) or len(left["edges"]) != len(right["edges"]):
        return False
    if Counter(canonical_bytes(value) for value in left["nodes"].values()) != Counter(
        canonical_bytes(value) for value in right["nodes"].values()
    ):
        return False
    search_states = 0
    work_units = 0

    class _BudgetExceeded(Exception):
        pass

    def consume(units: int = 1) -> None:
        nonlocal work_units
        if assessment_work_budget is not None:
            if assessment_work_budget[0] < units:
                raise _BudgetExceeded
            assessment_work_budget[0] -= units
        work_units += units
        if work_units > MAX_ISOMORPHISM_WORK_UNITS:
            raise _BudgetExceeded

    try:
        refined = _joint_refinement(left, right, consume)
    except _BudgetExceeded:
        return None
    if refined is None:
        return None
    left_colors, right_colors = refined
    if Counter(left_colors.values()) != Counter(right_colors.values()):
        return False

    right_by_color: dict[int, list[str]] = defaultdict(list)
    for node_id, color in right_colors.items():
        right_by_color[color].append(node_id)
    for candidates in right_by_color.values():
        candidates.sort()

    mapping: dict[str, str] = {}
    used: set[str] = set()
    left_between: dict[tuple[str, str], Counter[str]] = {}
    right_between: dict[tuple[str, str], Counter[str]] = {}
    left_degree: Counter[str] = Counter()
    try:
        consume(len(left["edges"]) + len(right["edges"]))
    except _BudgetExceeded:
        return None
    for source, label, target in left["edges"]:
        left_between.setdefault((source, target), Counter())[label] += 1
        left_degree[source] += 1
        left_degree[target] += 1
    for source, label, target in right["edges"]:
        right_between.setdefault((source, target), Counter())[label] += 1
    empty_edges: Counter[str] = Counter()

    def compatible(left_node: str, right_node: str) -> bool:
        consume()
        if canonical_bytes(left["nodes"][left_node]) != canonical_bytes(right["nodes"][right_node]):
            return False
        if left_between.get((left_node, left_node), empty_edges) != right_between.get(
            (right_node, right_node), empty_edges
        ):
            return False
        for mapped_left, mapped_right in mapping.items():
            consume(2)
            if left_between.get((left_node, mapped_left), empty_edges) != right_between.get(
                (right_node, mapped_right), empty_edges
            ):
                return False
            if left_between.get((mapped_left, left_node), empty_edges) != right_between.get(
                (mapped_right, right_node), empty_edges
            ):
                return False
        return True

    left_by_color: dict[int, list[str]] = defaultdict(list)
    for node_id, color in left_colors.items():
        left_by_color[color].append(node_id)
    for color, right_nodes in right_by_color.items():
        left_nodes = left_by_color[color]
        if len(left_nodes) == len(right_nodes) == 1:
            mapping[left_nodes[0]] = right_nodes[0]
            used.add(right_nodes[0])

    def choose() -> tuple[str, list[str]] | None:
        choices = []
        for left_node, color in left_colors.items():
            if left_node in mapping:
                continue
            candidates = [
                right_node
                for right_node in right_by_color[color]
                if right_node not in used and compatible(left_node, right_node)
            ]
            if not candidates:
                return left_node, []
            choices.append((len(candidates), -left_degree[left_node], left_node, candidates))
        if not choices:
            return None
        _count, _degree, left_node, candidates = min(choices, key=lambda item: item[:3])
        return left_node, candidates

    def search() -> bool | None:
        nonlocal search_states
        if len(mapping) == len(left["nodes"]):
            remapped = Counter((mapping[source], label, mapping[target]) for source, label, target in left["edges"])
            return remapped == Counter(right["edges"])
        choice = choose()
        if choice is None:
            return True
        left_node, candidates = choice
        if not candidates:
            return False
        for right_node in candidates:
            search_states += 1
            if search_states > MAX_ISOMORPHISM_SEARCH_STATES:
                return None
            mapping[left_node] = right_node
            used.add(right_node)
            result = search()
            if result is True:
                return True
            used.remove(right_node)
            del mapping[left_node]
            if result is None:
                return None
        return False

    try:
        return search()
    except _BudgetExceeded:
        return None


def _case_graphs_isomorphic(
    left: list[dict[str, Any]],
    right: list[dict[str, Any]],
    assessment_work_budget: list[int] | None = None,
) -> bool | None:
    if len(left) != len(right):
        return False
    unresolved = False
    for ordering in permutations(range(len(right))):
        permutation_unresolved = False
        for left_index, right_index in enumerate(ordering):
            result = _graphs_isomorphic(
                left[left_index],
                right[right_index],
                assessment_work_budget,
            )
            if result is False:
                break
            if result is None:
                permutation_unresolved = True
                break
        else:
            return True
        unresolved = unresolved or permutation_unresolved
    return None if unresolved else False


def _replay_inputs(
    challenge_root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    entrant_view_path: Path,
    expected_view_checkpoint_sha256: str,
    nonce_path: Path,
    expected_nonce_checkpoint_sha256: str,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, Any], bytes]:
    require_sha256(expected_manifest_sha256, "challenge manifest checkpoint")
    require_sha256(expected_race_spec_sha256, "race specification checkpoint")
    require_sha256(expected_view_checkpoint_sha256, "entrant view checkpoint")
    require_sha256(expected_nonce_checkpoint_sha256, "nonce checkpoint")
    preflight, case_lanes = load_protocol_cases(challenge_root, expected_manifest_sha256, expected_sequence)
    if preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST":
        raise CausalFrontierError("registry candidate assessment v1 is restricted to synthetic protocol tests")
    _raw_view, view_value = blind._read_checkpointed_json(
        entrant_view_path, expected_view_checkpoint_sha256, "registry entrant view"
    )
    view = blind._validate_view(view_value)
    nonce = blind.read_checkpointed_blinding_nonce(nonce_path, expected_nonce_checkpoint_sha256)
    rebuilt = blind.build_sanitized_entrant_view(
        challenge_root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        nonce,
    )
    if canonical_bytes(rebuilt) != canonical_bytes(view):
        raise CausalFrontierError("registry entrant view does not exactly replay from challenge, race, and nonce")
    return preflight, case_lanes, view, nonce


def _union_class_sizes(items: list[str], equal_pairs: set[tuple[str, str]]) -> list[int]:
    parent = {item: item for item in items}

    def root(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for left, right in equal_pairs:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[right_root] = left_root
    sizes = Counter(root(item) for item in items)
    return sorted(sizes.values(), reverse=True)


def _gate(gate_id: str, state: str, reason: str) -> dict[str, str]:
    return {"id": gate_id, "state": state, "reason": reason}


def assess_registry_candidate(
    challenge_root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    entrant_view_path: Path,
    expected_view_checkpoint_sha256: str,
    nonce_path: Path,
    expected_nonce_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Assess a steward candidate without writing, a reveal channel, or scoring.

    The strongest positive result is that this bounded v1 screen found no exact
    structural duplicate.  Every candidate remains unregistered and all
    scientific-independence and prospective-admissibility gates remain NO_CALL.
    """

    first = _replay_inputs(
        challenge_root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        entrant_view_path,
        expected_view_checkpoint_sha256,
        nonce_path,
        expected_nonce_checkpoint_sha256,
    )
    preflight, case_lanes, view, nonce = first
    case_ids = sorted(case_lanes)
    if len(case_ids) < 3:
        raise CausalFrontierError("registry candidate must contain at least three cases")

    entrant_by_alias = {item["entrant_case_id"]: item for item in view["cases"]}
    registration_sha256 = preflight["challenge_registration_sha256"]
    layers: dict[str, dict[str, Any]] = {layer: {} for layer in ALL_LAYERS}
    for case_id in case_ids:
        lanes = case_lanes[case_id]
        representative = lanes[0]["case"]
        layers["DECISION_CRITICAL_EVIDENCE"][case_id] = _evidence_fingerprint(representative, critical_only=True)
        layers["ALL_EVIDENCE"][case_id] = _evidence_fingerprint(representative, critical_only=False)

    graph_construction_limited = False
    try:
        for case_id in case_ids:
            lanes = case_lanes[case_id]
            layers["STEWARD_FULL"][case_id] = [
                _steward_lane_graph(lane["case"], include_bytes=True, include_resources=True) for lane in lanes
            ]
            layers["CAUSAL_TOPOLOGY"][case_id] = [
                _steward_lane_graph(lane["case"], include_bytes=False, include_resources=False) for lane in lanes
            ]
            layers["EXECUTION_CONTRACT"][case_id] = [
                _steward_lane_graph(lane["case"], include_bytes=False, include_resources=True) for lane in lanes
            ]
            alias = blind._opaque_id("case", case_id, registration_sha256, nonce)
            if alias not in entrant_by_alias:
                raise CausalFrontierError("registry cannot bind a steward case to the replayed entrant view")
            layers["ENTRANT_GEOMETRY"][case_id] = _entrant_case_graph(view, entrant_by_alias[alias])
    except _GraphLimitExceeded:
        graph_construction_limited = True

    pair_results: dict[tuple[str, str], dict[str, bool | None]] = {}
    assessment_work_budget = [MAX_ASSESSMENT_ISOMORPHISM_WORK_UNITS]
    for left, right in combinations(case_ids, 2):
        results: dict[str, bool | None] = {}
        for layer in ALL_LAYERS:
            if layer in EVIDENCE_LAYERS:
                results[layer] = layers[layer][left] == layers[layer][right]
            elif graph_construction_limited:
                results[layer] = None
            elif layer == "ENTRANT_GEOMETRY":
                results[layer] = _graphs_isomorphic(
                    layers[layer][left],
                    layers[layer][right],
                    assessment_work_budget,
                )
            else:
                results[layer] = _case_graphs_isomorphic(
                    layers[layer][left],
                    layers[layer][right],
                    assessment_work_budget,
                )
        pair_results[(left, right)] = results

    layer_reports = []
    for layer in ALL_LAYERS:
        equal_pairs = {pair for pair, results in pair_results.items() if results[layer] is True}
        no_call_n = sum(results[layer] is None for results in pair_results.values())
        unequal_n = sum(results[layer] is False for results in pair_results.values())
        layer_reports.append(
            {
                "layer": layer,
                "verified_equivalence_class_sizes": _union_class_sizes(case_ids, equal_pairs),
                "equal_pairs_n": len(equal_pairs),
                "unequal_pairs_n": unequal_n,
                "no_call_pairs_n": no_call_n,
            }
        )

    collision_pairs: set[tuple[str, str]] = set()
    unresolved_pairs: set[tuple[str, str]] = set()
    canonicalization_no_call_pairs: set[tuple[str, str]] = set()
    patterns: Counter[tuple[str, ...]] = Counter()
    for pair, results in pair_results.items():
        matched = tuple(layer for layer in ALL_LAYERS if results[layer] is True)
        patterns[matched] += 1
        if any(results[layer] is None for layer in GRAPH_LAYERS):
            canonicalization_no_call_pairs.add(pair)
        if results["STEWARD_FULL"] is True:
            collision_pairs.add(pair)
        elif any(
            results[layer] is True
            for layer in (
                "CAUSAL_TOPOLOGY",
                "EXECUTION_CONTRACT",
                "DECISION_CRITICAL_EVIDENCE",
                "ALL_EVIDENCE",
            )
        ):
            unresolved_pairs.add(pair)

    collision_group_sizes = [size for size in _union_class_sizes(case_ids, collision_pairs) if size > 1]
    if collision_pairs:
        assessment_state = "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED"
    elif canonicalization_no_call_pairs:
        assessment_state = "NO_CALL_CANONICALIZATION_LIMIT"
    elif unresolved_pairs:
        assessment_state = "NO_CALL_STRUCTURAL_SIMILARITY"
    else:
        assessment_state = "NO_V1_STRUCTURAL_COLLISION_FOUND_NOT_REGISTERED"
    structural_state, structural_reason = STRUCTURAL_GATE_BY_STATE[assessment_state]
    gates = [
        *(_gate(gate_id, state, reason) for gate_id, (state, reason) in FIXED_GATES.items()),
        _gate("STRUCTURAL_CLONE_DETECTION", structural_state, structural_reason),
    ]

    second = _replay_inputs(
        challenge_root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        entrant_view_path,
        expected_view_checkpoint_sha256,
        nonce_path,
        expected_nonce_checkpoint_sha256,
    )
    if (
        canonical_bytes(first[0]) != canonical_bytes(second[0])
        or canonical_bytes(first[1]) != canonical_bytes(second[1])
        or canonical_bytes(first[2]) != canonical_bytes(second[2])
        or first[3] != second[3]
    ):
        raise CausalFrontierError(
            "registry inputs changed during assessment",
            reason_code="INPUT_CHANGED",
            operation="registry.assess_registry_candidate",
        )

    core = {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS,
        "implementation_status": IMPLEMENTATION_STATUS,
        "audience": AUDIENCE,
        "base_compiler_version": COMPILER_VERSION,
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "scope": preflight["scope"],
        "challenge_manifest_sha256": expected_manifest_sha256,
        "challenge_sequence": preflight["challenge_sequence"],
        "race_spec_sha256": expected_race_spec_sha256,
        "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
        "nonce_checkpoint_sha256": expected_nonce_checkpoint_sha256,
        "graph_contract": graph_contract(),
        "graph_contract_sha256": graph_contract_sha256(),
        "cases_n": len(case_ids),
        "declared_domains_n": len(preflight["domains"]),
        "declared_control_classes_n": len(preflight["control_classes"]),
        "layer_equivalence": layer_reports,
        "pair_collision_patterns": [
            {"matched_layers": list(matched_layers), "pairs_n": count}
            for matched_layers, count in sorted(patterns.items())
        ],
        "structural_collision_pairs_n": len(collision_pairs),
        "structural_collision_group_sizes": collision_group_sizes,
        "unresolved_similarity_pairs_n": len(unresolved_pairs),
        "canonicalization_no_call_pairs_n": len(canonicalization_no_call_pairs),
        "assessment_state": assessment_state,
        "candidate_registered": False,
        "registration_write_performed": False,
        "designated_outcome_input_accepted": False,
        "content_outcome_isolation_verified": False,
        "semantic_cohort_uniqueness_verified": False,
        "domain_independence_verified": False,
        "encoder_independence_verified": False,
        "store_independence_verified": False,
        "temporal_admissibility_verified": False,
        "prospective_registration_verified": False,
        "privacy_certified": False,
        "scientific_scoring_ready": False,
        "gates": sorted(gates, key=lambda gate: gate["id"]),
        "nonclaims": list(NONCLAIMS),
    }
    return validate_assessment_report(
        {**core, "assessment_sha256": sha256_bytes(canonical_bytes(core))},
        expected_manifest_sha256=expected_manifest_sha256,
        expected_sequence=expected_sequence,
        expected_race_spec_sha256=expected_race_spec_sha256,
        expected_view_checkpoint_sha256=expected_view_checkpoint_sha256,
        expected_nonce_checkpoint_sha256=expected_nonce_checkpoint_sha256,
    )
