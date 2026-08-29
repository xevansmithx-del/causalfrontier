"""Strict, frozen CausalFrontier case model."""

from __future__ import annotations

from copy import deepcopy
from itertools import product
from pathlib import Path
from typing import Any, Dict, List, Set

from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    contained_file,
    read_json,
    reject_private_material,
    require_enum,
    require_exact_keys,
    require_id,
    require_id_list,
    require_sha256,
    require_text,
    require_unique_ids,
    require_utc_timestamp,
    sha256_bytes,
    sha256_file,
)
from .classifier import classifier_sha256, validate_classifier

SCHEMA_VERSION = "causalfrontier.case.v1"
COMPILER_VERSION = "0.1.0a2"
FIXED_PARAMETER = "OPEN_MACHINE_VERIFIABLE_TRANSLATION_FROM_FRAGMENTED_BIOMEDICAL_EVIDENCE_TO_NEXT_FALSIFIABLE_ACTION"
WORLD_PARTITION = "DECLARED_MUTUALLY_EXCLUSIVE_COLLECTIVELY_EXHAUSTIVE_WITH_RESIDUAL"
OUTCOME_PARTITION = "PREDECLARED_TOTAL_WITH_CONTRADICTION_FAILURE_AND_NO_CALL"
BOUNDARY = {
    "clinical_authority": False,
    "human_decision_authority": False,
    "material_execution_authority": False,
    "patient_level_data": False,
    "prospective_benchmark_cases_scored_n": 0,
    "prospective_experiments_executed_n": 0,
    "prospective_results_recorded": False,
}
OUTCOME_CLASSES = {"INFORMATIVE", "CONTRADICTION", "FAILURE", "NO_CALL"}
RELATIONS = {"SURVIVES", "EXCLUDES", "UNKNOWN"}
DATA_CLASSES = {"PUBLIC_AGGREGATE", "SYNTHETIC"}
SOURCE_AUTHORITIES = {"PUBLIC_DATA", "SYNTHETIC_DATA"}
TEMPORAL_BASES = {
    "DATASET_SNAPSHOT_DATE",
    "REGISTRY_POSTED_DATE",
    "SOURCE_PUBLICATION_DATE",
    "SYNTHETIC_CREATION_DATE",
}
RETRIEVAL_STATES = {"COMPLETE", "PARTIAL", "FAILED", "NOT_RUN"}
SEMANTIC_STATES = {
    "USABLE_FOR_DECLARED_SCOPE",
    "SYNTHETIC_FIXTURE_ONLY",
    "CONTEXT_ONLY_PARTIAL",
    "QUERY_FAILURE_NOT_EVIDENCE",
    "NO_RESULT_NOT_ABSENCE",
}
USABLE_SEMANTIC_STATES = {
    "USABLE_FOR_DECLARED_SCOPE",
    "SYNTHETIC_FIXTURE_ONLY",
}
AUTHORITIES = {
    "SOFTWARE",
    "PUBLIC_DATA",
    "SYNTHETIC_DATA",
    "BIOLOGICAL",
    "CLINICAL",
    "HUMAN",
    "LEGAL",
    "MATERIAL",
}
GRANTED_AUTHORITIES = {"SOFTWARE", "PUBLIC_DATA", "SYNTHETIC_DATA"}
EXECUTION_CLASSES = {
    "READ_ONLY_COMPUTATION",
    "NONINTERVENTIONAL_MEASUREMENT",
    "MATERIAL_PERTURBATION",
}
RESOURCE_FIELDS = (
    "duration_minutes",
    "compute_units",
    "external_dependencies",
    "reversibility_risk",
    "authority_burden",
)
FORBIDDEN_KEYS = {
    "prior",
    "priors",
    "probability",
    "probabilities",
    "likelihood",
    "likelihoods",
    "posterior",
    "posteriors",
    "weight",
    "weights",
    "score",
    "scores",
    "utility",
    "utilities",
    "expected_value",
    "observed_outcome",
    "chosen_after_observation",
}
SOURCE_TEXT_LIMIT = 1024 * 1024


def fixed_boundary() -> Dict[str, Any]:
    return dict(BOUNDARY)


def _reject_forbidden_keys(value: Any, field: str = "case") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                raise CausalFrontierError("%s.%s is forbidden in a prior-free frozen case" % (field, key))
            _reject_forbidden_keys(item, "%s.%s" % (field, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden_keys(item, "%s[%d]" % (field, index))


def _validate_boundary(value: Any) -> Dict[str, Any]:
    boundary = require_exact_keys(value, set(BOUNDARY), "boundary")
    if boundary != BOUNDARY:
        raise CausalFrontierError("alpha boundary is immutable and grants no prospective or clinical authority")
    return boundary


def _validate_provenance(
    value: Any,
    root: Path | None,
    evidence_cutoff: str,
    frozen_at: str,
) -> List[Dict[str, Any]]:
    sources = require_unique_ids(value, "provenance")
    if not sources:
        raise CausalFrontierError("provenance must contain at least one frozen source")
    declared_paths = set()
    for source in sources:
        require_exact_keys(
            source,
            {
                "id",
                "path",
                "sha256",
                "data_class",
                "authority",
                "license",
                "description",
                "source_locator",
                "submitted_query",
                "executed_query",
                "knowledge_date",
                "retrieved_at",
                "temporal_basis",
                "retrieval_state",
                "semantic_state",
                "coverage_complete",
            },
            "provenance %s" % source["id"],
        )
        source["path"] = require_text(source["path"], "provenance path", 1000)
        source["description"] = require_text(source["description"], "provenance description")
        source["license"] = require_text(source["license"], "provenance license", 200)
        source["source_locator"] = require_text(source["source_locator"], "provenance source_locator", 1000)
        source["submitted_query"] = require_text(source["submitted_query"], "provenance submitted_query", 2000)
        source["executed_query"] = require_text(source["executed_query"], "provenance executed_query", 2000)
        source["knowledge_date"] = require_utc_timestamp(source["knowledge_date"], "provenance knowledge_date")
        source["retrieved_at"] = require_utc_timestamp(source["retrieved_at"], "provenance retrieved_at")
        if source["knowledge_date"] > evidence_cutoff:
            raise CausalFrontierError("source %s became available after the evidence cutoff" % source["id"])
        if source["knowledge_date"] > source["retrieved_at"]:
            raise CausalFrontierError("source %s knowledge date follows retrieval" % source["id"])
        if source["retrieved_at"] > frozen_at:
            raise CausalFrontierError("source %s retrieval follows case freeze" % source["id"])
        source["temporal_basis"] = require_enum(source["temporal_basis"], TEMPORAL_BASES, "source temporal_basis")
        source["retrieval_state"] = require_enum(source["retrieval_state"], RETRIEVAL_STATES, "source retrieval_state")
        source["semantic_state"] = require_enum(source["semantic_state"], SEMANTIC_STATES, "source semantic_state")
        if not isinstance(source["coverage_complete"], bool):
            raise CausalFrontierError("source coverage_complete must be boolean")
        if source["semantic_state"] in USABLE_SEMANTIC_STATES and (
            source["retrieval_state"] != "COMPLETE" or not source["coverage_complete"]
        ):
            raise CausalFrontierError(
                "source %s cannot be usable when retrieval or coverage is incomplete" % source["id"]
            )
        if source["semantic_state"] == "QUERY_FAILURE_NOT_EVIDENCE" and source["retrieval_state"] != "FAILED":
            raise CausalFrontierError("query-failure source %s must retain FAILED retrieval state" % source["id"])
        source["data_class"] = require_enum(source["data_class"], DATA_CLASSES, "source data_class")
        source["authority"] = require_enum(source["authority"], SOURCE_AUTHORITIES, "source authority")
        if source["data_class"] not in DATA_CLASSES:
            raise CausalFrontierError("source %s is not public aggregate or synthetic" % source["id"])
        if source["data_class"] == "SYNTHETIC" and source["authority"] != "SYNTHETIC_DATA":
            raise CausalFrontierError("synthetic source must use SYNTHETIC_DATA authority")
        if source["data_class"] == "PUBLIC_AGGREGATE" and source["authority"] != "PUBLIC_DATA":
            raise CausalFrontierError("public aggregate source must use PUBLIC_DATA authority")
        if source["data_class"] == "SYNTHETIC" and (
            source["semantic_state"] != "SYNTHETIC_FIXTURE_ONLY"
            or source["temporal_basis"] != "SYNTHETIC_CREATION_DATE"
        ):
            raise CausalFrontierError("synthetic source must retain synthetic semantic and temporal states")
        if source["data_class"] == "PUBLIC_AGGREGATE" and (
            source["semantic_state"] == "SYNTHETIC_FIXTURE_ONLY"
            or source["temporal_basis"] == "SYNTHETIC_CREATION_DATE"
        ):
            raise CausalFrontierError("public aggregate source cannot use synthetic semantic or temporal states")
        source["sha256"] = require_sha256(source["sha256"], "provenance sha256")
        if source["path"] in declared_paths:
            raise CausalFrontierError("duplicate provenance path: %s" % source["path"])
        declared_paths.add(source["path"])
        if root is not None:
            path = contained_file(root, source["path"], "provenance path")
            if path.stat().st_size > SOURCE_TEXT_LIMIT:
                raise CausalFrontierError("source %s exceeds alpha size limit" % source["id"])
            if sha256_file(path) != source["sha256"]:
                raise CausalFrontierError("source %s digest mismatch" % source["id"])
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise CausalFrontierError("source %s must be UTF-8 text: %s" % (source["id"], exc)) from exc
            reject_private_material(text, "source %s" % source["id"])
    if root is not None:
        actual = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise CausalFrontierError("case root contains a symlink: %s" % path.name)
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                if relative != "case.json":
                    actual.add(relative)
        if actual != declared_paths:
            raise CausalFrontierError(
                "case inventory differs from provenance; unmanifested=%s missing=%s"
                % (sorted(actual - declared_paths), sorted(declared_paths - actual))
            )
    return sorted(sources, key=lambda item: item["id"])


def _validate_decision(value: Any) -> Dict[str, Any]:
    decision = require_exact_keys(value, {"id", "question", "defer_option_id", "options"}, "decision")
    decision["id"] = require_id(decision["id"], "decision.id")
    decision["question"] = require_text(decision["question"], "decision.question")
    options = require_unique_ids(decision["options"], "decision.options")
    if len(options) < 3:
        raise CausalFrontierError("decision needs at least two substantive options plus defer")
    for option in options:
        require_exact_keys(option, {"id", "label"}, "decision option %s" % option["id"])
        option["label"] = require_text(option["label"], "decision option label")
    option_ids = {item["id"] for item in options}
    decision["defer_option_id"] = require_id(decision["defer_option_id"], "decision.defer_option_id")
    if decision["defer_option_id"] not in option_ids:
        raise CausalFrontierError("defer option is not declared")
    decision["options"] = sorted(options, key=lambda item: item["id"])
    return decision


def _validate_worlds(value: Any, decision: Dict[str, Any], source_ids: Set[str]) -> List[Dict[str, Any]]:
    worlds = require_unique_ids(value, "worlds")
    if not 3 <= len(worlds) <= 32:
        raise CausalFrontierError("world partition must contain 3-32 worlds")
    option_ids = {item["id"] for item in decision["options"]}
    defer_id = decision["defer_option_id"]
    residuals = []
    represented = set()
    for world in worlds:
        require_exact_keys(
            world,
            {"id", "label", "is_residual", "admissible_option_ids", "source_ids"},
            "world %s" % world["id"],
        )
        world["label"] = require_text(world["label"], "world label")
        if not isinstance(world["is_residual"], bool):
            raise CausalFrontierError("world is_residual must be boolean")
        options = require_id_list(world["admissible_option_ids"], "world admissible options", False)
        sources = require_id_list(world["source_ids"], "world source_ids", False)
        if not set(options) <= option_ids:
            raise CausalFrontierError("world %s references unknown decision options" % world["id"])
        if not set(sources) <= source_ids:
            raise CausalFrontierError("world %s references unknown or semantically unusable provenance" % world["id"])
        substantive = set(options) - {defer_id}
        if world["is_residual"]:
            residuals.append(world["id"])
            if set(options) != {defer_id}:
                raise CausalFrontierError("residual world must map only to the defer option")
        else:
            if defer_id not in options or len(substantive) != 1:
                raise CausalFrontierError("each non-residual world must map to one substantive option plus defer")
            represented.update(substantive)
        world["admissible_option_ids"] = sorted(options)
        world["source_ids"] = sorted(sources)
    if len(residuals) != 1:
        raise CausalFrontierError("world partition must contain exactly one residual world")
    if represented != option_ids - {defer_id}:
        raise CausalFrontierError("world partition does not represent every substantive option")
    return sorted(worlds, key=lambda item: item["id"])


def _validate_gates(value: Any) -> List[Dict[str, Any]]:
    gates = require_unique_ids(value, "gates")
    for gate in gates:
        require_exact_keys(gate, {"id", "label", "state", "authority"}, "gate %s" % gate["id"])
        gate["label"] = require_text(gate["label"], "gate label")
        gate["state"] = require_enum(gate["state"], {"SATISFIED", "OPEN"}, "gate state")
        gate["authority"] = require_enum(gate["authority"], AUTHORITIES, "gate authority")
        if gate["state"] == "SATISFIED" and gate["authority"] not in GRANTED_AUTHORITIES:
            raise CausalFrontierError("alpha case cannot satisfy %s authority" % gate["authority"])
    return sorted(gates, key=lambda item: item["id"])


def _validate_resources(value: Any, experiment_id: str) -> Dict[str, int]:
    resources = require_exact_keys(value, set(RESOURCE_FIELDS), "resources %s" % experiment_id)
    for field in RESOURCE_FIELDS:
        item = resources[field]
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 1_000_000:
            raise CausalFrontierError("resource %s.%s must be a bounded nonnegative integer" % (experiment_id, field))
    return resources


def branch_plan_core(experiment: Dict[str, Any]) -> Dict[str, Any]:
    """Return exactly the frozen material that binds all outcome branches."""

    return {
        "experiment_id": experiment["id"],
        "classifier": experiment["classifier"],
        "classifier_sha256": experiment["classifier_sha256"],
        "outcome_partition": experiment["outcome_partition"],
        "outcomes": sorted(experiment["outcomes"], key=lambda item: item["id"]),
        "predictions": sorted(
            experiment["predictions"],
            key=lambda item: (item["world_id"], item["outcome_id"]),
        ),
    }


def branch_plan_sha256(experiment: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(branch_plan_core(experiment)))


def _validate_experiments(
    value: Any,
    worlds: List[Dict[str, Any]],
    gates: List[Dict[str, Any]],
    source_authorities: Dict[str, str],
) -> List[Dict[str, Any]]:
    experiments = require_unique_ids(value, "experiments")
    if not experiments:
        raise CausalFrontierError("case must declare at least one discriminator")
    world_ids = {item["id"] for item in worlds}
    world_source_ids = {source_id for world in worlds for source_id in world["source_ids"]}
    residual_id = next(item["id"] for item in worlds if item["is_residual"])
    gate_ids = {item["id"] for item in gates}
    for experiment in experiments:
        require_exact_keys(
            experiment,
            {
                "id",
                "label",
                "protocol",
                "execution_class",
                "required_gate_ids",
                "required_authorities",
                "resources",
                "outcome_partition",
                "outcomes",
                "predictions",
                "classifier",
                "classifier_sha256",
                "branch_plan_sha256",
            },
            "experiment %s" % experiment["id"],
        )
        experiment["label"] = require_text(experiment["label"], "experiment label")
        experiment["protocol"] = require_text(experiment["protocol"], "experiment protocol")
        experiment["execution_class"] = require_enum(
            experiment["execution_class"],
            EXECUTION_CLASSES,
            "experiment execution_class",
        )
        required_gates = require_id_list(experiment["required_gate_ids"], "required_gate_ids")
        if set(required_gates) != gate_ids:
            raise CausalFrontierError("experiment %s must bind every declared case-level gate" % experiment["id"])
        required_authorities = require_id_list(experiment["required_authorities"], "required_authorities", False)
        if not set(required_authorities) <= AUTHORITIES:
            raise CausalFrontierError("experiment %s references unknown authority" % experiment["id"])
        experiment["required_gate_ids"] = sorted(required_gates)
        experiment["required_authorities"] = sorted(required_authorities)
        experiment["resources"] = _validate_resources(experiment["resources"], experiment["id"])
        if experiment["outcome_partition"] != OUTCOME_PARTITION:
            raise CausalFrontierError("experiment %s does not declare the total outcome partition" % experiment["id"])
        outcomes = require_unique_ids(experiment["outcomes"], "experiment outcomes")
        classes = set()
        for outcome in outcomes:
            require_exact_keys(outcome, {"id", "label", "class"}, "outcome %s" % outcome["id"])
            outcome["label"] = require_text(outcome["label"], "outcome label")
            outcome["class"] = require_enum(outcome["class"], OUTCOME_CLASSES, "outcome class")
            classes.add(outcome["class"])
        if classes != OUTCOME_CLASSES:
            raise CausalFrontierError(
                "experiment %s must predeclare informative, contradiction, failure, and no-call branches"
                % experiment["id"]
            )
        outcome_ids = {item["id"] for item in outcomes}
        outcome_map = {item["id"]: item for item in outcomes}
        experiment["classifier"] = validate_classifier(
            experiment["classifier"],
            experiment["id"],
            outcome_map,
            set(source_authorities),
        )
        supplied_classifier_sha256 = require_sha256(experiment["classifier_sha256"], "classifier_sha256")
        expected_classifier_sha256 = classifier_sha256(experiment["classifier"])
        if supplied_classifier_sha256 != expected_classifier_sha256:
            raise CausalFrontierError("experiment %s classifier digest mismatch" % experiment["id"])
        predictions = experiment["predictions"]
        if not isinstance(predictions, list) or any(not isinstance(item, dict) for item in predictions):
            raise CausalFrontierError("experiment predictions must be a list of objects")
        cells = set()
        relation_map = {}
        for prediction in predictions:
            require_exact_keys(
                prediction,
                {"world_id", "outcome_id", "relation", "source_ids"},
                "prediction",
            )
            world_id = require_id(prediction["world_id"], "prediction.world_id")
            outcome_id = require_id(prediction["outcome_id"], "prediction.outcome_id")
            cell = (world_id, outcome_id)
            if cell in cells:
                raise CausalFrontierError("duplicate prediction cell: %s/%s" % cell)
            cells.add(cell)
            if world_id not in world_ids or outcome_id not in outcome_ids:
                raise CausalFrontierError("prediction references unknown world or outcome")
            prediction["relation"] = require_enum(prediction["relation"], RELATIONS, "prediction relation")
            sources = require_id_list(prediction["source_ids"], "prediction.source_ids", False)
            if not set(sources) <= set(source_authorities):
                raise CausalFrontierError("prediction references unknown or semantically unusable provenance")
            prediction["source_ids"] = sorted(sources)
            relation_map[cell] = prediction["relation"]
        implied_authorities = {
            "SOFTWARE",
            *(gate["authority"] for gate in gates),
            *(source_authorities[source_id] for source_id in world_source_ids),
            source_authorities[experiment["classifier"]["source_id"]],
            *(source_authorities[source_id] for prediction in predictions for source_id in prediction["source_ids"]),
        }
        missing_authorities = implied_authorities - set(required_authorities)
        if missing_authorities:
            raise CausalFrontierError(
                "experiment %s omits implied authorities: %s" % (experiment["id"], sorted(missing_authorities))
            )
        expected = set(product(world_ids, outcome_ids))
        if cells != expected:
            raise CausalFrontierError(
                "experiment %s prediction matrix is not total; missing=%s extra=%s"
                % (experiment["id"], sorted(expected - cells), sorted(cells - expected))
            )
        for outcome_id, outcome in outcome_map.items():
            relations = {world_id: relation_map[(world_id, outcome_id)] for world_id in world_ids}
            if outcome["class"] == "INFORMATIVE":
                if relations[residual_id] != "UNKNOWN":
                    raise CausalFrontierError("residual world must remain UNKNOWN on informative branches")
                non_residual = [value for key, value in relations.items() if key != residual_id]
                if "EXCLUDES" not in non_residual or not any(value != "EXCLUDES" for value in non_residual):
                    raise CausalFrontierError(
                        "informative branch must discriminate without excluding every named world"
                    )
            elif outcome["class"] == "CONTRADICTION":
                named_relations = [relation for world_id, relation in relations.items() if world_id != residual_id]
                if set(named_relations) != {"EXCLUDES"} or relations[residual_id] != "UNKNOWN":
                    raise CausalFrontierError("contradiction must exclude named worlds while preserving the residual")
            elif set(relations.values()) != {"UNKNOWN"}:
                raise CausalFrontierError("failure and no-call branches must preserve every world as UNKNOWN")
        experiment["outcomes"] = sorted(outcomes, key=lambda item: item["id"])
        experiment["predictions"] = sorted(predictions, key=lambda item: (item["world_id"], item["outcome_id"]))
        supplied = require_sha256(experiment["branch_plan_sha256"], "branch_plan_sha256")
        expected_digest = branch_plan_sha256(experiment)
        if supplied != expected_digest:
            raise CausalFrontierError("experiment %s branch plan digest mismatch" % experiment["id"])
    return sorted(experiments, key=lambda item: item["id"])


def validate_case(value: Any, root: Path | None = None) -> Dict[str, Any]:
    """Validate and normalize one frozen case without adding scientific authority."""

    case = deepcopy(value)
    require_exact_keys(
        case,
        {
            "schema_version",
            "case_id",
            "title",
            "frozen_at",
            "evidence_cutoff",
            "fixed_parameter",
            "purpose",
            "boundary",
            "provenance",
            "decision",
            "world_partition",
            "worlds",
            "gates",
            "experiments",
            "nonclaims",
        },
        "case",
    )
    _reject_forbidden_keys(case)
    if case["schema_version"] != SCHEMA_VERSION:
        raise CausalFrontierError("unsupported case schema")
    case["case_id"] = require_id(case["case_id"], "case_id")
    case["title"] = require_text(case["title"], "title")
    case["purpose"] = require_text(case["purpose"], "purpose")
    if case["fixed_parameter"] != FIXED_PARAMETER:
        raise CausalFrontierError("case changed the fixed moonshot parameter")
    case["frozen_at"] = require_utc_timestamp(case["frozen_at"], "frozen_at")
    case["evidence_cutoff"] = require_utc_timestamp(case["evidence_cutoff"], "evidence_cutoff")
    if case["evidence_cutoff"] > case["frozen_at"]:
        raise CausalFrontierError("evidence_cutoff must not follow frozen_at")
    case["boundary"] = _validate_boundary(case["boundary"])
    case["provenance"] = _validate_provenance(
        case["provenance"],
        root,
        case["evidence_cutoff"],
        case["frozen_at"],
    )
    source_authorities = {
        item["id"]: item["authority"] for item in case["provenance"] if item["semantic_state"] in USABLE_SEMANTIC_STATES
    }
    case["decision"] = _validate_decision(case["decision"])
    if case["world_partition"] != WORLD_PARTITION:
        raise CausalFrontierError("world partition must be mutually exclusive and include a residual")
    case["worlds"] = _validate_worlds(case["worlds"], case["decision"], set(source_authorities))
    case["gates"] = _validate_gates(case["gates"])
    case["experiments"] = _validate_experiments(
        case["experiments"],
        case["worlds"],
        case["gates"],
        source_authorities,
    )
    if not isinstance(case["nonclaims"], list) or len(case["nonclaims"]) < 4:
        raise CausalFrontierError("case must declare at least four nonclaims")
    case["nonclaims"] = sorted(require_text(item, "nonclaim") for item in case["nonclaims"])
    return case


def load_case(root: Path) -> Dict[str, Any]:
    """Load case.json and verify every declared source against the exact root inventory."""

    if root.is_symlink():
        raise CausalFrontierError("case root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise CausalFrontierError("case root must be a directory")
    return validate_case(read_json(root / "case.json"), root)
