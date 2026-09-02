"""Structurally blinded synthetic policy execution with byte-derived outcomes.

This successor protocol keeps three trust zones explicit:

* a steward challenge and tariff specification;
* an allowlisted entrant view consumed by a view-only selector; and
* a committed observation oracle opened only after a selection checkpoint.

It is deliberately a synthetic software exercise.  Opaque identifiers and
function boundaries are not an operating-system sandbox, synthetic tariffs are
not measured resources, and the resulting traces are not scientific scores.
"""

from __future__ import annotations

import hmac
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    MAX_JSON_BYTES,
    CausalFrontierError,
    canonical_bytes,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    sha256_bytes,
)
from .challenge import BASELINE_FAMILIES, REVEAL_COMMITMENT_SCHEME, load_protocol_cases
from .classifier import (
    CLASSIFIER_CELL_MAX_BYTES,
    CLASSIFIER_INPUT_MAX_BYTES,
    classifier_parser_contract_sha256,
    execute_classifier_observation,
)
from .comparators import fixed_policy_contract, policy_contract_sha256
from .frontier import compile_case
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary
from .reveal import reveal_commitment

RACE_SCHEMA_VERSION = "causalfrontier.synthetic-race-spec.v1"
VIEW_SCHEMA_VERSION = "causalfrontier.synthetic-entrant-view.v1"
SELECTION_SCHEMA_VERSION = "causalfrontier.blind-reference-selection-lock.v1"
SELECTION_ENVELOPE_SCHEMA_VERSION = "causalfrontier.blind-selection-precommitment-envelope.v1"
ORACLE_OPENING_SCHEMA_VERSION = "causalfrontier.synthetic-observation-opening.v1"
ORACLE_PAYLOAD_SCHEMA_VERSION = "causalfrontier.synthetic-observation-oracle.v1"
COMMITMENT_PREFLIGHT_SCHEMA_VERSION = "causalfrontier.synthetic-observation-commitment-preflight.v1"
COMMITMENT_PREFLIGHT_STATUS = "SYNTHETIC_OBSERVATION_ORACLE_READY_TO_SEAL_SCIENTIFIC_SCORING_DISABLED"
EXECUTION_SCHEMA_VERSION = "causalfrontier.synthetic-policy-execution.v1"
EVENT_SCHEMA_VERSION = "causalfrontier.policy-event.v1"
EVENT_DOMAIN_TAG = b"causalfrontier.policy-event.v1\0"
ALIAS_DOMAIN_TAG = b"causalfrontier.opaque-entrant-id.v1\0"
BINDING_DOMAIN_TAG = b"causalfrontier.opaque-entrant-binding.v1\0"
GENESIS = "0" * 64
ORACLE_MANIFEST = "opening.json"
MIN_REPLICATES = 2
MAX_REPLICATES = 8
MAX_ORACLE_FILES = 256
MAX_ORACLE_TOTAL_BYTES = 64 * 1024 * 1024
RESOURCE_DIMENSIONS = (
    "calendar_minutes",
    "human_minutes",
    "compute_units",
    "direct_cost_minor_units_same_currency_and_date_basis",
    "action_batches",
)
RESOURCE_ACCOUNTING_MODE = "SYNTHETIC_PRECOMMITTED_TARIFF_NOT_MEASURED_RESOURCE"
PROHIBITED_OBSERVATION_FIELD_MARKERS = frozenset(
    {
        "dateofbirth",
        "dob",
        "emailaddress",
        "individualid",
        "medicalrecordnumber",
        "mrn",
        "participantid",
        "patientid",
        "patientname",
        "personid",
        "phonenumber",
        "socialsecuritynumber",
        "ssn",
        "streetaddress",
        "subjectid",
    }
)

VIEW_NONCLAIMS = (
    "The view is an allowlisted structural projection, not proof of semantic blinding.",
    "Opaque identifiers do not prove process, filesystem, model-training, or investigator isolation.",
    "Free-text and statistical side channels require independent review outside this projection.",
    "Nonce length and syntax do not verify entropy, uniqueness, or secrecy until selection lock.",
    "No explicit control, domain, organization, reveal, observation-path, observation-digest, or raw steward-digest "
    "field is serialized; case-specific structural fingerprints remain possible.",
    "No outcome, experiment, patient datum, material, scientific baseline, or scientific score is executed.",
)

EXECUTION_NONCLAIMS = (
    "This is a synthetic execution-lifecycle exercise, not a scientific horse race.",
    "Authenticated bytes drive registered classifiers, but synthetic fixtures do not establish scientific truth.",
    "Same-process execution is not operating-system entrant isolation or independent blinding attestation.",
    "Nonce length and syntax do not verify entropy, uniqueness, or secrecy until selection lock.",
    "A checkpointed preflight is not independent attestation of who ran it or of later unselected-byte stability.",
    "The complete execution receipt is steward-only: payload and checkpoint digests can confirm guesses about "
    "otherwise known hidden artifacts, and no public unlinkable projection is implemented.",
    "Synthetic precommitted tariffs are not measured, audited, or fully loaded real resources.",
    "Replicate byte identity and independence are reported structurally, not independently established.",
    "The reference proxies are not executions of the fifteen required scientific baseline families.",
    "Encoder lanes remain separate sensitivity strata and are not combined into a winner.",
    "A hash chain proves deterministic byte linkage, not authorship, time, currentness, or rollback resistance.",
    "No 10x acceleration, causal validity, biological result, clinical utility, patient benefit, or human, material, "
    "or clinical authority is claimed.",
)

SELECTION_ENVELOPE_NONCLAIMS = (
    "The entrant selector received only the sanitized view, not the commitment preflight or oracle opening.",
    "This steward-side envelope binds exact checkpoints but does not prove wall-clock order, authorship, or custody.",
    "External digests may be correlation channels and are not entrant-view fields.",
    "No scientific baseline family or scientific score is executed by this binding step.",
)


def _oracle_limit_contract() -> dict[str, Any]:
    return {
        "max_oracle_entries": MAX_ORACLE_FILES,
        "max_oracle_total_bytes": MAX_ORACLE_TOTAL_BYTES,
        "max_regular_file_bytes": receipt_io.MAX_FILE_BYTES,
        "max_json_bytes": MAX_JSON_BYTES,
        "max_observation_bytes": CLASSIFIER_INPUT_MAX_BYTES,
        "max_classifier_cell_bytes": CLASSIFIER_CELL_MAX_BYTES,
        "classifier_parser_contract_sha256": classifier_parser_contract_sha256(),
    }


def _oracle_limit_contract_sha256() -> str:
    return sha256_bytes(canonical_bytes(_oracle_limit_contract()))


def _bounded_integer(value: Any, field: str, *, minimum: int = 0, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CausalFrontierError("%s must be a bounded integer" % field)
    return value


def _resource_vector(value: Any, field: str, *, action_batch: bool = False) -> dict[str, int]:
    result = require_exact_keys(value, set(RESOURCE_DIMENSIONS), field)
    normalized = {
        dimension: _bounded_integer(result[dimension], "%s.%s" % (field, dimension))
        for dimension in RESOURCE_DIMENSIONS
    }
    if action_batch and normalized["action_batches"] != 1:
        raise CausalFrontierError("every action tariff must charge exactly one complete replicate batch")
    return normalized


def _read_checkpointed_json(path: Path, expected_sha256: str, label: str) -> tuple[bytes, dict[str, Any]]:
    require_sha256(expected_sha256, "%s external checkpoint" % label)
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError:
        raise CausalFrontierError("%s cannot be read safely" % label) from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("%s external checkpoint mismatch" % label)
    receipt_io._screen(raw)
    value = read_json_bytes(raw, label)
    receipt_io._screen(canonical_bytes(value))
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % label)
    return raw, value


def _nonce_bytes(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise CausalFrontierError("blinding nonce must be exactly 32 bytes")
    return value


def _require_opaque_alias(value: Any, kind: str, field: str) -> str:
    require_enum(kind, {"case", "lane", "action"}, "opaque alias kind")
    alias = require_id(value, field)
    if re.fullmatch(r"entrant:%s:[0-9a-f]{64}" % kind, alias) is None:
        raise CausalFrontierError("%s must be an exact opaque alias" % field)
    return alias


def read_checkpointed_blinding_nonce(path: Path, expected_sha256: str) -> bytes:
    """Read a 32-byte secret from an exact, no-follow checkpointed file.

    The file format is exactly 64 lowercase hexadecimal characters followed by
    one newline.  Keeping the secret out of command arguments avoids routine
    shell-history disclosure; it does not establish secret storage security.
    """

    require_sha256(expected_sha256, "blinding nonce external checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError:
        raise CausalFrontierError("blinding nonce cannot be read safely") from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("blinding nonce external checkpoint mismatch")
    if len(raw) != 65 or raw[-1:] != b"\n" or any(byte not in b"0123456789abcdef" for byte in raw[:-1]):
        raise CausalFrontierError("blinding nonce file must contain exactly 32 lowercase hexadecimal bytes")
    return bytes.fromhex(raw[:-1].decode("ascii"))


def _screen_synthetic_observation(raw: bytes) -> None:
    """Apply transport screening plus a conservative TSV-oriented identifier gate.

    This bounded marker screen is defense in depth for the synthetic-only
    exercise. It is not de-identification, privacy certification, or proof that
    an arbitrary free-text value is non-identifying.
    """

    receipt_io._screen(raw)
    text = raw.decode("utf-8")
    for cell in re.split(r"[\t\n\r\v\f\x1c-\x1e\x85\u2028\u2029]+", text.casefold()):
        normalized_cell = "".join(character for character in cell if character.isalnum())
        if any(marker in normalized_cell for marker in PROHIBITED_OBSERVATION_FIELD_MARKERS):
            raise CausalFrontierError(
                "synthetic observation contains a prohibited patient-level identifier field marker"
            )


def _opaque_id(kind: str, original_id: str, registration_sha256: str, nonce: bytes) -> str:
    require_enum(kind, {"case", "lane", "action"}, "opaque identifier kind")
    if not isinstance(original_id, str) or not original_id or len(original_id) > 512:
        raise CausalFrontierError("opaque identifier context must be bounded text")
    require_sha256(registration_sha256, "challenge registration digest")
    digest = hmac.new(
        nonce,
        ALIAS_DOMAIN_TAG
        + kind.encode("ascii")
        + b"\0"
        + bytes.fromhex(registration_sha256)
        + b"\0"
        + original_id.encode("utf-8"),
        "sha256",
    ).hexdigest()
    return "entrant:%s:%s" % (kind, digest)


def _opaque_binding(kind: str, steward_sha256: str, nonce: bytes) -> str:
    require_enum(kind, {"challenge", "race"}, "opaque binding kind")
    require_sha256(steward_sha256, "steward binding digest")
    return hmac.new(
        nonce,
        BINDING_DOMAIN_TAG + kind.encode("ascii") + b"\0" + bytes.fromhex(steward_sha256),
        "sha256",
    ).hexdigest()


def _experiment_ids(case_lanes: list[dict[str, Any]], case_id: str) -> list[str]:
    inventories = [{item["id"] for item in lane["case"]["experiments"]} for lane in case_lanes]
    if not inventories or any(inventory != inventories[0] for inventory in inventories[1:]):
        raise CausalFrontierError("case %s encoder lanes do not share one action inventory" % case_id)
    return sorted(inventories[0])


def _validate_race_spec(
    value: Any,
    raw_sha256: str,
    preflight: dict[str, Any],
    case_lanes: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    spec = require_exact_keys(
        value,
        {
            "schema_version",
            "id",
            "challenge_id",
            "challenge_sequence",
            "challenge_registration_sha256",
            "scope",
            "required_replicates",
            "resource_accounting_mode",
            "resource_dimensions",
            "policy_contract_sha256",
            "cases",
        },
        "synthetic race specification",
    )
    if (
        spec["schema_version"] != RACE_SCHEMA_VERSION
        or spec["challenge_id"] != preflight["challenge_id"]
        or spec["challenge_sequence"] != preflight["challenge_sequence"]
        or spec["challenge_registration_sha256"] != preflight["challenge_registration_sha256"]
        or spec["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or spec["resource_accounting_mode"] != RESOURCE_ACCOUNTING_MODE
        or spec["resource_dimensions"] != list(RESOURCE_DIMENSIONS)
        or spec["policy_contract_sha256"] != policy_contract_sha256()
    ):
        raise CausalFrontierError("synthetic race specification targets another contract or scope")
    require_id(spec["id"], "synthetic race id")
    require_id(spec["challenge_id"], "synthetic race challenge id")
    require_sha256(spec["challenge_registration_sha256"], "synthetic race registration digest")
    require_sha256(spec["policy_contract_sha256"], "synthetic race policy contract digest")
    _bounded_integer(spec["challenge_sequence"], "synthetic race challenge sequence", minimum=1)
    required_replicates = _bounded_integer(
        spec["required_replicates"],
        "synthetic race required replicates",
        minimum=MIN_REPLICATES,
        maximum=MAX_REPLICATES,
    )
    cases = spec["cases"]
    if (
        not isinstance(cases, list)
        or len(cases) != len(case_lanes)
        or any(not isinstance(item, dict) for item in cases)
    ):
        raise CausalFrontierError("synthetic race case inventory differs from the challenge")
    normalized_cases = []
    seen_cases: set[str] = set()
    for case_value in cases:
        case_spec = require_exact_keys(
            case_value,
            {"case_id", "budget", "action_batch_tariffs"},
            "synthetic race case",
        )
        case_id = require_id(case_spec["case_id"], "synthetic race case id")
        if case_id in seen_cases or case_id not in case_lanes:
            raise CausalFrontierError("synthetic race contains a duplicate or unknown case")
        seen_cases.add(case_id)
        budget = _resource_vector(case_spec["budget"], "synthetic race budget")
        action_ids = _experiment_ids(case_lanes[case_id], case_id)
        tariffs = case_spec["action_batch_tariffs"]
        if not isinstance(tariffs, list) or len(tariffs) != len(action_ids):
            raise CausalFrontierError("synthetic race action tariff inventory is incomplete")
        normalized_tariffs = []
        seen_actions: set[str] = set()
        for tariff_value in tariffs:
            tariff = require_exact_keys(
                tariff_value,
                {"experiment_id", "resources"},
                "synthetic race action tariff",
            )
            experiment_id = require_id(tariff["experiment_id"], "synthetic race tariff experiment id")
            if experiment_id in seen_actions or experiment_id not in action_ids:
                raise CausalFrontierError("synthetic race contains a duplicate or unknown action tariff")
            seen_actions.add(experiment_id)
            resources = _resource_vector(
                tariff["resources"],
                "synthetic race action tariff resources",
                action_batch=True,
            )
            normalized_tariffs.append({"experiment_id": experiment_id, "resources": resources})
        if seen_actions != set(action_ids):
            raise CausalFrontierError("synthetic race action tariff inventory is incomplete")
        tariff_by_action = {item["experiment_id"]: item["resources"] for item in normalized_tariffs}
        for lane in case_lanes[case_id]:
            analysis = compile_case(lane["case"])
            eligible_actions = [
                item["id"]
                for item in analysis["experiments"]
                if item["current_status"] == "STRUCTURALLY_ADMISSIBLE_UNEXECUTED" and item["decision_separating"]
            ]
            eligible_pass_tariff = {
                dimension: sum(tariff_by_action[action_id][dimension] for action_id in eligible_actions)
                for dimension in RESOURCE_DIMENSIONS
            }
            if any(eligible_pass_tariff[dimension] > budget[dimension] for dimension in RESOURCE_DIMENSIONS):
                raise CausalFrontierError("case budget cannot fund one complete lane-specific uniform-enumeration pass")
        normalized_cases.append(
            {
                "case_id": case_id,
                "budget": budget,
                "action_batch_tariffs": sorted(normalized_tariffs, key=lambda item: item["experiment_id"]),
            }
        )
    if seen_cases != set(case_lanes):
        raise CausalFrontierError("synthetic race case inventory is incomplete")
    return {
        **spec,
        "required_replicates": required_replicates,
        "cases": sorted(normalized_cases, key=lambda item: item["case_id"]),
        "race_spec_sha256": raw_sha256,
    }


def _load_race_spec(
    path: Path,
    expected_sha256: str,
    preflight: dict[str, Any],
    case_lanes: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    _raw, value = _read_checkpointed_json(path, expected_sha256, "synthetic race specification")
    return _validate_race_spec(value, expected_sha256, preflight, case_lanes)


def _lane_projection(analysis: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    eligible = sorted(
        aliases[item["id"]]
        for item in analysis["experiments"]
        if item["current_status"] == "STRUCTURALLY_ADMISSIBLE_UNEXECUTED" and item["decision_separating"]
    )
    minimax = analysis["minimax"]["structurally_admissible_unexecuted"]
    co_minimax = [] if minimax is None else sorted(aliases[item] for item in minimax["co_minimax_experiment_ids"])
    core = {
        "eligible_action_ids": eligible,
        "co_minimax_action_ids": [item for item in co_minimax if item in eligible],
    }
    return {**core, "selection_projection_sha256": sha256_bytes(canonical_bytes(core))}


def build_sanitized_entrant_view(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    blinding_nonce: bytes,
) -> dict[str, Any]:
    """Build an allowlisted policy view from a steward challenge.

    This is the only API in this module that accepts both the challenge root and
    the secret aliasing nonce.  The returned object never includes either.
    """

    nonce = _nonce_bytes(blinding_nonce)
    preflight, case_lanes = load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    if preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST":
        raise CausalFrontierError("sanitized entrant views are restricted to synthetic protocol tests")
    race = _load_race_spec(race_spec_path, expected_race_spec_sha256, preflight, case_lanes)
    race_cases = {item["case_id"]: item for item in race["cases"]}
    public_cases = []
    all_aliases: set[str] = set()
    for case_id, lanes in sorted(case_lanes.items()):
        entrant_case_id = _opaque_id("case", case_id, preflight["challenge_registration_sha256"], nonce)
        action_ids = _experiment_ids(lanes, case_id)
        action_aliases = {
            action_id: _opaque_id(
                "action",
                "%s\0%s" % (case_id, action_id),
                preflight["challenge_registration_sha256"],
                nonce,
            )
            for action_id in action_ids
        }
        tariff_map = {item["experiment_id"]: item["resources"] for item in race_cases[case_id]["action_batch_tariffs"]}
        public_tariffs = [
            {"entrant_action_id": action_aliases[action_id], "resources": tariff_map[action_id]}
            for action_id in action_ids
        ]
        public_lanes = []
        for lane in sorted(lanes, key=lambda item: item["encoding_id"]):
            entrant_lane_id = _opaque_id(
                "lane",
                "%s\0%s" % (case_id, lane["encoding_id"]),
                preflight["challenge_registration_sha256"],
                nonce,
            )
            projection = _lane_projection(compile_case(lane["case"]), action_aliases)
            public_lanes.append({"entrant_lane_id": entrant_lane_id, **projection})
        aliases = {
            entrant_case_id,
            *(item["entrant_action_id"] for item in public_tariffs),
            *(item["entrant_lane_id"] for item in public_lanes),
        }
        if all_aliases & aliases:
            raise CausalFrontierError("opaque entrant identifier collision")
        all_aliases |= aliases
        public_cases.append(
            {
                "entrant_case_id": entrant_case_id,
                "budget": race_cases[case_id]["budget"],
                "action_batch_tariffs": sorted(public_tariffs, key=lambda item: item["entrant_action_id"]),
                "lanes": sorted(public_lanes, key=lambda item: item["entrant_lane_id"]),
            }
        )
    core = {
        "schema_version": VIEW_SCHEMA_VERSION,
        "status": "SANITIZED_STRUCTURAL_ENTRANT_VIEW_NO_OUTCOMES",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "challenge_sequence": preflight["challenge_sequence"],
        "opaque_challenge_binding_sha256": _opaque_binding(
            "challenge", preflight["challenge_registration_sha256"], nonce
        ),
        "scope": preflight["scope"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "opaque_race_binding_sha256": _opaque_binding("race", expected_race_spec_sha256, nonce),
        "policy_contract": fixed_policy_contract(),
        "policy_contract_sha256": policy_contract_sha256(),
        "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
        "resource_dimensions": list(RESOURCE_DIMENSIONS),
        "required_replicates": race["required_replicates"],
        "cases": sorted(public_cases, key=lambda item: item["entrant_case_id"]),
        "blinding_nonce_entropy_verified": False,
        "blinding_nonce_uniqueness_verified": False,
        "blinding_nonce_secrecy_until_selection_verified": False,
        "environment_isolation_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(VIEW_NONCLAIMS),
    }
    return {**core, "view_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_view(value: Any) -> dict[str, Any]:
    view = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "challenge_sequence",
            "opaque_challenge_binding_sha256",
            "scope",
            "fixed_parameter",
            "boundary",
            "opaque_race_binding_sha256",
            "policy_contract",
            "policy_contract_sha256",
            "resource_accounting_mode",
            "resource_dimensions",
            "required_replicates",
            "cases",
            "blinding_nonce_entropy_verified",
            "blinding_nonce_uniqueness_verified",
            "blinding_nonce_secrecy_until_selection_verified",
            "environment_isolation_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "view_sha256",
        },
        "sanitized entrant view",
    )
    if (
        view["schema_version"] != VIEW_SCHEMA_VERSION
        or view["status"] != "SANITIZED_STRUCTURAL_ENTRANT_VIEW_NO_OUTCOMES"
        or view["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or view["base_compiler_version"] != COMPILER_VERSION
        or view["scope"] != "SYNTHETIC_PROTOCOL_TEST"
        or view["fixed_parameter"] != FIXED_PARAMETER
        or canonical_bytes(view["boundary"]) != canonical_bytes(fixed_boundary())
        or canonical_bytes(view["policy_contract"]) != canonical_bytes(fixed_policy_contract())
        or view["policy_contract_sha256"] != policy_contract_sha256()
        or view["resource_accounting_mode"] != RESOURCE_ACCOUNTING_MODE
        or view["resource_dimensions"] != list(RESOURCE_DIMENSIONS)
        or view["blinding_nonce_entropy_verified"] is not False
        or view["blinding_nonce_uniqueness_verified"] is not False
        or view["blinding_nonce_secrecy_until_selection_verified"] is not False
        or view["environment_isolation_verified"] is not False
        or view["scientific_scoring_ready"] is not False
        or view["nonclaims"] != list(VIEW_NONCLAIMS)
    ):
        raise CausalFrontierError("sanitized entrant view targets another contract or overclaims its boundary")
    _bounded_integer(view["challenge_sequence"], "entrant view challenge sequence", minimum=1)
    _bounded_integer(
        view["required_replicates"],
        "entrant view required replicates",
        minimum=MIN_REPLICATES,
        maximum=MAX_REPLICATES,
    )
    require_sha256(view["opaque_challenge_binding_sha256"], "entrant view opaque challenge binding")
    require_sha256(view["opaque_race_binding_sha256"], "entrant view opaque race binding")
    require_sha256(view["policy_contract_sha256"], "entrant view policy digest")
    cases = view["cases"]
    if not isinstance(cases, list) or not cases or any(not isinstance(item, dict) for item in cases):
        raise CausalFrontierError("entrant view must contain cases")
    seen_cases: set[str] = set()
    seen_global: set[str] = set()
    normalized_cases = []
    for case_value in cases:
        case = require_exact_keys(
            case_value,
            {"entrant_case_id", "budget", "action_batch_tariffs", "lanes"},
            "entrant view case",
        )
        case_id = _require_opaque_alias(case["entrant_case_id"], "case", "entrant case id")
        if case_id in seen_cases:
            raise CausalFrontierError("entrant view contains an invalid or duplicate case alias")
        seen_cases.add(case_id)
        budget = _resource_vector(case["budget"], "entrant view budget")
        tariffs = case["action_batch_tariffs"]
        if not isinstance(tariffs, list) or not tariffs or any(not isinstance(item, dict) for item in tariffs):
            raise CausalFrontierError("entrant view must contain action tariffs")
        seen_actions: set[str] = set()
        normalized_tariffs = []
        for tariff_value in tariffs:
            tariff = require_exact_keys(tariff_value, {"entrant_action_id", "resources"}, "entrant action tariff")
            action_id = _require_opaque_alias(tariff["entrant_action_id"], "action", "entrant action id")
            if action_id in seen_actions:
                raise CausalFrontierError("entrant view contains an invalid or duplicate action alias")
            seen_actions.add(action_id)
            resources = _resource_vector(tariff["resources"], "entrant action tariff resources", action_batch=True)
            normalized_tariffs.append({"entrant_action_id": action_id, "resources": resources})
        lanes = case["lanes"]
        if not isinstance(lanes, list) or len(lanes) < 2 or any(not isinstance(item, dict) for item in lanes):
            raise CausalFrontierError("entrant view needs at least two encoder lanes per case")
        seen_lanes: set[str] = set()
        normalized_lanes = []
        for lane_value in lanes:
            lane = require_exact_keys(
                lane_value,
                {
                    "entrant_lane_id",
                    "eligible_action_ids",
                    "co_minimax_action_ids",
                    "selection_projection_sha256",
                },
                "entrant view lane",
            )
            lane_id = _require_opaque_alias(lane["entrant_lane_id"], "lane", "entrant lane id")
            if lane_id in seen_lanes:
                raise CausalFrontierError("entrant view contains an invalid or duplicate lane alias")
            seen_lanes.add(lane_id)
            eligible = lane["eligible_action_ids"]
            co_minimax = lane["co_minimax_action_ids"]
            if (
                not isinstance(eligible, list)
                or not isinstance(co_minimax, list)
                or any(not isinstance(item, str) for item in [*eligible, *co_minimax])
                or len(eligible) != len(set(eligible))
                or len(co_minimax) != len(set(co_minimax))
                or eligible != sorted(eligible)
                or co_minimax != sorted(co_minimax)
                or not set(eligible) <= seen_actions
                or not set(co_minimax) <= set(eligible)
            ):
                raise CausalFrontierError("entrant lane selection projection is invalid")
            projection = {"eligible_action_ids": eligible, "co_minimax_action_ids": co_minimax}
            if sha256_bytes(canonical_bytes(projection)) != lane["selection_projection_sha256"]:
                raise CausalFrontierError("entrant lane selection projection digest mismatch")
            normalized_lanes.append(dict(lane))
        tariff_by_alias = {item["entrant_action_id"]: item["resources"] for item in normalized_tariffs}
        for lane in normalized_lanes:
            eligible_pass = {
                dimension: sum(tariff_by_alias[action_id][dimension] for action_id in lane["eligible_action_ids"])
                for dimension in RESOURCE_DIMENSIONS
            }
            if any(eligible_pass[dimension] > budget[dimension] for dimension in RESOURCE_DIMENSIONS):
                raise CausalFrontierError(
                    "entrant case budget cannot fund one complete lane-specific uniform-enumeration pass"
                )
        aliases = {case_id, *seen_actions, *seen_lanes}
        if seen_global & aliases:
            raise CausalFrontierError("entrant aliases are not globally unique")
        seen_global |= aliases
        normalized_cases.append(
            {
                "entrant_case_id": case_id,
                "budget": budget,
                "action_batch_tariffs": sorted(normalized_tariffs, key=lambda item: item["entrant_action_id"]),
                "lanes": sorted(normalized_lanes, key=lambda item: item["entrant_lane_id"]),
            }
        )
    core = {key: value for key, value in view.items() if key != "view_sha256"}
    require_sha256(view["view_sha256"], "entrant view semantic digest")
    if sha256_bytes(canonical_bytes(core)) != view["view_sha256"]:
        raise CausalFrontierError("entrant view semantic digest mismatch")
    normalized = dict(view)
    normalized["cases"] = sorted(normalized_cases, key=lambda item: item["entrant_case_id"])
    if canonical_bytes(normalized) != canonical_bytes(view):
        raise CausalFrontierError("entrant view inventories must use canonical order")
    return normalized


def _terminal(action: str) -> dict[str, Any]:
    return {"action": action, "entrant_action_id": None, "enumeration_numerator": 1, "enumeration_denominator": 1}


def _select(action_id: str, numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "action": "SELECT",
        "entrant_action_id": action_id,
        "enumeration_numerator": numerator,
        "enumeration_denominator": denominator,
    }


def _trace(
    policy_id: str,
    status: str,
    eligible: list[str],
    selections: list[dict[str, Any]],
    reasons: list[str],
) -> dict[str, Any]:
    core = {
        "policy_id": policy_id,
        "status": status,
        "eligible_action_ids": eligible,
        "selections": selections,
        "reason_codes": reasons,
    }
    return {**core, "trace_sha256": sha256_bytes(canonical_bytes(core))}


def _view_lane_selections(lane: dict[str, Any]) -> list[dict[str, Any]]:
    eligible = lane["eligible_action_ids"]
    minimax = lane["co_minimax_action_ids"]
    if len(minimax) == 1:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "SELECTED",
            eligible,
            [_select(minimax[0], 1, 1)],
            ["UNIQUE_CO_MINIMAX_ACTION"],
        )
    elif minimax:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["CO_MINIMAX_TIE_NOT_BROKEN_BY_OPAQUE_DISPLAY_ID"],
        )
    else:
        candidate = _trace(
            "CAUSALFRONTIER_UNIQUE_MINIMAX_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"],
        )
    abstain = _trace(
        "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
        "ABSTAINED",
        eligible,
        [_terminal("ABSTAIN")],
        ["POLICY_ALWAYS_ABSTAINS"],
    )
    uniform = (
        _trace(
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "ENUMERATED",
            eligible,
            [_select(item, 1, len(eligible)) for item in eligible],
            ["ALL_ELIGIBLE_ACTIONS_ENUMERATED_ONCE_WITHOUT_REPLACEMENT"],
        )
        if eligible
        else _trace(
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
            "NO_CALL",
            eligible,
            [_terminal("NO_CALL")],
            ["NO_STRUCTURALLY_ADMISSIBLE_DECISION_SEPARATING_ACTION"],
        )
    )
    return [candidate, abstain, uniform]


def lock_blind_reference_selections(view_path: Path, expected_view_sha256: str) -> dict[str, Any]:
    """Lock policies using only a checkpointed sanitized view."""

    _raw, value = _read_checkpointed_json(view_path, expected_view_sha256, "sanitized entrant view")
    view = _validate_view(value)
    lanes = []
    for case in view["cases"]:
        for lane in case["lanes"]:
            lanes.append(
                {
                    "entrant_case_id": case["entrant_case_id"],
                    "entrant_lane_id": lane["entrant_lane_id"],
                    "selection_projection_sha256": lane["selection_projection_sha256"],
                    "reference_policy_traces": _view_lane_selections(lane),
                }
            )
    core = {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "status": "BLIND_REFERENCE_SELECTIONS_LOCKED_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "entrant_view_checkpoint_sha256": expected_view_sha256,
        "entrant_view_sha256": view["view_sha256"],
        "opaque_challenge_binding_sha256": view["opaque_challenge_binding_sha256"],
        "opaque_race_binding_sha256": view["opaque_race_binding_sha256"],
        "policy_contract_sha256": view["policy_contract_sha256"],
        "reveal_input_accepted": False,
        "reference_lanes": sorted(lanes, key=lambda item: (item["entrant_case_id"], item["entrant_lane_id"])),
        "reference_proxy_families": ["DO_NOTHING_OR_ABSTAIN", "RANDOM"],
        "scientific_baseline_families_executed": [],
        "required_scientific_baseline_families_unexecuted": sorted(BASELINE_FAMILIES),
        "blinding_nonce_entropy_verified": view["blinding_nonce_entropy_verified"],
        "blinding_nonce_uniqueness_verified": view["blinding_nonce_uniqueness_verified"],
        "blinding_nonce_secrecy_until_selection_verified": view["blinding_nonce_secrecy_until_selection_verified"],
        "environment_isolation_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(VIEW_NONCLAIMS),
    }
    return {**core, "selection_lock_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_selection_lock(value: Any) -> dict[str, Any]:
    selection = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "entrant_view_checkpoint_sha256",
            "entrant_view_sha256",
            "opaque_challenge_binding_sha256",
            "opaque_race_binding_sha256",
            "policy_contract_sha256",
            "reveal_input_accepted",
            "reference_lanes",
            "reference_proxy_families",
            "scientific_baseline_families_executed",
            "required_scientific_baseline_families_unexecuted",
            "blinding_nonce_entropy_verified",
            "blinding_nonce_uniqueness_verified",
            "blinding_nonce_secrecy_until_selection_verified",
            "environment_isolation_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "selection_lock_sha256",
        },
        "blind selection lock",
    )
    for field in (
        "entrant_view_checkpoint_sha256",
        "entrant_view_sha256",
        "opaque_challenge_binding_sha256",
        "opaque_race_binding_sha256",
        "policy_contract_sha256",
        "selection_lock_sha256",
    ):
        require_sha256(selection[field], "blind selection %s" % field)
    if (
        selection["schema_version"] != SELECTION_SCHEMA_VERSION
        or selection["status"] != "BLIND_REFERENCE_SELECTIONS_LOCKED_SCIENTIFIC_SCORING_DISABLED"
        or selection["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or selection["base_compiler_version"] != COMPILER_VERSION
        or selection["policy_contract_sha256"] != policy_contract_sha256()
        or selection["reveal_input_accepted"] is not False
        or selection["reference_proxy_families"] != ["DO_NOTHING_OR_ABSTAIN", "RANDOM"]
        or selection["scientific_baseline_families_executed"] != []
        or selection["required_scientific_baseline_families_unexecuted"] != sorted(BASELINE_FAMILIES)
        or selection["environment_isolation_verified"] is not False
        or selection["scientific_scoring_ready"] is not False
        or selection["nonclaims"] != list(VIEW_NONCLAIMS)
        or not isinstance(selection["reference_lanes"], list)
        or not selection["reference_lanes"]
    ):
        raise CausalFrontierError("blind selection lock overclaims or targets another contract")
    core = {key: value for key, value in selection.items() if key != "selection_lock_sha256"}
    if sha256_bytes(canonical_bytes(core)) != selection["selection_lock_sha256"]:
        raise CausalFrontierError("blind selection semantic digest mismatch")
    if (
        selection["blinding_nonce_entropy_verified"] is not False
        or selection["blinding_nonce_uniqueness_verified"] is not False
        or selection["blinding_nonce_secrecy_until_selection_verified"] is not False
    ):
        raise CausalFrontierError("blind selection lock overclaims nonce security")
    return selection


def bind_blind_selection_precommitment(
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    selection_path: Path,
    expected_selection_checkpoint_sha256: str,
    expected_commitment_preflight_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Create a steward-side envelope without exposing preflight data to the selector."""

    require_sha256(
        expected_commitment_preflight_checkpoint_sha256,
        "commitment preflight external checkpoint",
    )
    _raw, selection_value = _read_checkpointed_json(
        selection_path,
        expected_selection_checkpoint_sha256,
        "blind selection lock",
    )
    selection = _validate_selection_lock(selection_value)
    replayed_selection = lock_blind_reference_selections(view_path, expected_view_checkpoint_sha256)
    if canonical_bytes(selection) != canonical_bytes(replayed_selection):
        raise CausalFrontierError("blind selection lock does not replay from the checkpointed entrant view")
    core = {
        "schema_version": SELECTION_ENVELOPE_SCHEMA_VERSION,
        "status": "BLIND_SELECTION_AND_PRECOMMITMENT_CHECKPOINTS_BOUND_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
        "entrant_view_sha256": selection["entrant_view_sha256"],
        "selection_checkpoint_sha256": expected_selection_checkpoint_sha256,
        "selection_lock_sha256": selection["selection_lock_sha256"],
        "commitment_preflight_checkpoint_sha256": expected_commitment_preflight_checkpoint_sha256,
        "selector_preflight_input_accepted": False,
        "temporal_order_independently_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(SELECTION_ENVELOPE_NONCLAIMS),
    }
    return {**core, "selection_envelope_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_selection_envelope(value: Any) -> dict[str, Any]:
    envelope = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "entrant_view_checkpoint_sha256",
            "entrant_view_sha256",
            "selection_checkpoint_sha256",
            "selection_lock_sha256",
            "commitment_preflight_checkpoint_sha256",
            "selector_preflight_input_accepted",
            "temporal_order_independently_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "selection_envelope_sha256",
        },
        "blind selection precommitment envelope",
    )
    if (
        envelope["schema_version"] != SELECTION_ENVELOPE_SCHEMA_VERSION
        or envelope["status"] != "BLIND_SELECTION_AND_PRECOMMITMENT_CHECKPOINTS_BOUND_SCIENTIFIC_SCORING_DISABLED"
        or envelope["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or envelope["base_compiler_version"] != COMPILER_VERSION
        or envelope["selector_preflight_input_accepted"] is not False
        or envelope["temporal_order_independently_verified"] is not False
        or envelope["scientific_scoring_ready"] is not False
        or envelope["nonclaims"] != list(SELECTION_ENVELOPE_NONCLAIMS)
    ):
        raise CausalFrontierError("blind selection precommitment envelope overclaims or targets another contract")
    for field in (
        "selection_checkpoint_sha256",
        "selection_lock_sha256",
        "commitment_preflight_checkpoint_sha256",
        "entrant_view_checkpoint_sha256",
        "entrant_view_sha256",
        "selection_envelope_sha256",
    ):
        require_sha256(envelope[field], "selection envelope %s" % field)
    core = {key: item for key, item in envelope.items() if key != "selection_envelope_sha256"}
    if sha256_bytes(canonical_bytes(core)) != envelope["selection_envelope_sha256"]:
        raise CausalFrontierError("blind selection precommitment envelope semantic digest mismatch")
    return envelope


def _validate_oracle_payload_shape(value: Any) -> dict[str, Any]:
    payload = require_exact_keys(
        value,
        {
            "schema_version",
            "challenge_registration_sha256",
            "challenge_sequence",
            "race_spec_sha256",
            "entrant_view_sha256",
            "policy_contract_sha256",
            "required_replicates",
            "cases",
        },
        "synthetic observation oracle",
    )
    if payload["schema_version"] != ORACLE_PAYLOAD_SCHEMA_VERSION:
        raise CausalFrontierError("unregistered synthetic observation oracle schema")
    for field in ("challenge_registration_sha256", "race_spec_sha256", "entrant_view_sha256", "policy_contract_sha256"):
        require_sha256(payload[field], "oracle %s" % field)
    _bounded_integer(payload["challenge_sequence"], "oracle challenge sequence", minimum=1)
    _bounded_integer(
        payload["required_replicates"],
        "oracle required replicates",
        minimum=MIN_REPLICATES,
        maximum=MAX_REPLICATES,
    )
    if not isinstance(payload["cases"], list) or any(not isinstance(item, dict) for item in payload["cases"]):
        raise CausalFrontierError("oracle cases must be a list of objects")
    for case_value in payload["cases"]:
        case = require_exact_keys(case_value, {"case_id", "entrant_case_id", "actions"}, "oracle case")
        require_id(case["case_id"], "oracle case id")
        require_id(case["entrant_case_id"], "oracle entrant case id")
        if not isinstance(case["actions"], list) or any(not isinstance(item, dict) for item in case["actions"]):
            raise CausalFrontierError("oracle actions must be a list of objects")
        for action_value in case["actions"]:
            action = require_exact_keys(
                action_value,
                {"experiment_id", "entrant_action_id", "observations"},
                "oracle action",
            )
            require_id(action["experiment_id"], "oracle experiment id")
            require_id(action["entrant_action_id"], "oracle entrant action id")
            if not isinstance(action["observations"], list) or any(
                not isinstance(item, dict) for item in action["observations"]
            ):
                raise CausalFrontierError("oracle observations must be a list of objects")
            for observation_value in action["observations"]:
                observation = require_exact_keys(
                    observation_value,
                    {"id", "replicate_index", "path", "sha256", "media_type"},
                    "oracle observation",
                )
                require_id(observation["id"], "oracle observation id")
                _bounded_integer(
                    observation["replicate_index"], "oracle replicate index", minimum=1, maximum=MAX_REPLICATES
                )
                receipt_io._relative(observation["path"])
                require_sha256(observation["sha256"], "oracle observation digest")
                if observation["media_type"] != "text/tab-separated-values":
                    raise CausalFrontierError("oracle observation media type is not registered")
    return payload


def _strict_inventory(
    root_fd: int,
    *,
    observation_paths: set[str] | None = None,
) -> tuple[set[str], set[str], int, int]:
    files: set[str] = set()
    directories: set[str] = set()
    visited = [0]
    total_bytes = [0]

    def walk(descriptor: int, prefix: str) -> None:
        names = []
        with os.scandir(descriptor) as directory:
            for entry in directory:
                visited[0] += 1
                if visited[0] > MAX_ORACLE_FILES:
                    raise CausalFrontierError("oracle inventory exceeds its entry limit")
                names.append(entry.name)
        for name in sorted(names):
            relative = receipt_io._relative(prefix + name)
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
                with ExitStack() as stack:
                    child = receipt_io._open_directory(stack, name, descriptor)
                    walk(child, relative + "/")
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= receipt_io.MAX_FILE_BYTES:
                if (
                    observation_paths is not None
                    and relative in observation_paths
                    and info.st_size > CLASSIFIER_INPUT_MAX_BYTES
                ):
                    raise CausalFrontierError("oracle observation exceeds the registered classifier input byte limit")
                total_bytes[0] += info.st_size
                if total_bytes[0] > MAX_ORACLE_TOTAL_BYTES:
                    raise CausalFrontierError("oracle inventory exceeds its total byte limit")
                files.add(relative)
            else:
                raise CausalFrontierError("oracle inventory contains an unsafe or oversized filesystem object")

    walk(root_fd, "")
    return files, directories, visited[0], total_bytes[0]


def _expected_directories(paths: set[str]) -> set[str]:
    result: set[str] = set()
    for path in paths:
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            result.add(str(parent))
            parent = parent.parent
    return result


def _open_oracle(
    oracle_root: Path,
    expected_opening_sha256: str,
    expected_commitment_sha256: str,
) -> tuple[dict[str, Any], int, ExitStack, bytes]:
    require_sha256(expected_opening_sha256, "oracle opening external checkpoint")
    require_sha256(expected_commitment_sha256, "oracle commitment")
    stack = ExitStack()
    try:
        descriptor = receipt_io._root_descriptor(stack, oracle_root)
        raw = receipt_io._snapshot(descriptor, ORACLE_MANIFEST)
        if sha256_bytes(raw) != expected_opening_sha256:
            raise CausalFrontierError("oracle opening external checkpoint mismatch")
        # Parsing and top-level framing are necessary to compute the opening,
        # but every failure before commitment equality is deliberately collapsed
        # so unauthenticated bytes cannot become a content-reflecting error oracle.
        try:
            opening_value = read_json_bytes(raw, "synthetic observation opening")
            opening = require_exact_keys(
                opening_value,
                {"schema_version", "nonce_hex", "payload"},
                "synthetic observation opening",
            )
            computed = reveal_commitment(opening["payload"], opening["nonce_hex"])
        except (CausalFrontierError, TypeError, ValueError):
            raise CausalFrontierError("synthetic observation oracle authentication failed") from None
        if not hmac.compare_digest(computed, expected_commitment_sha256):
            raise CausalFrontierError("synthetic observation oracle authentication failed")
        receipt_io._screen(raw)
        if opening["schema_version"] != ORACLE_OPENING_SCHEMA_VERSION:
            raise CausalFrontierError("unregistered synthetic observation opening schema")
        if raw != canonical_bytes(opening) + b"\n":
            raise CausalFrontierError("authenticated synthetic observation opening is not canonical JSON")
        payload = _validate_oracle_payload_shape(opening["payload"])
        return {"nonce_hex": opening["nonce_hex"], "payload": payload}, descriptor, stack, raw
    except Exception:
        stack.close()
        raise


def _validate_oracle_inventory(
    payload: dict[str, Any],
    descriptor: int,
    case_lanes: dict[str, list[dict[str, Any]]],
    preflight: dict[str, Any],
    race: dict[str, Any],
    view: dict[str, Any],
    nonce: bytes,
    *,
    opening_present: bool = True,
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], int, int]:
    if (
        payload["challenge_registration_sha256"] != preflight["challenge_registration_sha256"]
        or payload["challenge_sequence"] != preflight["challenge_sequence"]
        or payload["race_spec_sha256"] != race["race_spec_sha256"]
        or payload["entrant_view_sha256"] != view["view_sha256"]
        or payload["policy_contract_sha256"] != policy_contract_sha256()
        or payload["required_replicates"] != race["required_replicates"]
    ):
        raise CausalFrontierError("synthetic observation oracle targets another bound execution")
    view_cases = {item["entrant_case_id"]: item for item in view["cases"]}
    seen_cases: set[str] = set()
    observations: dict[tuple[str, str], list[dict[str, Any]]] = {}
    paths: set[str] = set()
    observation_ids: set[str] = set()
    for case_value in payload["cases"]:
        case_id = case_value["case_id"]
        expected_case_alias = _opaque_id("case", case_id, preflight["challenge_registration_sha256"], nonce)
        if (
            case_id in seen_cases
            or case_id not in case_lanes
            or case_value["entrant_case_id"] != expected_case_alias
            or expected_case_alias not in view_cases
        ):
            raise CausalFrontierError("oracle contains a duplicate, unknown, or mismatched case binding")
        seen_cases.add(case_id)
        action_ids = _experiment_ids(case_lanes[case_id], case_id)
        if len(case_value["actions"]) != len(action_ids):
            raise CausalFrontierError("oracle action inventory differs from the frozen catalog")
        seen_actions: set[str] = set()
        view_actions = {item["entrant_action_id"] for item in view_cases[expected_case_alias]["action_batch_tariffs"]}
        for action_value in case_value["actions"]:
            experiment_id = action_value["experiment_id"]
            expected_action_alias = _opaque_id(
                "action",
                "%s\0%s" % (case_id, experiment_id),
                preflight["challenge_registration_sha256"],
                nonce,
            )
            if (
                experiment_id in seen_actions
                or experiment_id not in action_ids
                or action_value["entrant_action_id"] != expected_action_alias
                or expected_action_alias not in view_actions
            ):
                raise CausalFrontierError("oracle contains a duplicate, unknown, or mismatched action binding")
            seen_actions.add(experiment_id)
            batch = action_value["observations"]
            if len(batch) != race["required_replicates"]:
                raise CausalFrontierError("oracle replicate inventory differs from the precommitted count")
            seen_indexes: set[int] = set()
            normalized_batch = []
            for observation in batch:
                index = observation["replicate_index"]
                if index in seen_indexes or index not in range(1, race["required_replicates"] + 1):
                    raise CausalFrontierError("oracle contains a duplicate or post-hoc replicate index")
                seen_indexes.add(index)
                if (
                    observation["id"] in observation_ids
                    or observation["path"] in paths
                    or observation["path"] == ORACLE_MANIFEST
                ):
                    raise CausalFrontierError("oracle observation identities and paths must bind one coordinate each")
                observation_ids.add(observation["id"])
                paths.add(observation["path"])
                normalized_batch.append(dict(observation))
            if seen_indexes != set(range(1, race["required_replicates"] + 1)):
                raise CausalFrontierError("oracle replicate inventory is incomplete")
            observations[(case_id, experiment_id)] = sorted(normalized_batch, key=lambda item: item["replicate_index"])
        if seen_actions != set(action_ids):
            raise CausalFrontierError("oracle action inventory is incomplete")
    if seen_cases != set(case_lanes):
        raise CausalFrontierError("oracle case inventory is incomplete")
    files, directories, entries_n, total_bytes_n = _strict_inventory(
        descriptor,
        observation_paths=paths,
    )
    expected_files = ({ORACLE_MANIFEST} if opening_present else set()) | paths
    if files != expected_files or directories != _expected_directories(paths):
        raise CausalFrontierError("oracle filesystem inventory differs from its committed coordinate table")
    return observations, entries_n, total_bytes_n


def prepare_synthetic_observation_commitment(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    oracle_root: Path,
    payload_path: Path,
    expected_payload_checkpoint_sha256: str,
    nonce_path: Path,
    expected_nonce_checkpoint_sha256: str,
) -> dict[str, Any]:
    """Validate a complete observation oracle before returning its commitment.

    The oracle root must contain exactly the observation files at this stage;
    ``opening.json`` is added only after the returned commitment is sealed into
    the challenge. This preflight prevents committing an internally malformed or
    presently unexecutable coordinate table through the supported API.
    """

    preflight, case_lanes = load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    race = _load_race_spec(race_spec_path, expected_race_spec_sha256, preflight, case_lanes)
    _view_raw, view_value = _read_checkpointed_json(
        view_path, expected_view_checkpoint_sha256, "sanitized entrant view"
    )
    view = _validate_view(view_value)
    payload_raw, payload_value = _read_checkpointed_json(
        payload_path,
        expected_payload_checkpoint_sha256,
        "synthetic observation payload",
    )
    payload = _validate_oracle_payload_shape(payload_value)
    nonce = read_checkpointed_blinding_nonce(nonce_path, expected_nonce_checkpoint_sha256)
    canonical_payload_raw = canonical_bytes(payload) + b"\n"
    if payload_raw != canonical_payload_raw:
        raise CausalFrontierError("synthetic observation payload checkpoint must use canonical JSON plus newline")
    prospective_opening = {
        "schema_version": ORACLE_OPENING_SCHEMA_VERSION,
        "nonce_hex": nonce.hex(),
        "payload": payload,
    }
    prospective_opening_raw = canonical_bytes(prospective_opening) + b"\n"
    if len(prospective_opening_raw) > min(receipt_io.MAX_FILE_BYTES, MAX_JSON_BYTES):
        raise CausalFrontierError("prospective oracle opening exceeds its executable JSON byte limit")
    receipt_io._screen(prospective_opening_raw)
    recomputed_view = build_sanitized_entrant_view(
        root,
        expected_manifest_sha256,
        expected_sequence,
        race_spec_path,
        expected_race_spec_sha256,
        nonce,
    )
    if canonical_bytes(view) != canonical_bytes(recomputed_view):
        raise CausalFrontierError("commitment nonce does not reproduce the checkpointed entrant view")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, oracle_root)
            observations, oracle_entries_before_opening, oracle_bytes_before_opening = _validate_oracle_inventory(
                payload,
                descriptor,
                case_lanes,
                preflight,
                race,
                view,
                nonce,
                opening_present=False,
            )
            observation_count = 0
            for batch in observations.values():
                for observation in batch:
                    raw = receipt_io._snapshot(descriptor, observation["path"])
                    if len(raw) > CLASSIFIER_INPUT_MAX_BYTES:
                        raise CausalFrontierError(
                            "oracle observation exceeds the registered classifier input byte limit"
                        )
                    if sha256_bytes(raw) != observation["sha256"]:
                        raise CausalFrontierError("observation bytes do not match the proposed commitment")
                    _screen_synthetic_observation(raw)
                    observation_count += 1
            committed_paths = {observation["path"] for batch in observations.values() for observation in batch}
            files_after, directories_after, entries_after, bytes_after = _strict_inventory(
                descriptor,
                observation_paths=committed_paths,
            )
            if (
                files_after != committed_paths
                or directories_after != _expected_directories(committed_paths)
                or entries_after != oracle_entries_before_opening
                or bytes_after != oracle_bytes_before_opening
            ):
                raise CausalFrontierError("observation oracle changed during commitment preflight")
            # A second complete byte pass closes the same-length replacement
            # window between the first digest pass and the metadata inventory.
            # It is still a local point-in-time check, not an immutable snapshot
            # or independent custody attestation.
            for batch in observations.values():
                for observation in batch:
                    raw = receipt_io._snapshot(descriptor, observation["path"])
                    if sha256_bytes(raw) != observation["sha256"]:
                        raise CausalFrontierError("observation bytes changed during commitment preflight")
                    _screen_synthetic_observation(raw)
            files_final, directories_final, entries_final, bytes_final = _strict_inventory(
                descriptor,
                observation_paths=committed_paths,
            )
            if (
                files_final != committed_paths
                or directories_final != _expected_directories(committed_paths)
                or entries_final != oracle_entries_before_opening
                or bytes_final != oracle_bytes_before_opening
            ):
                raise CausalFrontierError("observation oracle changed during commitment preflight")
    except OSError:
        raise CausalFrontierError("observation oracle cannot be preflighted safely") from None
    oracle_entries_n = oracle_entries_before_opening + 1
    oracle_total_bytes_n = oracle_bytes_before_opening + len(prospective_opening_raw)
    if oracle_entries_n > MAX_ORACLE_FILES or oracle_total_bytes_n > MAX_ORACLE_TOTAL_BYTES:
        raise CausalFrontierError("prospective oracle opening would exceed the registered inventory limits")
    commitment = reveal_commitment(payload, nonce.hex())
    core = {
        "schema_version": COMMITMENT_PREFLIGHT_SCHEMA_VERSION,
        "status": COMMITMENT_PREFLIGHT_STATUS,
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "challenge_registration_sha256": preflight["challenge_registration_sha256"],
        "challenge_sequence": preflight["challenge_sequence"],
        "race_spec_sha256": expected_race_spec_sha256,
        "policy_contract_sha256": policy_contract_sha256(),
        "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
        "entrant_view_sha256": view["view_sha256"],
        "payload_checkpoint_sha256": expected_payload_checkpoint_sha256,
        "payload_sha256": sha256_bytes(canonical_bytes(payload)),
        "nonce_checkpoint_sha256": expected_nonce_checkpoint_sha256,
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": commitment,
        "oracle_opening_sha256": sha256_bytes(prospective_opening_raw),
        "oracle_entries_n": oracle_entries_n,
        "oracle_total_bytes_n": oracle_total_bytes_n,
        "oracle_limit_contract_sha256": _oracle_limit_contract_sha256(),
        "cases_n": len(case_lanes),
        "actions_n": len(observations),
        "observations_n": observation_count,
        "required_replicates": race["required_replicates"],
        "all_committed_observation_bytes_read_and_digest_matched": True,
        "prohibited_observation_field_marker_screen_passed": True,
        "oracle_opening_present_during_preflight": False,
        "blinding_nonce_entropy_verified": False,
        "blinding_nonce_uniqueness_verified": False,
        "blinding_nonce_secrecy_until_selection_verified": False,
        "independent_attestation_verified": False,
        "preflight_temporal_order_verified": False,
        "scientific_scoring_ready": False,
        "nonclaims": list(EXECUTION_NONCLAIMS),
    }
    return {**core, "commitment_preflight_sha256": sha256_bytes(canonical_bytes(core))}


def _validate_commitment_preflight(value: Any) -> dict[str, Any]:
    report = require_exact_keys(
        value,
        {
            "schema_version",
            "status",
            "implementation_status",
            "base_compiler_version",
            "challenge_registration_sha256",
            "challenge_sequence",
            "race_spec_sha256",
            "policy_contract_sha256",
            "entrant_view_checkpoint_sha256",
            "entrant_view_sha256",
            "payload_checkpoint_sha256",
            "payload_sha256",
            "nonce_checkpoint_sha256",
            "reveal_commitment_scheme",
            "reveal_commitment_sha256",
            "oracle_opening_sha256",
            "oracle_entries_n",
            "oracle_total_bytes_n",
            "oracle_limit_contract_sha256",
            "cases_n",
            "actions_n",
            "observations_n",
            "required_replicates",
            "all_committed_observation_bytes_read_and_digest_matched",
            "prohibited_observation_field_marker_screen_passed",
            "oracle_opening_present_during_preflight",
            "blinding_nonce_entropy_verified",
            "blinding_nonce_uniqueness_verified",
            "blinding_nonce_secrecy_until_selection_verified",
            "independent_attestation_verified",
            "preflight_temporal_order_verified",
            "scientific_scoring_ready",
            "nonclaims",
            "commitment_preflight_sha256",
        },
        "synthetic observation commitment preflight",
    )
    if (
        report["schema_version"] != COMMITMENT_PREFLIGHT_SCHEMA_VERSION
        or report["status"] != COMMITMENT_PREFLIGHT_STATUS
        or report["implementation_status"] != "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE"
        or report["base_compiler_version"] != COMPILER_VERSION
        or report["policy_contract_sha256"] != policy_contract_sha256()
        or report["reveal_commitment_scheme"] != REVEAL_COMMITMENT_SCHEME
        or report["oracle_limit_contract_sha256"] != _oracle_limit_contract_sha256()
        or report["all_committed_observation_bytes_read_and_digest_matched"] is not True
        or report["prohibited_observation_field_marker_screen_passed"] is not True
        or report["oracle_opening_present_during_preflight"] is not False
        or report["blinding_nonce_entropy_verified"] is not False
        or report["blinding_nonce_uniqueness_verified"] is not False
        or report["blinding_nonce_secrecy_until_selection_verified"] is not False
        or report["independent_attestation_verified"] is not False
        or report["preflight_temporal_order_verified"] is not False
        or report["scientific_scoring_ready"] is not False
        or report["nonclaims"] != list(EXECUTION_NONCLAIMS)
    ):
        raise CausalFrontierError("synthetic observation commitment preflight overclaims or targets another contract")
    for field in (
        "challenge_registration_sha256",
        "race_spec_sha256",
        "policy_contract_sha256",
        "entrant_view_checkpoint_sha256",
        "entrant_view_sha256",
        "payload_checkpoint_sha256",
        "payload_sha256",
        "nonce_checkpoint_sha256",
        "reveal_commitment_sha256",
        "oracle_opening_sha256",
        "oracle_limit_contract_sha256",
        "commitment_preflight_sha256",
    ):
        require_sha256(report[field], "commitment preflight %s" % field)
    _bounded_integer(report["challenge_sequence"], "commitment preflight challenge sequence", minimum=1)
    _bounded_integer(
        report["required_replicates"],
        "commitment preflight required replicates",
        minimum=MIN_REPLICATES,
        maximum=MAX_REPLICATES,
    )
    _bounded_integer(report["cases_n"], "commitment preflight case count", minimum=1, maximum=MAX_ORACLE_FILES)
    _bounded_integer(
        report["actions_n"],
        "commitment preflight action count",
        minimum=1,
        maximum=MAX_ORACLE_FILES,
    )
    _bounded_integer(
        report["observations_n"],
        "commitment preflight observation count",
        minimum=1,
        maximum=MAX_ORACLE_FILES,
    )
    _bounded_integer(
        report["oracle_entries_n"],
        "commitment preflight oracle entry count",
        minimum=1,
        maximum=MAX_ORACLE_FILES,
    )
    _bounded_integer(
        report["oracle_total_bytes_n"],
        "commitment preflight oracle total bytes",
        minimum=1,
        maximum=MAX_ORACLE_TOTAL_BYTES,
    )
    if report["observations_n"] != report["actions_n"] * report["required_replicates"]:
        raise CausalFrontierError("commitment preflight counts are internally inconsistent")
    if report["oracle_entries_n"] < report["observations_n"] + 1:
        raise CausalFrontierError("commitment preflight oracle entry count is internally inconsistent")
    core = {key: item for key, item in report.items() if key != "commitment_preflight_sha256"}
    if sha256_bytes(canonical_bytes(core)) != report["commitment_preflight_sha256"]:
        raise CausalFrontierError("commitment preflight semantic digest mismatch")
    return report


def _event(events: list[dict[str, Any]], episode_id: str, kind: str, payload: dict[str, Any]) -> None:
    core = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "episode_id": episode_id,
        "seq": len(events) + 1,
        "prev_digest": GENESIS if not events else events[-1]["digest"],
        "type": kind,
        "payload": payload,
    }
    events.append({**core, "digest": sha256_bytes(EVENT_DOMAIN_TAG + canonical_bytes(core))})


def _add_resources(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    return {key: left[key] + right[key] for key in RESOURCE_DIMENSIONS}


def _zero_resources() -> dict[str, int]:
    return dict.fromkeys(RESOURCE_DIMENSIONS, 0)


def _redact_classifier_result(result: dict[str, Any], replicate_index: int) -> dict[str, Any]:
    diagnostic_code = result["metrics"].get("reason") if set(result["metrics"]) == {"reason"} else None
    core = {
        "schema_version": "causalfrontier.redacted-observation-classifier-result.v1",
        "replicate_index": replicate_index,
        "classifier_sha256": result["classifier_sha256"],
        "adapter_contract_sha256": result["adapter_contract_sha256"],
        "branch_token": result["branch_token"],
        "outcome_id": result["outcome_id"],
        "diagnostic_code": diagnostic_code,
        "group_keyed_metrics_omitted": True,
        "direct_observation_identifier_field_omitted": True,
        "direct_observation_digest_field_omitted": True,
    }
    return {**core, "redacted_result_sha256": sha256_bytes(canonical_bytes(core))}


def _adjudicate(results: list[dict[str, Any]], experiment: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    tokens = {item["branch_token"] for item in results}
    outcomes = {item["outcome_id"] for item in results}
    outcome_classes = {item["id"]: item["class"] for item in experiment["outcomes"]}
    any_contradiction = any(outcome_classes[item["outcome_id"]] == "CONTRADICTION" for item in results)
    duplicate_observation_bytes = len({item["observation_sha256"] for item in results}) != len(results)
    aggregate_outcome_id: str | None = None
    decision_class_reduction = 0
    if len(tokens) == 1 and len(outcomes) == 1:
        aggregate_outcome_id = next(iter(outcomes))
        outcome_class = outcome_classes[aggregate_outcome_id]
        if outcome_class == "INFORMATIVE":
            state = "CONSISTENT_INFORMATIVE_SYNTHETIC_BATCH_INDEPENDENCE_UNVERIFIED"
            analysis_experiment = next(item for item in analysis["experiments"] if item["id"] == experiment["id"])
            analysis_outcome = next(
                item for item in analysis_experiment["outcomes"] if item["id"] == aggregate_outcome_id
            )
            decision_class_reduction = (
                analysis_experiment["baseline_decision_class_count"]
                - analysis_outcome["remaining_decision_class_count"]
            )
        elif outcome_class == "CONTRADICTION":
            state = "PARTITION_INVALIDATED_REQUIRES_NEW_CASE"
        elif outcome_class == "FAILURE":
            state = "CONSISTENT_EXECUTION_FAILURE_BATCH_NO_UPDATE"
        else:
            state = "CONSISTENT_NO_CALL_BATCH_NO_UPDATE"
    elif any_contradiction:
        state = "REPLICATION_DISCORDANT_PARTITION_INVALIDATED"
    else:
        state = "REPLICATION_DISCORDANT_NO_CALL"
    core = {
        "state": state,
        "aggregate_outcome_id": aggregate_outcome_id,
        "replicate_tokens": sorted(tokens),
        "synthetic_decision_class_reduction": decision_class_reduction,
        "replicate_bytes_distinct": not duplicate_observation_bytes,
        "replicate_independence_verified": False,
    }
    return {**core, "adjudication_sha256": sha256_bytes(canonical_bytes(core))}


def execute_blind_synthetic_policy(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    race_spec_path: Path,
    expected_race_spec_sha256: str,
    view_path: Path,
    expected_view_checkpoint_sha256: str,
    selection_path: Path,
    expected_selection_checkpoint_sha256: str,
    selection_envelope_path: Path,
    expected_selection_envelope_checkpoint_sha256: str,
    commitment_preflight_path: Path,
    expected_commitment_preflight_checkpoint_sha256: str,
    oracle_root: Path,
    expected_opening_sha256: str,
    entrant_case_id: str,
    entrant_lane_id: str,
    policy_id: str,
) -> dict[str, Any]:
    """Replay one locked reference-policy episode against committed observations."""

    entrant_case_id = require_id(entrant_case_id, "execution entrant case id")
    entrant_lane_id = require_id(entrant_lane_id, "execution entrant lane id")
    policy_id = require_id(policy_id, "execution policy id")
    preflight, case_lanes = load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    race = _load_race_spec(race_spec_path, expected_race_spec_sha256, preflight, case_lanes)
    _view_raw, view_value = _read_checkpointed_json(
        view_path, expected_view_checkpoint_sha256, "sanitized entrant view"
    )
    view = _validate_view(view_value)
    _commitment_preflight_raw, commitment_preflight_value = _read_checkpointed_json(
        commitment_preflight_path,
        expected_commitment_preflight_checkpoint_sha256,
        "synthetic observation commitment preflight",
    )
    commitment_preflight = _validate_commitment_preflight(commitment_preflight_value)
    if (
        commitment_preflight["challenge_registration_sha256"] != preflight["challenge_registration_sha256"]
        or commitment_preflight["challenge_sequence"] != preflight["challenge_sequence"]
        or commitment_preflight["race_spec_sha256"] != expected_race_spec_sha256
        or commitment_preflight["policy_contract_sha256"] != policy_contract_sha256()
        or commitment_preflight["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256
        or commitment_preflight["entrant_view_sha256"] != view["view_sha256"]
        or commitment_preflight["required_replicates"] != race["required_replicates"]
        or commitment_preflight["reveal_commitment_sha256"] != preflight["reveal_commitment_sha256"]
    ):
        raise CausalFrontierError("commitment preflight targets another bound execution")
    _selection_raw, selection_value = _read_checkpointed_json(
        selection_path,
        expected_selection_checkpoint_sha256,
        "blind selection lock",
    )
    selection = _validate_selection_lock(selection_value)
    replayed_selection = lock_blind_reference_selections(view_path, expected_view_checkpoint_sha256)
    if canonical_bytes(selection) != canonical_bytes(replayed_selection):
        raise CausalFrontierError("blind selection lock does not replay from the entrant view")
    if selection["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256:
        raise CausalFrontierError("blind selection lock targets another entrant view checkpoint")
    _selection_envelope_raw, selection_envelope_value = _read_checkpointed_json(
        selection_envelope_path,
        expected_selection_envelope_checkpoint_sha256,
        "blind selection precommitment envelope",
    )
    selection_envelope = _validate_selection_envelope(selection_envelope_value)
    if (
        selection_envelope["entrant_view_checkpoint_sha256"] != expected_view_checkpoint_sha256
        or selection_envelope["entrant_view_sha256"] != view["view_sha256"]
        or selection_envelope["selection_checkpoint_sha256"] != expected_selection_checkpoint_sha256
        or selection_envelope["selection_lock_sha256"] != selection["selection_lock_sha256"]
        or selection_envelope["commitment_preflight_checkpoint_sha256"]
        != expected_commitment_preflight_checkpoint_sha256
    ):
        raise CausalFrontierError("selection envelope targets another selection or commitment preflight")
    if expected_opening_sha256 != commitment_preflight["oracle_opening_sha256"]:
        raise CausalFrontierError("oracle opening checkpoint differs from commitment preflight")

    oracle, oracle_descriptor, oracle_stack, opening_raw = _open_oracle(
        oracle_root,
        expected_opening_sha256,
        preflight["reveal_commitment_sha256"],
    )
    try:
        if sha256_bytes(opening_raw) != commitment_preflight["oracle_opening_sha256"]:
            raise CausalFrontierError("authenticated opening differs from the checkpointed commitment preflight")
        nonce = bytes.fromhex(oracle["nonce_hex"])
        if (
            sha256_bytes(canonical_bytes(oracle["payload"])) != commitment_preflight["payload_sha256"]
            or sha256_bytes(canonical_bytes(oracle["payload"]) + b"\n")
            != commitment_preflight["payload_checkpoint_sha256"]
            or sha256_bytes((oracle["nonce_hex"] + "\n").encode("ascii"))
            != commitment_preflight["nonce_checkpoint_sha256"]
        ):
            raise CausalFrontierError("opened oracle does not replay the checkpointed commitment preflight")
        recomputed_view = build_sanitized_entrant_view(
            root,
            expected_manifest_sha256,
            expected_sequence,
            race_spec_path,
            expected_race_spec_sha256,
            nonce,
        )
        if canonical_bytes(view) != canonical_bytes(recomputed_view):
            raise CausalFrontierError("opened nonce does not reproduce the checkpointed entrant view")
        observation_map, oracle_entries_n, oracle_total_bytes_n = _validate_oracle_inventory(
            oracle["payload"],
            oracle_descriptor,
            case_lanes,
            preflight,
            race,
            view,
            nonce,
        )
        if (
            len(case_lanes) != commitment_preflight["cases_n"]
            or len(observation_map) != commitment_preflight["actions_n"]
            or sum(len(batch) for batch in observation_map.values()) != commitment_preflight["observations_n"]
            or oracle_entries_n != commitment_preflight["oracle_entries_n"]
        ):
            raise CausalFrontierError("opened oracle inventory counts differ from commitment preflight")
        initial_oracle_total_bytes_match = oracle_total_bytes_n == commitment_preflight["oracle_total_bytes_n"]
        lane_trace = next(
            (
                item
                for item in selection["reference_lanes"]
                if item["entrant_case_id"] == entrant_case_id and item["entrant_lane_id"] == entrant_lane_id
            ),
            None,
        )
        if lane_trace is None:
            raise CausalFrontierError("execution references an unknown entrant case or lane")
        policy_trace = next(
            (item for item in lane_trace["reference_policy_traces"] if item["policy_id"] == policy_id),
            None,
        )
        if policy_trace is None:
            raise CausalFrontierError("execution references an unknown locked policy")
        original_case_id = next(
            (
                case_id
                for case_id in case_lanes
                if _opaque_id("case", case_id, preflight["challenge_registration_sha256"], nonce) == entrant_case_id
            ),
            None,
        )
        if original_case_id is None:
            raise CausalFrontierError("entrant case alias does not open to the challenge")
        original_lane = next(
            (
                lane
                for lane in case_lanes[original_case_id]
                if _opaque_id(
                    "lane",
                    "%s\0%s" % (original_case_id, lane["encoding_id"]),
                    preflight["challenge_registration_sha256"],
                    nonce,
                )
                == entrant_lane_id
            ),
            None,
        )
        if original_lane is None:
            raise CausalFrontierError("entrant lane alias does not open to the challenge")
        action_aliases = {
            _opaque_id(
                "action",
                "%s\0%s" % (original_case_id, item["id"]),
                preflight["challenge_registration_sha256"],
                nonce,
            ): item["id"]
            for item in original_lane["case"]["experiments"]
        }
        view_case = next(item for item in view["cases"] if item["entrant_case_id"] == entrant_case_id)
        tariffs = {item["entrant_action_id"]: item["resources"] for item in view_case["action_batch_tariffs"]}
        experiments = {item["id"]: item for item in original_lane["case"]["experiments"]}
        analysis = compile_case(original_lane["case"])
        episode_core = {
            "challenge_registration_sha256": preflight["challenge_registration_sha256"],
            "challenge_manifest_sha256": expected_manifest_sha256,
            "race_spec_sha256": expected_race_spec_sha256,
            "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
            "commitment_preflight_checkpoint_sha256": expected_commitment_preflight_checkpoint_sha256,
            "commitment_preflight_sha256": commitment_preflight["commitment_preflight_sha256"],
            "selection_checkpoint_sha256": expected_selection_checkpoint_sha256,
            "selection_lock_sha256": selection["selection_lock_sha256"],
            "selection_envelope_checkpoint_sha256": expected_selection_envelope_checkpoint_sha256,
            "selection_envelope_sha256": selection_envelope["selection_envelope_sha256"],
            "oracle_opening_checkpoint_sha256": expected_opening_sha256,
            "entrant_case_id": entrant_case_id,
            "entrant_lane_id": entrant_lane_id,
            "policy_id": policy_id,
            "policy_trace_sha256": policy_trace["trace_sha256"],
        }
        episode_id = "episode:%s" % sha256_bytes(canonical_bytes(episode_core))
        events: list[dict[str, Any]] = []
        used = _zero_resources()
        _event(
            events,
            episode_id,
            "EPISODE_REGISTERED",
            {
                **episode_core,
                "budget": view_case["budget"],
                "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
            },
        )
        _event(events, episode_id, "POLICY_OUTPUT", {"trace": policy_trace})
        action_reports = []
        terminal_reasons: set[str] = set()
        integrity_valid = True
        selected: list[dict[str, Any]] = []
        if not initial_oracle_total_bytes_match:
            _event(
                events,
                episode_id,
                "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY",
                {
                    "entrant_action_id": None,
                    "reason_code": "PREFLIGHT_ORACLE_TOTAL_BYTES_MISMATCH",
                    "resources_retained": used,
                },
            )
            terminal_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
            integrity_valid = False
        else:
            selected = [item for item in policy_trace["selections"] if item["action"] == "SELECT"]
        if policy_id == "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1":
            # Uniform enumeration is a set-valued complete replay. Secret
            # aliases must never determine action order or early-stop semantics.
            selected.sort(key=lambda item: action_aliases[item["entrant_action_id"]])
        if integrity_valid and not selected:
            terminal_reasons.add("ABSTAINED" if policy_trace["selections"][0]["action"] == "ABSTAIN" else "NO_CALL")
        for selected_action in selected:
            alias = selected_action["entrant_action_id"]
            if alias not in action_aliases or alias not in tariffs:
                raise CausalFrontierError("locked policy selects an action outside its opened case")
            next_used = _add_resources(used, tariffs[alias])
            exceeded = sorted(key for key in RESOURCE_DIMENSIONS if next_used[key] > view_case["budget"][key])
            if exceeded:
                _event(
                    events,
                    episode_id,
                    "ACTION_REJECTED",
                    {"entrant_action_id": alias, "reason": "BUDGET_EXCEEDED", "exceeded_dimensions": exceeded},
                )
                terminal_reasons.add("BUDGET_EXHAUSTED_CENSORED")
                break
            _event(
                events,
                episode_id,
                "ACTION_DEBITED",
                {
                    "entrant_action_id": alias,
                    "tariff": tariffs[alias],
                    "resources_before": used,
                    "resources_after": next_used,
                },
            )
            used = next_used
            experiment_id = action_aliases[alias]
            experiment = experiments[experiment_id]
            results = []
            try:
                batch = observation_map[(original_case_id, experiment_id)]
                authenticated_batch: list[tuple[dict[str, Any], bytes]] = []
                for observation in batch:
                    raw_observation = receipt_io._snapshot(oracle_descriptor, observation["path"])
                    if sha256_bytes(raw_observation) != observation["sha256"]:
                        raise CausalFrontierError("selected oracle observation digest mismatch")
                    _screen_synthetic_observation(raw_observation)
                    authenticated_batch.append((observation, raw_observation))
                for observation, raw_observation in authenticated_batch:
                    result = execute_classifier_observation(
                        original_lane["case"],
                        experiment_id,
                        observation["id"],
                        "replicate:%d" % observation["replicate_index"],
                        raw_observation,
                        observation["sha256"],
                    )
                    results.append(result)
                adjudication = _adjudicate(results, experiment, analysis)
                redacted_results = [
                    _redact_classifier_result(result, observation["replicate_index"])
                    for observation, result in zip(batch, results, strict=True)
                ]
                for observation, result, redacted_result in zip(batch, results, redacted_results, strict=True):
                    _event(
                        events,
                        episode_id,
                        "OBSERVATION_CLASSIFIED",
                        {
                            "entrant_action_id": alias,
                            "replicate_index": observation["replicate_index"],
                            "redacted_result_sha256": redacted_result["redacted_result_sha256"],
                            "branch_token": result["branch_token"],
                            "outcome_id": result["outcome_id"],
                        },
                    )
            except (CausalFrontierError, OSError):
                _event(
                    events,
                    episode_id,
                    "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY",
                    {
                        "entrant_action_id": alias,
                        "reason_code": "SELECTED_OBSERVATION_INTEGRITY_PRIVACY_OR_CLASSIFIER_ABORT",
                        "resources_retained": used,
                    },
                )
                terminal_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
                integrity_valid = False
                break
            report_core = {
                "entrant_action_id": alias,
                "experiment_id": experiment_id,
                "branch_plan_sha256": experiment["branch_plan_sha256"],
                "classifier_sha256": experiment["classifier_sha256"],
                "classifier_results": redacted_results,
                "adjudication": adjudication,
            }
            action_report = {**report_core, "action_report_sha256": sha256_bytes(canonical_bytes(report_core))}
            action_reports.append(action_report)
            _event(
                events,
                episode_id,
                "ACTION_ADJUDICATED",
                {
                    "entrant_action_id": alias,
                    "action_report_sha256": action_report["action_report_sha256"],
                    "adjudication_sha256": adjudication["adjudication_sha256"],
                    "state": adjudication["state"],
                },
            )
            if adjudication["state"] in {
                "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
                "REPLICATION_DISCORDANT_PARTITION_INVALIDATED",
            }:
                terminal_reasons.add("PARTITION_INVALIDATED_REQUIRES_NEW_CASE")
                if policy_id != "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1":
                    break
        # Detect selected-byte or inventory mutation during execution without
        # reading any unselected observation payload.
        if integrity_valid:
            try:
                committed_paths = {observation["path"] for batch in observation_map.values() for observation in batch}
                files_after, directories_after, entries_after, bytes_after = _strict_inventory(
                    oracle_descriptor,
                    observation_paths=committed_paths,
                )
                if (
                    files_after != {ORACLE_MANIFEST, *committed_paths}
                    or directories_after != _expected_directories(committed_paths)
                    or entries_after != oracle_entries_n
                    or bytes_after != oracle_total_bytes_n
                ):
                    raise CausalFrontierError("oracle inventory changed during execution")
            except (CausalFrontierError, OSError):
                _event(
                    events,
                    episode_id,
                    "EPISODE_ABORTED_INTEGRITY_OR_AUTHORITY",
                    {
                        "entrant_action_id": None,
                        "reason_code": "POST_EXECUTION_ORACLE_INVENTORY_ABORT",
                        "resources_retained": used,
                    },
                )
                terminal_reasons.add("INTEGRITY_OR_AUTHORITY_ABORT_INVALID")
                integrity_valid = False
        if not terminal_reasons:
            terminal_reasons.add("COMPLETED_REFERENCE_PROXY")
        terminal = next(
            reason
            for reason in (
                "INTEGRITY_OR_AUTHORITY_ABORT_INVALID",
                "PARTITION_INVALIDATED_REQUIRES_NEW_CASE",
                "BUDGET_EXHAUSTED_CENSORED",
                "ABSTAINED",
                "NO_CALL",
                "COMPLETED_REFERENCE_PROXY",
            )
            if reason in terminal_reasons
        )
        _event(
            events,
            episode_id,
            "EPISODE_TERMINATED",
            {
                "terminal_kind": terminal,
                "terminal_reason_codes": sorted(terminal_reasons),
                "resources_used": used,
                "actions_adjudicated_n": len(action_reports),
            },
        )
        if not integrity_valid:
            execution_status = "SYNTHETIC_POLICY_EXECUTION_ABORTED_INTEGRITY_INVALID_SCIENTIFIC_SCORING_DISABLED"
        elif action_reports:
            execution_status = "SYNTHETIC_BLIND_OBSERVATIONS_CLASSIFIED_SCIENTIFIC_SCORING_DISABLED"
        else:
            execution_status = (
                "SYNTHETIC_BLIND_POLICY_TERMINATED_WITHOUT_OBSERVATION_CLASSIFICATION_SCIENTIFIC_SCORING_DISABLED"
            )
        core = {
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "status": execution_status,
            "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
            "audience": "STEWARD_ONLY_NOT_A_PUBLIC_UNLINKABLE_PROJECTION",
            "public_unlinkable_projection_available": False,
            "base_compiler_version": COMPILER_VERSION,
            "episode_id": episode_id,
            "challenge_manifest_sha256": expected_manifest_sha256,
            "challenge_registration_sha256": preflight["challenge_registration_sha256"],
            "race_spec_sha256": expected_race_spec_sha256,
            "entrant_view_checkpoint_sha256": expected_view_checkpoint_sha256,
            "entrant_view_sha256": view["view_sha256"],
            "commitment_preflight_checkpoint_sha256": expected_commitment_preflight_checkpoint_sha256,
            "commitment_preflight_sha256": commitment_preflight["commitment_preflight_sha256"],
            "selection_checkpoint_sha256": expected_selection_checkpoint_sha256,
            "selection_lock_sha256": selection["selection_lock_sha256"],
            "selection_envelope_checkpoint_sha256": expected_selection_envelope_checkpoint_sha256,
            "selection_envelope_sha256": selection_envelope["selection_envelope_sha256"],
            "oracle_opening_checkpoint_sha256": expected_opening_sha256,
            "oracle_opening_sha256": sha256_bytes(opening_raw),
            "oracle_payload_sha256": sha256_bytes(canonical_bytes(oracle["payload"])),
            "preflight_oracle_entries_n": commitment_preflight["oracle_entries_n"],
            "preflight_oracle_total_bytes_n": commitment_preflight["oracle_total_bytes_n"],
            "preflight_oracle_total_bytes_matched_at_execution_start": initial_oracle_total_bytes_match,
            "oracle_limit_contract_sha256": commitment_preflight["oracle_limit_contract_sha256"],
            "entrant_case_id": entrant_case_id,
            "entrant_lane_id": entrant_lane_id,
            "policy_id": policy_id,
            "policy_trace_sha256": policy_trace["trace_sha256"],
            "terminal_kind": terminal,
            "terminal_reason_codes": sorted(terminal_reasons),
            "integrity_valid": integrity_valid,
            "commitment_preflight_checkpoint_verified": True,
            "commitment_preflight_independent_attestation_verified": False,
            "preflight_prohibited_observation_field_marker_screen_passed": True,
            "patient_level_data_absence_independently_verified": False,
            "current_full_oracle_byte_readiness_verified": False,
            "blinding_nonce_entropy_verified": False,
            "blinding_nonce_uniqueness_verified": False,
            "blinding_nonce_secrecy_until_selection_verified": False,
            "selector_preflight_input_accepted": False,
            "precommitment_temporal_order_independently_verified": False,
            "resources_used": used,
            "resource_accounting_mode": RESOURCE_ACCOUNTING_MODE,
            "action_reports": action_reports,
            "events": events,
            "ledger_head": events[-1]["digest"],
            "environment_isolation_verified": False,
            "replicate_independence_verified": False,
            "scientific_baseline_families_executed": [],
            "required_scientific_baseline_families_unexecuted": sorted(BASELINE_FAMILIES),
            "scientific_scoring_ready": False,
            "nonclaims": list(EXECUTION_NONCLAIMS),
        }
        return {**core, "execution_report_sha256": sha256_bytes(canonical_bytes(core))}
    finally:
        oracle_stack.close()
