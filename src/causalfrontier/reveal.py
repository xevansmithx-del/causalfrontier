"""Fail-closed opening for committed synthetic complete-replay branch tables.

The v1 opening validates only commitment framing and branch-table totality. It
does not derive outcomes from hidden observations, adjudicate truth, or score a
scientific run.
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
    io_error,
    read_json_bytes,
    require_enum,
    require_exact_keys,
    require_id,
    require_sha256,
    sha256_bytes,
)
from .challenge import REVEAL_COMMITMENT_SCHEME, load_protocol_cases
from .model import COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

OPENING_SCHEMA_VERSION = "causalfrontier.synthetic-reveal-opening.v1"
PAYLOAD_SCHEMA_VERSION = "causalfrontier.synthetic-reveal-payload.v1"
DOMAIN_TAG = b"causalfrontier.reveal.v1\0"
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_REPLICATES = 2
MAX_REPLICATES = 8

NONCLAIMS = (
    "The opening is a synthetic protocol exercise, not a prospective scientific result.",
    "Outcome identifiers are organizer-authored branch labels, not classifications derived from hidden raw "
    "observations.",
    "Nonce length and commitment equality are checked; entropy, secrecy before opening, and external timestamping "
    "are not.",
    "Complete branch-table syntax does not establish counterfactual, biological, causal, or adjudicative validity.",
    "No policy trace, resource ledger, experiment, patient datum, or material is executed or scored.",
)


def _nonce_bytes(nonce_hex: Any) -> bytes:
    if not isinstance(nonce_hex, str) or NONCE_RE.fullmatch(nonce_hex) is None:
        raise CausalFrontierError("reveal nonce must be exactly 32 lowercase hexadecimal bytes")
    return bytes.fromhex(nonce_hex)


def reveal_commitment(payload: dict[str, Any], nonce_hex: str) -> str:
    """Return the normative domain-separated v1 reveal commitment."""

    nonce = _nonce_bytes(nonce_hex)
    return sha256_bytes(DOMAIN_TAG + canonical_bytes(payload) + b"\0" + nonce)


def _read_checkpointed_opening(path: Path, expected_sha256: str) -> tuple[bytes, dict[str, Any]]:
    require_sha256(expected_sha256, "external reveal-opening checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = receipt_io._root_descriptor(stack, path.parent)
            raw = receipt_io._snapshot(descriptor, path.name)
    except OSError as exc:
        raise io_error(
            exc, "reveal opening cannot be read safely", operation="reveal._read_checkpointed_opening"
        ) from None
    if sha256_bytes(raw) != expected_sha256:
        raise CausalFrontierError("external reveal-opening checkpoint mismatch")
    receipt_io._screen(raw)
    value = read_json_bytes(raw, "synthetic reveal opening")
    receipt_io._screen(canonical_bytes(value))
    return raw, require_exact_keys(value, {"schema_version", "nonce_hex", "payload"}, "reveal opening")


def _positive_replicates(value: Any) -> int:
    if type(value) is not int or not MIN_REPLICATES <= value <= MAX_REPLICATES:
        raise CausalFrontierError("required replicates must be a bounded integer from 2 through 8")
    return value


def open_synthetic_reveal(
    root: Path,
    expected_manifest_sha256: str,
    expected_sequence: int,
    opening_path: Path,
    expected_opening_sha256: str,
) -> dict[str, Any]:
    """Open and structurally replay a synthetic branch table; never score it."""

    preflight, case_lanes = load_protocol_cases(root, expected_manifest_sha256, expected_sequence)
    if preflight["scope"] != "SYNTHETIC_PROTOCOL_TEST":
        raise CausalFrontierError("synthetic reveal v1 cannot open a historical or prospective challenge")
    raw_opening, opening = _read_checkpointed_opening(opening_path, expected_opening_sha256)
    if opening["schema_version"] != OPENING_SCHEMA_VERSION:
        raise CausalFrontierError("unregistered synthetic reveal-opening schema")
    nonce_hex = opening["nonce_hex"]
    nonce = _nonce_bytes(nonce_hex)
    payload = require_exact_keys(
        opening["payload"],
        {
            "schema_version",
            "challenge_id",
            "challenge_sequence",
            "challenge_registration_sha256",
            "predecessor_manifest_sha256",
            "scope",
            "required_replicates",
            "cases",
        },
        "synthetic reveal payload",
    )
    if (
        payload["schema_version"] != PAYLOAD_SCHEMA_VERSION
        or payload["challenge_id"] != preflight["challenge_id"]
        or payload["challenge_sequence"] != preflight["challenge_sequence"]
        or payload["challenge_registration_sha256"] != preflight["challenge_registration_sha256"]
        or payload["predecessor_manifest_sha256"] != preflight["predecessor_manifest_sha256"]
        or payload["scope"] != "SYNTHETIC_PROTOCOL_TEST"
    ):
        raise CausalFrontierError("synthetic reveal payload targets another challenge or scope")
    require_id(payload["challenge_id"], "reveal challenge id")
    require_sha256(payload["challenge_registration_sha256"], "reveal challenge registration digest")
    require_sha256(payload["predecessor_manifest_sha256"], "reveal predecessor digest")
    require_enum(payload["scope"], {"SYNTHETIC_PROTOCOL_TEST"}, "reveal scope")
    if type(payload["challenge_sequence"]) is not int or payload["challenge_sequence"] < 1:
        raise CausalFrontierError("reveal challenge sequence must be a positive integer")
    required_replicates = _positive_replicates(payload["required_replicates"])

    cases = payload["cases"]
    if not isinstance(cases, list) or any(not isinstance(item, dict) for item in cases):
        raise CausalFrontierError("synthetic reveal cases must be a list of objects")
    if len(cases) != len(case_lanes):
        raise CausalFrontierError("synthetic reveal case inventory differs from the challenge")
    seen_cases: set[str] = set()
    case_oracle_sha256: dict[str, str] = {}
    action_count = 0
    for case_value in cases:
        case = require_exact_keys(case_value, {"case_id", "action_outcomes"}, "synthetic reveal case")
        case_id = require_id(case["case_id"], "synthetic reveal case id")
        if case_id in seen_cases or case_id not in case_lanes:
            raise CausalFrontierError("synthetic reveal contains a duplicate or unknown case")
        seen_cases.add(case_id)
        frozen_case = case_lanes[case_id][0]["case"]
        experiment_map = {item["id"]: item for item in frozen_case["experiments"]}
        actions = case["action_outcomes"]
        if not isinstance(actions, list) or len(actions) != len(experiment_map):
            raise CausalFrontierError("synthetic reveal action inventory differs from the frozen catalog")
        seen_actions: set[str] = set()
        for action_value in actions:
            action = require_exact_keys(
                action_value,
                {"experiment_id", "replicate_outcome_ids"},
                "synthetic reveal action",
            )
            experiment_id = require_id(action["experiment_id"], "synthetic reveal experiment id")
            if experiment_id in seen_actions or experiment_id not in experiment_map:
                raise CausalFrontierError("synthetic reveal contains a duplicate or unknown action")
            seen_actions.add(experiment_id)
            outcomes = action["replicate_outcome_ids"]
            valid_outcomes = {item["id"] for item in experiment_map[experiment_id]["outcomes"]}
            if (
                not isinstance(outcomes, list)
                or len(outcomes) != required_replicates
                or any(not isinstance(item, str) or item not in valid_outcomes for item in outcomes)
            ):
                raise CausalFrontierError("synthetic reveal replicate outcomes are incomplete or post-hoc")
            action_count += 1
        if seen_actions != set(experiment_map):
            raise CausalFrontierError("synthetic reveal action inventory is incomplete")
        case_oracle_sha256[case_id] = sha256_bytes(canonical_bytes(case))
    if seen_cases != set(case_lanes):
        raise CausalFrontierError("synthetic reveal case inventory is incomplete")

    computed = reveal_commitment(payload, nonce_hex)
    if not hmac.compare_digest(computed, preflight["reveal_commitment_sha256"]):
        raise CausalFrontierError("synthetic reveal commitment does not open")
    payload_sha256 = sha256_bytes(canonical_bytes(payload))
    core = {
        "schema_version": "causalfrontier.synthetic-reveal-report.v1",
        "status": "SYNTHETIC_REVEAL_OPENED_OUTCOME_DERIVATION_AND_SCIENTIFIC_SCORING_DISABLED",
        "implementation_status": "LOCAL_UNRELEASED_SYNTHETIC_PROTOCOL_EXERCISE",
        "base_compiler_version": COMPILER_VERSION,
        "challenge_id": preflight["challenge_id"],
        "challenge_sequence": preflight["challenge_sequence"],
        "challenge_manifest_sha256": preflight["challenge_manifest_sha256"],
        "challenge_registration_sha256": preflight["challenge_registration_sha256"],
        "scope": preflight["scope"],
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "reveal_commitment_scheme": REVEAL_COMMITMENT_SCHEME,
        "reveal_commitment_sha256": preflight["reveal_commitment_sha256"],
        "reveal_opening_sha256": sha256_bytes(raw_opening),
        "reveal_payload_sha256": payload_sha256,
        "nonce_sha256": sha256_bytes(nonce),
        "required_replicates": required_replicates,
        "cases_n": len(cases),
        "actions_n": action_count,
        "case_oracle_sha256": dict(sorted(case_oracle_sha256.items())),
        "outcome_derivation_ready": False,
        "scientific_scoring_ready": False,
        "gates": [
            {
                "id": "branch_table_totality",
                "status": "PASS",
                "reason": "EVERY_FROZEN_SYNTHETIC_ACTION_HAS_THE_PREDECLARED_REPLICATE_COUNT",
            },
            {
                "id": "external_timestamp",
                "status": "NO_CALL",
                "reason": "COMMITMENT_AND_OPENING_HAVE_NO_INDEPENDENT_TIMESTAMP_ATTESTATION",
            },
            {
                "id": "outcome_derivation",
                "status": "NO_CALL",
                "reason": "ORGANIZER_BRANCH_IDS_NOT_DERIVED_FROM_HIDDEN_RAW_OBSERVATIONS",
            },
            {
                "id": "reveal_commitment",
                "status": "PASS",
                "reason": "DOMAIN_SEPARATED_CANONICAL_PAYLOAD_AND_EXACT_32_BYTE_NONCE_MATCH",
            },
            {
                "id": "rollback",
                "status": "NO_CALL",
                "reason": "CALLER_OPENING_DIGEST_NOT_PROVEN_INDEPENDENTLY_STORED_OR_MONOTONIC",
            },
            {"id": "scientific_scoring", "status": "NO_CALL", "reason": "NO_POLICY_OR_RESOURCE_TRACE_SCORED"},
        ],
        "nonclaims": list(NONCLAIMS),
    }
    return {**core, "reveal_report_sha256": sha256_bytes(canonical_bytes(core))}
