"""Assertion-independent normal/-O probe for blinded synthetic execution."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from copy import deepcopy
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
SRC = PROJECT / "src"
TESTS = PROJECT / "tests"
for directory in (SRC, TESTS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from test_blind_execution import (  # noqa: E402
    NONCE,
    NONCE_HEX,
    _oracle_payload,
    _race_spec,
    _write_json,
)
from test_challenge import _build, _reseal  # noqa: E402

from causalfrontier import blind, challenge  # noqa: E402
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes  # noqa: E402


def _execute(
    challenge_root: Path,
    manifest_digest: str,
    race_path: Path,
    race_digest: str,
    view_path: Path,
    view_digest: str,
    selection_path: Path,
    selection_digest: str,
    selection_envelope_path: Path,
    selection_envelope_digest: str,
    commitment_preflight_path: Path,
    commitment_preflight_digest: str,
    oracle_root: Path,
    opening_digest: str,
    payload: dict,
    view: dict,
    case_id: str,
    policy_id: str,
) -> dict:
    payload_case = next(item for item in payload["cases"] if item["case_id"] == case_id)
    view_case = next(item for item in view["cases"] if item["entrant_case_id"] == payload_case["entrant_case_id"])
    return blind.execute_blind_synthetic_policy(
        challenge_root,
        manifest_digest,
        1,
        race_path,
        race_digest,
        view_path,
        view_digest,
        selection_path,
        selection_digest,
        selection_envelope_path,
        selection_envelope_digest,
        commitment_preflight_path,
        commitment_preflight_digest,
        oracle_root,
        opening_digest,
        payload_case["entrant_case_id"],
        view_case["lanes"][0]["entrant_lane_id"],
        policy_id,
    )


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-blind-optimized-")).resolve(strict=True)
    try:
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        raw_case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        challenge_root = temporary / "challenge"
        document, initial_digest = _build(challenge_root, raw_case, case_root)
        race_path, race_digest = _race_spec(document, challenge_root, initial_digest)
        view = blind.build_sanitized_entrant_view(
            challenge_root,
            initial_digest,
            1,
            race_path,
            race_digest,
            NONCE,
        )
        view_path = temporary / "view.json"
        view_digest = _write_json(view_path, view)
        oracle_root = temporary / "oracle"
        oracle_root.mkdir()
        payload, _markers = _oracle_payload(
            document,
            challenge_root,
            initial_digest,
            race_digest,
            view,
            oracle_root,
        )
        payload_path = temporary / "payload.json"
        payload_digest = _write_json(payload_path, payload)
        nonce_path = temporary / "nonce.secret"
        nonce_raw = NONCE_HEX.encode("ascii") + b"\n"
        nonce_path.write_bytes(nonce_raw)
        nonce_digest = sha256_bytes(nonce_raw)
        commitment_preflight = blind.prepare_synthetic_observation_commitment(
            challenge_root,
            initial_digest,
            1,
            race_path,
            race_digest,
            view_path,
            view_digest,
            oracle_root,
            payload_path,
            payload_digest,
            nonce_path,
            nonce_digest,
        )
        commitment_preflight_path = temporary / "commitment-preflight.json"
        commitment_preflight_digest = _write_json(commitment_preflight_path, commitment_preflight)
        document["reveal_commitment_sha256"] = commitment_preflight["reveal_commitment_sha256"]
        manifest_digest = _reseal(challenge_root, document)
        selection = blind.lock_blind_reference_selections(view_path, view_digest)
        selection_path = temporary / "selection.json"
        selection_digest = _write_json(selection_path, selection)
        selection_envelope = blind.bind_blind_selection_precommitment(
            view_path,
            view_digest,
            selection_path,
            selection_digest,
            commitment_preflight_digest,
        )
        selection_envelope_path = temporary / "selection-envelope.json"
        selection_envelope_digest = _write_json(selection_envelope_path, selection_envelope)
        opening = {
            "schema_version": blind.ORACLE_OPENING_SCHEMA_VERSION,
            "nonce_hex": NONCE_HEX,
            "payload": payload,
        }
        opening_path = oracle_root / blind.ORACLE_MANIFEST
        opening_digest = _write_json(opening_path, opening)
        positive = _execute(
            challenge_root,
            manifest_digest,
            race_path,
            race_digest,
            view_path,
            view_digest,
            selection_path,
            selection_digest,
            selection_envelope_path,
            selection_envelope_digest,
            commitment_preflight_path,
            commitment_preflight_digest,
            oracle_root,
            opening_digest,
            payload,
            view,
            "case:positive",
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
        )
        ambiguous = _execute(
            challenge_root,
            manifest_digest,
            race_path,
            race_digest,
            view_path,
            view_digest,
            selection_path,
            selection_digest,
            selection_envelope_path,
            selection_envelope_digest,
            commitment_preflight_path,
            commitment_preflight_digest,
            oracle_root,
            opening_digest,
            payload,
            view,
            "case:ambiguous",
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
        )
        abstain = _execute(
            challenge_root,
            manifest_digest,
            race_path,
            race_digest,
            view_path,
            view_digest,
            selection_path,
            selection_digest,
            selection_envelope_path,
            selection_envelope_digest,
            commitment_preflight_path,
            commitment_preflight_digest,
            oracle_root,
            opening_digest,
            payload,
            view,
            "case:failed-translation",
            "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
        )
        if any(item["scientific_scoring_ready"] is not False for item in (positive, ambiguous, abstain)):
            raise SystemExit("blind synthetic execution enabled scientific scoring")
        if not all(
            receipt["branch_token"] == "HIGH"
            for action in positive["action_reports"]
            for receipt in action["classifier_results"]
        ):
            raise SystemExit("hidden HIGH observations did not drive every positive-control classifier")
        if (
            sum(
                action["adjudication"]["state"] == "REPLICATION_DISCORDANT_NO_CALL"
                for action in ambiguous["action_reports"]
            )
            != 2
        ):
            raise SystemExit("ambiguous-control discordance was not preserved")
        if abstain["action_reports"] or abstain["terminal_kind"] != "ABSTAINED":
            raise SystemExit("abstention opened or adjudicated an observation")
        if "WITHOUT_OBSERVATION_CLASSIFICATION" not in abstain["status"]:
            raise SystemExit("abstention overclaimed observation classification")
        expected_action_order = sorted(item["experiment_id"] for item in positive["action_reports"])
        observed_action_order = [item["experiment_id"] for item in positive["action_reports"]]
        if observed_action_order != expected_action_order:
            raise SystemExit("uniform execution order depends on opaque aliases")

        forged = deepcopy(payload)
        forged["cases"][0]["actions"][0]["outcome_id"] = "organizer:forged"
        forged_path = temporary / "forged-payload.json"
        forged_digest = _write_json(forged_path, forged)
        try:
            blind.prepare_synthetic_observation_commitment(
                challenge_root,
                manifest_digest,
                1,
                race_path,
                race_digest,
                view_path,
                view_digest,
                oracle_root,
                forged_path,
                forged_digest,
                nonce_path,
                nonce_digest,
            )
        except CausalFrontierError:
            forged_rejected = True
        else:
            forged_rejected = False
        if not forged_rejected:
            raise SystemExit("organizer-authored outcome was accepted")

        valid_raw = opening_path.read_bytes()
        invalid_raw = valid_raw.replace(b'"required_replicates":2', b'"required_replicates":2.0', 1)
        if invalid_raw == valid_raw:
            raise SystemExit("probe could not construct float opening")
        opening_path.write_bytes(invalid_raw)
        try:
            blind.execute_blind_synthetic_policy(
                challenge_root,
                manifest_digest,
                1,
                race_path,
                race_digest,
                view_path,
                view_digest,
                selection_path,
                selection_digest,
                selection_envelope_path,
                selection_envelope_digest,
                commitment_preflight_path,
                commitment_preflight_digest,
                oracle_root,
                sha256_bytes(invalid_raw),
                payload["cases"][0]["entrant_case_id"],
                view["cases"][0]["lanes"][0]["entrant_lane_id"],
                "DO_NOTHING_OR_ABSTAIN_REFERENCE_V1",
            )
        except CausalFrontierError:
            float_rejected = True
        else:
            float_rejected = False
        finally:
            opening_path.write_bytes(valid_raw)
        if not float_rejected:
            raise SystemExit("floating-point opening did not fail closed")

        positive_case = next(item for item in payload["cases"] if item["case_id"] == "case:positive")
        first_action = min(positive_case["actions"], key=lambda item: item["experiment_id"])
        second_observation = first_action["observations"][1]
        second_path = oracle_root / second_observation["path"]
        second_raw = second_path.read_bytes()
        second_path.write_bytes(second_raw + b"tamper\n")
        integrity_abort = _execute(
            challenge_root,
            manifest_digest,
            race_path,
            race_digest,
            view_path,
            view_digest,
            selection_path,
            selection_digest,
            selection_envelope_path,
            selection_envelope_digest,
            commitment_preflight_path,
            commitment_preflight_digest,
            oracle_root,
            opening_digest,
            payload,
            view,
            "case:positive",
            "UNIFORM_ACTION_ENUMERATION_REFERENCE_V1",
        )
        second_path.write_bytes(second_raw)
        if (
            integrity_abort["integrity_valid"] is not False
            or integrity_abort["action_reports"]
            or any(item["type"] == "OBSERVATION_CLASSIFIED" for item in integrity_abort["events"])
        ):
            raise SystemExit("replicate-batch integrity abort leaked a partial classification")

        output = {
            "challenge_manifest_sha256": manifest_digest,
            "race_spec_sha256": race_digest,
            "view_sha256": view["view_sha256"],
            "view_checkpoint_sha256": view_digest,
            "selection_lock_sha256": selection["selection_lock_sha256"],
            "selection_checkpoint_sha256": selection_digest,
            "selection_envelope_sha256": selection_envelope["selection_envelope_sha256"],
            "selection_envelope_checkpoint_sha256": selection_envelope_digest,
            "commitment_preflight_sha256": commitment_preflight["commitment_preflight_sha256"],
            "commitment_preflight_checkpoint_sha256": commitment_preflight_digest,
            "oracle_opening_sha256": opening_digest,
            "positive_execution_sha256": positive["execution_report_sha256"],
            "ambiguous_execution_sha256": ambiguous["execution_report_sha256"],
            "abstain_execution_sha256": abstain["execution_report_sha256"],
            "integrity_abort_execution_sha256": integrity_abort["execution_report_sha256"],
            "uniform_original_action_order": observed_action_order,
            "forged_outcome_rejected": forged_rejected,
            "float_opening_rejected": float_rejected,
            "serialized_view_sha256": sha256_bytes(canonical_bytes(view)),
            "registration_sha256": challenge.challenge_registration_sha256(document),
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
