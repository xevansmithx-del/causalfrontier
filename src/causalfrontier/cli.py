"""Command-line interface for frozen-case compilation and deterministic replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .attestation import verify_rfc3161_attestation
from .blind import (
    bind_blind_selection_precommitment,
    build_sanitized_entrant_view,
    execute_blind_synthetic_policy,
    lock_blind_reference_selections,
    prepare_synthetic_observation_commitment,
    read_checkpointed_blinding_nonce,
)
from .calibration import evaluate_calibration_tripwire, lock_calibration_tripwire
from .calibration_v2 import (
    finalize_calibration_v2,
    preflight_calibration_v2_view,
    seal_calibration_v2_submission,
    verify_calibration_v2_report,
)
from .canonical import CausalFrontierError, io_error
from .capsule import build_capsule, record_rehearsal, verify_capsule
from .challenge import preflight_challenge
from .claim import preflight_goal_claim_plan, verify_goal_claim_plan_preflight
from .classifier import execute_classifiers
from .comparators import lock_reference_selections
from .doctor import diagnose_environment
from .frontier import compile_case, simulate_branch
from .horse_race import (
    PLAN_STATUS,
    REPORT_STATUS,
    VALID_VERIFICATION_STATUS,
    execute_synthetic_horse_race,
    prepare_synthetic_horse_race_plan,
    verify_synthetic_horse_race_report,
)
from .model import load_case
from .neutral import (
    exercise_neutral_baselines,
    load_neutral_action_catalog,
    lock_neutral_baseline_orders,
    prepare_neutral_baseline_plan,
    seed_commitment_sha256,
    verify_neutral_baseline_exercise,
)
from .receipts import preflight_receipts
from .registry import assess_registry_candidate, validate_assessment_report
from .reveal import open_synthetic_reveal
from .sentinel import (
    preflight_sentinel_admission,
    preflight_sentinel_generation_plan,
    verify_sentinel_admission_preflight,
)
from .sentinel_continuity import (
    preflight_sentinel_dual_log_continuity,
    verify_sentinel_dual_log_continuity_preflight,
)
from .sentinel_phase import (
    preflight_sentinel_phase_bound_admission,
    verify_sentinel_phase_bound_admission_preflight,
)
from .sentinel_witness import preflight_sentinel_dual_witness_lock
from .version import DISTRIBUTION_VERSION


def _emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _read_checkpointed_seed(path: Path, expected_sha256: str) -> bytes:
    """Reuse the exact no-follow 32-byte secret transport for a baseline seed."""

    try:
        return read_checkpointed_blinding_nonce(path, expected_sha256)
    except CausalFrontierError as exc:
        message = str(exc).replace("blinding nonce", "neutral baseline seed")
        raise CausalFrontierError(message, **exc.diagnostic()) from None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="causalfrontier",
        description="Compile frozen causal worlds into a prior-free discriminator frontier.",
    )
    result.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {DISTRIBUTION_VERSION}",
    )
    result.add_argument(
        "--error-format",
        choices=("text", "json"),
        default="text",
        help="format runtime errors on stderr; JSON omits messages and paths",
    )
    commands = result.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="check local prerequisites without inspecting evidence")
    doctor.add_argument("--openssl-binary", type=Path, help="trusted local OpenSSL executable to check")
    doctor.add_argument("--expected-openssl-sha256", help="caller-preserved SHA-256 of the trusted executable")
    analyze = commands.add_parser("analyze", help="analyze a frozen case root")
    analyze.add_argument("case_root", type=Path)
    classify = commands.add_parser("classify", help="execute digest-bound classifiers on frozen inputs")
    classify.add_argument("case_root", type=Path)
    receipts = commands.add_parser("preflight-receipts", help="bind receipt bytes; historical scoring stays disabled")
    receipts.add_argument("receipt_root", type=Path)
    receipts.add_argument(
        "--expected-set-sha256", required=True, help="independently preserved receipt-set byte digest"
    )
    challenge = commands.add_parser(
        "preflight-challenge", help="bind a challenge cohort; scientific scoring stays disabled"
    )
    challenge.add_argument("challenge_root", type=Path)
    challenge.add_argument(
        "--expected-manifest-sha256", required=True, help="independently preserved challenge-manifest digest"
    )
    challenge.add_argument(
        "--expected-sequence", required=True, type=int, help="independently preserved positive challenge sequence"
    )
    claim_plan = commands.add_parser(
        "preflight-goal-claim-plan",
        help="bind the full five-comparator 10x goal before outcomes; scoring stays disabled",
    )
    claim_plan.add_argument("plan", type=Path)
    claim_plan.add_argument(
        "--expected-plan-checkpoint-sha256",
        required=True,
        help="independently preserved digest of the exact preregistration-plan bytes",
    )
    sentinel_generation = commands.add_parser(
        "preflight-sentinel-generation-plan",
        help="replay a steward-only pre-generation assignment lock; scoring stays disabled",
    )
    sentinel_generation.add_argument("generation_plan", type=Path)
    sentinel_generation.add_argument(
        "--expected-generation-plan-sha256",
        required=True,
        help="independently preserved digest of the exact pre-generation plan bytes",
    )
    sentinel_admission = commands.add_parser(
        "preflight-sentinel-admission",
        help="close the sentinel cohort artifact graph; admission and scoring stay disabled",
    )
    sentinel_admission.add_argument("sentinel_root", type=Path)
    sentinel_admission.add_argument("generation_plan", type=Path)
    sentinel_admission.add_argument("goal_claim_plan", type=Path)
    sentinel_admission.add_argument("--expected-manifest-sha256", required=True)
    sentinel_admission.add_argument("--expected-sequence", required=True, type=int)
    sentinel_admission.add_argument("--expected-generation-plan-sha256", required=True)
    sentinel_admission.add_argument("--expected-goal-claim-plan-sha256", required=True)
    timestamp = commands.add_parser(
        "verify-rfc3161-attestation",
        help="verify offline signed-target-imprint evidence; unqualified timestamp and scoring stay disabled",
    )
    timestamp.add_argument("target", type=Path)
    timestamp.add_argument("attestation_root", type=Path)
    timestamp.add_argument("trust_policy_root", type=Path)
    timestamp.add_argument("openssl", type=Path)
    timestamp.add_argument("--expected-target-sha256", required=True)
    timestamp.add_argument("--expected-attestation-checkpoint-sha256", required=True)
    timestamp.add_argument("--expected-trust-policy-checkpoint-sha256", required=True)
    timestamp.add_argument("--expected-openssl-sha256", required=True)
    timestamp.add_argument("--expected-not-after", required=True)
    dual_witness = commands.add_parser(
        "preflight-sentinel-dual-witness-lock",
        help="replay two pre-generation witness bundles and derive an unadmitted generation epoch",
    )
    dual_witness.add_argument("lock_root", type=Path)
    dual_witness.add_argument("generation_plan", type=Path)
    dual_witness.add_argument("--expected-lock-manifest-sha256", required=True)
    dual_witness.add_argument("--expected-generation-plan-sha256", required=True)
    dual_witness.add_argument("--expected-sequence", required=True, type=int)
    dual_witness.add_argument(
        "--openssl",
        required=True,
        action="append",
        type=Path,
        help="aligned witness verifier runtime; pass exactly twice",
    )
    dual_witness.add_argument(
        "--expected-openssl-sha256",
        required=True,
        action="append",
        help="aligned verifier checkpoint; pass exactly twice",
    )
    phase_bound = commands.add_parser(
        "preflight-sentinel-phase-bound-admission",
        help="replay phase 1 and bind every sentinel payload/provenance packet; admission and scoring stay disabled",
    )
    phase_bound.add_argument("composition_root", type=Path)
    phase_bound.add_argument("--expected-composition-manifest-sha256", required=True)
    phase_bound.add_argument("--expected-sequence", required=True, type=int)
    phase_bound.add_argument(
        "--openssl",
        required=True,
        action="append",
        type=Path,
        help="aligned phase-1 witness verifier runtime; pass exactly twice",
    )
    phase_bound.add_argument(
        "--expected-openssl-sha256",
        required=True,
        action="append",
        help="aligned phase-1 verifier checkpoint; pass exactly twice",
    )
    continuity = commands.add_parser(
        "preflight-sentinel-dual-log-continuity",
        help=(
            "replay a dual-timestamped custody target, two reserved log slots, and one cross-log seal; "
            "admission and scoring stay disabled"
        ),
    )
    continuity.add_argument("continuity_root", type=Path)
    continuity.add_argument("--expected-composition-manifest-sha256", required=True)
    continuity.add_argument("--expected-sequence", required=True, type=int)
    continuity.add_argument("--expected-predecessor-continuity-state-sha256")
    continuity.add_argument(
        "--predecessor-continuity-state",
        type=Path,
        help="canonical prior continuity-state file; required after sequence 1",
    )
    continuity.add_argument(
        "--expected-prior-store-checkpoint-sha256",
        required=True,
        action="append",
        help="caller-preserved prior signed checkpoint in sorted store order; pass exactly twice",
    )
    continuity.add_argument(
        "--expected-final-store-checkpoint-sha256",
        required=True,
        action="append",
        help="caller-preserved final signed checkpoint in sorted store order; pass exactly twice",
    )
    for prefix, description in (
        ("phase", "Phase 1 witness"),
        ("custody", "pre-token custody witness"),
        ("store", "C2SP checkpoint"),
    ):
        continuity.add_argument(
            "--%s-openssl" % prefix,
            required=True,
            action="append",
            type=Path,
            help="aligned %s verifier runtime; pass exactly twice" % description,
        )
        continuity.add_argument(
            "--expected-%s-openssl-sha256" % prefix,
            required=True,
            action="append",
            help="aligned %s verifier checkpoint; pass exactly twice" % description,
        )
    selections = commands.add_parser(
        "lock-reference-selections",
        help="lock deterministic synthetic reference selections before reveal; scientific scoring stays disabled",
    )
    selections.add_argument("challenge_root", type=Path)
    selections.add_argument("--expected-manifest-sha256", required=True)
    selections.add_argument("--expected-sequence", required=True, type=int)
    opening = commands.add_parser(
        "open-synthetic-reveal",
        help="open a committed synthetic branch table; outcome derivation and scoring stay disabled",
    )
    opening.add_argument("challenge_root", type=Path)
    opening.add_argument("opening", type=Path)
    opening.add_argument("--expected-manifest-sha256", required=True)
    opening.add_argument("--expected-sequence", required=True, type=int)
    opening.add_argument("--expected-opening-sha256", required=True)
    entrant_view = commands.add_parser(
        "build-sanitized-view",
        help="project a synthetic steward challenge into an opaque entrant view; scoring stays disabled",
    )
    entrant_view.add_argument("challenge_root", type=Path)
    entrant_view.add_argument("race_spec", type=Path)
    entrant_view.add_argument("nonce_file", type=Path)
    entrant_view.add_argument("--expected-manifest-sha256", required=True)
    entrant_view.add_argument("--expected-sequence", required=True, type=int)
    entrant_view.add_argument("--expected-race-spec-sha256", required=True)
    entrant_view.add_argument("--expected-nonce-sha256", required=True)
    registry = commands.add_parser(
        "assess-registry-candidate",
        help="detect label-invariant synthetic case clones; registration and scoring stay disabled",
    )
    registry.add_argument("challenge_root", type=Path)
    registry.add_argument("race_spec", type=Path)
    registry.add_argument("entrant_view", type=Path)
    registry.add_argument("nonce_file", type=Path)
    registry.add_argument("--expected-manifest-sha256", required=True)
    registry.add_argument("--expected-sequence", required=True, type=int)
    registry.add_argument("--expected-race-spec-sha256", required=True)
    registry.add_argument("--expected-view-sha256", required=True)
    registry.add_argument("--expected-nonce-sha256", required=True)
    blind_selection = commands.add_parser(
        "lock-blind-selections",
        help="lock reference policies from only a checkpointed sanitized view",
    )
    blind_selection.add_argument("entrant_view", type=Path)
    blind_selection.add_argument("--expected-view-sha256", required=True)
    selection_envelope = commands.add_parser(
        "bind-blind-selection-precommitment",
        help="bind a view-only selection lock to an opaque precommitment checkpoint",
    )
    selection_envelope.add_argument("entrant_view", type=Path)
    selection_envelope.add_argument("selection_lock", type=Path)
    selection_envelope.add_argument("--expected-view-sha256", required=True)
    selection_envelope.add_argument("--expected-selection-sha256", required=True)
    selection_envelope.add_argument("--expected-commitment-preflight-sha256", required=True)
    commitment = commands.add_parser(
        "prepare-observation-commitment",
        help="preflight a complete synthetic observation oracle before sealing its commitment",
    )
    commitment.add_argument("challenge_root", type=Path)
    commitment.add_argument("race_spec", type=Path)
    commitment.add_argument("entrant_view", type=Path)
    commitment.add_argument("oracle_root", type=Path)
    commitment.add_argument("payload", type=Path)
    commitment.add_argument("nonce_file", type=Path)
    commitment.add_argument("--expected-manifest-sha256", required=True)
    commitment.add_argument("--expected-sequence", required=True, type=int)
    commitment.add_argument("--expected-race-spec-sha256", required=True)
    commitment.add_argument("--expected-view-sha256", required=True)
    commitment.add_argument("--expected-payload-sha256", required=True)
    commitment.add_argument("--expected-nonce-sha256", required=True)
    blind_execution = commands.add_parser(
        "execute-blind-synthetic",
        help="execute one locked synthetic policy against committed raw observations; scoring stays disabled",
    )
    blind_execution.add_argument("challenge_root", type=Path)
    blind_execution.add_argument("race_spec", type=Path)
    blind_execution.add_argument("entrant_view", type=Path)
    blind_execution.add_argument("selection_lock", type=Path)
    blind_execution.add_argument("selection_envelope", type=Path)
    blind_execution.add_argument("commitment_preflight", type=Path)
    blind_execution.add_argument("oracle_root", type=Path)
    blind_execution.add_argument("entrant_case_id")
    blind_execution.add_argument("entrant_lane_id")
    blind_execution.add_argument("policy_id")
    blind_execution.add_argument("--expected-manifest-sha256", required=True)
    blind_execution.add_argument("--expected-sequence", required=True, type=int)
    blind_execution.add_argument("--expected-race-spec-sha256", required=True)
    blind_execution.add_argument("--expected-view-sha256", required=True)
    blind_execution.add_argument("--expected-selection-sha256", required=True)
    blind_execution.add_argument("--expected-selection-envelope-sha256", required=True)
    blind_execution.add_argument("--expected-commitment-preflight-sha256", required=True)
    blind_execution.add_argument("--expected-opening-sha256", required=True)
    horse_plan = commands.add_parser(
        "prepare-synthetic-horse-race",
        help="hash-bind a complete six-case matrix; temporal order and scientific scoring stay disabled",
    )
    horse_plan.add_argument("challenge_root", type=Path)
    horse_plan.add_argument("race_spec", type=Path)
    horse_plan.add_argument("entrant_view", type=Path)
    horse_plan.add_argument("selection_lock", type=Path)
    horse_plan.add_argument("selection_envelope", type=Path)
    horse_plan.add_argument("commitment_preflight", type=Path)
    horse_plan.add_argument("--expected-manifest-sha256", required=True)
    horse_plan.add_argument("--expected-sequence", required=True, type=int)
    horse_plan.add_argument("--expected-race-spec-sha256", required=True)
    horse_plan.add_argument("--expected-view-sha256", required=True)
    horse_plan.add_argument("--expected-selection-sha256", required=True)
    horse_plan.add_argument("--expected-selection-envelope-sha256", required=True)
    horse_plan.add_argument("--expected-commitment-preflight-sha256", required=True)
    horse_plan.add_argument("--expected-opening-sha256", required=True)
    horse_execution = commands.add_parser(
        "execute-synthetic-horse-race",
        help="replay the complete hash-bound synthetic matrix; scientific scoring stays disabled",
    )
    horse_execution.add_argument("challenge_root", type=Path)
    horse_execution.add_argument("race_spec", type=Path)
    horse_execution.add_argument("entrant_view", type=Path)
    horse_execution.add_argument("selection_lock", type=Path)
    horse_execution.add_argument("selection_envelope", type=Path)
    horse_execution.add_argument("commitment_preflight", type=Path)
    horse_execution.add_argument("horse_race_plan", type=Path)
    horse_execution.add_argument("oracle_root", type=Path)
    horse_execution.add_argument("--expected-manifest-sha256", required=True)
    horse_execution.add_argument("--expected-sequence", required=True, type=int)
    horse_execution.add_argument("--expected-race-spec-sha256", required=True)
    horse_execution.add_argument("--expected-view-sha256", required=True)
    horse_execution.add_argument("--expected-selection-sha256", required=True)
    horse_execution.add_argument("--expected-selection-envelope-sha256", required=True)
    horse_execution.add_argument("--expected-commitment-preflight-sha256", required=True)
    horse_execution.add_argument("--expected-plan-sha256", required=True)
    horse_execution.add_argument("--expected-opening-sha256", required=True)
    horse_verification = commands.add_parser(
        "verify-synthetic-horse-race-report",
        help="verify a saved complete-matrix no-score report against its exact plan",
    )
    horse_verification.add_argument("report", type=Path)
    horse_verification.add_argument("horse_race_plan", type=Path)
    horse_verification.add_argument("--expected-report-sha256", required=True)
    horse_verification.add_argument("--expected-plan-sha256", required=True)
    neutral_catalog = commands.add_parser(
        "validate-neutral-action-catalog",
        help="validate an exact policy-neutral action catalog; scientific scoring stays disabled",
    )
    neutral_catalog.add_argument("catalog", type=Path)
    neutral_catalog.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_seed = commands.add_parser(
        "neutral-commit-seed",
        help="bind one checkpointed 256-bit seed to an exact neutral action universe",
    )
    neutral_seed.add_argument("catalog", type=Path)
    neutral_seed.add_argument("seed_file", type=Path)
    neutral_seed.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_seed.add_argument("--expected-seed-checkpoint-sha256", required=True)
    neutral_plan = commands.add_parser(
        "prepare-neutral-baseline-plan",
        help="precommit the complete case-level neutral baseline matrix; outcomes and scoring stay disabled",
    )
    neutral_plan.add_argument("catalog", type=Path)
    neutral_plan.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_plan.add_argument("--seed-commitment-sha256", action="append", required=True)
    neutral_lock = commands.add_parser(
        "lock-neutral-baseline-orders",
        help="open every committed seed and lock neutral baseline orders without reading outcomes",
    )
    neutral_lock.add_argument("catalog", type=Path)
    neutral_lock.add_argument("plan", type=Path)
    neutral_lock.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_lock.add_argument("--expected-plan-checkpoint-sha256", required=True)
    neutral_lock.add_argument(
        "--seed-opening",
        action="append",
        nargs=2,
        required=True,
        metavar=("SEED_FILE", "EXPECTED_SEED_CHECKPOINT_SHA256"),
        help="checkpointed seed file and byte digest; repeat in precommitted seed order",
    )
    neutral_exercise = commands.add_parser(
        "exercise-neutral-baselines",
        help="materialize locked synthetic protocol-cost receipts; outcomes and scoring stay disabled",
    )
    neutral_exercise.add_argument("catalog", type=Path)
    neutral_exercise.add_argument("plan", type=Path)
    neutral_exercise.add_argument("order_lock", type=Path)
    neutral_exercise.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_exercise.add_argument("--expected-plan-checkpoint-sha256", required=True)
    neutral_exercise.add_argument("--expected-lock-checkpoint-sha256", required=True)
    neutral_exercise.add_argument(
        "--capture-observational-telemetry",
        action="store_true",
        help="capture non-score wall/CPU/RSS observations in a separately hashed telemetry field",
    )
    neutral_verification = commands.add_parser(
        "verify-neutral-baseline-exercise",
        help="replay an exact neutral baseline report; scientific scoring stays disabled",
    )
    neutral_verification.add_argument("catalog", type=Path)
    neutral_verification.add_argument("plan", type=Path)
    neutral_verification.add_argument("order_lock", type=Path)
    neutral_verification.add_argument("report", type=Path)
    neutral_verification.add_argument("--expected-catalog-checkpoint-sha256", required=True)
    neutral_verification.add_argument("--expected-plan-checkpoint-sha256", required=True)
    neutral_verification.add_argument("--expected-lock-checkpoint-sha256", required=True)
    neutral_verification.add_argument("--expected-report-checkpoint-sha256", required=True)
    calibration_lock = commands.add_parser(
        "lock-calibration-tripwire",
        help="bind known-hindsight calibration inputs and outputs without reading the opening",
    )
    calibration_lock.add_argument("calibration_root", type=Path)
    calibration_lock.add_argument("--expected-manifest-sha256", required=True)
    calibration_lock.add_argument("--expected-execution-checkpoint-sha256", required=True)
    calibration_evaluation = commands.add_parser(
        "evaluate-calibration-tripwire",
        help="open the committed known-hindsight tripwire; scientific scoring stays disabled",
    )
    calibration_evaluation.add_argument("calibration_root", type=Path)
    calibration_evaluation.add_argument("lock", type=Path)
    calibration_evaluation.add_argument("opening", type=Path)
    calibration_evaluation.add_argument("--expected-manifest-sha256", required=True)
    calibration_evaluation.add_argument("--expected-execution-checkpoint-sha256", required=True)
    calibration_evaluation.add_argument("--expected-lock-sha256", required=True)
    calibration_evaluation.add_argument("--expected-opening-sha256", required=True)
    calibration_v2_view = commands.add_parser(
        "preflight-calibration-v2-view",
        help="bind an exact role-hidden V2 evidence view; scientific scoring stays disabled",
    )
    calibration_v2_view.add_argument("calibration_root", type=Path)
    calibration_v2_view.add_argument("--expected-manifest-sha256", required=True)
    calibration_v2_seal = commands.add_parser(
        "seal-calibration-v2-submission",
        help="seal a V2 intention-to-test submission without reading opening or rubric material",
    )
    calibration_v2_seal.add_argument("calibration_root", type=Path)
    calibration_v2_seal.add_argument("view_lock", type=Path)
    calibration_v2_seal.add_argument("submission", type=Path)
    calibration_v2_seal.add_argument("--expected-manifest-sha256", required=True)
    calibration_v2_seal.add_argument("--expected-view-lock-sha256", required=True)
    calibration_v2_seal.add_argument("--expected-submission-sha256", required=True)
    calibration_v2_finalize = commands.add_parser(
        "finalize-calibration-v2",
        help="replay every V2 zone into a known-hindsight calibration-only report",
    )
    calibration_v2_finalize.add_argument("calibration_root", type=Path)
    calibration_v2_finalize.add_argument("view_lock", type=Path)
    calibration_v2_finalize.add_argument("submission", type=Path)
    calibration_v2_finalize.add_argument("submission_seal", type=Path)
    calibration_v2_finalize.add_argument("opening", type=Path)
    calibration_v2_finalize.add_argument("rubric", type=Path)
    calibration_v2_finalize.add_argument("adjudication", type=Path)
    calibration_v2_finalize.add_argument("--expected-manifest-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-view-lock-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-submission-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-submission-seal-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-opening-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-rubric-sha256", required=True)
    calibration_v2_finalize.add_argument("--expected-adjudication-sha256", required=True)
    calibration_v2_verify = commands.add_parser(
        "verify-calibration-v2-report",
        help="verify a saved V2 report by replaying every upstream artifact",
    )
    calibration_v2_verify.add_argument("calibration_root", type=Path)
    calibration_v2_verify.add_argument("view_lock", type=Path)
    calibration_v2_verify.add_argument("submission", type=Path)
    calibration_v2_verify.add_argument("submission_seal", type=Path)
    calibration_v2_verify.add_argument("opening", type=Path)
    calibration_v2_verify.add_argument("rubric", type=Path)
    calibration_v2_verify.add_argument("adjudication", type=Path)
    calibration_v2_verify.add_argument("report", type=Path)
    calibration_v2_verify.add_argument("--expected-manifest-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-view-lock-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-submission-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-submission-seal-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-opening-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-rubric-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-adjudication-sha256", required=True)
    calibration_v2_verify.add_argument("--expected-report-sha256", required=True)
    compile_command = commands.add_parser("compile", help="build a no-clobber capsule")
    compile_command.add_argument("case_root", type=Path)
    compile_command.add_argument("destination", type=Path)
    verify = commands.add_parser("verify", help="replay and verify a capsule")
    verify.add_argument("capsule", type=Path)
    verify.add_argument(
        "--expected-ledger-head",
        help="external SHA-256 checkpoint used to detect local ledger rollback",
    )
    simulate = commands.add_parser("simulate", help="rehearse a predeclared outcome branch")
    simulate.add_argument("case_root", type=Path)
    simulate.add_argument("experiment_id")
    simulate.add_argument("outcome_id")
    simulate.add_argument("branch_plan_sha256")
    remember = commands.add_parser("remember-rehearsal", help="append one counterfactual rehearsal to capsule memory")
    remember.add_argument("capsule", type=Path)
    remember.add_argument(
        "--expected-ledger-head",
        required=True,
        help="independently stored current SHA-256 checkpoint required before append",
    )
    remember.add_argument("timestamp", help="whole-second RFC3339 UTC")
    remember.add_argument("experiment_id")
    remember.add_argument("outcome_id")
    remember.add_argument("branch_plan_sha256")
    return result


def main(argv: Optional[list] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            output = diagnose_environment(args.openssl_binary, args.expected_openssl_sha256)
            _emit(output)
            return {"READY_FOR_LOCAL_VERIFICATION": 0, "BLOCKED": 2, "INCOMPLETE": 3}[output["status"]]
        elif args.command == "analyze":
            output = compile_case(load_case(args.case_root))
        elif args.command == "classify":
            case = load_case(args.case_root)
            output = execute_classifiers(case, args.case_root.resolve(strict=True))
        elif args.command == "preflight-receipts":
            output = preflight_receipts(args.receipt_root, args.expected_set_sha256)
        elif args.command == "preflight-challenge":
            output = preflight_challenge(args.challenge_root, args.expected_manifest_sha256, args.expected_sequence)
        elif args.command == "preflight-goal-claim-plan":
            output = preflight_goal_claim_plan(args.plan, args.expected_plan_checkpoint_sha256)
        elif args.command == "preflight-sentinel-generation-plan":
            output = preflight_sentinel_generation_plan(
                args.generation_plan,
                args.expected_generation_plan_sha256,
            )
        elif args.command == "preflight-sentinel-admission":
            output = preflight_sentinel_admission(
                args.sentinel_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.generation_plan,
                args.expected_generation_plan_sha256,
                args.goal_claim_plan,
                args.expected_goal_claim_plan_sha256,
            )
        elif args.command == "verify-rfc3161-attestation":
            output = verify_rfc3161_attestation(
                args.target,
                args.expected_target_sha256,
                args.attestation_root,
                args.expected_attestation_checkpoint_sha256,
                args.trust_policy_root,
                args.expected_trust_policy_checkpoint_sha256,
                args.openssl,
                args.expected_openssl_sha256,
                args.expected_not_after,
            )
        elif args.command == "preflight-sentinel-dual-witness-lock":
            output = preflight_sentinel_dual_witness_lock(
                args.lock_root,
                args.expected_lock_manifest_sha256,
                args.generation_plan,
                args.expected_generation_plan_sha256,
                args.expected_sequence,
                args.openssl,
                args.expected_openssl_sha256,
            )
        elif args.command == "preflight-sentinel-phase-bound-admission":
            output = preflight_sentinel_phase_bound_admission(
                args.composition_root,
                args.expected_composition_manifest_sha256,
                args.expected_sequence,
                args.openssl,
                args.expected_openssl_sha256,
            )
        elif args.command == "preflight-sentinel-dual-log-continuity":
            output = preflight_sentinel_dual_log_continuity(
                args.continuity_root,
                args.expected_composition_manifest_sha256,
                args.expected_sequence,
                args.expected_predecessor_continuity_state_sha256,
                args.predecessor_continuity_state,
                args.expected_prior_store_checkpoint_sha256,
                args.expected_final_store_checkpoint_sha256,
                args.phase_openssl,
                args.expected_phase_openssl_sha256,
                args.custody_openssl,
                args.expected_custody_openssl_sha256,
                args.store_openssl,
                args.expected_store_openssl_sha256,
            )
        elif args.command == "lock-reference-selections":
            output = lock_reference_selections(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
            )
        elif args.command == "open-synthetic-reveal":
            output = open_synthetic_reveal(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.opening,
                args.expected_opening_sha256,
            )
        elif args.command == "build-sanitized-view":
            nonce = read_checkpointed_blinding_nonce(args.nonce_file, args.expected_nonce_sha256)
            output = build_sanitized_entrant_view(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                nonce,
            )
        elif args.command == "assess-registry-candidate":
            output = assess_registry_candidate(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                args.entrant_view,
                args.expected_view_sha256,
                args.nonce_file,
                args.expected_nonce_sha256,
            )
        elif args.command == "lock-blind-selections":
            output = lock_blind_reference_selections(args.entrant_view, args.expected_view_sha256)
        elif args.command == "bind-blind-selection-precommitment":
            output = bind_blind_selection_precommitment(
                args.entrant_view,
                args.expected_view_sha256,
                args.selection_lock,
                args.expected_selection_sha256,
                args.expected_commitment_preflight_sha256,
            )
        elif args.command == "prepare-observation-commitment":
            output = prepare_synthetic_observation_commitment(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                args.entrant_view,
                args.expected_view_sha256,
                args.oracle_root,
                args.payload,
                args.expected_payload_sha256,
                args.nonce_file,
                args.expected_nonce_sha256,
            )
        elif args.command == "execute-blind-synthetic":
            output = execute_blind_synthetic_policy(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                args.entrant_view,
                args.expected_view_sha256,
                args.selection_lock,
                args.expected_selection_sha256,
                args.selection_envelope,
                args.expected_selection_envelope_sha256,
                args.commitment_preflight,
                args.expected_commitment_preflight_sha256,
                args.oracle_root,
                args.expected_opening_sha256,
                args.entrant_case_id,
                args.entrant_lane_id,
                args.policy_id,
            )
        elif args.command == "prepare-synthetic-horse-race":
            output = prepare_synthetic_horse_race_plan(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                args.entrant_view,
                args.expected_view_sha256,
                args.selection_lock,
                args.expected_selection_sha256,
                args.selection_envelope,
                args.expected_selection_envelope_sha256,
                args.commitment_preflight,
                args.expected_commitment_preflight_sha256,
                args.expected_opening_sha256,
            )
        elif args.command == "execute-synthetic-horse-race":
            output = execute_synthetic_horse_race(
                args.challenge_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.race_spec,
                args.expected_race_spec_sha256,
                args.entrant_view,
                args.expected_view_sha256,
                args.selection_lock,
                args.expected_selection_sha256,
                args.selection_envelope,
                args.expected_selection_envelope_sha256,
                args.commitment_preflight,
                args.expected_commitment_preflight_sha256,
                args.horse_race_plan,
                args.expected_plan_sha256,
                args.oracle_root,
                args.expected_opening_sha256,
            )
        elif args.command == "verify-synthetic-horse-race-report":
            output = verify_synthetic_horse_race_report(
                args.report,
                args.expected_report_sha256,
                args.horse_race_plan,
                args.expected_plan_sha256,
            )
        elif args.command == "validate-neutral-action-catalog":
            output = load_neutral_action_catalog(args.catalog, args.expected_catalog_checkpoint_sha256)
        elif args.command == "neutral-commit-seed":
            catalog = load_neutral_action_catalog(args.catalog, args.expected_catalog_checkpoint_sha256)
            seed = _read_checkpointed_seed(args.seed_file, args.expected_seed_checkpoint_sha256)
            action_universe_sha256 = catalog["authorized_action_universe_sha256"]
            output = {
                "authorized_action_universe_sha256": action_universe_sha256,
                "seed_commitment_sha256": seed_commitment_sha256(seed, action_universe_sha256),
            }
        elif args.command == "prepare-neutral-baseline-plan":
            output = prepare_neutral_baseline_plan(
                args.catalog,
                args.expected_catalog_checkpoint_sha256,
                args.seed_commitment_sha256,
            )
        elif args.command == "lock-neutral-baseline-orders":
            seed_openings = [
                _read_checkpointed_seed(Path(seed_file), expected_seed_sha256)
                for seed_file, expected_seed_sha256 in args.seed_opening
            ]
            output = lock_neutral_baseline_orders(
                args.catalog,
                args.expected_catalog_checkpoint_sha256,
                args.plan,
                args.expected_plan_checkpoint_sha256,
                seed_openings,
            )
        elif args.command == "exercise-neutral-baselines":
            output = exercise_neutral_baselines(
                args.catalog,
                args.expected_catalog_checkpoint_sha256,
                args.plan,
                args.expected_plan_checkpoint_sha256,
                args.order_lock,
                args.expected_lock_checkpoint_sha256,
                capture_observational_telemetry=args.capture_observational_telemetry,
            )
        elif args.command == "verify-neutral-baseline-exercise":
            output = verify_neutral_baseline_exercise(
                args.catalog,
                args.expected_catalog_checkpoint_sha256,
                args.plan,
                args.expected_plan_checkpoint_sha256,
                args.order_lock,
                args.expected_lock_checkpoint_sha256,
                args.report,
                args.expected_report_checkpoint_sha256,
            )
        elif args.command == "lock-calibration-tripwire":
            output = lock_calibration_tripwire(
                args.calibration_root,
                args.expected_manifest_sha256,
                args.expected_execution_checkpoint_sha256,
            )
        elif args.command == "evaluate-calibration-tripwire":
            output = evaluate_calibration_tripwire(
                args.calibration_root,
                args.expected_manifest_sha256,
                args.expected_execution_checkpoint_sha256,
                args.lock,
                args.expected_lock_sha256,
                args.opening,
                args.expected_opening_sha256,
            )
        elif args.command == "preflight-calibration-v2-view":
            output = preflight_calibration_v2_view(
                args.calibration_root,
                args.expected_manifest_sha256,
            )
        elif args.command == "seal-calibration-v2-submission":
            output = seal_calibration_v2_submission(
                args.calibration_root,
                args.expected_manifest_sha256,
                args.view_lock,
                args.expected_view_lock_sha256,
                args.submission,
                args.expected_submission_sha256,
            )
        elif args.command == "finalize-calibration-v2":
            output = finalize_calibration_v2(
                args.calibration_root,
                args.expected_manifest_sha256,
                args.view_lock,
                args.expected_view_lock_sha256,
                args.submission,
                args.expected_submission_sha256,
                args.submission_seal,
                args.expected_submission_seal_sha256,
                args.opening,
                args.expected_opening_sha256,
                args.rubric,
                args.expected_rubric_sha256,
                args.adjudication,
                args.expected_adjudication_sha256,
            )
        elif args.command == "verify-calibration-v2-report":
            output = verify_calibration_v2_report(
                args.calibration_root,
                args.expected_manifest_sha256,
                args.view_lock,
                args.expected_view_lock_sha256,
                args.submission,
                args.expected_submission_sha256,
                args.submission_seal,
                args.expected_submission_seal_sha256,
                args.opening,
                args.expected_opening_sha256,
                args.rubric,
                args.expected_rubric_sha256,
                args.adjudication,
                args.expected_adjudication_sha256,
                args.report,
                args.expected_report_sha256,
            )
        elif args.command == "compile":
            output = build_capsule(args.case_root, args.destination)
        elif args.command == "verify":
            output = verify_capsule(
                args.capsule,
                expected_ledger_head=args.expected_ledger_head,
            )
        elif args.command == "simulate":
            output = simulate_branch(
                load_case(args.case_root),
                args.experiment_id,
                args.outcome_id,
                branch_plan_sha256=args.branch_plan_sha256,
            )
        elif args.command == "remember-rehearsal":
            output = record_rehearsal(
                args.capsule,
                args.expected_ledger_head,
                args.timestamp,
                args.experiment_id,
                args.outcome_id,
                args.branch_plan_sha256,
            )
        else:
            raise CausalFrontierError("unknown command")
        if args.command == "assess-registry-candidate":
            output = validate_assessment_report(
                output,
                expected_manifest_sha256=args.expected_manifest_sha256,
                expected_sequence=args.expected_sequence,
                expected_race_spec_sha256=args.expected_race_spec_sha256,
                expected_view_checkpoint_sha256=args.expected_view_sha256,
                expected_nonce_checkpoint_sha256=args.expected_nonce_sha256,
            )
        if args.command == "preflight-goal-claim-plan":
            output = verify_goal_claim_plan_preflight(
                output,
                args.plan,
                args.expected_plan_checkpoint_sha256,
            )
        if args.command == "preflight-sentinel-admission":
            output = verify_sentinel_admission_preflight(
                output,
                args.sentinel_root,
                args.expected_manifest_sha256,
                args.expected_sequence,
                args.generation_plan,
                args.expected_generation_plan_sha256,
                args.goal_claim_plan,
                args.expected_goal_claim_plan_sha256,
            )
        if args.command == "preflight-sentinel-phase-bound-admission":
            output = verify_sentinel_phase_bound_admission_preflight(
                output,
                args.composition_root,
                args.expected_composition_manifest_sha256,
                args.expected_sequence,
                args.openssl,
                args.expected_openssl_sha256,
            )
        if args.command == "preflight-sentinel-dual-log-continuity":
            output = verify_sentinel_dual_log_continuity_preflight(
                output,
                args.continuity_root,
                args.expected_composition_manifest_sha256,
                args.expected_sequence,
                args.expected_predecessor_continuity_state_sha256,
                args.predecessor_continuity_state,
                args.expected_prior_store_checkpoint_sha256,
                args.expected_final_store_checkpoint_sha256,
                args.phase_openssl,
                args.expected_phase_openssl_sha256,
                args.custody_openssl,
                args.expected_custody_openssl_sha256,
                args.store_openssl,
                args.expected_store_openssl_sha256,
            )
        _emit(output)
        if args.command == "execute-blind-synthetic" and output.get("integrity_valid") is not True:
            return 2
        if args.command == "execute-synthetic-horse-race" and not (
            output.get("status") == REPORT_STATUS
            and output.get("all_episode_integrity_valid") is True
            and output.get("matrix_complete") is True
            and output.get("challenge_unchanged_during_matrix_execution") is True
            and output.get("scientific_scoring_ready") is False
        ):
            return 2
        if args.command == "prepare-synthetic-horse-race" and not (
            output.get("status") == PLAN_STATUS
            and output.get("oracle_opening_read_during_planning") is False
            and output.get("matrix_cells_n") == 36
            and output.get("scientific_scoring_ready") is False
        ):
            return 2
        if args.command == "verify-synthetic-horse-race-report" and not (
            output.get("status") == VALID_VERIFICATION_STATUS
            and output.get("contained_execution_integrity_valid") is True
            and output.get("winner") is None
            and output.get("ranking") == []
            and output.get("acceleration_ratio") is None
            and output.get("scientific_scoring_ready") is False
        ):
            return 2
        if args.command in {
            "preflight-receipts",
            "preflight-challenge",
            "preflight-goal-claim-plan",
            "preflight-sentinel-generation-plan",
            "preflight-sentinel-admission",
            "verify-rfc3161-attestation",
            "preflight-sentinel-dual-witness-lock",
            "preflight-sentinel-phase-bound-admission",
            "preflight-sentinel-dual-log-continuity",
            "lock-reference-selections",
            "open-synthetic-reveal",
            "build-sanitized-view",
            "assess-registry-candidate",
            "lock-blind-selections",
            "bind-blind-selection-precommitment",
            "prepare-observation-commitment",
            "execute-blind-synthetic",
            "prepare-synthetic-horse-race",
            "execute-synthetic-horse-race",
            "verify-synthetic-horse-race-report",
            "validate-neutral-action-catalog",
            "neutral-commit-seed",
            "prepare-neutral-baseline-plan",
            "lock-neutral-baseline-orders",
            "exercise-neutral-baselines",
            "verify-neutral-baseline-exercise",
            "lock-calibration-tripwire",
            "evaluate-calibration-tripwire",
            "preflight-calibration-v2-view",
            "seal-calibration-v2-submission",
            "finalize-calibration-v2",
            "verify-calibration-v2-report",
        }:
            return 3  # Safe structural receipt inspection is still historical abstention.
        if args.command == "verify" and output.get("status") == "INVALID":
            return 2
        return 0
    except (CausalFrontierError, OSError, ValueError) as exc:
        if args.error_format == "json":
            if isinstance(exc, CausalFrontierError):
                diagnostic = exc.diagnostic()
            elif isinstance(exc, OSError):
                diagnostic = io_error(exc, "command I/O failed", operation="command_io").diagnostic()
            else:
                diagnostic = CausalFrontierError("command rejected").diagnostic()
            print(
                json.dumps({"schema_version": "causalfrontier.error.v1", **diagnostic}, sort_keys=True), file=sys.stderr
            )
        else:
            print("causalfrontier: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
