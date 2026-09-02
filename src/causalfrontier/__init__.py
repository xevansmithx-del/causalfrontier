"""CausalFrontier public API."""

from .version import DISTRIBUTION_VERSION

__version__ = DISTRIBUTION_VERSION

from .attestation import verify_rfc3161_attestation
from .blind import (
    bind_blind_selection_precommitment,
    build_sanitized_entrant_view,
    execute_blind_synthetic_policy,
    lock_blind_reference_selections,
    prepare_synthetic_observation_commitment,
)
from .calibration import evaluate_calibration_tripwire, lock_calibration_tripwire
from .calibration_v2 import (
    canonical_branch_rows,
    finalize_calibration_v2,
    observation_axes_v2,
    preflight_calibration_v2_view,
    reveal_commitment_v2,
    rubric_commitment_v2,
    seal_calibration_v2_submission,
    verify_calibration_v2_report,
    view_content_binding_v2,
)
from .capsule import build_capsule, record_rehearsal, verify_capsule
from .challenge import preflight_challenge
from .claim import goal_claim_contract, goal_claim_contract_sha256, preflight_goal_claim_plan
from .comparators import lock_reference_selections
from .frontier import compile_case, simulate_branch
from .horse_race import (
    execute_synthetic_horse_race,
    prepare_synthetic_horse_race_plan,
    verify_synthetic_horse_race_report,
)
from .ledger import append_event, create_ledger, verify_ledger
from .model import load_case, validate_case
from .neutral import (
    exercise_neutral_baselines,
    load_neutral_action_catalog,
    lock_neutral_baseline_orders,
    prepare_neutral_baseline_plan,
    seed_commitment_sha256,
    validate_neutral_action_catalog,
    verify_neutral_baseline_exercise,
)
from .registry import assess_registry_candidate
from .reveal import open_synthetic_reveal, reveal_commitment
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
from .sentinel_witness import (
    preflight_sentinel_dual_witness_lock,
    verify_sentinel_dual_witness_lock_preflight,
)

__all__ = [
    "append_event",
    "assess_registry_candidate",
    "bind_blind_selection_precommitment",
    "build_capsule",
    "build_sanitized_entrant_view",
    "canonical_branch_rows",
    "compile_case",
    "create_ledger",
    "evaluate_calibration_tripwire",
    "execute_blind_synthetic_policy",
    "execute_synthetic_horse_race",
    "exercise_neutral_baselines",
    "finalize_calibration_v2",
    "goal_claim_contract",
    "goal_claim_contract_sha256",
    "load_case",
    "load_neutral_action_catalog",
    "lock_blind_reference_selections",
    "lock_calibration_tripwire",
    "lock_neutral_baseline_orders",
    "lock_reference_selections",
    "observation_axes_v2",
    "open_synthetic_reveal",
    "preflight_calibration_v2_view",
    "preflight_challenge",
    "preflight_goal_claim_plan",
    "preflight_sentinel_admission",
    "preflight_sentinel_dual_log_continuity",
    "preflight_sentinel_dual_witness_lock",
    "preflight_sentinel_generation_plan",
    "preflight_sentinel_phase_bound_admission",
    "prepare_neutral_baseline_plan",
    "prepare_synthetic_horse_race_plan",
    "prepare_synthetic_observation_commitment",
    "record_rehearsal",
    "reveal_commitment",
    "reveal_commitment_v2",
    "rubric_commitment_v2",
    "seal_calibration_v2_submission",
    "seed_commitment_sha256",
    "simulate_branch",
    "validate_case",
    "validate_neutral_action_catalog",
    "verify_calibration_v2_report",
    "verify_capsule",
    "verify_ledger",
    "verify_neutral_baseline_exercise",
    "verify_rfc3161_attestation",
    "verify_sentinel_admission_preflight",
    "verify_sentinel_dual_log_continuity_preflight",
    "verify_sentinel_dual_witness_lock_preflight",
    "verify_sentinel_phase_bound_admission_preflight",
    "verify_synthetic_horse_race_report",
    "view_content_binding_v2",
]
