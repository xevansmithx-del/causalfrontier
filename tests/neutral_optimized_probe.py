"""Assertion-independent normal/-O probe for neutral baseline protocols."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
SRC = PROJECT / "src"
TESTS = PROJECT / "tests"
for directory in (SRC, TESTS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from test_neutral_baselines import SEEDS, _catalog, _write  # noqa: E402

from causalfrontier import neutral  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-neutral-optimized-")).resolve(strict=True)
    try:
        catalog = _catalog()
        catalog_path = temporary / "catalog.json"
        catalog_checkpoint = _write(catalog_path, catalog)
        plan = neutral.prepare_neutral_baseline_plan(
            catalog_path,
            catalog_checkpoint,
            [neutral.seed_commitment_sha256(seed, catalog["authorized_action_universe_sha256"]) for seed in SEEDS],
        )
        if (
            plan["matrix_cells_n"] != len(SEEDS) + 2
            or plan["seeds_opened_during_planning"] is not False
            or plan["scientific_scoring_ready"] is not False
        ):
            raise SystemExit("neutral baseline plan is incomplete or overclaims")
        plan_path = temporary / "plan.json"
        plan_checkpoint = _write(plan_path, plan)
        lock = neutral.lock_neutral_baseline_orders(
            catalog_path,
            catalog_checkpoint,
            plan_path,
            plan_checkpoint,
            SEEDS,
        )
        if lock["all_precommitted_seeds_opened"] is not True or lock["scientific_scoring_ready"] is not False:
            raise SystemExit("neutral baseline order lock is incomplete or overclaims")
        lock_path = temporary / "lock.json"
        lock_checkpoint = _write(lock_path, lock)
        report = neutral.exercise_neutral_baselines(
            catalog_path,
            catalog_checkpoint,
            plan_path,
            plan_checkpoint,
            lock_path,
            lock_checkpoint,
        )
        if (
            report["receipts_n"] != len(SEEDS) + 2
            or report["all_precommitted_seed_receipts_retained"] is not True
            or report["best_seed_selected"] is not False
            or report["winner"] is not None
            or report["acceleration_ratio"] is not None
            or report["real_resource_verified"] is not False
            or report["scientific_scoring_ready"] is not False
        ):
            raise SystemExit("neutral baseline exercise is incomplete or overclaims")
        report_path = temporary / "report.json"
        report_checkpoint = _write(report_path, report)
        verification = neutral.verify_neutral_baseline_exercise(
            catalog_path,
            catalog_checkpoint,
            plan_path,
            plan_checkpoint,
            lock_path,
            lock_checkpoint,
            report_path,
            report_checkpoint,
        )
        if (
            verification["score_cores_replayed_n"] != len(SEEDS) + 2
            or verification["common_input_structural_neutrality_verified"] is not True
            or verification["factor_space_and_action_payloads_replayed"] is not True
            or verification["execution_gate_derivation_verified"] is not True
            or verification["semantic_policy_neutrality_verified"] is not False
            or verification["precompilation_timing_and_currentness_verified"] is not False
            or verification["rollback_protection_verified"] is not False
            or verification["authority_declarations_attested"] is not False
            or verification["telemetry_authenticity_verified"] is not False
            or verification["cohort_uniqueness_verified"] is not False
            or verification["real_resource_verified"] is not False
            or verification["scientific_scoring_ready"] is not False
        ):
            raise SystemExit("neutral baseline verification did not replay its contract and nonclaims")
        output = {
            "catalog_checkpoint_sha256": catalog_checkpoint,
            "catalog_sha256": catalog["catalog_sha256"],
            "plan_checkpoint_sha256": plan_checkpoint,
            "plan_sha256": plan["plan_sha256"],
            "lock_checkpoint_sha256": lock_checkpoint,
            "lock_sha256": lock["lock_sha256"],
            "score_core_sha256s": [item["score_core_sha256"] for item in report["receipts"]],
            "report_checkpoint_sha256": report_checkpoint,
            "report_sha256": report["report_sha256"],
            "report_canonical_sha256": sha256_bytes(canonical_bytes(report)),
            "verification_sha256": verification["verification_sha256"],
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
