"""Assertion-independent normal/-O probe for the complete synthetic matrix."""

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

from test_blind_execution import _build_blind_fixture, _write_json  # noqa: E402

from causalfrontier import horse_race  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-horse-race-optimized-")).resolve(strict=True)
    try:
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        raw_case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        fixture = _build_blind_fixture(
            temporary,
            raw_case,
            case_root,
            balanced_six_case_cohort=True,
        )
        plan = horse_race.prepare_synthetic_horse_race_plan(
            fixture["challenge_root"],
            fixture["digest"],
            1,
            fixture["race_path"],
            fixture["race_digest"],
            fixture["view_path"],
            fixture["view_digest"],
            fixture["selection_path"],
            fixture["selection_digest"],
            fixture["selection_envelope_path"],
            fixture["selection_envelope_checkpoint_digest"],
            fixture["commitment_preflight_path"],
            fixture["commitment_preflight_checkpoint_digest"],
            fixture["opening_digest"],
        )
        if plan["matrix_cells_n"] != 36 or plan["scientific_scoring_ready"] is not False:
            raise SystemExit("horse-race plan overclaimed or omitted matrix cells")
        plan_path = temporary / "horse-race-plan.json"
        plan_checkpoint = _write_json(plan_path, plan)
        report = horse_race.execute_synthetic_horse_race(
            fixture["challenge_root"],
            fixture["digest"],
            1,
            fixture["race_path"],
            fixture["race_digest"],
            fixture["view_path"],
            fixture["view_digest"],
            fixture["selection_path"],
            fixture["selection_digest"],
            fixture["selection_envelope_path"],
            fixture["selection_envelope_checkpoint_digest"],
            fixture["commitment_preflight_path"],
            fixture["commitment_preflight_checkpoint_digest"],
            plan_path,
            plan_checkpoint,
            fixture["oracle_root"],
            fixture["opening_digest"],
        )
        if (
            report["executed_matrix_cells_n"] != 36
            or report["all_episode_integrity_valid"] is not True
            or report["scientific_scoring_ready"] is not False
            or report["winner"] is not None
            or report["acceleration_ratio"] is not None
        ):
            raise SystemExit("horse-race report is incomplete, invalid, or overclaims")
        candidate_terminals = [
            item["terminal_kind"]
            for item in report["episode_summaries"]
            if item["policy_id"] == "CAUSALFRONTIER_UNIQUE_MINIMAX_V1"
        ]
        if candidate_terminals != ["NO_CALL"] * 12:
            raise SystemExit("candidate no-call signal changed")
        report_path = temporary / "horse-race-report.json"
        report_checkpoint = _write_json(report_path, report)
        verification = horse_race.verify_synthetic_horse_race_report(
            report_path,
            report_checkpoint,
            plan_path,
            plan_checkpoint,
        )
        if verification["contained_execution_integrity_valid"] is not True:
            raise SystemExit("saved horse-race report did not verify")
        output = {
            "plan_checkpoint_sha256": plan_checkpoint,
            "plan_sha256": plan["plan_sha256"],
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
