"""Assertion-independent normal/-O probe for the goal-claim firewall."""

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

from test_claim import _plan, _write_plan  # noqa: E402

from causalfrontier import claim  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-claim-optimized-")).resolve(strict=True)
    try:
        plan_path = temporary / "goal-claim-plan.json"
        checkpoint = _write_plan(plan_path, _plan())
        report = claim.preflight_goal_claim_plan(plan_path, checkpoint)
        if (
            report["status"] != claim.PREFLIGHT_STATUS
            or report["mandatory_comparator_families"] != list(claim.MANDATORY_COMPARATOR_FAMILIES)
            or report["declared_domains_n"] != 3
            or report["precommitted_decision_points_n"] != 30
            or report["calibration_decision_points_n"] != 9
            or report["scientific_claim_ready"] is not False
            or report["acceleration_verified"] is not False
            or report["provenance_verified"] is not False
            or report["comparator_family_conformance_verified"] is not False
        ):
            raise SystemExit("goal-claim firewall changed or overclaimed")
        output = {
            "goal_claim_contract_sha256": claim.goal_claim_contract_sha256(),
            "plan_checkpoint_sha256": checkpoint,
            "plan_sha256": report["plan_sha256"],
            "preflight_sha256": report["preflight_sha256"],
            "canonical_report_sha256": sha256_bytes(canonical_bytes(report)),
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
