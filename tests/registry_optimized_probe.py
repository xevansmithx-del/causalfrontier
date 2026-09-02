"""Assertion-independent normal/-O probe for registry clone rejection."""

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

from test_blind_execution import _build_blind_fixture  # noqa: E402

from causalfrontier import registry  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-registry-optimized-")).resolve(strict=True)
    try:
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        raw_case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        fixture = _build_blind_fixture(
            temporary,
            raw_case,
            case_root,
            balanced_six_case_cohort=True,
        )
        report = registry.assess_registry_candidate(
            fixture["challenge_root"],
            fixture["digest"],
            1,
            fixture["race_path"],
            fixture["race_digest"],
            fixture["view_path"],
            fixture["view_digest"],
            fixture["nonce_path"],
            fixture["nonce_digest"],
        )
        if (
            report["assessment_state"] != "REJECTED_V1_STRUCTURAL_COLLISIONS_REVIEW_REQUIRED"
            or report["structural_collision_pairs_n"] != 15
            or report["structural_collision_group_sizes"] != [6]
            or report["candidate_registered"] is not False
            or report["scientific_scoring_ready"] is not False
        ):
            raise SystemExit("registry clone rejection changed or overclaimed")
        output = {
            "assessment_sha256": report["assessment_sha256"],
            "canonical_report_sha256": sha256_bytes(canonical_bytes(report)),
            "graph_contract_sha256": report["graph_contract_sha256"],
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
