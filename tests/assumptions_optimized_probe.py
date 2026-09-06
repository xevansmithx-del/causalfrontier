"""Assertion-independent deterministic single-cell audit and hostile replay."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from causalfrontier import audit_assumptions, load_case, verify_assumption_audit  # noqa: E402
from causalfrontier.assumptions import AUDIT_DOMAIN  # noqa: E402
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    case = load_case(PROJECT / "examples/synthetic-aggregate")
    original = canonical_bytes(case)
    report = audit_assumptions(case)
    counts = report["counts"]
    if (counts["eligible_cells"], counts["valid_variants"], counts["requires_reauthoring"]) != (12, 6, 6):
        raise SystemExit("single-cell denominator/contract regression")
    if counts["strict_pair_separation_changed_valid_variants"] != 6:
        raise SystemExit("strict separation regression")
    for scope in ("structurally_admissible_unexecuted", "conditional_scientific_structure"):
        if counts[scope] != {
            "frontiers_changed_valid_variants": 0,
            "co_minimax_experiment_ids_changed_valid_variants": 4,
        }:
            raise SystemExit("frontier/co-minimax regression")
    if canonical_bytes(case) != original or audit_assumptions(case) != report:
        raise SystemExit("nondeterministic or mutated case")
    verified = verify_assumption_audit(case, report)
    if verified["verified"] is not True or verified["scoring_enabled"] is not False:
        raise SystemExit("replay or authority regression")
    forged = deepcopy(report)
    forged["rows"].pop()
    forged.pop("audit_sha256")
    forged["audit_sha256"] = sha256_bytes(AUDIT_DOMAIN + canonical_bytes(forged))
    try:
        verify_assumption_audit(case, forged)
    except CausalFrontierError:
        pass
    else:
        raise SystemExit("coherently rehashed row omission accepted")
    print(
        json.dumps(
            {
                "audit_sha256": report["audit_sha256"],
                "counts": counts,
                "verification": verified,
                "rehashed_omission_rejected": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
