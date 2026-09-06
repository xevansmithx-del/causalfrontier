"""Assertion-independent grouped replay, forgery and finite-oracle checks."""

from __future__ import annotations

import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
sys.path.insert(0, str(PROJECT / "src"))

from group_oracle_fixture import (  # noqa: E402
    EXPERIMENTS,
    SCOPES,
    build_case,
    build_manifest,
    expected_from_mask,
    masked_case,
)

from causalfrontier import (  # noqa: E402
    audit_assumption_groups,
    compile_case,
    load_case,
    verify_group_assumption_audit,
)
from causalfrontier.canonical import CausalFrontierError, canonical_bytes, sha256_bytes  # noqa: E402
from causalfrontier.group_assumptions import AUDIT_DOMAIN  # noqa: E402


def main():
    case = build_case(load_case(PROJECT / "examples/synthetic-aggregate"))
    manifest = build_manifest(case)
    original = canonical_bytes(case), canonical_bytes(manifest)
    report = audit_assumption_groups(case, manifest)
    rows = report["group_rows"]
    if len(rows) != 6 or len(report["singleton_rows"]) != 10:
        raise SystemExit("group/member coverage mismatch")
    if sum(row["singleton_masked_joint_selection_change"] for row in rows) != 4:
        raise SystemExit("masked-joint witness mismatch")
    if Counter(row["status"] for row in rows) != {
        "VALID_HYPOTHETICAL_VARIANT": 5,
        "REQUIRES_REAUTHORING": 1,
    }:
        raise SystemExit("group contract rejection mismatch")
    if Counter(row["status"] for row in report["singleton_rows"]) != {
        "VALID_HYPOTHETICAL_VARIANT": 8,
        "REQUIRES_REAUTHORING": 2,
    }:
        raise SystemExit("singleton contract rejection mismatch")
    for field in ("authority_granted", "scoring_enabled", "empirical_evidence", "classifier_executed"):
        if report[field] is not False:
            raise SystemExit("authority boundary changed")
    verified = verify_group_assumption_audit(case, manifest, report)
    if verified["verified"] is not True or verified["scoring_enabled"] is not False:
        raise SystemExit("exact replay failed")
    forged = deepcopy(report)
    forged["group_rows"].pop()
    forged.pop("audit_sha256")
    forged["audit_sha256"] = sha256_bytes(AUDIT_DOMAIN + canonical_bytes(forged))
    try:
        verify_group_assumption_audit(case, manifest, forged)
    except CausalFrontierError:
        pass
    else:
        raise SystemExit("rehashed omission accepted")
    observed = Counter()
    for mask in range(256):
        analysis = compile_case(masked_case(case, mask))
        expected = expected_from_mask(mask)
        for scope in SCOPES:
            minimax = analysis["minimax"][scope]
            members = [] if minimax is None else minimax["co_minimax_experiment_ids"]
            if analysis["frontiers"][scope] != expected["frontier"] or members != expected["co_minimax"]:
                raise SystemExit("finite selection oracle mismatch")
        for experiment in analysis["experiments"]:
            truth = expected["experiments"][experiment["id"]]
            if (
                experiment["conditional_guaranteed_decision_class_pair_count"] != truth["guaranteed_pairs"]
                or experiment["conditional_possible_decision_class_pair_count"] != truth["possible_pairs"]
                or experiment["conditional_worst_remaining_decision_class_count"] != truth["worst_remaining_classes"]
            ):
                raise SystemExit("finite epistemic oracle mismatch")
        observed[tuple(analysis["frontiers"][SCOPES[0]])] += 1
    if observed != {EXPERIMENTS: 117, (EXPERIMENTS[0],): 69, (EXPERIMENTS[1],): 69, (): 1}:
        raise SystemExit("finite panel denominator mismatch")
    if (canonical_bytes(case), canonical_bytes(manifest)) != original:
        raise SystemExit("inputs changed")
    if audit_assumption_groups(case, manifest) != report:
        raise SystemExit("nondeterministic audit")
    print(
        json.dumps(
            {
                "case_sha256": report["case_sha256"],
                "audit_sha256": report["audit_sha256"],
                "counts": report["counts"],
                "finite_masks_verified": 256,
                "frontier_distribution": [{"members": list(key), "count": observed[key]} for key in sorted(observed)],
                "rehashed_omission_rejected": True,
                "verification": verified,
                "known_synthetic_control_not_prospective_discovery": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
