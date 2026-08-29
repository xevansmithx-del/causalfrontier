"""Assertion-independent normal/-O replay probe."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
SRC = PROJECT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402
from causalfrontier.capsule import build_capsule, verify_capsule  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-optimized-"))
    try:
        capsule = temporary / "capsule"
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        built = build_capsule(case_root, capsule)
        replayed = verify_capsule(capsule)
        if built["status"] != "SELF_CONSISTENT_UNAUTHENTICATED_PROTOTYPE":
            raise SystemExit("build did not verify")
        if replayed["run_id"] != built["run_id"]:
            raise SystemExit("replay changed the run identifier")
        if replayed["boundary"]["clinical_authority"] is not False:
            raise SystemExit("clinical authority boundary changed")
        if replayed["boundary"]["prospective_results_recorded"] is not False:
            raise SystemExit("prospective-results boundary changed")
        if replayed["frontiers"]["structurally_admissible_unexecuted"] != [
            "experiment:held-out-invariance",
            "experiment:negative-control",
        ]:
            raise SystemExit("frontier changed")
        classifier_outcomes = {
            item["experiment_id"]: item["outcome_id"] for item in replayed["classifier_results"]["results"]
        }
        if classifier_outcomes != {
            "experiment:global-recompute": "outcome:global-invariant",
            "experiment:held-out-invariance": "outcome:held-invariant",
            "experiment:negative-control": "outcome:control-tracks-context",
        }:
            raise SystemExit("classifier replay changed")
        output = {
            "run_id": replayed["run_id"],
            "verification_sha256": sha256_bytes(canonical_bytes(replayed)),
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
