"""Assertion-independent normal/-O/hash-seed probe for calibration."""

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

from test_calibration import build_calibration_fixture  # noqa: E402

from causalfrontier import calibration  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-calibration-optimized-")).resolve(strict=True)
    try:
        fixture = build_calibration_fixture(temporary)
        lock = calibration.lock_calibration_tripwire(
            fixture["root"], fixture["manifest_sha256"], fixture["execution_checkpoint"]
        )
        report = calibration.evaluate_calibration_tripwire(
            fixture["root"],
            fixture["manifest_sha256"],
            fixture["execution_checkpoint"],
            fixture["lock_path"],
            fixture["lock_sha256"],
            fixture["opening_path"],
            fixture["opening_sha256"],
        )
        if lock["status"] != calibration.LOCK_STATUS or lock["opening_read"] is not False:
            raise SystemExit("calibration lock changed or read the opening")
        if (
            report["status"] != calibration.REPORT_PASS_STATUS
            or report["controls_passed_n"] != 3
            or report["primary_scoring_blocked"] is not True
            or report["scientific_scoring_ready"] is not False
            or report["winner"] is not None
        ):
            raise SystemExit("calibration result changed or overclaimed")
        result = {
            "lock_status": lock["status"],
            "lock_sha256": lock["lock_sha256"],
            "lock_canonical_sha256": sha256_bytes(canonical_bytes(lock)),
            "report_status": report["status"],
            "report_sha256": report["report_sha256"],
            "report_canonical_sha256": sha256_bytes(canonical_bytes(report)),
            "controls_passed_n": report["controls_passed_n"],
            "scientific_scoring_ready": report["scientific_scoring_ready"],
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
