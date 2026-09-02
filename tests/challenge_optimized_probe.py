"""Assertion-independent normal/-O probe for challenge preflight."""

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

from test_challenge import _build  # noqa: E402

from causalfrontier import challenge  # noqa: E402
from causalfrontier.canonical import canonical_bytes, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-challenge-optimized-")).resolve(strict=True)
    try:
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        raw_case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        challenge_root = temporary / "challenge"
        _document, manifest_digest = _build(challenge_root, raw_case, case_root)
        result = challenge.preflight_challenge(challenge_root, manifest_digest, 1)
        gates = {item["id"]: item for item in result["gates"]}
        if result["status"] != "STRUCTURALLY_BOUND_AND_REPLAYED_SCIENTIFIC_SCORING_DISABLED":
            raise SystemExit("challenge status changed")
        if result["scientific_scoring_ready"] is not False:
            raise SystemExit("scientific scoring was enabled")
        if gates["receipt_replay"]["status"] != "PASS":
            raise SystemExit("receipt replay did not pass")
        if gates["temporal_leakage"]["status"] != "NO_CALL":
            raise SystemExit("temporal leakage gate was upgraded")
        if gates["rollback"]["status"] != "NO_CALL":
            raise SystemExit("rollback gate was upgraded")
        output = {
            "challenge_manifest_sha256": manifest_digest,
            "preflight_sha256": sha256_bytes(canonical_bytes(result)),
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
