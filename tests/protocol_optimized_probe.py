"""Assertion-independent normal/-O probe for the synthetic protocol kernel."""

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

from test_challenge import _build, _reseal  # noqa: E402
from test_protocol_exercise import NONCE_HEX, _payload, _write_opening  # noqa: E402

from causalfrontier import comparators, reveal  # noqa: E402
from causalfrontier.canonical import CausalFrontierError, sha256_bytes  # noqa: E402


def main() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="causalfrontier-protocol-optimized-")).resolve(strict=True)
    try:
        case_root = PROJECT / "examples" / "synthetic-aggregate"
        raw_case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        challenge_root = temporary / "challenge"
        document, _digest = _build(challenge_root, raw_case, case_root)
        payload = _payload(challenge_root, document)
        document["reveal_commitment_sha256"] = reveal.reveal_commitment(payload, NONCE_HEX)
        manifest_digest = _reseal(challenge_root, document)
        opening = temporary / "opening.json"
        opening_digest = _write_opening(opening, payload)
        selections = comparators.lock_reference_selections(challenge_root, manifest_digest, 1)
        opened = reveal.open_synthetic_reveal(challenge_root, manifest_digest, 1, opening, opening_digest)
        if selections["scientific_scoring_ready"] is not False or opened["scientific_scoring_ready"] is not False:
            raise SystemExit("synthetic protocol exercise enabled scientific scoring")
        for lane in selections["reference_lanes"]:
            candidate = next(
                item
                for item in lane["reference_policy_traces"]
                if item["policy_id"] == "CAUSALFRONTIER_UNIQUE_MINIMAX_V1"
            )
            if candidate["status"] != "NO_CALL" or candidate["selections"][0]["action"] != "NO_CALL":
                raise SystemExit("co-minimax tie did not remain NO_CALL")

        invalid_opening = temporary / "invalid-opening.json"
        valid_raw = opening.read_bytes()
        invalid_raw = valid_raw.replace(b'"required_replicates":2', b'"required_replicates":2.0', 1)
        if invalid_raw == valid_raw:
            raise SystemExit("optimized probe could not construct an invalid opening")
        invalid_opening.write_bytes(invalid_raw)
        try:
            reveal.open_synthetic_reveal(
                challenge_root,
                manifest_digest,
                1,
                invalid_opening,
                sha256_bytes(invalid_raw),
            )
        except CausalFrontierError:
            pass
        else:
            raise SystemExit("floating-point reveal opening did not fail closed")
        output = {
            "challenge_manifest_sha256": manifest_digest,
            "opening_sha256": opening_digest,
            "reveal_report_sha256": opened["reveal_report_sha256"],
            "selection_lock_sha256": selections["selection_lock_sha256"],
        }
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    raise SystemExit(main())
