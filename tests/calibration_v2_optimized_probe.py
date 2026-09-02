"""Emit one deterministic V2 report under normal and optimized Python."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve(strict=True).parents[1]
TESTS = PROJECT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from test_calibration_v2 import build_v2_fixture  # noqa: E402

with tempfile.TemporaryDirectory(prefix="causalfrontier-v2-probe-") as temporary:
    fixture = build_v2_fixture(Path(temporary).resolve(strict=True))
    print(json.dumps(fixture["report"], sort_keys=True, separators=(",", ":")))
