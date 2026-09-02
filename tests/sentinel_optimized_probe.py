"""Assertion-independent deterministic sentinel admission probe."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel_fixture import build_sentinel_fixture

from causalfrontier.canonical import canonical_bytes
from causalfrontier.sentinel import preflight_sentinel_admission


def main() -> None:
    with TemporaryDirectory() as directory:
        fixture = build_sentinel_fixture(Path(directory).resolve())
        report = preflight_sentinel_admission(
            fixture["root"],
            fixture["manifest_sha256"],
            1,
            fixture["generation_plan_path"],
            fixture["generation_plan_sha256"],
            fixture["goal_plan_path"],
            fixture["goal_plan_sha256"],
        )
    print(canonical_bytes(report).decode("utf-8"))


if __name__ == "__main__":
    main()
