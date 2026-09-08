"""Replay retained v1 results with the exact archived prerequisite source.

Current production code is never substituted into the original evaluation.
This launcher is a later transport addition, not part of the frozen v1 protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

DIRECTORY = Path(__file__).resolve().parent
ARCHIVE = DIRECTORY / "frozen-source-2f34b5d.json"
ARCHIVE_SHA256 = "fe9f2532ecb13b0c3a350af9498719e09b8f40a82bcbbfc7d2ef4e769378d4f1"
RUN_MANIFEST_SHA256 = "9d6b59a0de407d100b609e66f788f4fd211ed56b8db04ee3149b013996030dd7"
PREREQUISITE_COMMIT = "2f34b5d7279241e842e263e4dfbad5c023336d2e"
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_EXPANDED_BYTES = 2_000_000


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Frozen source archive has duplicate object keys")
        result[key] = value
    return result


def bounded_read(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Frozen source transport exceeds byte bound")
    return raw


def validated_payloads(archive_raw: bytes, source_hashes: dict) -> dict[str, bytes]:
    """Validate the complete closed UTF-8 snapshot before writing any member."""
    if len(archive_raw) > MAX_ARCHIVE_BYTES or sha256(archive_raw) != ARCHIVE_SHA256:
        raise ValueError("Frozen source archive checkpoint differs")
    if len(source_hashes) != 41:
        raise ValueError("Frozen source inventory differs")
    members = json.loads(archive_raw, object_pairs_hook=_unique_object)
    if type(members) is not list or len(members) != 41:
        raise ValueError("Frozen source archive inventory differs")
    payloads = {}
    for item in members:
        if type(item) is not dict or set(item) != {"path", "text"}:
            raise ValueError("Frozen source archive member shape rejected")
        name, content = item["path"], item["text"]
        if type(name) is not str or type(content) is not str:
            raise ValueError("Frozen source archive member type rejected")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
            raise ValueError("Frozen source archive path rejected")
        if name in payloads or name not in source_hashes:
            raise ValueError("Frozen source archive inventory differs")
        raw = content.encode("utf-8")
        if sha256(raw) != source_hashes[name]:
            raise ValueError("Frozen source member checkpoint differs")
        payloads[name] = raw
    if set(payloads) != set(source_hashes) or sum(map(len, payloads.values())) > MAX_EXPANDED_BYTES:
        raise ValueError("Frozen source archive inventory or expansion bound differs")
    return payloads


def replay(results: Path) -> dict:
    manifest_raw = bounded_read(results / "run_manifest.json", 64 * 1024)
    if sha256(manifest_raw) != RUN_MANIFEST_SHA256:
        raise ValueError("Original evaluation run manifest checkpoint differs")
    source_hashes = json.loads(manifest_raw)["frozen_files_sha256"]
    payloads = validated_payloads(bounded_read(ARCHIVE, MAX_ARCHIVE_BYTES), source_hashes)
    with tempfile.TemporaryDirectory(prefix="evidence-fit-frozen-source-") as temporary:
        checkout = Path(temporary).resolve()
        for relative, raw in payloads.items():
            destination = checkout / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        optimization = ["-" + "O" * sys.flags.optimize] if sys.flags.optimize else []
        process = subprocess.run(
            [
                sys.executable,
                *optimization,
                str(checkout / "evaluation/evidence-fit-v1/run.py"),
                "--verify-existing",
                str(results),
            ],
            cwd=checkout,
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            # The original executable may retain its original error limitations.
            # Do not expose arbitrary child exception text or temporary paths.
            raise ValueError("Original frozen evaluation replay failed")
        summary = json.loads(process.stdout)
        if summary["run_mode"] != "FULL" or summary["cases_n"] != 132 or summary["failed_case_ids"]:
            raise ValueError("Original frozen evaluation did not complete its full design")
    return {
        "schema": "causalfrontier.frozen-evaluation-replay.v1",
        "scope": "ORIGINAL_V1_SOURCE_AND_RETAINED_RESULTS",
        "prerequisite_commit": PREREQUISITE_COMMIT,
        "frozen_source_archive_sha256": ARCHIVE_SHA256,
        "original_run_manifest_sha256": RUN_MANIFEST_SHA256,
        "frozen_source_files_n": len(payloads),
        "summary": summary,
        "current_production_source_evaluated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = replay(args.verify_existing.resolve())
    except (OSError, ValueError, KeyError) as error:
        print(
            json.dumps(
                {
                    "schema": "causalfrontier.frozen-evaluation-replay-error.v1",
                    "reason_code": "FROZEN_REPLAY_FAILED",
                    "error_type": type(error).__name__,
                    "errno": error.errno if isinstance(error, OSError) else None,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
