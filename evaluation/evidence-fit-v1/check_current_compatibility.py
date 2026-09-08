"""Later compatibility check: current APIs against retained original v1 reports.

This is not a replay of the original evaluation with its frozen source bindings.
It writes no report or result artifacts and does not rerun the baseline or oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from causalfrontier.canonical import CausalFrontierError  # noqa: E402
from causalfrontier.evidence_fit import audit_evidence_fit, verify_evidence_fit  # noqa: E402

RUN_MANIFEST_SHA256 = "9d6b59a0de407d100b609e66f788f4fd211ed56b8db04ee3149b013996030dd7"
ARTIFACT_INVENTORY_SHA256 = "444bc0e07e0d8b343715941b791c198359465cf49fa697f86b003f3af6b1dcee"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check(results: Path) -> dict:
    manifest_raw = (results / "run_manifest.json").read_bytes()
    inventory_raw = (results / "artifact_hashes.json").read_bytes()
    if sha256(manifest_raw) != RUN_MANIFEST_SHA256 or sha256(inventory_raw) != ARTIFACT_INVENTORY_SHA256:
        raise ValueError("Original evaluation metadata checkpoint differs")
    inventory = json.loads(inventory_raw)
    actual_files = {path.relative_to(results).as_posix() for path in results.rglob("*") if path.is_file()}
    if actual_files != {*inventory, "artifact_hashes.json"}:
        raise ValueError("Original evaluation artifact inventory differs")
    if any(sha256((results / relative).read_bytes()) != expected for relative, expected in inventory.items()):
        raise ValueError("Original evaluation artifact bytes differ")
    manifest = json.loads(manifest_raw)
    failures = []
    reports_matched = reports_verified = records = 0
    for identifier in manifest["case_ids"]:
        directory = results / "cases" / identifier
        receipt_root = directory / "receipt-root"
        metadata = (receipt_root / "receipt-set.json").read_bytes()
        extraction = (directory / "extraction.json").read_bytes()
        report_raw = (directory / "report.json").read_bytes()
        expected = json.loads(report_raw)
        records += len(expected["records"])
        try:
            actual = audit_evidence_fit(receipt_root, sha256(metadata), extraction, sha256(extraction))
            if actual != expected:
                failures.append({"case_id": identifier, "reason": "FULL_REPORT_DIFFERS"})
                continue
            reports_matched += 1
            verification = verify_evidence_fit(
                receipt_root,
                sha256(metadata),
                extraction,
                sha256(extraction),
                report_raw,
                sha256(report_raw),
            )
            if verification["verified"] is not True:
                failures.append({"case_id": identifier, "reason": "REPORT_NOT_VERIFIED"})
            else:
                reports_verified += 1
        except CausalFrontierError as error:
            failures.append({"case_id": identifier, **error.diagnostic()})
        except (OSError, ValueError, KeyError) as error:
            failures.append({"case_id": identifier, "reason": "CURRENT_API_ERROR", "type": type(error).__name__})
    return {
        "schema": "causalfrontier.current-evidence-fit-compatibility.v1",
        "scope": "LATER_CURRENT_API_COMPARISON_WITH_RETAINED_ORIGINAL_REPORTS",
        "cases_n": len(manifest["case_ids"]),
        "original_records_n": records,
        "full_reports_identical_n": reports_matched,
        "full_reports_verified_n": reports_verified,
        "failures": failures,
        "current_source_sha256": {
            path.relative_to(ROOT).as_posix(): sha256(path.read_bytes())
            for path in sorted((ROOT / "src").rglob("*.py"))
        },
        "current_checker_sha256": sha256(Path(__file__).read_bytes()),
        "original_run_manifest_sha256": RUN_MANIFEST_SHA256,
        "original_artifact_inventory_sha256": ARTIFACT_INVENTORY_SHA256,
        "original_frozen_evaluation_reexecuted": False,
        "baseline_or_semantic_accuracy_evaluated": False,
        "result_files_modified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(args.results.resolve())
    except (OSError, ValueError, KeyError) as error:
        print(
            json.dumps(
                {
                    "schema": "causalfrontier.current-evidence-fit-compatibility-error.v1",
                    "reason_code": "COMPATIBILITY_CHECK_FAILED",
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return bool(result["failures"])


if __name__ == "__main__":
    raise SystemExit(main())
