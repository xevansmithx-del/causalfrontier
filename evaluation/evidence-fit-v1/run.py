"""Run/replay the finite synthetic evaluation without changing production source."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from baseline import evaluate
from generator import FACTORS, ROOT, digest, encoded, fixture_inputs, generate_cases

sys.path.insert(0, str(ROOT / "src"))

from causalfrontier.evidence_fit import audit_evidence_fit, verify_evidence_fit

AVAILABILITY_FIELDS = (
    "declared_date_relation",
    "input_date_fit",
    "input_date_constraint_applies",
    "historical_eligible",
    "interval",
)


def frozen_paths() -> list[str]:
    paths = [*ROOT.glob("src/**/*.py"), *ROOT.glob("examples/synthetic-evidence-fit/**/*.json")]
    paths.extend(
        ROOT / "evaluation/evidence-fit-v1" / name for name in ("generator.py", "baseline.py", "run.py", "PROTOCOL.md")
    )
    paths.extend(ROOT / name for name in ("pyproject.toml", "uv.lock"))
    return sorted(path.relative_to(ROOT).as_posix() for path in paths)


def source_binding(freeze_commit: str | None, saved: dict | None = None) -> dict:
    binding = {relative: digest((ROOT / relative).read_bytes()) for relative in frozen_paths()}
    if saved is not None:
        if binding != saved:
            raise ValueError("Current evaluation, fixture or production source differs from recorded prerequisite")
    elif freeze_commit is not None:
        if re.fullmatch(r"[0-9a-f]{40}", freeze_commit) is None:
            raise ValueError("Supply the complete lowercase 40-character prerequisite commit")
        for relative, actual in binding.items():
            checkpoint = subprocess.run(
                ["git", "show", f"{freeze_commit}:{relative}"],
                cwd=ROOT,
                capture_output=True,
                check=True,
            ).stdout
            if digest(checkpoint) != actual:
                raise ValueError(f"Current bytes differ from prerequisite commit: {relative}")
    return binding


def projection(report: dict) -> dict:
    return {
        "records": [
            {
                "id": row["record"]["id"],
                "fit": {key: row["dimension_fit"][key] for key in (*FACTORS, "study_version", "role")},
                "availability": {key: row["availability"][key] for key in AVAILABILITY_FIELDS},
            }
            for row in report["records"]
        ],
        "missing_source_requirements": report["missing_source_requirements"],
    }


def preservation(report: dict, case: dict) -> dict:
    extraction, document = case["extraction"], case["receipt_set"]
    original = {row["id"]: row for row in extraction["records"]}
    records_ok = len(report["records"]) == len(original)
    dates_ok = quality_ok = availability_ok = True
    unknowns_retained = True
    for row in report["records"]:
        record = row["record"]
        records_ok &= record == original[record["id"]]
        receipt = next(item for item in document["receipts"] if item["id"] == record["receipt_id"])
        source = next(item for item in receipt["source_records"] if item["id"] == record["source_id"])
        dates_ok &= row["receipt_dates"] == source["dates"]
        quality_ok &= all(row[key] == receipt[key] for key in ("coverage", "retrieval_state", "semantic_state"))
        quality_ok &= row["temporal_attestation_state"] == receipt["temporal_attestation"]["state"]
        selected = record["availability_date_field"]
        availability_ok &= row["availability"]["selected_date_field"] == selected
        availability_ok &= row["availability"]["selected_date"] == (
            None if selected is None else source["dates"][selected]
        )
        availability_ok &= row["availability"]["evidence_cutoff"] == document["evidence_cutoff"]
        # Presence of any mismatch must not remove UNKNOWN declarations from the selected projection.
        expected_row = next(item for item in case["expected"]["records"] if item["id"] == record["id"])
        unknowns_retained &= all(
            row["dimension_fit"][key] == "UNKNOWN" for key, state in expected_row["fit"].items() if state == "UNKNOWN"
        )
    return {
        "exact_records_retained": bool(records_ok),
        "all_source_dates_retained": bool(dates_ok),
        "source_quality_and_attestation_retained": bool(quality_ok),
        "selected_date_and_cutoff_retained": bool(availability_ok),
        "selected_unknowns_retained": bool(unknowns_retained),
        "authority_restrictions_retained": (
            report["historically_eligible_records_n"] == 0
            and report["scientific_scoring"] == "DISABLED"
            and report["scientific_authority"] is False
            and report["semantic_authentication"] is False
            and report["boundary"] == extraction["boundary"]
            and all(
                row["historical_eligible"] is False and row["availability"]["historical_eligible"] is False
                for row in report["records"]
            )
        ),
    }


def save(path: Path, value: object) -> bytes:
    raw = encoded(value)
    path.write_bytes(raw)
    return raw


def execute_case(output: Path, case: dict, raw_fixture: bytes) -> dict:
    case_dir = output / "cases" / case["id"]
    receipt_root = case_dir / "receipt-root"
    (receipt_root / "raw").mkdir(parents=True)
    (receipt_root / "raw/response.json").write_bytes(raw_fixture)
    metadata = save(receipt_root / "receipt-set.json", case["receipt_set"])
    extraction = save(case_dir / "extraction.json", case["extraction"])
    save(case_dir / "case.json", case)
    outcome = {
        "case_id": case["id"],
        "stratum": case["stratum"],
        "semantic_stipulation": case["semantic_stipulation"],
        "expected": case["expected"],
        "input_sha256": {"receipt_set": digest(metadata), "extraction": digest(extraction)},
        "engine_error": None,
        "baseline_error": None,
    }
    try:
        baseline = evaluate(case["receipt_set"], case["extraction"])
        outcome.update(baseline_projection=baseline, baseline_matches_expected=baseline == case["expected"])
    except Exception as exc:  # Retain a failed case rather than silently exclude it.
        outcome.update(baseline_error=type(exc).__name__, baseline_matches_expected=False)
    try:
        report = audit_evidence_fit(receipt_root, digest(metadata), extraction, digest(extraction))
        report_raw = save(case_dir / "report.json", report)
        engine = projection(report)
        replay = verify_evidence_fit(
            receipt_root,
            digest(metadata),
            extraction,
            digest(extraction),
            report_raw,
            digest(report_raw),
        )
        save(case_dir / "verification.json", replay)
        outcome.update(
            engine_projection=engine,
            engine_matches_expected=engine == case["expected"],
            paired_projection_agreement=engine == outcome.get("baseline_projection"),
            preservation_checks=preservation(report, case),
            exact_report_replay_verified=replay["verified"] is True,
            report_file_sha256=digest(report_raw),
        )
    except Exception as exc:  # The stable exception class is retained; host paths are not.
        outcome.update(
            engine_error=type(exc).__name__,
            engine_matches_expected=False,
            paired_projection_agreement=False,
            preservation_checks={},
            exact_report_replay_verified=False,
        )
    outcome["all_checks_pass"] = (
        outcome["engine_matches_expected"]
        and outcome["baseline_matches_expected"]
        and outcome["paired_projection_agreement"]
        and outcome["exact_report_replay_verified"]
        and bool(outcome["preservation_checks"])
        and all(outcome["preservation_checks"].values())
    )
    save(case_dir / "outcome.json", outcome)
    return outcome


def summarize(outcomes: list[dict], run_mode: str) -> dict:
    strata = {}
    for stratum in sorted({row["stratum"] for row in outcomes}):
        selected = [row for row in outcomes if row["stratum"] == stratum]
        strata[stratum] = {
            "cases": len(selected),
            **{
                key + "_n": sum(bool(row[key]) for row in selected)
                for key in (
                    "engine_matches_expected",
                    "baseline_matches_expected",
                    "paired_projection_agreement",
                    "all_checks_pass",
                )
            },
        }
    confusion = {}
    for system in ("engine", "baseline"):
        cells = Counter()
        for row in outcomes:
            if row["stratum"] != "factorial":
                continue
            prediction = row.get(system + "_projection", {}).get("records", [])
            for factor in FACTORS:
                expected = row["expected"]["records"][0]["fit"][factor]
                observed = prediction[0]["fit"][factor] if prediction else "ERROR"
                cells[(expected, observed)] += 1
        confusion[system] = [
            {"expected": expected, "observed": observed, "cells": count}
            for (expected, observed), count in sorted(cells.items())
        ]
    return {
        "schema": "causalfrontier.synthetic-evidence-fit-evaluation.v1",
        "run_mode": run_mode,
        "cases_n": len(outcomes),
        "failed_case_ids": [row["case_id"] for row in outcomes if not row["all_checks_pass"]],
        "strata": strata,
        "factorial_selected_label_confusion": confusion,
        "zero_record_cases_n": sum(not row["expected"]["records"] for row in outcomes),
        "semantic_counterexample_cases_n": sum(row["semantic_stipulation"] is not None for row in outcomes),
        "interpretation": "AUTHORED_DECLARED_POLICY_AND_PRESERVATION_ONLY",
        "independent_semantic_validation": False,
        "human_performance_measured": False,
        "biological_validation": False,
        "scientific_authority": False,
    }


def run(output: Path, manifest: dict) -> dict:
    if output.exists():
        raise ValueError("Output directory already exists; use --verify-existing to replay")
    cases = generate_cases()
    selected_ids = manifest["case_ids"]
    by_id = {case["id"]: case for case in cases}
    if len(selected_ids) != len(set(selected_ids)) or not set(selected_ids) <= set(by_id):
        raise ValueError("Unknown or duplicate case identity")
    if manifest["run_mode"] == "FULL" and selected_ids != [case["id"] for case in cases]:
        raise ValueError("Full run must include the complete ordered finite design")
    output.mkdir(parents=True)
    save(output / "run_manifest.json", manifest)
    _, _, raw_fixture = fixture_inputs()
    outcomes = [execute_case(output, by_id[identifier], raw_fixture) for identifier in selected_ids]
    summary = summarize(outcomes, manifest["run_mode"])
    save(output / "summary.json", summary)
    artifacts = {
        path.relative_to(output).as_posix(): digest(path.read_bytes())
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    save(output / "artifact_hashes.json", artifacts)
    return summary


def verify_existing(output: Path) -> dict:
    manifest = json.loads((output / "run_manifest.json").read_bytes())
    source_binding(None, manifest["frozen_files_sha256"])
    with tempfile.TemporaryDirectory(prefix="evidence-fit-replay-") as temporary:
        replay = Path(temporary).resolve() / "artifact"
        summary = run(replay, manifest)
        actual_files = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
        expected_files = {path.relative_to(replay).as_posix() for path in replay.rglob("*") if path.is_file()}
        if actual_files != expected_files or any(
            (output / relative).read_bytes() != (replay / relative).read_bytes() for relative in actual_files
        ):
            raise ValueError("Replay differs from retained artifact bytes or exact inventory")
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--verify-existing", type=Path)
    parser.add_argument("--freeze-commit")
    smoke = parser.add_mutually_exclusive_group()
    smoke.add_argument("--smoke-limit", type=int, choices=range(1, 9))
    smoke.add_argument("--smoke-case", action="append", default=[])
    args = parser.parse_args()
    if args.verify_existing is not None:
        if args.freeze_commit or args.smoke_limit or args.smoke_case:
            parser.error("Replay uses the retained manifest; do not supply freeze or smoke arguments")
        summary = verify_existing(args.verify_existing.resolve())
    else:
        is_smoke = bool(args.smoke_limit or args.smoke_case)
        if not is_smoke and not args.freeze_commit:
            parser.error("Full run requires --freeze-commit; development may use a labelled smoke run")
        if len(args.smoke_case) > 8:
            parser.error("Development smoke runs are bounded to eight cases")
        cases = generate_cases()
        identifiers = args.smoke_case or [case["id"] for case in cases[: args.smoke_limit]]
        manifest = {
            "schema": "causalfrontier.synthetic-evidence-fit-evaluation-run.v1",
            "run_mode": "SMOKE_ONLY" if is_smoke else "FULL",
            "prerequisite_commit": args.freeze_commit,
            "remote_prerequisite_attestation": "OPERATOR_RECORD_REQUIRED_NOT_ATTESTED_BY_RUNNER",
            "frozen_files_sha256": source_binding(args.freeze_commit),
            "case_ids": identifiers,
        }
        summary = run(args.output.resolve(), manifest)
    print(json.dumps(summary, sort_keys=True))
    return bool(summary["failed_case_ids"])


if __name__ == "__main__":
    raise SystemExit(main())
