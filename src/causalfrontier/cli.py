"""Command-line interface for frozen-case compilation and deterministic replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .canonical import CausalFrontierError
from .capsule import build_capsule, record_rehearsal, verify_capsule
from .classifier import execute_classifiers
from .frontier import compile_case, simulate_branch
from .model import COMPILER_VERSION, load_case


def _emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="causalfrontier",
        description="Compile frozen causal worlds into a prior-free discriminator frontier.",
    )
    result.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {COMPILER_VERSION}",
    )
    commands = result.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="analyze a frozen case root")
    analyze.add_argument("case_root", type=Path)
    classify = commands.add_parser("classify", help="execute digest-bound classifiers on frozen inputs")
    classify.add_argument("case_root", type=Path)
    compile_command = commands.add_parser("compile", help="build a no-clobber capsule")
    compile_command.add_argument("case_root", type=Path)
    compile_command.add_argument("destination", type=Path)
    verify = commands.add_parser("verify", help="replay and verify a capsule")
    verify.add_argument("capsule", type=Path)
    verify.add_argument(
        "--expected-ledger-head",
        help="external SHA-256 checkpoint used to detect local ledger rollback",
    )
    simulate = commands.add_parser("simulate", help="rehearse a predeclared outcome branch")
    simulate.add_argument("case_root", type=Path)
    simulate.add_argument("experiment_id")
    simulate.add_argument("outcome_id")
    simulate.add_argument("branch_plan_sha256")
    remember = commands.add_parser("remember-rehearsal", help="append one counterfactual rehearsal to capsule memory")
    remember.add_argument("capsule", type=Path)
    remember.add_argument(
        "--expected-ledger-head",
        required=True,
        help="independently stored current SHA-256 checkpoint required before append",
    )
    remember.add_argument("timestamp", help="whole-second RFC3339 UTC")
    remember.add_argument("experiment_id")
    remember.add_argument("outcome_id")
    remember.add_argument("branch_plan_sha256")
    return result


def main(argv: Optional[list] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "analyze":
            output = compile_case(load_case(args.case_root))
        elif args.command == "classify":
            case = load_case(args.case_root)
            output = execute_classifiers(case, args.case_root.resolve(strict=True))
        elif args.command == "compile":
            output = build_capsule(args.case_root, args.destination)
        elif args.command == "verify":
            output = verify_capsule(
                args.capsule,
                expected_ledger_head=args.expected_ledger_head,
            )
        elif args.command == "simulate":
            output = simulate_branch(
                load_case(args.case_root),
                args.experiment_id,
                args.outcome_id,
                branch_plan_sha256=args.branch_plan_sha256,
            )
        elif args.command == "remember-rehearsal":
            output = record_rehearsal(
                args.capsule,
                args.expected_ledger_head,
                args.timestamp,
                args.experiment_id,
                args.outcome_id,
                args.branch_plan_sha256,
            )
        else:
            raise CausalFrontierError("unknown command")
        _emit(output)
        if args.command == "verify" and output.get("status") == "INVALID":
            return 2
        return 0
    except (CausalFrontierError, OSError, ValueError) as exc:
        print("causalfrontier: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
