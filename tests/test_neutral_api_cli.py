"""Public API and CLI coverage for the neutral-baseline workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import causalfrontier
from causalfrontier import cli as cli_module
from causalfrontier import neutral
from causalfrontier.canonical import sha256_bytes

PUBLIC_NEUTRAL_FUNCTIONS = (
    "exercise_neutral_baselines",
    "load_neutral_action_catalog",
    "lock_neutral_baseline_orders",
    "prepare_neutral_baseline_plan",
    "seed_commitment_sha256",
    "validate_neutral_action_catalog",
    "verify_neutral_baseline_exercise",
)


def _output(capsys: pytest.CaptureFixture[str]) -> tuple[dict, str]:
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.err


def test_neutral_workflow_is_exported_from_the_package_root():
    for name in PUBLIC_NEUTRAL_FUNCTIONS:
        assert name in causalfrontier.__all__
        assert getattr(causalfrontier, name) is getattr(neutral, name)


def test_seed_commitment_cli_binds_exact_catalog_and_seed_checkpoints(tmp_path: Path, monkeypatch, capsys):
    seed = b"\x07" * 32
    raw = seed.hex().encode("ascii") + b"\n"
    seed_path = tmp_path / "seed.txt"
    seed_path.write_bytes(raw)
    checkpoint = sha256_bytes(raw)
    catalog_checkpoint = "a" * 64
    action_universe_sha256 = "b" * 64
    monkeypatch.setattr(
        cli_module,
        "load_neutral_action_catalog",
        lambda path, expected: {
            "authorized_action_universe_sha256": action_universe_sha256,
            "loaded_from": [str(path), expected],
        },
    )

    assert (
        cli_module.main(
            [
                "neutral-commit-seed",
                "catalog.json",
                str(seed_path),
                "--expected-catalog-checkpoint-sha256",
                catalog_checkpoint,
                "--expected-seed-checkpoint-sha256",
                checkpoint,
            ]
        )
        == 3
    )
    output, error = _output(capsys)
    assert error == ""
    assert output == {
        "authorized_action_universe_sha256": action_universe_sha256,
        "seed_commitment_sha256": neutral.seed_commitment_sha256(seed, action_universe_sha256),
    }

    assert (
        cli_module.main(
            [
                "neutral-commit-seed",
                "catalog.json",
                str(seed_path),
                "--expected-catalog-checkpoint-sha256",
                catalog_checkpoint,
                "--expected-seed-checkpoint-sha256",
                "0" * 64,
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "neutral baseline seed external checkpoint mismatch" in captured.err


def test_neutral_cli_dispatches_every_explicit_checkpoint(monkeypatch, capsys):
    digests = {
        "catalog": "a" * 64,
        "plan": "b" * 64,
        "lock": "c" * 64,
        "report": "d" * 64,
        "seed_1": "e" * 64,
        "seed_2": "f" * 64,
        "commitment_1": "1" * 64,
        "commitment_2": "2" * 64,
    }
    calls = []
    seed_reads = []

    def fake_load(*args):
        calls.append(("load", args, {}))
        return {"command": "load"}

    def fake_prepare(*args):
        calls.append(("prepare", args, {}))
        return {"command": "prepare"}

    def fake_read_seed(path, checkpoint):
        seed_reads.append((path, checkpoint))
        return bytes([len(seed_reads)]) * 32

    def fake_lock(*args):
        calls.append(("lock", args, {}))
        return {"command": "lock"}

    def fake_exercise(*args, **kwargs):
        calls.append(("exercise", args, kwargs))
        return {"command": "exercise"}

    def fake_verify(*args):
        calls.append(("verify", args, {}))
        return {"command": "verify"}

    monkeypatch.setattr(cli_module, "load_neutral_action_catalog", fake_load)
    monkeypatch.setattr(cli_module, "prepare_neutral_baseline_plan", fake_prepare)
    monkeypatch.setattr(cli_module, "_read_checkpointed_seed", fake_read_seed)
    monkeypatch.setattr(cli_module, "lock_neutral_baseline_orders", fake_lock)
    monkeypatch.setattr(cli_module, "exercise_neutral_baselines", fake_exercise)
    monkeypatch.setattr(cli_module, "verify_neutral_baseline_exercise", fake_verify)

    common = ["--expected-catalog-checkpoint-sha256", digests["catalog"]]
    assert cli_module.main(["validate-neutral-action-catalog", "catalog.json", *common]) == 3
    assert _output(capsys) == ({"command": "load"}, "")
    assert calls.pop(0) == ("load", (Path("catalog.json"), digests["catalog"]), {})

    assert (
        cli_module.main(
            [
                "prepare-neutral-baseline-plan",
                "catalog.json",
                *common,
                "--seed-commitment-sha256",
                digests["commitment_1"],
                "--seed-commitment-sha256",
                digests["commitment_2"],
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "prepare"}, "")
    assert calls.pop(0) == (
        "prepare",
        (Path("catalog.json"), digests["catalog"], [digests["commitment_1"], digests["commitment_2"]]),
        {},
    )

    assert (
        cli_module.main(
            [
                "lock-neutral-baseline-orders",
                "catalog.json",
                "plan.json",
                *common,
                "--expected-plan-checkpoint-sha256",
                digests["plan"],
                "--seed-opening",
                "seed-1.txt",
                digests["seed_1"],
                "--seed-opening",
                "seed-2.txt",
                digests["seed_2"],
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "lock"}, "")
    assert seed_reads == [
        (Path("seed-1.txt"), digests["seed_1"]),
        (Path("seed-2.txt"), digests["seed_2"]),
    ]
    assert calls.pop(0) == (
        "lock",
        (
            Path("catalog.json"),
            digests["catalog"],
            Path("plan.json"),
            digests["plan"],
            [b"\x01" * 32, b"\x02" * 32],
        ),
        {},
    )

    assert (
        cli_module.main(
            [
                "exercise-neutral-baselines",
                "catalog.json",
                "plan.json",
                "lock.json",
                *common,
                "--expected-plan-checkpoint-sha256",
                digests["plan"],
                "--expected-lock-checkpoint-sha256",
                digests["lock"],
                "--capture-observational-telemetry",
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "exercise"}, "")
    assert calls.pop(0) == (
        "exercise",
        (
            Path("catalog.json"),
            digests["catalog"],
            Path("plan.json"),
            digests["plan"],
            Path("lock.json"),
            digests["lock"],
        ),
        {"capture_observational_telemetry": True},
    )

    assert (
        cli_module.main(
            [
                "verify-neutral-baseline-exercise",
                "catalog.json",
                "plan.json",
                "lock.json",
                "report.json",
                *common,
                "--expected-plan-checkpoint-sha256",
                digests["plan"],
                "--expected-lock-checkpoint-sha256",
                digests["lock"],
                "--expected-report-checkpoint-sha256",
                digests["report"],
            ]
        )
        == 3
    )
    assert _output(capsys) == ({"command": "verify"}, "")
    assert calls.pop(0) == (
        "verify",
        (
            Path("catalog.json"),
            digests["catalog"],
            Path("plan.json"),
            digests["plan"],
            Path("lock.json"),
            digests["lock"],
            Path("report.json"),
            digests["report"],
        ),
        {},
    )
    assert calls == []


@pytest.mark.parametrize(
    "argv",
    [
        ["validate-neutral-action-catalog", "catalog.json"],
        [
            "neutral-commit-seed",
            "catalog.json",
            "seed.txt",
            "--expected-catalog-checkpoint-sha256",
            "a" * 64,
        ],
        [
            "prepare-neutral-baseline-plan",
            "catalog.json",
            "--expected-catalog-checkpoint-sha256",
            "a" * 64,
        ],
        [
            "lock-neutral-baseline-orders",
            "catalog.json",
            "plan.json",
            "--expected-catalog-checkpoint-sha256",
            "a" * 64,
            "--expected-plan-checkpoint-sha256",
            "b" * 64,
        ],
        [
            "exercise-neutral-baselines",
            "catalog.json",
            "plan.json",
            "lock.json",
            "--expected-catalog-checkpoint-sha256",
            "a" * 64,
            "--expected-plan-checkpoint-sha256",
            "b" * 64,
        ],
        [
            "verify-neutral-baseline-exercise",
            "catalog.json",
            "plan.json",
            "lock.json",
            "report.json",
            "--expected-catalog-checkpoint-sha256",
            "a" * 64,
            "--expected-plan-checkpoint-sha256",
            "b" * 64,
            "--expected-lock-checkpoint-sha256",
            "c" * 64,
        ],
    ],
)
def test_neutral_cli_requires_every_checkpoint(argv):
    with pytest.raises(SystemExit, match="2"):
        cli_module.parser().parse_args(argv)
