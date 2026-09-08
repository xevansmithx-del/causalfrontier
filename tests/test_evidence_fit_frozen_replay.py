"""The later replay transport must not replace the original source or trust edits."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path

import pytest

EVALUATION = Path(__file__).resolve().parents[1] / "evaluation/evidence-fit-v1"


def wrapper():
    return runpy.run_path(str(EVALUATION / "replay_frozen.py"))


def test_archived_source_is_the_complete_original_binding_set():
    module = wrapper()
    manifest_raw = (EVALUATION / "results/run_manifest.json").read_bytes()
    assert hashlib.sha256(manifest_raw).hexdigest() == module["RUN_MANIFEST_SHA256"]
    expected = json.loads(manifest_raw)["frozen_files_sha256"]
    payloads = module["validated_payloads"](module["ARCHIVE"].read_bytes(), expected)
    assert len(payloads) == 41
    assert {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()} == expected
    seal = json.loads((EVALUATION / "frozen-source-seal.json").read_bytes())
    assert seal["archive"] == module["ARCHIVE"].name
    assert seal["archive_sha256"] == module["ARCHIVE_SHA256"]
    assert seal["archive_bytes"] == module["ARCHIVE"].stat().st_size
    assert seal["members_sha256"] == expected
    assert seal["expanded_bytes"] == sum(map(len, payloads.values()))
    for name in ("PROTOCOL.md", "generator.py", "baseline.py", "run.py"):
        assert payloads["evaluation/evidence-fit-v1/" + name] == (EVALUATION / name).read_bytes()


def test_archive_digest_failure_is_rejected():
    module = wrapper()
    source_hashes = json.loads((EVALUATION / "results/run_manifest.json").read_bytes())["frozen_files_sha256"]
    raw = module["ARCHIVE"].read_bytes()
    with pytest.raises(ValueError, match="archive checkpoint differs"):
        module["validated_payloads"](raw + b"changed", source_hashes)


@pytest.mark.parametrize(
    "variant",
    ["duplicate", "missing", "traversal", "modified-payload", "non-text", "extra-metadata", "duplicate-object-key"],
)
def test_snapshot_member_guards_survive_a_recomputed_container_hash(monkeypatch, variant):
    module = wrapper()
    validate = module["validated_payloads"]
    source_hashes = json.loads((EVALUATION / "results/run_manifest.json").read_bytes())["frozen_files_sha256"]
    members = json.loads(module["ARCHIVE"].read_bytes())
    if variant == "duplicate":
        members[-1] = members[0]
    elif variant == "missing":
        members.pop()
    elif variant == "traversal":
        members[0]["path"] = "../outside.py"
    elif variant == "modified-payload":
        members[0]["text"] += "\n"
    elif variant == "non-text":
        members[0]["text"] = {}
    elif variant == "extra-metadata":
        members[0]["symlink_target"] = "outside.py"
    raw = json.dumps(members, ensure_ascii=False).encode()
    if variant == "duplicate-object-key":
        raw = raw.replace(b'"path":', b'"path":"ignored","path":', 1)
    # Bypass only the outer checkpoint in this controlled injection to exercise
    # independent member guards. The actual launcher has no hash-override option.
    monkeypatch.setitem(validate.__globals__, "ARCHIVE_SHA256", hashlib.sha256(raw).hexdigest())
    with pytest.raises(
        ValueError, match=r"inventory differs|member .*rejected|member checkpoint differs|path rejected|duplicate"
    ):
        validate(raw, source_hashes)


def test_snapshot_read_is_bounded_before_json_parsing(tmp_path):
    module = wrapper()
    path = tmp_path / "too-large.json"
    path.write_bytes(b"synthetic payload")
    with pytest.raises(ValueError, match="byte bound"):
        module["bounded_read"](path, 4)


def test_changed_original_manifest_cannot_start_archived_source(monkeypatch, tmp_path):
    module = wrapper()
    results = tmp_path / "results"
    results.mkdir()
    (results / "run_manifest.json").write_bytes(b"{}\n")

    def unexpected_execution(*_args, **_kwargs):
        pytest.fail("Altered prerequisite manifest reached child execution")

    monkeypatch.setattr(module["subprocess"], "run", unexpected_execution)
    with pytest.raises(ValueError, match="run manifest checkpoint differs"):
        module["replay"](results)


def test_current_compatibility_rejects_reauthored_original_metadata(tmp_path):
    module = runpy.run_path(str(EVALUATION / "check_current_compatibility.py"))
    (tmp_path / "run_manifest.json").write_bytes((EVALUATION / "results/run_manifest.json").read_bytes())
    (tmp_path / "artifact_hashes.json").write_bytes(b"{}\n")
    with pytest.raises(ValueError, match="metadata checkpoint differs"):
        module["check"](tmp_path)
