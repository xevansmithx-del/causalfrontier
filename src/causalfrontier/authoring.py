"""Turn an explicitly authored draft into a new frozen case, without inference."""

from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from . import receipts as receipt_io
from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    reject_private_material,
    require_id_list,
    require_unique_ids,
    sha256_bytes,
)
from .capsule import _remove_created_capsule
from .classifier import classifier_sha256, validate_classifier
from .frontier import compile_case
from .model import SCHEMA_VERSION, SOURCE_TEXT_LIMIT, branch_plan_sha256, load_case, validate_case

DRAFT_SCHEMA_VERSION = "causalfrontier.case-draft.v1"
STATUS = "AUTHORED_DRAFT_FROZEN_STRUCTURAL_VALIDATION_ONLY"


def _null_digest(record: dict[str, Any], field: str) -> None:
    if field not in record or record[field] is not None:
        raise CausalFrontierError("draft %s must be an explicit null placeholder" % field)


def _prepare_draft(draft: Any, sources: dict[str, bytes]) -> dict[str, Any]:
    if not isinstance(draft, dict) or draft.get("schema_version") != DRAFT_SCHEMA_VERSION:
        raise CausalFrontierError("freeze-draft requires an explicit causalfrontier.case-draft.v1 draft")
    draft["schema_version"] = SCHEMA_VERSION
    provenance = require_unique_ids(draft.get("provenance"), "draft provenance")
    for source in provenance:
        _null_digest(source, "sha256")
        source["sha256"] = sha256_bytes(sources[receipt_io._relative(source.get("path"))])
    source_ids = {source["id"] for source in provenance}
    for experiment in require_unique_ids(draft.get("experiments"), "draft experiments"):
        _null_digest(experiment, "classifier_sha256")
        _null_digest(experiment, "branch_plan_sha256")
        outcomes = require_unique_ids(experiment.get("outcomes"), "draft outcomes")
        if any("class" not in outcome for outcome in outcomes):
            raise CausalFrontierError("draft outcomes must declare their classes")
        experiment["classifier"] = validate_classifier(
            experiment.get("classifier"),
            experiment["id"],
            {item["id"]: item for item in outcomes},
            source_ids,
        )
        experiment["classifier_sha256"] = classifier_sha256(experiment["classifier"])
        predictions = experiment.get("predictions")
        if not isinstance(predictions, list) or any(not isinstance(item, dict) for item in predictions):
            raise CausalFrontierError("draft predictions must be a list of objects")
        for prediction in predictions:
            for field in ("world_id", "outcome_id"):
                require_id_list([prediction.get(field)], "draft prediction %s" % field, False)
            prediction["source_ids"] = sorted(
                require_id_list(prediction.get("source_ids"), "draft prediction source_ids", False)
            )
        if "outcome_partition" not in experiment:
            raise CausalFrontierError("draft experiment must declare its outcome partition")
        experiment["branch_plan_sha256"] = branch_plan_sha256(experiment)
    # The ordinary validator remains the sole authority for the complete case
    # contract. Hash completion never supplies a missing scientific declaration.
    return validate_case(draft)


def freeze_draft(draft_root: Path, destination: Path) -> dict[str, Any]:
    """Snapshot draft.json and declared sources into a new no-clobber case root.

    Dates, sources, worlds, predictions, resources, and authority declarations
    come from the author. This operation does not attest their truth or timing.
    """
    if destination.exists() or destination.is_symlink():
        raise CausalFrontierError("refusing to overwrite frozen case destination")
    if ".." in destination.parts or destination.name in {"", ".", ".."}:
        raise CausalFrontierError("destination must be a new named directory without parent traversal")
    with ExitStack() as stack:
        try:
            root_fd = receipt_io._root_descriptor(stack, draft_root)
            parent_fd = receipt_io._root_descriptor(stack, destination.parent)
            output = destination.absolute()
            root_info = os.fstat(root_fd)
            ancestor_info = [parent.stat() for parent in (output.parent, *output.parent.parents)]
            if any((item.st_dev, item.st_ino) == (root_info.st_dev, root_info.st_ino) for item in ancestor_info):
                raise CausalFrontierError("destination must be outside the draft root")
            inventory = receipt_io._inventory(root_fd)
            raw_draft = receipt_io._snapshot(root_fd, "draft.json")
            draft = read_json_bytes(raw_draft, "draft.json")
            if not isinstance(draft, dict):
                raise CausalFrontierError("draft.json must be an object")
            provenance = require_unique_ids(draft.get("provenance"), "draft provenance")
            paths = [receipt_io._relative(source.get("path")) for source in provenance]
            if "draft.json" in paths or "case.json" in paths or len(paths) != len(set(paths)):
                raise CausalFrontierError("draft source paths must be unique and exclude draft.json and case.json")
            if inventory != {"draft.json", *paths}:
                raise CausalFrontierError("draft inventory must contain only draft.json and every declared source")
            sources = {}
            total = len(raw_draft)
            for relative in sorted(paths):
                raw = receipt_io._snapshot(root_fd, relative)
                total += len(raw)
                if len(raw) > SOURCE_TEXT_LIMIT or total > receipt_io.MAX_TOTAL_BYTES:
                    raise CausalFrontierError("draft sources exceed the authoring size limits")
                try:
                    reject_private_material(raw.decode("utf-8"), "draft source")
                except UnicodeError:
                    raise CausalFrontierError("draft source must be UTF-8 text") from None
                sources[relative] = raw
            case = _prepare_draft(draft, sources)
            analysis = compile_case(case)
            # Re-read the bounded inventory and bytes before creating any output.
            # This detects observed draft edits, not hostile whole-host mutation.
            if receipt_io._inventory(root_fd) != inventory or any(
                receipt_io._snapshot(root_fd, name) != raw for name, raw in {"draft.json": raw_draft, **sources}.items()
            ):
                raise CausalFrontierError("draft changed during freezing", reason_code="INPUT_CHANGED")
            created_inode = None
            try:
                os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
                created_inode = output.stat().st_ino
                for relative, raw in {"case.json": canonical_bytes(case) + b"\n", **sources}.items():
                    target = output / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as handle:
                        handle.write(raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                replay = compile_case(load_case(output))
                if canonical_bytes(replay) != canonical_bytes(analysis):
                    raise CausalFrontierError("new frozen case did not replay exactly")
            except BaseException:
                _remove_created_capsule(output, created_inode)
                raise
        except OSError as exc:
            raise io_error(exc, "cannot freeze draft: %s" % exc, operation="freeze_draft") from exc
    return {
        "schema_version": "causalfrontier.draft-freeze.v1",
        "status": STATUS,
        "draft_sha256": sha256_bytes(raw_draft),
        "case_id": case["case_id"],
        "case_sha256": analysis["case_sha256"],
        "analysis_sha256": analysis["analysis_sha256"],
        "sources": [{"path": name, "sha256": sha256_bytes(raw)} for name, raw in sorted(sources.items())],
        "boundary": case["boundary"],
        "scientific_scoring_ready": False,
        "nonclaims": [
            "Dates and scientific declarations are authored, not authenticated or inferred.",
            "This is a frozen input case, not an observation, capsule, calibration, or scientific result.",
            "Local byte checks do not establish prospective timing, external custody, privacy, or biological validity.",
        ],
    }
