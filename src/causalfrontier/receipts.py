"""Read-only receipt preparation, explicitly NOT historical attestation or scoring.

This local milestone binds bytes and preserves uncertainty. No trusted archive
or timestamp verifier is implemented: every receipt remains historically
inadmissible, including a perfectly hashed, self-declared old attestation.
"""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import (
    CausalFrontierError,
    canonical_bytes,
    io_error,
    read_json_bytes,
    reject_private_material,
    require_enum,
    require_id,
    require_sha256,
    require_text,
    require_utc_timestamp,
    sha256_bytes,
)
from .model import BOUNDARY_CANONICAL, COMPILER_VERSION, FIXED_PARAMETER, fixed_boundary

SET_SCHEMA = "causalfrontier.receipt-set.v1"
RECEIPT_SCHEMA = "causalfrontier.receipt.v1"
MANIFEST = "receipt-set.json"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FILES = 128
DATE_FIELDS = frozenset(
    {
        "publication_unspecified",
        "publication_online",
        "publication_print",
        "registry_first_posted",
        "source_updated",
        "index_entry",
        "snapshot_created",
    }
)
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROHIBITED_FIELDS = re.compile(
    r'["\'](?:patient_id|subject_id|medical_record_number|date_of_birth|ssn|api_key|access_token|authorization)["\']\s*:',
    re.IGNORECASE,
)


def _shape(value: Any, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise CausalFrontierError("receipt schema mismatch")
    return value


def _text(value: Any) -> str:
    result = require_text(value, "receipt text", 8000)
    if any(ord(char) < 32 for char in result):
        raise CausalFrontierError("receipt text contains control characters")
    return result


def _url(value: Any) -> None:
    text = _text(value)
    try:
        parsed = urlsplit(text)
        invalid = parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port
    except ValueError:
        raise CausalFrontierError("receipt locator must be credential-free HTTPS") from None
    if invalid:
        raise CausalFrontierError("receipt locator must be credential-free HTTPS")


def _strings(value: Any, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > 128 or (nonempty and not value):
        raise CausalFrontierError("receipt text list has invalid size or type")
    return [_text(item) for item in value]


def _integer(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise CausalFrontierError("receipt count must be a bounded nonnegative integer")
    return value


def _date(value: Any) -> None:
    item = _shape(value, {"value", "precision", "source_field"})
    precision = require_enum(item["precision"], {"DAY", "MONTH", "YEAR", "UNKNOWN"}, "date precision")
    if precision == "UNKNOWN":
        if item["value"] is not None or item["source_field"] is not None:
            raise CausalFrontierError("unknown date must not contain an invented value or source field")
        return
    _text(item["source_field"])
    raw = item["value"]
    pattern = {"DAY": r"\d{4}-\d{2}-\d{2}", "MONTH": r"\d{4}-\d{2}", "YEAR": r"\d{4}"}[precision]
    if not isinstance(raw, str) or re.fullmatch(pattern, raw) is None:
        raise CausalFrontierError("receipt date value does not match its precision")
    suffix = {"DAY": "", "MONTH": "-01", "YEAR": "-01-01"}[precision]
    try:
        date.fromisoformat(raw + suffix)
    except ValueError:
        raise CausalFrontierError("receipt date is not a real calendar date") from None


def _relative(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 1000:
        raise CausalFrontierError("invalid receipt file path")
    parts = value.split("/")
    if len(parts) > 8 or any(part in {".", ".."} or COMPONENT.fullmatch(part) is None for part in parts):
        raise CausalFrontierError(
            "receipt paths must be canonical relative paths",
            reason_code="SAFE_PATH_REJECTED",
            operation="receipts._relative",
        )
    return value


def _open_directory(stack: ExitStack, name: str, parent: int | None = None) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise CausalFrontierError(
            "receipt preflight requires no-follow directory descriptors",
            reason_code="ENVIRONMENT_UNSUPPORTED",
            operation="receipts._open_directory",
        )
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    stack.callback(os.close, descriptor)
    return descriptor


def _root_descriptor(stack: ExitStack, root: Path) -> int:
    if ".." in root.parts:
        raise CausalFrontierError(
            "receipt root must not contain parent traversal",
            reason_code="SAFE_PATH_REJECTED",
            operation="receipts._root_descriptor",
        )
    absolute = root.absolute()
    descriptor = _open_directory(stack, absolute.anchor)
    for component in absolute.parts[1:]:
        descriptor = _open_directory(stack, component, descriptor)
    return descriptor


def _snapshot(root_fd: int, relative: str) -> bytes:
    """No-follow descriptor walk; inspect and hash the same bounded bytes."""
    parts = _relative(relative).split("/")
    with ExitStack() as stack:
        parent = root_fd
        for part in parts[:-1]:
            parent = _open_directory(stack, part, parent)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        stack.callback(os.close, descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            raise CausalFrontierError(
                "receipt payload must be a bounded single-link regular file",
                reason_code="SAFE_FILE_REJECTED",
                operation="receipts._snapshot",
            )
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > MAX_FILE_BYTES
            or len(raw) != before.st_size
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
        ):
            raise CausalFrontierError(
                "receipt payload changed while being read",
                reason_code="INPUT_CHANGED",
                operation="receipts._snapshot",
            )
    return raw


def _inventory(
    root_fd: int, prefix: str = "", entries: set[str] | None = None, visited: list[int] | None = None
) -> set[str]:
    entries = set() if entries is None else entries
    visited = [0] if visited is None else visited
    names = []
    with os.scandir(root_fd) as directory:
        for entry in directory:
            visited[0] += 1
            if visited[0] > MAX_FILES:
                raise CausalFrontierError("receipt inventory exceeds limit")
            names.append(entry.name)
    for name in sorted(names):
        relative = _relative(prefix + name)
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            with ExitStack() as stack:
                child = _open_directory(stack, name, root_fd)
                before = len(entries)
                _inventory(child, relative + "/", entries, visited)
                if len(entries) == before:
                    raise CausalFrontierError(
                        "receipt inventory contains an empty directory",
                        reason_code="INVENTORY_MISMATCH",
                        operation="receipts._inventory",
                    )
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            entries.add(relative)
        else:
            raise CausalFrontierError(
                "receipt inventory contains an unsafe filesystem object",
                reason_code="SAFE_FILE_REJECTED",
                operation="receipts._inventory",
            )
    return entries


def _screen(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise CausalFrontierError("receipt payload is not UTF-8 text") from None
    reject_private_material(text, "receipt payload")
    if "\x00" in text or PROHIBITED_FIELDS.search(text):
        raise CausalFrontierError("receipt payload contains prohibited material")


def _binding(value: Any, bindings: dict[str, str]) -> None:
    item = _shape(value, {"path", "sha256"})
    relative = _relative(item["path"])
    digest = require_sha256(item["sha256"], "receipt payload digest")
    if relative == MANIFEST or (relative in bindings and bindings[relative] != digest):
        raise CausalFrontierError("receipt payload binding conflicts")
    bindings[relative] = digest


def _validate_receipt(receipt: Any, frozen_at: str, bindings: dict[str, str]) -> dict:
    item = _shape(
        receipt,
        {
            "schema_version",
            "id",
            "data_class",
            "authority",
            "raw_response",
            "response_layer",
            "request",
            "retrieved_at",
            "retrieval_state",
            "semantic_state",
            "declared_scope",
            "coverage",
            "source_records",
            "context",
            "funding_conflicts",
            "license",
            "temporal_attestation",
        },
    )
    if item["schema_version"] != RECEIPT_SCHEMA:
        raise CausalFrontierError("unregistered receipt schema version")
    require_id(item["id"], "receipt id")
    data_class = require_enum(item["data_class"], {"PUBLIC_METADATA", "PUBLIC_AGGREGATE", "SYNTHETIC"}, "data class")
    if item["authority"] != ("SYNTHETIC_DATA" if data_class == "SYNTHETIC" else "PUBLIC_DATA"):
        raise CausalFrontierError("receipt data class and authority differ")
    _binding(item["raw_response"], bindings)
    require_enum(
        item["response_layer"], {"TOOL_SERIALIZED_RESPONSE", "RAW_HTTP_BODY", "SYNTHETIC_TEXT"}, "response layer"
    )
    if (data_class == "SYNTHETIC") != (item["response_layer"] == "SYNTHETIC_TEXT"):
        raise CausalFrontierError("receipt response layer and data class differ")
    request = _shape(
        item["request"], {"tool_name", "tool_version", "submitted_arguments", "executed_query", "query_rewrites"}
    )
    require_id(request["tool_name"], "receipt tool name")
    _text(request["tool_version"])
    if not isinstance(request["submitted_arguments"], dict):
        raise CausalFrontierError("submitted arguments must be an object")
    if request["executed_query"] is not None:
        _text(request["executed_query"])
    if request["query_rewrites"] is not None:
        _strings(request["query_rewrites"])
    retrieved_at = require_utc_timestamp(item["retrieved_at"], "receipt retrieval timestamp")
    if retrieved_at > frozen_at:
        raise CausalFrontierError("receipt retrieval follows freeze")
    retrieval = require_enum(
        item["retrieval_state"], {"COMPLETE", "PARTIAL", "FAILED", "TIMEOUT", "NOT_RUN"}, "retrieval state"
    )
    semantic = require_enum(
        item["semantic_state"],
        {
            "METADATA_ONLY",
            "USABLE_FOR_DECLARED_SCOPE",
            "CONTEXT_ONLY",
            "UNUSABLE",
            "SYNTHETIC_FIXTURE_ONLY",
        },
        "semantic state",
    )
    if data_class == "PUBLIC_METADATA" and semantic not in {"METADATA_ONLY", "UNUSABLE", "CONTEXT_ONLY"}:
        raise CausalFrontierError("public metadata cannot become decision evidence")
    if (data_class == "SYNTHETIC") != (semantic == "SYNTHETIC_FIXTURE_ONLY") and semantic != "UNUSABLE":
        raise CausalFrontierError("synthetic semantic state and data class differ")
    _text(item["declared_scope"])
    coverage = _shape(
        item["coverage"],
        {"scope", "state", "returned_records", "total_records", "pages_received", "next_cursor", "truncated"},
    )
    _text(coverage["scope"])
    require_enum(coverage["state"], {"COMPLETE", "PARTIAL", "UNKNOWN"}, "coverage state")
    returned = _integer(coverage["returned_records"])
    total = None if coverage["total_records"] is None else _integer(coverage["total_records"])
    _integer(coverage["pages_received"])
    if type(coverage["truncated"]) is not bool:
        raise CausalFrontierError("truncated must be boolean")
    if coverage["next_cursor"] is not None:
        _text(coverage["next_cursor"])
    if total is not None and returned > total:
        raise CausalFrontierError("returned record count exceeds total")
    if coverage["state"] == "COMPLETE" and (
        total is None
        or returned != total
        or coverage["truncated"]
        or coverage["next_cursor"] is not None
        or (returned > 0 and coverage["pages_received"] == 0)
    ):
        raise CausalFrontierError("complete coverage conflicts with pagination")
    if semantic in {"USABLE_FOR_DECLARED_SCOPE", "SYNTHETIC_FIXTURE_ONLY"} and (
        retrieval != "COMPLETE" or coverage["state"] != "COMPLETE"
    ):
        raise CausalFrontierError("usable declaration requires complete acquisition and coverage")
    records = item["source_records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 128:
        raise CausalFrontierError("receipt must name its source records")
    record_ids = set()
    for record in records:
        _shape(record, {"id", "locator", "dates"})
        identity = require_id(record["id"], "source record id")
        if identity in record_ids:
            raise CausalFrontierError("duplicate source record id")
        record_ids.add(identity)
        _url(record["locator"])
        dates = _shape(record["dates"], DATE_FIELDS)
        for value in dates.values():
            _date(value)
    context = _shape(
        item["context"], {"entity_mappings", "population", "comparator", "endpoint", "model", "exposure", "duration"}
    )
    _strings(context["entity_mappings"], nonempty=True)
    for key in set(context) - {"entity_mappings"}:
        if context[key] is not None:
            _text(context[key])
    for key in ("funding_conflicts", "license"):
        metadata = _shape(item[key], {"state", "detail"})
        require_enum(metadata["state"], {"SOURCE_REPORTED", "NOT_EXTRACTED", "SYNTHETIC"}, "metadata state")
        if metadata["detail"] is not None:
            _text(metadata["detail"])
        if metadata["state"] != "NOT_EXTRACTED" and metadata["detail"] is None:
            raise CausalFrontierError("reported metadata requires a detail")
    attestation = _shape(item["temporal_attestation"], {"state", "artifact", "claimed_available_at", "locator"})
    require_enum(attestation["state"], {"ABSENT", "UNVERIFIED_CLAIM"}, "temporal attestation state")
    if attestation["state"] == "ABSENT":
        if any(attestation[key] is not None for key in ("artifact", "claimed_available_at", "locator")):
            raise CausalFrontierError("absent attestation must not contain invented evidence")
    else:
        _binding(attestation["artifact"], bindings)
        require_utc_timestamp(attestation["claimed_available_at"], "claimed availability")
        _url(attestation["locator"])
    return item


def preflight_receipts(root: Path, expected_set_sha256: str) -> dict:
    """Bind a receipt set to a caller's external checkpoint; never admit/score it.

    No network, execution of source content, file writes, world updates, or ledger
    appends occur here. The caller must preserve the expected digest independently.
    """
    require_sha256(expected_set_sha256, "external receipt-set checkpoint")
    try:
        with ExitStack() as stack:
            descriptor = _root_descriptor(stack, root)
            raw_set = _snapshot(descriptor, MANIFEST)
            if sha256_bytes(raw_set) != expected_set_sha256:
                raise CausalFrontierError("external receipt-set checkpoint mismatch")
            _screen(raw_set)
            try:
                document = read_json_bytes(raw_set)
            except CausalFrontierError:
                raise CausalFrontierError("receipt set must use strict JSON") from None
            _screen(canonical_bytes(document))  # Also screen decoded JSON escape sequences.
            _shape(
                document,
                {
                    "schema_version",
                    "id",
                    "fixed_parameter",
                    "boundary",
                    "frozen_at",
                    "evidence_cutoff",
                    "selection_origin",
                    "receipts",
                },
            )
            if document["schema_version"] != SET_SCHEMA or document["fixed_parameter"] != FIXED_PARAMETER:
                raise CausalFrontierError("receipt-set schema or fixed parameter differs")
            require_id(document["id"], "receipt-set id")
            if canonical_bytes(document["boundary"]) != BOUNDARY_CANONICAL:
                raise CausalFrontierError("receipt boundary is immutable with exact value types")
            frozen_at = require_utc_timestamp(document["frozen_at"], "receipt-set freeze")
            cutoff = require_utc_timestamp(document["evidence_cutoff"], "receipt-set cutoff")
            if cutoff > frozen_at:
                raise CausalFrontierError("receipt cutoff follows freeze")
            origin = require_enum(
                document["selection_origin"], {"KNOWN_HINDSIGHT", "UNASSESSED", "SYNTHETIC_FIXTURE"}, "selection origin"
            )
            receipts = document["receipts"]
            if not isinstance(receipts, list) or not 1 <= len(receipts) <= 32:
                raise CausalFrontierError("receipt-set size is invalid")
            bindings: dict[str, str] = {}
            for receipt in receipts:
                _validate_receipt(receipt, frozen_at, bindings)
            if len({item["id"] for item in receipts}) != len(receipts):
                raise CausalFrontierError("duplicate receipt id")
            expected_files = {MANIFEST, *bindings}
            if _inventory(descriptor) != expected_files:
                raise CausalFrontierError(
                    "receipt file inventory differs",
                    reason_code="INVENTORY_MISMATCH",
                    operation="receipts.preflight_receipts",
                )
            total_size = len(raw_set)
            for relative, digest in sorted(bindings.items()):
                raw = _snapshot(descriptor, relative)
                total_size += len(raw)
                if total_size > MAX_TOTAL_BYTES:
                    raise CausalFrontierError("receipt total byte limit exceeded")
                if sha256_bytes(raw) != digest:
                    raise CausalFrontierError("receipt payload digest mismatch")
                _screen(raw)
            if _inventory(descriptor) != expected_files:
                raise CausalFrontierError(
                    "receipt inventory changed during preflight",
                    reason_code="INPUT_CHANGED",
                    operation="receipts.preflight_receipts",
                )
    except OSError as exc:
        raise io_error(
            exc, "receipt filesystem cannot be read safely", operation="receipts.preflight_receipts"
        ) from None
    results = []
    for item in sorted(receipts, key=lambda value: value["id"]):
        reasons = [
            "INDEPENDENT_TEMPORAL_ATTESTATION_MISSING"
            if item["temporal_attestation"]["state"] == "ABSENT"
            else "TEMPORAL_ATTESTATION_VERIFIER_NOT_IMPLEMENTED"
        ]
        if item["retrieval_state"] in {"FAILED", "TIMEOUT"}:
            outcome = "FAILURE"
            reasons.append("ACQUISITION_FAILURE_NOT_EVIDENCE_ABSENCE")
        else:
            outcome = "NO_CALL"
            if item["retrieval_state"] != "COMPLETE" or item["coverage"]["state"] != "COMPLETE":
                reasons.append("ACQUISITION_OR_COVERAGE_INCOMPLETE")
        if item["semantic_state"] != "USABLE_FOR_DECLARED_SCOPE":
            reasons.append("NOT_PUBLIC_DECISION_EVIDENCE")
        if item["request"]["executed_query"] is None or item["request"]["query_rewrites"] is None:
            reasons.append("EXECUTED_QUERY_OR_REWRITES_UNREPORTED")
        results.append(
            {
                "receipt_id": item["id"],
                "outcome_class": outcome,
                "reason_codes": sorted(reasons),
                "historical_eligible": False,
                "temporal_state": "DECLARED_TEMPORAL_METADATA_UNATTESTED",
                "submitted_arguments_sha256": sha256_bytes(canonical_bytes(item["request"]["submitted_arguments"])),
                "raw_response_sha256": item["raw_response"]["sha256"],
            }
        )
    return {
        "schema_version": "causalfrontier.receipt-preflight.v1",
        "status": "STRUCTURALLY_BOUND_NOT_HISTORICALLY_ADMISSIBLE",
        "implementation_status": "LOCAL_UNRELEASED_RECEIPT_PREFLIGHT",
        "base_compiler_version": COMPILER_VERSION,
        "receipt_set_sha256": expected_set_sha256,
        "canonical_receipt_set_sha256": sha256_bytes(canonical_bytes(document)),
        "fixed_parameter": FIXED_PARAMETER,
        "boundary": fixed_boundary(),
        "selection_origin": origin,
        "historical_scoring": "DISABLED",
        "historically_eligible_receipts_n": 0,
        "privacy_status": "PATTERN_SCREEN_ONLY_NOT_PRIVACY_CERTIFICATION",
        "control_trio_status": "NOT_EVALUATED_NO_SCORING_PATH",
        "files_sha256": {MANIFEST: expected_set_sha256, **dict(sorted(bindings.items()))},
        "receipt_results": results,
    }
