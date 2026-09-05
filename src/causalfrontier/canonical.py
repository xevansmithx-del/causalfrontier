"""Canonical JSON, digests, path containment, and fail-closed helpers."""

from __future__ import annotations

import errno as errno_codes
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

MAX_JSON_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
FORBIDDEN_TEXT = (
    re.compile(r"(?:^|[\s\"'(=])/(?:Users|home|Volumes|private|tmp|root)/"),
    re.compile(r"\bfile://", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:ghp_|github_pat_|sk-proj-|xox[baprs]-)[A-Za-z0-9_-]{8,}"),
)


class CausalFrontierError(ValueError):
    """A fail-closed error with optional, path-free diagnostic metadata.

    The human-readable message and ValueError compatibility are preserved.
    Diagnostics describe an observed software failure, never scientific truth.
    """

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "VALIDATION_REJECTED",
        operation: str | None = None,
        errno: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.operation = operation
        self.errno = errno

    def diagnostic(self) -> dict[str, str | int | None]:
        """Exclude message, exception text, filenames, and subprocess output."""
        return {"reason_code": self.reason_code, "operation": self.operation, "errno": self.errno}


def io_error(exc: OSError, message: str, *, operation: str) -> CausalFrontierError:
    """Classify numeric OS evidence without guessing from message strings.

    A safe-path rejection does not establish malicious input. Missing input
    and access denial do not establish absence of scientific evidence.
    """
    if exc.errno in {errno_codes.EACCES, errno_codes.EPERM}:
        reason_code = "ENVIRONMENT_DENIED"
    elif exc.errno == errno_codes.ENOENT:
        reason_code = "INPUT_MISSING"
    elif exc.errno in {errno_codes.ELOOP, errno_codes.ENOTDIR}:
        reason_code = "SAFE_PATH_REJECTED"
    else:
        reason_code = "IO_FAILURE"
    return CausalFrontierError(message, reason_code=reason_code, operation=operation, errno=exc.errno)


def canonical_bytes(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes; NaN and infinities are forbidden."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CausalFrontierError("value is not canonical JSON: %s" % exc) from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise io_error(exc, "cannot hash %s: %s" % (path.name, exc), operation="hash_file") from exc
    return digest.hexdigest()


def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CausalFrontierError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def _bounded_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 64:
        raise CausalFrontierError("JSON integer exceeds lexical limit")
    return int(value)


def _reject_float(value: str) -> Any:
    raise CausalFrontierError("floating-point JSON is forbidden: %s" % value)


def _reject_constant(value: str) -> Any:
    raise CausalFrontierError("non-finite JSON constant is forbidden: %s" % value)


def read_json_bytes(raw: bytes, label: str = "JSON") -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise CausalFrontierError("%s exceeds %d bytes" % (label, MAX_JSON_BYTES))
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_int=_bounded_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CausalFrontierError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CausalFrontierError("cannot parse %s: %s" % (label, exc)) from exc


def read_json(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > MAX_JSON_BYTES:
                raise CausalFrontierError("%s exceeds %d bytes" % (path.name, MAX_JSON_BYTES))
            raw = handle.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise io_error(exc, "cannot read %s: %s" % (path.name, exc), operation="read_json") from exc
    return read_json_bytes(raw, path.name)


def write_canonical(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def require_exact_keys(value: Any, keys: set, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise CausalFrontierError("%s must be an object" % field)
    missing = sorted(keys - set(value))
    unknown = sorted(set(value) - keys)
    if missing or unknown:
        raise CausalFrontierError("%s schema mismatch; missing=%s unknown=%s" % (field, missing, unknown))
    return value


def require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise CausalFrontierError("%s must be a stable identifier" % field)
    return value


def require_text(value: Any, field: str, limit: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise CausalFrontierError("%s must be nonempty text <= %d characters" % (field, limit))
    if "\n" in value or "\r" in value:
        raise CausalFrontierError("%s must be a single line" % field)
    reject_private_material(value, field)
    return value


def reject_private_material(value: str, field: str) -> None:
    if any(pattern.search(value) for pattern in FORBIDDEN_TEXT):
        raise CausalFrontierError("%s contains private path or credential material" % field)


def require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CausalFrontierError("%s must be a lowercase SHA-256 digest" % field)
    return value


def require_enum(value: Any, allowed: set, field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CausalFrontierError("%s has an unregistered value" % field)
    return value


def require_utc_timestamp(value: Any, field: str) -> str:
    """Require a real, whole-second RFC 3339 UTC timestamp."""

    if not isinstance(value, str) or RFC3339_UTC_RE.fullmatch(value) is None:
        raise CausalFrontierError("%s must be whole-second RFC3339 UTC" % field)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CausalFrontierError("%s must be whole-second RFC3339 UTC" % field) from exc
    return value


def require_unique_ids(value: Any, field: str) -> List[Dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CausalFrontierError("%s must be a list of objects" % field)
    seen = set()
    for index, item in enumerate(value):
        identity = require_id(item.get("id"), "%s[%d].id" % (field, index))
        if identity in seen:
            raise CausalFrontierError("duplicate %s id: %s" % (field, identity))
        seen.add(identity)
    return value


def require_id_list(value: Any, field: str, allow_empty: bool = True) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CausalFrontierError("%s must be a list of identifiers" % field)
    normalized = [require_id(item, field) for item in value]
    if not allow_empty and not normalized:
        raise CausalFrontierError("%s must not be empty" % field)
    if len(normalized) != len(set(normalized)):
        raise CausalFrontierError("%s contains duplicate identifiers" % field)
    return normalized


def contained_file(root: Path, relative_value: Any, field: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value.strip():
        raise CausalFrontierError("%s must be a nonempty relative path" % field)
    relative = Path(relative_value)
    if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
        raise CausalFrontierError(
            "%s must stay inside the case root" % field,
            reason_code="SAFE_PATH_REJECTED",
            operation="canonical.contained_file",
        )
    if root.is_symlink():
        raise CausalFrontierError(
            "case root must not be a symlink",
            reason_code="SAFE_PATH_REJECTED",
            operation="canonical.contained_file",
        )
    resolved_root = root.resolve(strict=True)
    cursor = resolved_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise CausalFrontierError(
                "%s traverses a symlink" % field,
                reason_code="SAFE_PATH_REJECTED",
                operation="canonical.contained_file",
            )
    try:
        target = (resolved_root / relative).resolve(strict=True)
        target.relative_to(resolved_root)
    except OSError as exc:
        raise io_error(exc, "%s does not resolve inside the case root" % field, operation="contained_file") from exc
    except ValueError as exc:
        raise CausalFrontierError("%s does not resolve inside the case root" % field) from exc
    if not target.is_file() or target.is_symlink() or target.stat().st_nlink != 1:
        raise CausalFrontierError(
            "%s must resolve to a single-link regular file" % field,
            reason_code="SAFE_FILE_REJECTED",
            operation="canonical.contained_file",
        )
    return target
