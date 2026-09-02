"""Normalize a built source distribution to reproducible tar/gzip metadata."""

from __future__ import annotations

import argparse
import copy
import gzip
import io
import os
import tarfile
import tempfile
from contextlib import suppress
from pathlib import Path, PurePosixPath

MINIMUM_ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z


def _epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or not raw.isascii() or not raw.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be an explicit nonnegative integer")
    value = int(raw)
    if value < MINIMUM_ZIP_EPOCH:
        raise SystemExit("SOURCE_DATE_EPOCH must be at least 1980-01-01 for wheel compatibility")
    return value


def _safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise SystemExit("sdist contains an unsafe path")


def normalize(path: Path, epoch: int) -> None:
    if not path.name.endswith(".tar.gz") or not path.is_file():
        raise SystemExit("expected one existing .tar.gz source distribution")
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for item in source.getmembers():
            _safe_name(item.name)
            if not (item.isfile() or item.isdir()):
                raise SystemExit("sdist may contain only regular files and directories")
            payload = None
            if item.isfile():
                handle = source.extractfile(item)
                if handle is None:
                    raise SystemExit("sdist regular file could not be read")
                payload = handle.read()
                if len(payload) != item.size:
                    raise SystemExit("sdist regular file size changed while normalizing")
            members.append((item, payload))

    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as target:
        for original, payload in sorted(members, key=lambda pair: pair[0].name):
            item = copy.copy(original)
            item.mtime = epoch
            item.uid = 0
            item.gid = 0
            item.uname = ""
            item.gname = ""
            item.mode = 0o755 if item.isdir() or original.mode & 0o111 else 0o644
            item.pax_headers = {}
            target.addfile(item, None if payload is None else io.BytesIO(payload))

    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with (
            os.fdopen(descriptor, "wb") as raw_target,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw_target, mtime=epoch, compresslevel=9) as zipped,
        ):
            zipped.write(archive.getvalue())
        os.replace(temporary_name, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()
    normalize(args.sdist, _epoch())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
