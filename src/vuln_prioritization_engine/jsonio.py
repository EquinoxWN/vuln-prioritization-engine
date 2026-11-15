"""Bounded file reads and atomic file writes."""

from __future__ import annotations

import gzip
import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import InputError

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_GZIP_BYTES = 256 * 1024 * 1024


def read_bytes(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a regular file, refusing anything over the limit."""
    try:
        if not path.is_file():
            raise InputError(f"{path}: not a regular file")
        size = path.stat().st_size
        if size > limit:
            raise InputError(f"{path}: {size} bytes is over the {limit}-byte limit")
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        raise InputError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    if len(data) > limit:
        raise InputError(f"{path}: grew past the {limit}-byte limit while reading")
    if path.suffix == ".gz":
        return gunzip(data, str(path))
    return data


def gunzip(data: bytes, label: str, limit: int = MAX_GZIP_BYTES) -> bytes:
    """Decompress gzip data with a cap on the output size."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            out = gz.read(limit + 1)
    except (OSError, EOFError) as exc:
        raise InputError(f"{label}: not valid gzip ({exc})") from exc
    if len(out) > limit:
        raise InputError(f"{label}: decompresses past the {limit}-byte limit")
    return out


def parse_json(data: bytes, label: str) -> Any:
    """Decode UTF-8 JSON, turning every decoder failure into an InputError."""
    try:
        return json.loads(data.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise InputError(f"{label}: not UTF-8 ({exc.reason})") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{label}: invalid JSON at line {exc.lineno} ({exc.msg})") from exc
    except RecursionError as exc:
        raise InputError(f"{label}: JSON nested too deeply") from exc


def load_json(path: Path, limit: int = MAX_FILE_BYTES) -> Any:
    """Read and decode one JSON file."""
    return parse_json(read_bytes(path, limit), str(path))


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file in the same folder, fsync, then rename over the target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def dump_json(value: Any) -> bytes:
    """Stable, human-readable JSON bytes."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
