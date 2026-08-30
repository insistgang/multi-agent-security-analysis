#!/usr/bin/env python3
"""Resolve user-supplied log paths under an allowlisted directory."""

from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
ALLOWED_SUFFIXES = {".xlsx", ".xls", ".csv", ".json"}


class UnsafePathError(ValueError):
    """Raised when a path is remote, escapes the allowlist, or has a bad suffix."""


def resolve_log_path(file_path: str, allowed_root: Optional[Path] = None) -> Path:
    """Return a canonical path that is a local file under `allowed_root`.

    Rejects empty values, URLs (including pandas http/https/s3 loaders),
    and any path that does not stay inside the data directory after resolve().
    """
    if not file_path or not str(file_path).strip():
        raise UnsafePathError("file_path is required")

    raw = str(file_path).strip()
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https", "ftp", "s3", "file"}:
        raise UnsafePathError("remote URLs are not allowed")
    if "://" in raw:
        raise UnsafePathError("remote URLs are not allowed")

    root = (allowed_root or DEFAULT_DATA_DIR).resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.expanduser().resolve()

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise UnsafePathError("file_path must be under the data/ directory") from exc

    if not resolved.is_file():
        raise UnsafePathError(f"file not found: {resolved}")

    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise UnsafePathError(f"unsupported file type: {resolved.suffix}")

    return resolved
