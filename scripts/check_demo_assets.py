#!/usr/bin/env python3
"""Read-only checks for the pj2.0 demo assets.

This script intentionally avoids importing Streamlit, pandas, torch,
transformers, or any project module. It reads only filesystem metadata and
JSON files needed to confirm the demo assets are present.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


MODEL_WEIGHT_SUFFIXES = {
    ".bin",
    ".gguf",
    ".pt",
    ".pth",
    ".safetensors",
}


def relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def file_size(path: Path) -> str:
    size = path.stat().st_size
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


class Reporter:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def ok(self, message: str) -> None:
        print(f"OK    {message}")

    def info(self, message: str) -> None:
        print(f"INFO  {message}")

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        print(f"WARN  {message}")

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"FAIL  {message}")


def check_file(
    reporter: Reporter,
    root: Path,
    path: Path,
    label: str,
    *,
    required: bool = True,
    min_bytes: int = 1,
) -> bool:
    display = relative(root, path)
    if not path.exists():
        message = f"{label} missing: {display}"
        if required:
            reporter.fail(message)
        else:
            reporter.warn(message)
        return False

    if not path.is_file():
        reporter.fail(f"{label} is not a file: {display}")
        return False

    size = path.stat().st_size
    if size < min_bytes:
        reporter.fail(f"{label} is empty or too small: {display}")
        return False

    reporter.ok(f"{label}: {display} ({file_size(path)})")
    return True


def check_json_file(
    reporter: Reporter,
    root: Path,
    path: Path,
    label: str,
    *,
    required: bool = True,
) -> Any | None:
    if not check_file(reporter, root, path, label, required=required):
        return None

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - report any JSON/read issue.
        reporter.fail(f"{label} is not valid JSON: {relative(root, path)} ({exc})")
        return None

    if isinstance(data, list):
        reporter.ok(f"{label} JSON parsed: list with {len(data):,} items")
        if required and not data:
            reporter.fail(f"{label} JSON list is empty: {relative(root, path)}")
    elif isinstance(data, dict):
        reporter.ok(f"{label} JSON parsed: object with {len(data):,} keys")
    else:
        reporter.warn(f"{label} JSON parsed as {type(data).__name__}")

    return data


def check_entry(reporter: Reporter, root: Path) -> None:
    entry = root / "web_demo" / "excel_final.py"
    if not check_file(reporter, root, entry, "recommended Streamlit entry"):
        return

    try:
        text = entry.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 - keep the check read-only.
        reporter.warn(f"could not read entry for path hint check: {exc}")
        return

    if "../data/processed/excel_attack_data.json" in text:
        reporter.info(
            "entry uses cwd-relative ../data/processed/excel_attack_data.json; "
            "run Streamlit from web_demo"
        )


def check_excel_assets(reporter: Reporter, root: Path) -> None:
    data_dir = root / "data"
    check_file(reporter, root, data_dir / "攻击日志V2.xlsx", "attack Excel source")

    risk_files = sorted(data_dir.glob("风险信息*.xlsx"))
    if not risk_files:
        reporter.fail("risk Excel source missing: data/风险信息*.xlsx")
        return

    for risk_file in risk_files:
        check_file(reporter, root, risk_file, "risk Excel source")


def check_json_assets(reporter: Reporter, root: Path) -> None:
    processed_dir = root / "data" / "processed"
    main_data = check_json_file(
        reporter,
        root,
        processed_dir / "excel_attack_data.json",
        "processed attack JSON",
    )
    check_json_file(
        reporter,
        root,
        processed_dir / "excel_data_stats.json",
        "processed stats JSON",
        required=False,
    )
    check_json_file(
        reporter,
        root,
        processed_dir / "excel_attack_data_sample.json",
        "processed sample JSON",
        required=False,
    )

    if isinstance(main_data, list):
        sources = {
            str(item.get("data_source", "")).strip()
            for item in main_data[:100]
            if isinstance(item, dict)
        }
        if sources:
            reporter.info(
                "sample data_source values: "
                + ", ".join(sorted(source for source in sources if source)[:5])
            )


def load_config(reporter: Reporter, root: Path) -> dict[str, Any] | None:
    config_path = root / "config" / "model_config.json"
    data = check_json_file(reporter, root, config_path, "model config JSON")
    if data is None:
        return None
    if not isinstance(data, dict):
        reporter.fail("model config JSON must be an object")
        return None
    return data


def configured_model_path(root: Path, config: dict[str, Any] | None) -> Path:
    configured = "./models/Qwen2-7B"
    if config:
        model_config = config.get("model_config")
        if isinstance(model_config, dict):
            configured = str(model_config.get("model_path", configured))

    model_path = Path(configured)
    if not model_path.is_absolute():
        model_path = root / model_path
    return model_path.resolve()


def check_model_dir(
    reporter: Reporter,
    root: Path,
    config: dict[str, Any] | None,
) -> None:
    model_dir = configured_model_path(root, config)
    fallback_mode = config.get("fallback_mode") if config else None
    reporter.info(f"fallback_mode: {fallback_mode!r}")
    reporter.info(f"configured model path: {relative(root, model_dir)}")

    if not model_dir.exists():
        reporter.warn(
            "model directory is missing; demo mode can still run from processed JSON"
        )
        if fallback_mode is not True:
            reporter.warn("fallback_mode is not true while model directory is missing")
        return

    if not model_dir.is_dir():
        reporter.fail(f"configured model path is not a directory: {relative(root, model_dir)}")
        return

    files = [path for path in model_dir.rglob("*") if path.is_file()]
    if not files:
        reporter.warn(
            "model directory is empty; real Qwen2-7B inference is not available"
        )
        if fallback_mode is not True:
            reporter.warn("fallback_mode is not true while model directory is empty")
        return

    weights = [
        path
        for path in files
        if path.suffix.lower() in MODEL_WEIGHT_SUFFIXES
    ]
    reporter.ok(f"model directory contains {len(files):,} files")
    if weights:
        reporter.ok(f"model weight-like files found: {len(weights):,}")
    else:
        reporter.warn("model directory has files but no known weight file suffix")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check pj2.0 demo assets without importing heavy dependencies."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Project root. Defaults to the parent directory of this script.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    reporter = Reporter()

    print(f"Project root: {root}")
    print("Mode: read-only asset check; no model loading; no data generation")
    print()

    if not root.exists():
        reporter.fail(f"project root does not exist: {root}")
    elif not root.is_dir():
        reporter.fail(f"project root is not a directory: {root}")

    check_entry(reporter, root)
    check_excel_assets(reporter, root)
    check_json_assets(reporter, root)
    config = load_config(reporter, root)
    check_model_dir(reporter, root, config)

    print()
    print(f"Summary: {len(reporter.failures)} failure(s), {len(reporter.warnings)} warning(s)")

    if reporter.failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
