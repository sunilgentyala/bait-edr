#!/usr/bin/env python3
"""Render Graphviz diagram sources and optionally check committed assets."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "docs" / "diagrams"
ASSET_DIR = ROOT / "docs" / "assets"
DIAGRAMS = ("architecture", "response-flow", "trust-boundaries")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render(source: Path, output: Path, output_format: str) -> None:
    subprocess.run(
        ["dot", f"-T{output_format}", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when committed diagram assets do not match their DOT sources.",
    )
    args = parser.parse_args()

    if shutil.which("dot") is None:
        raise SystemExit("Graphviz 'dot' is required to render diagrams.")

    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    mismatches: list[str] = []

    if args.check:
        with tempfile.TemporaryDirectory(prefix="bait-diagrams-") as temp_dir:
            temp = Path(temp_dir)
            for name in DIAGRAMS:
                source = SOURCE_DIR / f"{name}.dot"
                for output_format in ("svg", "png"):
                    generated = temp / f"{name}.{output_format}"
                    committed = ASSET_DIR / generated.name
                    render(source, generated, output_format)
                    if not committed.exists() or digest(generated) != digest(committed):
                        mismatches.append(str(committed.relative_to(ROOT)))
    else:
        for name in DIAGRAMS:
            source = SOURCE_DIR / f"{name}.dot"
            render(source, ASSET_DIR / f"{name}.svg", "svg")
            render(source, ASSET_DIR / f"{name}.png", "png")

    if mismatches:
        print("Diagram assets are stale:")
        for mismatch in mismatches:
            print(f"  - {mismatch}")
        print("Run: python scripts/render_diagrams.py")
        return 1

    action = "verified" if args.check else "rendered"
    print(f"{len(DIAGRAMS)} diagrams {action} successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
