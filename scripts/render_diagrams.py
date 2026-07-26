#!/usr/bin/env python3
"""Render Graphviz diagram sources and optionally check that they still render.

Graphviz layout output is not byte-stable across Graphviz versions or
platforms, so committed SVG/PNG assets can never be reliably compared
byte-for-byte against a freshly rendered copy in CI without pinning the exact
toolchain used to produce them. Instead, ``--check`` verifies that every DOT
source still compiles cleanly to both formats, which catches syntax errors
and renderer breakage. Regenerate the committed assets locally with
``python scripts/render_diagrams.py`` whenever a ``docs/diagrams/*.dot``
source changes and review the resulting image in the pull request.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "docs" / "diagrams"
ASSET_DIR = ROOT / "docs" / "assets"
DIAGRAMS = ("architecture", "response-flow", "trust-boundaries")


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
        help="Verify every DOT source still renders successfully, without overwriting assets.",
    )
    args = parser.parse_args()

    if shutil.which("dot") is None:
        raise SystemExit("Graphviz 'dot' is required to render diagrams.")

    failures: list[str] = []

    if args.check:
        with tempfile.TemporaryDirectory(prefix="bait-diagrams-") as temp_dir:
            temp = Path(temp_dir)
            for name in DIAGRAMS:
                source = SOURCE_DIR / f"{name}.dot"
                for output_format in ("svg", "png"):
                    try:
                        render(source, temp / f"{name}.{output_format}", output_format)
                    except subprocess.CalledProcessError as error:
                        failures.append(f"{name}.{output_format}: {error.stderr.strip()}")
                asset_svg = ASSET_DIR / f"{name}.svg"
                asset_png = ASSET_DIR / f"{name}.png"
                if not asset_svg.exists() or not asset_png.exists():
                    failures.append(f"{name}: missing committed asset in {ASSET_DIR}")
    else:
        ASSET_DIR.mkdir(parents=True, exist_ok=True)
        for name in DIAGRAMS:
            source = SOURCE_DIR / f"{name}.dot"
            render(source, ASSET_DIR / f"{name}.svg", "svg")
            render(source, ASSET_DIR / f"{name}.png", "png")

    if failures:
        print("Diagram rendering check failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    action = "verified" if args.check else "rendered"
    print(f"{len(DIAGRAMS)} diagrams {action} successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
