"""On-demand file metadata and optional YARA scanning."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


class FileScanner:
    def hash_file(self, path: str | Path) -> str:
        target = Path(path)
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def inspect(self, path: str | Path, yara_rules: str | Path | None = None) -> dict[str, Any]:
        target = Path(path).expanduser().resolve(strict=True)
        result: dict[str, Any] = {
            "path": str(target),
            "size": target.stat().st_size,
            "sha256": self.hash_file(target),
            "yara_matches": [],
        }
        if yara_rules:
            try:
                import yara  # type: ignore
            except ImportError as exc:
                raise RuntimeError("Install bait-edr[yara] to enable YARA scanning") from exc
            compiled = yara.compile(filepath=str(yara_rules))
            result["yara_matches"] = [match.rule for match in compiled.match(str(target))]
        return result
