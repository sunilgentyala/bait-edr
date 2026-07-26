#!/usr/bin/env python3
"""Perform dependency-free structural checks for the static project website."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
HTML_FILES = (DOCS / "index.html", DOCS / "404.html")


class SiteParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[tuple[str, str]] = []
        self.ids: set[str] = set()
        self.has_lang = False
        self.has_main = False
        self.has_h1 = False
        self.has_viewport = False
        self.has_description = False
        self.image_alt_errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html" and values.get("lang"):
            self.has_lang = True
        if tag == "main":
            self.has_main = True
        if tag == "h1":
            self.has_h1 = True
        if tag == "meta" and values.get("name") == "viewport":
            self.has_viewport = True
        if tag == "meta" and values.get("name") == "description":
            self.has_description = bool(values.get("content"))
        if tag == "img" and "alt" not in values:
            self.image_alt_errors.append(values.get("src", "<unknown image>"))
        if element_id := values.get("id"):
            self.ids.add(element_id)
        for attribute in ("href", "src"):
            if reference := values.get(attribute):
                self.references.append((attribute, reference))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


# HTMLParser does not expose current parent tags, so title is checked directly.
def validate_html(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    parser = SiteParser()
    parser.feed(text)

    required = {
        "language declaration": parser.has_lang,
        "title": "<title>" in text and "</title>" in text,
        "viewport metadata": parser.has_viewport,
        "description metadata": parser.has_description,
        "main landmark": parser.has_main,
        "level-one heading": parser.has_h1,
    }
    for label, present in required.items():
        if not present:
            errors.append(f"{path.name}: missing {label}")

    for image in parser.image_alt_errors:
        errors.append(f"{path.name}: image lacks alt text: {image}")

    for attribute, reference in parser.references:
        parsed = urlsplit(reference)
        if parsed.scheme in {"http", "https", "mailto", "tel", "data"}:
            continue
        if reference.startswith("#"):
            target_id = reference[1:]
            if target_id and target_id not in parser.ids:
                errors.append(f"{path.name}: broken fragment {reference}")
            continue
        if parsed.path in {"", ".", "./", "/"}:
            continue
        local_path = (path.parent / parsed.path).resolve()
        if DOCS.resolve() not in local_path.parents and local_path != DOCS.resolve():
            errors.append(f"{path.name}: reference escapes docs directory: {reference}")
        elif not local_path.exists():
            errors.append(f"{path.name}: missing {attribute} target: {reference}")

    return errors


def main() -> int:
    errors: list[str] = []
    for html_file in HTML_FILES:
        if not html_file.exists():
            errors.append(f"Missing required page: {html_file.relative_to(ROOT)}")
            continue
        errors.extend(validate_html(html_file))

    for required_asset in (
        "assets/bait-logo.svg",
        "assets/favicon.svg",
        "assets/architecture.svg",
        "assets/response-flow.svg",
        "assets/trust-boundaries.svg",
        "styles.css",
        "app.js",
    ):
        if not (DOCS / required_asset).exists():
            errors.append(f"Missing required site asset: docs/{required_asset}")

    if errors:
        print("Site validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("GitHub Pages site validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
