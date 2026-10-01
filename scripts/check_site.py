#!/usr/bin/env python3
"""Check the GitHub Pages site before it is published.

A static site has no compiler, so nothing otherwise catches a broken anchor, a missing
asset, an image a screen reader would read out by file name, or draft text that escaped.
This is that gate; the Pages workflow runs it on every push, and so does the test suite.

Standard library only, on purpose: the workflow should not install anything to verify a
page that has no build step.

Usage::

    python scripts/check_site.py            # the site in this repository
    python scripts/check_site.py path/to/site Keyring   # any site, naming its product
"""

from __future__ import annotations

import re
import sys
from html.parser import HTMLParser
from pathlib import Path

SITE = Path(__file__).resolve().parents[1] / "site"
PRODUCT = "Keyring"
OWNER = "tochi-mba"
"""Every GitHub link on a family site points at this owner; anything else is a stale copy."""

FORBIDDEN_PATTERNS = (
    r"\bTODO\b",
    r"\bFIXME\b",
    r"\bTBD\b",
    r"\bLorem ipsum\b",
    r"\bXXX\b",
    r"\bcoming soon\b",
)
"""Text that means a draft escaped."""

REMOTE = ("http://", "https://", "data:", "//", "mailto:")


class PageParser(HTMLParser):
    """Collects the ids, links and asset references a page depends on."""

    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.assets: list[str] = []
        self.title = ""
        self.images_without_alt: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: (value or "") for key, value in attrs}
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "title":
            self._in_title = True
        if tag == "a" and "href" in values:
            self.hrefs.append(values["href"])
        if tag == "img":
            self.assets.append(values.get("src", ""))
            # An explicitly empty alt marks an image decorative; a missing one does not.
            if "alt" not in values:
                self.images_without_alt.append(values.get("src") or "(no src)")
        if tag == "link" and "href" in values:
            self.assets.append(values["href"])
        if tag == "script" and values.get("src"):
            self.assets.append(values["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def check(site: Path = SITE, product: str = PRODUCT) -> list[str]:
    """Every problem with the site. Empty means it is publishable."""
    problems: list[str] = []
    pages = sorted(site.glob("*.html"))
    if not (site / "index.html").exists():
        return [f"{site / 'index.html'} is missing; there is no site to publish."]
    if not (site / ".nojekyll").exists():
        problems.append(
            "site/.nojekyll is missing: without it Pages runs the site through Jekyll, "
            "which drops files beginning with an underscore."
        )
    for page in pages:
        problems.extend(f"{page.name}: {problem}" for problem in _check_page(page, product))
    return problems


def _check_page(page: Path, product: str) -> list[str]:
    problems: list[str] = []
    html = page.read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(html)
    if product not in parser.title:
        problems.append(f"the title does not name {product}.")
    if "REX Technologies" not in html:
        problems.append("the page does not name REX Technologies.")
    for asset in parser.assets:
        if not asset or asset.startswith(REMOTE):
            continue
        if not (page.parent / asset.split("?")[0]).exists():
            problems.append(f"asset '{asset}' is referenced but missing.")
    problems.extend(
        f"anchor '{href}' points at an id that does not exist."
        for href in parser.hrefs
        if href.startswith("#") and href[1:] and href[1:] not in parser.ids
    )
    problems.extend(f"image '{image}' has no alt text." for image in parser.images_without_alt)
    for pattern in FORBIDDEN_PATTERNS:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            problems.append(f"draft text left in the page: '{match.group(0)}'.")
    owners = {owner for owner in re.findall(r"https://github\.com/([^/\"'\s]+)/", html) if owner}
    if owners - {OWNER}:
        problems.append(f"the page links to GitHub owners other than {OWNER}: {sorted(owners)}.")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    site = Path(args[0]) if args else SITE
    product = args[1] if len(args) > 1 else PRODUCT
    problems = check(site, product)
    if problems:
        print(f"{len(problems)} problem(s) with the site:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("site checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
