"""The Pages site is checked before it is published, and the shipped site passes."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_site  # noqa: E402

GOOD = """<!doctype html><html lang="en"><head><title>Thing — REX Technologies</title>
<link rel="stylesheet" href="styles.css"></head>
<body><a href="#top">top</a><main id="top"><img src="mark.svg" alt="">
<a href="https://github.com/tochi-mba/Thing">source</a></main>
<script src="app.js"></script></body></html>
"""


def _site(tmp_path: Path, html: str = GOOD, *, nojekyll: bool = True) -> Path:
    site = tmp_path / "site"
    site.mkdir()
    (site / "index.html").write_text(html, encoding="utf-8")
    for name in ("styles.css", "app.js", "mark.svg"):
        (site / name).write_text("", encoding="utf-8")
    if nojekyll:
        (site / ".nojekyll").write_text("", encoding="utf-8")
    return site


def test_the_shipped_site_passes() -> None:
    assert check_site.check() == []


def test_a_sound_site_has_no_problems(tmp_path: Path) -> None:
    assert check_site.check(_site(tmp_path), "Thing") == []


def test_a_missing_index_is_the_only_problem_worth_naming(tmp_path: Path) -> None:
    [problem] = check_site.check(tmp_path, "Thing")
    assert problem.endswith("is missing; there is no site to publish.")


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (("<title>Thing", "<title>Other"), "the title does not name Thing."),
        (("REX Technologies", "Somebody"), "the page does not name REX Technologies."),
        (
            ('href="styles.css"', 'href="missing.css"'),
            "asset 'missing.css' is referenced but missing.",
        ),
        (
            ('href="#top"', 'href="#nowhere"'),
            "anchor '#nowhere' points at an id that does not exist.",
        ),
        (
            ('<img src="mark.svg" alt="">', '<img src="mark.svg">'),
            "image 'mark.svg' has no alt text.",
        ),
        (("source</a>", "source</a> coming soon"), "draft text left in the page: 'coming soon'."),
        (
            ("github.com/tochi-mba/Thing", "github.com/somebody-else/Thing"),
            "the page links to GitHub owners other than tochi-mba: ['somebody-else'].",
        ),
    ],
)
def test_each_kind_of_problem_is_named(tmp_path: Path, change: tuple[str, str], said: str) -> None:
    old, new = change
    assert old in GOOD
    problems = check_site.check(_site(tmp_path, GOOD.replace(old, new)), "Thing")
    assert problems == [f"index.html: {said}"]


def test_a_site_without_nojekyll_is_named(tmp_path: Path) -> None:
    [problem] = check_site.check(_site(tmp_path, nojekyll=False), "Thing")
    assert problem.startswith("site/.nojekyll is missing")


def test_every_page_is_checked_not_only_the_index(tmp_path: Path) -> None:
    site = _site(tmp_path)
    (site / "404.html").write_text(GOOD.replace("<title>Thing", "<title>Lost"), encoding="utf-8")
    assert check_site.check(site, "Thing") == ["404.html: the title does not name Thing."]


def test_remote_assets_and_empty_sources_are_not_checked_for_existence(tmp_path: Path) -> None:
    html = GOOD.replace(
        '<link rel="stylesheet" href="styles.css">',
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">'
        '<link rel="preconnect" href="//fonts.gstatic.com"><img src="" alt="">',
    )
    assert check_site.check(_site(tmp_path, html), "Thing") == []


def test_main_reports_and_exits_as_a_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert check_site.main([str(_site(tmp_path)), "Thing"]) == 0
    assert "site checks passed" in capsys.readouterr().out
    assert check_site.main([str(tmp_path), "Thing"]) == 1
    out = capsys.readouterr().out
    assert "1 problem(s) with the site:" in out
    assert "there is no site to publish" in out


def test_main_defaults_to_the_shipped_site() -> None:
    assert check_site.main([]) == 0
