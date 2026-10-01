"""Untrusted text is rendered as text only: no HTML-injection sinks in the console/landing
sources. (``support.js`` is the design-component runtime that clones its own trusted template
markup; it never receives red-team, invoice, transcript or tool-argument text.)"""

import re
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[2] / "Landing page and dashboard implementation"
SINKS = re.compile(r"dangerouslySetInnerHTML|\.innerHTML\b|insertAdjacentHTML|document\.write\(")


@pytest.mark.acceptance("S-RT")
def test_console_and_landing_have_no_html_injection_sinks() -> None:
    files = [UI / "Trishul-Console.dc.html", UI / "Trishul-Landing.dc.html"]
    assert all(f.is_file() for f in files)
    for f in files:
        hits = [
            (n, line.strip()[:80])
            for n, line in enumerate(f.read_text().splitlines(), 1)
            if SINKS.search(line)
        ]
        assert hits == [], f"{f.name}: {hits}"
