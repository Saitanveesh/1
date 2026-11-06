"""Fail-fast checks for public-facing brand images and workflow documents.

This uses only Python standard library; it does not touch MON runtime modules.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SVG_NAMES = (
    "serrate-hero.svg",
    "lifecycle.svg",
    "system-boundaries.svg",
    "response-safety.svg",
)
BRAND = ROOT / "docs" / "brand"


def verify() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flow = (ROOT / "docs" / "WORKFLOWS.md").read_text(encoding="utf-8")
    identity = (ROOT / "docs" / "BRAND.md").read_text(encoding="utf-8")

    assert "SERRATE" in readme
    assert "MON" in identity and "MON_*" in identity
    assert "docs/repository-maintenance" in readme
    assert "not a production-certified" in readme.lower()
    for name in SVG_NAMES:
        path = BRAND / name
        assert path.exists(), f"Missing image: {path}"
        root = ET.parse(path).getroot()
        assert root.tag == "{http://www.w3.org/2000/svg}svg"
        assert root.attrib.get("viewBox"), f"Missing viewBox: {path}"
        assert root.find("{http://www.w3.org/2000/svg}title") is not None
        assert root.find("{http://www.w3.org/2000/svg}desc") is not None
        assert f"docs/brand/{name}" in readme or f"brand/{name}" in flow
    assert flow.count("```mermaid") >= 3
    assert "ROLLBACK" in readme.upper()
    assert "SaaS" in readme and "Site Controller" in readme
    print("PASS: brand artwork, README references and workflow boundaries")


if __name__ == "__main__":
    verify()
