"""Validate the README, retained architecture diagram, and source references."""

import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "docs" / "brand"
DIAGRAM = "system-boundaries.svg"


def verify() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    flow = (ROOT / "docs" / "WORKFLOWS.md").read_text(encoding="utf-8")
    identity = (ROOT / "docs" / "BRAND.md").read_text(encoding="utf-8")
    license_notice = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert "SERRATE" in readme
    assert "MON" in identity and "MON_*" in identity
    assert "docs/repository-maintenance" in readme
    assert "not a production-certified" in readme.lower()
    assert "https://github.com/Saitanveesh" in readme
    assert "https://www.linkedin.com/in/sai-tanveesh-028881215/" in readme
    assert "Saitanveesh/1" not in readme
    assert "<img" not in readme and "![" not in readme
    assert "All rights reserved" in license_notice

    path = BRAND / DIAGRAM
    assert path.exists(), f"Missing architecture diagram: {path}"
    root = ET.parse(path).getroot()
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert root.attrib.get("viewBox")
    assert root.find("{http://www.w3.org/2000/svg}title") is not None
    assert root.find("{http://www.w3.org/2000/svg}desc") is not None
    assert f"brand/{DIAGRAM}" in flow

    assert flow.count("```mermaid") >= 3
    assert "ROLLBACK" in readme.upper()
    assert "Site Controller" in readme
    print("PASS: documentation, authorship, and architecture references")


if __name__ == "__main__":
    verify()
