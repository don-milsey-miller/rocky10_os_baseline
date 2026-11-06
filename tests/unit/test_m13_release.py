"""Acceptance gates reject missing controls and unexpected target findings."""

import copy
import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

from hardener import __version__
from hardener.reporting import source_digest
from hardener.validation import load_catalog, load_profile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/integration"))
spec = importlib.util.spec_from_file_location("m13_release", ROOT / "tests/integration/m13.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_coverage_has_exactly_one_disposition_per_catalog_control():
    catalog = load_catalog()
    text = (ROOT / "docs/control-coverage.md").read_text()
    rows = re.findall(
        r"^\| ([a-z][a-z0-9.-]+) \| [^|]+ \| ([^|]+) \| ([^|]+) \|$", text, re.MULTILINE
    )
    assert len(rows) == len(catalog) == 102
    assert {row[0] for row in rows} == set(catalog)
    for cid, status, evidence in rows:
        assessment = "apply" not in catalog[cid].get(
            "supported_modes", ["audit", "apply", "verify"]
        )
        assert status.strip().startswith("Assessment" if assessment else "Implemented")
        link = re.search(r"\]\(([^)#]+)", evidence)
        assert link and (ROOT / "docs" / link.group(1)).is_file()
        assert catalog[cid]["implemented"] is True


def test_combined_profile_covers_catalog_and_excludes_only_assessments():
    catalog = load_catalog()
    path = ROOT / "profiles/examples/server-combined-lab.yaml"
    load_profile(path, catalog)
    profile = yaml.safe_load(path.read_text())
    original = copy.deepcopy(profile)
    applied = release.remediation_profile(profile, catalog)
    assert profile == original
    assert len(applied["controls"]) == len(catalog) == 102
    assert {c["id"] for c in applied["controls"]} == set(catalog)
    assert len([c for c in applied["controls"] if c["enabled"]]) == 90
    for before, after in zip(profile["controls"], applied["controls"], strict=True):
        assert before.get("parameters") == after.get("parameters")
        if not after["enabled"]:
            assert after["reason"]
            assert "apply" not in catalog[after["id"]]["supported_modes"]
    assert release.FINDINGS <= {c["id"] for c in applied["controls"] if not c["enabled"]}


def sample_report():
    return {
        "controls": [
            {"id": "repair", "status": "pass", "changed": False},
            {"id": "assessment", "status": "fail", "changed": False},
        ],
        "changed_tasks": 0,
        "engine_sha256": source_digest(),
        "engine_version": __version__,
    }


def test_report_gate_accepts_only_the_named_assessment_findings():
    release.assert_report(sample_report(), {"repair": {}, "assessment": {}}, {"assessment"})


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "error",
        "skipped",
        "unexpected-fail",
        "hidden-change",
        "changed-total",
        "engine",
        "version",
        "finding-disappeared",
    ],
)
def test_report_gate_fails_closed(fault):
    report = sample_report()
    if fault == "missing":
        report["controls"].pop()
    elif fault == "duplicate":
        report["controls"][1] = report["controls"][0].copy()
    elif fault in {"error", "skipped"}:
        report["controls"][1]["status"] = fault
    elif fault == "unexpected-fail":
        report["controls"][0]["status"] = "fail"
    elif fault == "hidden-change":
        report["controls"][0]["changed"] = True
    elif fault == "changed-total":
        report["changed_tasks"] = 1
    elif fault == "engine":
        report["engine_sha256"] = "0" * 64
    elif fault == "version":
        report["engine_version"] = "old"
    elif fault == "finding-disappeared":
        report["controls"][1]["status"] = "pass"
    with pytest.raises(AssertionError):
        release.assert_report(report, {"repair": {}, "assessment": {}}, {"assessment"})
