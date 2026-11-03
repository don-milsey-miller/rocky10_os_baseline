import json
from pathlib import Path

from hardener.reporting import STATUSES, exit_code, make_report, write_report
from hardener.validation import load_catalog, parse_yaml


def report(evidence, mode="apply"):
    profile = parse_yaml(
        (Path(__file__).resolve().parents[2] / "profiles/examples/server-minimal.yaml").read_bytes()
    )
    return make_report(mode, "test-vm", profile, "a" * 64, load_catalog(), evidence)


def test_partial_report_never_claims_success(tmp_path):
    evidence = {
        "preflight_passed": False,
        "errors": [{"task": "SSH reachability", "kind": "unreachable"}],
    }
    result = report(evidence)
    assert result["platform"] == "unverified"
    assert result["summary"]["error"] == 1
    assert result["summary"]["excluded"] == 4
    assert result["summary"]["pass"] == 0
    assert exit_code(evidence, result, 4) == 3
    write_report(result, tmp_path)
    assert json.loads((tmp_path / "report.json").read_text()) == result
    assert set(result["summary"]) == set(STATUSES)


def test_preflight_is_not_compliance():
    evidence = {"preflight_passed": True}
    result = report(evidence, "preflight")
    assert result["summary"]["skipped"] == 1
    assert result["summary"]["pass"] == 0
    assert exit_code(evidence, result, 0) == 0


def test_verification_failure_exit_code():
    evidence = {
        "preflight_passed": True,
        "records": {
            "files.passwd-permissions": {
                "id": "files.passwd-permissions",
                "status": "fail",
                "observed": "0:0:666:regular file:1",
                "expected": "0:0:644:regular file:1",
                "changed": True,
                "reason": None,
                "reboot_required": False,
            }
        },
    }
    result = report(evidence)
    assert exit_code(evidence, result, 0) == 5
    evidence["errors"] = [{"task": "control failed", "kind": "failed"}]
    assert exit_code(evidence, result, 0) == 4


def test_version_and_profile_identity():
    result = report({})
    assert result["engine_version"] == result["catalog_version"]
    assert len(result["engine_sha256"]) == 64
    assert result["profile_revision"] == 2
    assert result["profile_sha256"] == "a" * 64
    assert result["timestamp_utc"].endswith("Z")


def test_unavailable_execution_evidence_is_not_preflight_failure():
    evidence = {"errors": [{"task": "Ansible evidence unavailable", "kind": "execution"}]}
    result = report(evidence)
    assert exit_code(evidence, result, 4) == 4
    assert result["controls"][0]["changed"] is None
