"""Combined release acceptance on the prepared, disposable M12 guest.

Run twice, restoring the accepted stopped-disk snapshot before each run.
Use the independently installed wheel interpreter and a working directory
outside the checkout. Browser tests must have created the unchanged export.
"""

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import yaml
from lab import GuestLab

import hardener
from hardener.reporting import source_digest
from hardener.validation import load_catalog

ROOT = Path(__file__).resolve().parents[2]
FINDINGS = {
    "accounts.root-path-integrity",
    "selinux.no-unconfined-services",
    "storage.disk-encryption",
    "boot.secure-boot",
}
FAULTS = {"files.passwd-permissions", "kernel.protected-hardlinks"}


def remediation_profile(profile, catalog):
    """Preserve every selection, excluding only assessment-only controls."""
    result = copy.deepcopy(profile)
    for item in result["controls"]:
        if "apply" not in catalog[item["id"]].get("supported_modes", ["audit", "apply", "verify"]):
            item["enabled"] = False
            item["reason"] = "Assessment is verified separately. No remediation is defined."
    return result


def assert_report(report, catalog, failures=(), excluded=(), changed=0):
    """Reject omissions, duplicates, unexpected statuses and hidden changes."""
    records = report["controls"]
    assert len(records) == len(catalog)
    assert {r["id"] for r in records} == set(catalog)
    failures, excluded = set(failures), set(excluded)
    assert not failures & excluded
    for row in records:
        expected = (
            "fail" if row["id"] in failures else "excluded" if row["id"] in excluded else "pass"
        )
        assert row["status"] == expected, (row["id"], row["status"], expected)
        if changed == 0:
            assert row["changed"] is False, row["id"]
    assert report["changed_tasks"] == changed
    assert report["engine_sha256"] == source_digest()
    assert report["engine_version"] == hardener.__version__


def main():
    lab = GuestLab(__doc__)
    catalog = load_catalog()
    assert len(catalog) == 102
    profile = yaml.safe_load((ROOT / "profiles/examples/server-combined-lab.yaml").read_text())
    apply = remediation_profile(profile, catalog)
    excluded = {c["id"] for c in apply["controls"] if not c["enabled"]}
    assert len(excluded) == 12
    browser = ROOT / "reports/m13/browser-combined.yaml"
    raw = browser.read_bytes()
    exported = yaml.safe_load(raw)
    assert exported == apply, "Browser export differs from the approved remediation profile"
    assert all(c["implemented"] for c in catalog.values())
    report = lab.execute("audit", "baseline-audit", profile, expected=5)
    assert_report(report, catalog, FINDINGS)
    # Deliberate faults are confined to two established, low-impact controls.
    before = lab.remote("sudo sha256sum /etc/passwd").split()[0]
    lab.remote("sudo chmod 0666 /etc/passwd && sudo sysctl -w fs.protected_hardlinks=0")
    report = lab.execute("audit", "fault-audit", profile, expected=5)
    assert_report(report, catalog, FINDINGS | FAULTS)
    partial = copy.deepcopy(apply)
    for item in partial["controls"]:
        if item["id"] in FAULTS:
            item["enabled"] = False
            item["reason"] = "Release selection-boundary fixture"
    report = lab.execute("apply", "excluded-faults", partial)
    assert_report(report, catalog, excluded=excluded | FAULTS)
    assert lab.remote("stat -c %a /etc/passwd").strip() == "666"
    assert lab.remote("sysctl -n fs.protected_hardlinks").strip() == "0"
    report = lab.execute("apply", "repair", apply)
    # Ansible counts may evolve. Require real repair evidence for exactly these IDs.
    assert report["changed_tasks"] > 0
    assert {r["id"] for r in report["controls"] if r["changed"]} == FAULTS
    assert_report(report, catalog, excluded=excluded, changed=report["changed_tasks"])
    assert lab.remote("sudo sha256sum /etc/passwd").split()[0] == before
    for mode, name, selected, failures, omissions in [
        ("verify", "all-controls", profile, FINDINGS, ()),
        ("apply", "repeat-remediations", apply, (), excluded),
    ]:
        report = lab.execute(mode, name, selected, expected=5 if failures else 0)
        assert_report(report, catalog, failures, omissions)
    # Execute the download itself, not a reserialized copy.
    for mode in ["apply", "verify"]:
        argv = [
            __import__("sys").executable,
            "-m",
            "hardener.cli",
            mode,
            "--profile",
            str(browser),
            "--inventory",
            str(lab.inventory),
            "--target",
            lab.args.target,
            "--output",
            str(lab.output / ("browser-" + mode)),
            "--recovery-evidence",
            lab.args.recovery_evidence,
        ]
        lab.commands.append({"argv": argv, "expected_exit": 0})
        log = lab.run(argv)
        (lab.output / ("browser-" + mode + ".log")).write_text(log)
        report = json.loads((lab.output / ("browser-" + mode) / "report.json").read_text())
        assert_report(report, catalog, excluded=excluded)
        assert browser.read_bytes() == raw
    lab.reboot()
    # The native kdump unit can rebuild its image during startup.
    lab.python("""import subprocess,time
for _ in range(90):
 result=subprocess.run(['systemctl','show','kdump.service','-p','ActiveState','--value'],capture_output=True,text=True,check=True)
 if result.stdout.strip() != 'activating': break
 time.sleep(1)
else: raise AssertionError('kdump did not settle')
""")
    report = lab.execute("verify", "reboot-verify", profile, expected=5)
    assert_report(report, catalog, FINDINGS)
    report = lab.execute("apply", "reboot-repeat", apply)
    assert_report(report, catalog, excluded=excluded)
    for host in ["192.0.2.20", "fd90:9::20"]:
        assert (
            lab.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    "ControlPath=none",
                    "zero@" + host,
                    "sudo -n id -u",
                ]
            ).strip()
            == "0"
        )
    lab.finish(
        {
            "source_commit": subprocess.check_output(
                ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
            ).strip(),
            "engine_sha256": source_digest(),
            "installed_package": hardener.__file__,
            "controls": 102,
            "remediations": 90,
            "findings": sorted(FINDINGS),
            "faults_repaired": sorted(FAULTS),
            "exclusions_preserved": True,
            "zero_change_repeats": True,
            "reboot_verified": True,
            "fresh_dual_stack_admin": True,
            "browser_export_sha256": hashlib.sha256(raw).hexdigest(),
            "browser_export_unchanged": True,
        }
    )


if __name__ == "__main__":
    main()
