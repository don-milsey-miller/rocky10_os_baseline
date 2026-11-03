"""VS4: execute an unchanged browser export on a snapshotted disposable guest."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from hardener.cli import inventory_target
from hardener.validation import load_catalog, load_profile

SELECTED = {
    "files.passwd-permissions",
    "kernel.protected-hardlinks",
    "services.debug-shell-disabled",
}


def run(argv, expected=0):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != expected:
        raise AssertionError(
            f"{argv[0]} returned {result.returncode}, expected {expected}:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    profile_path = Path(args.profile).resolve()
    profile, digest = load_profile(profile_path, load_catalog())
    assert {c["id"] for c in profile["controls"] if c["enabled"]} == SELECTED
    excluded = next(c for c in profile["controls"] if c["id"] == "packages.telnet-client-absent")
    assert excluded["enabled"] is False and excluded["reason"]
    assert all(c["id"] != "packages.local-signature-check" for c in profile["controls"])
    inventory = inventory_target(args.inventory, args.target, os.environ.copy())
    root = Path("reports/m3/vs4")
    root.mkdir(parents=True, exist_ok=True)

    def hardener(mode, name, expected=0):
        output = run(
            [
                "hardener",
                mode,
                "--profile",
                str(profile_path),
                "--inventory",
                str(inventory),
                "--target",
                args.target,
                "--output",
                str(root / name),
            ],
            expected,
        )
        (root / f"{name}.txt").write_text(output)
        report = json.loads((root / name / "report.json").read_text())
        assert report["profile_sha256"] == digest
        return report

    run(["hardener", "validate", "--profile", str(profile_path)])
    hardener("preflight", "preflight")
    # Start from verified M2 state. Only the account-file mode is perturbed.
    hardener("verify", "baseline")
    host = json.loads(run(["ansible-inventory", "-i", str(inventory), "--list"]))["_meta"][
        "hostvars"
    ][args.target]
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-p",
        str(host.get("ansible_port", 22)),
        "--",
        f"{host['ansible_user']}@{host['ansible_host']}",
    ]

    def remote(command):
        return run(ssh + [command])

    preserved = (
        "sha256sum /etc/passwd /etc/dnf/dnf.conf; "
        "stat -c '%u:%g:%a' /etc/group; rpm -q telnet; true"
    )
    before = remote(preserved)
    try:
        remote("sudo chmod 0664 /etc/passwd")
        audit = hardener("audit", "before", 5)
        assert audit["summary"]["fail"] == 1 and audit["changed_tasks"] == 0
        applied = hardener("apply", "apply")
        assert applied["summary"]["pass"] == 3 and applied["changed_tasks"] == 1
        verified = hardener("verify", "verify")
        assert verified["summary"]["pass"] == 3 and verified["changed_tasks"] == 0
        rerun = hardener("apply", "second-apply")
        assert rerun["changed_tasks"] == 0
        for report in (audit, applied, verified, rerun):
            row = next(c for c in report["controls"] if c["id"] == "packages.telnet-client-absent")
            assert row["status"] == "excluded" and row["reason"] == excluded["reason"]
        assert remote(preserved) == before, "Excluded or unrelated state changed"
        assert hashlib.sha256(profile_path.read_bytes()).hexdigest() == digest
        evidence = {
            "vs4": "pass",
            "profile_sha256": digest,
            "selected_controls": sorted(SELECTED),
            "audit_fail": audit["summary"]["fail"],
            "verified_pass": verified["summary"]["pass"],
            "first_apply_changed_tasks": applied["changed_tasks"],
            "second_apply_changed_tasks": rerun["changed_tasks"],
            "exclusion_reason_preserved": True,
            "excluded_and_omitted_state_preserved": True,
            "profile_bytes_unchanged": True,
        }
        (root / "integration-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2))
    finally:
        remote("sudo chmod 0644 /etc/passwd")


if __name__ == "__main__":
    main()
