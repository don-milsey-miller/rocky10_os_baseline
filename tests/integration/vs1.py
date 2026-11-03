"""VS1 and exclusion/refusal smoke tests. Only run on a snapshotted disposable guest."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

from hardener.cli import inventory_target
from hardener.validation import load_catalog, load_profile


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
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    inventory = inventory_target(args.inventory, args.target, os.environ.copy())
    profile_path = Path("profiles/examples/server-minimal.yaml")
    profile, _ = load_profile(profile_path, load_catalog())
    root = Path("reports/vs1")
    root.mkdir(parents=True, exist_ok=True)
    hosts = json.loads(run(["ansible-inventory", "-i", str(inventory), "--list"]))["_meta"][
        "hostvars"
    ]
    host = hosts[args.target]
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

    def hardener(mode, name, expected=0, source=profile_path, inv=inventory):
        run(
            [
                "hardener",
                mode,
                "--profile",
                str(source),
                "--inventory",
                str(inv),
                "--target",
                args.target,
                "--output",
                str(root / name),
            ],
            expected,
        )
        return json.loads((root / name / "report.json").read_text())

    run(["hardener", "validate", "--profile", str(profile_path)])
    hardener("preflight", "preflight")
    before = remote(
        "sha256sum /etc/passwd; stat -c '%u:%g:%a' /etc/group; "
        "cat /proc/sys/fs/protected_hardlinks; systemctl is-enabled debug-shell.service; "
        "rpm -q telnet; true"
    )
    results = {}
    try:
        remote("sudo chmod 0664 /etc/passwd")
        audit = hardener("audit", "before", 5)
        assert audit["summary"]["fail"] == 1 and audit["changed_tasks"] == 0
        first = hardener("apply", "apply")
        assert first["summary"]["pass"] == 1 and first["changed_tasks"] == 1
        assert first["controls"][0]["changed"] is True
        verification = hardener("verify", "after")
        assert verification["summary"]["pass"] == 1 and verification["changed_tasks"] == 0
        second = hardener("apply", "second-apply")
        assert second["summary"]["pass"] == 1 and second["changed_tasks"] == 0
        assert second["controls"][0]["changed"] is False
        hardener("verify", "second-verify")
        after = remote(
            "sha256sum /etc/passwd; stat -c '%u:%g:%a' /etc/group; "
            "cat /proc/sys/fs/protected_hardlinks; systemctl is-enabled debug-shell.service; "
            "rpm -q telnet; true"
        )
        assert before == after, "Account content or unrelated settings changed"
        results["vs1"] = "pass"
        results["second_apply_changed_tasks"] = second["changed_tasks"]
        results["unrelated_state_preserved"] = True

        with tempfile.TemporaryDirectory() as tmp:
            excluded = Path(tmp) / "excluded.yaml"
            profile["controls"][0].update(enabled=False, reason="Integration exclusion test")
            excluded.write_text(json.dumps(profile))
            remote("sudo chmod 0664 /etc/passwd")
            exclusion = hardener("apply", "excluded", source=excluded)
            assert exclusion["summary"]["excluded"] == 5
            assert exclusion["changed_tasks"] == 0
            assert remote("stat -c %a /etc/passwd").strip() == "664"
            results["exclusion"] = "pass"

            bad_inventory = Path(tmp) / "unsafe.ini"
            bad_inventory.write_text(
                f"{args.target} ansible_host={host['ansible_host']} "
                f"ansible_user={host['ansible_user']} hardener_role=unspecified\n"
            )
            refusal = hardener("apply", "refused-role", 3, inv=bad_inventory)
            assert refusal["preflight_passed"] is False and refusal["changed_tasks"] == 0
            assert remote("stat -c %a /etc/passwd").strip() == "664"
            results["unsafe_role_refused"] = True

            bad_inventory.write_text(
                f"{args.target} ansible_host={host['ansible_host']} "
                f"ansible_user={host['ansible_user']} hardener_role=server ansible_become=false\n"
            )
            refusal = hardener("apply", "refused-privilege", 3, inv=bad_inventory)
            assert refusal["preflight_passed"] is False and refusal["changed_tasks"] == 0
            assert remote("stat -c %a /etc/passwd").strip() == "664"
            results["missing_privilege_refused"] = True
        hardener("apply", "restored")
        hardener("verify", "final")
    finally:
        remote("sudo chmod 0644 /etc/passwd")
    (root / "integration-evidence.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
