"""VS5: controlled partial failure and recovery on a snapshotted disposable guest."""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from hardener.cli import inventory_target
from hardener.validation import DATA, load_catalog, load_profile

ROOT = Path(__file__).resolve().parents[2]
SYSCTL = "/etc/sysctl.d/99-rocky10-hardener.conf"
SELECTED = {
    "files.passwd-permissions",
    "kernel.protected-hardlinks",
    "services.debug-shell-disabled",
}


def run(argv, expected=0, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)
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
    parser.add_argument("--output", default="reports/vs5")
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    inventory = inventory_target(args.inventory, args.target, os.environ.copy())
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Use a new, empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    profile, _ = load_profile(ROOT / "profiles/examples/server-five-controls.yaml", load_catalog())
    for item in profile["controls"]:
        item["enabled"] = item["id"] in SELECTED
        if not item["enabled"]:
            item["reason"] = "Outside the controlled failure test"
    source = output / "profile.yaml"
    source.write_text(json.dumps(profile, indent=2) + "\n")
    host = json.loads(run(["ansible-inventory", "-i", str(inventory), "--list"]))["_meta"][
        "hostvars"
    ][args.target]
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-p",
        str(host.get("ansible_port", 22)),
        "--",
        f"{host['ansible_user']}@{host['ansible_host']}",
    ]

    def remote(command):
        return run(ssh + [command], timeout=30)

    def execute(mode, name, expected=0, env=None, inv=inventory, cwd=ROOT):
        result = run(
            [
                sys.executable,
                "-m",
                "hardener.cli",
                mode,
                "--profile",
                str(source),
                "--inventory",
                str(inv),
                "--target",
                args.target,
                "--output",
                str(output / name),
            ],
            expected,
            env=env,
            cwd=cwd,
            timeout=300,
        )
        (output / f"{name}.txt").write_text(result)
        return json.loads((output / name / "report.json").read_text())

    execute("preflight", "preflight")
    execute("verify", "baseline")
    original = remote("sudo cat " + SYSCTL)
    original_mode = remote("stat -c %a /etc/passwd").strip()
    original_live = remote("cat /proc/sys/fs/protected_hardlinks").strip()
    preserved_command = "sha256sum /etc/passwd /etc/dnf/dnf.conf; stat -c '%u:%g:%a' /etc/group; rpm -q telnet; true"
    preserved = remote(preserved_command)
    result = {}
    try:
        remote("sudo chmod 0664 /etc/passwd")
        remote(
            "sudo /usr/bin/python3 -c "
            + shlex.quote(
                f"from pathlib import Path; Path({SYSCTL!r}).write_text('fs.protected_hardlinks = 0\\n')"
            )
        )
        remote("sudo sysctl -w fs.protected_hardlinks=0")
        # Failure injection is confined to a disposable copy of the installed engine.
        # No runtime test hooks, catalog fields, or target credentials are introduced.
        with tempfile.TemporaryDirectory(prefix="hardener-vs5-") as tmp:
            fixture = Path(tmp)
            shutil.copytree(
                DATA.parent, fixture / "hardener", ignore=shutil.ignore_patterns("__pycache__")
            )
            tasks = fixture / "hardener/data/ansible/tasks"
            fail = {
                "name": "M4 controlled failure",
                "ansible.builtin.fail": {"msg": "M4-private-redaction-sentinel"},
            }
            (tasks / "kernel.protected-hardlinks.audit.yml").write_text(yaml.safe_dump([fail]))
            apply_path = tasks / "kernel.protected-hardlinks.apply.yml"
            apply_tasks = yaml.safe_load(apply_path.read_text())
            assert apply_tasks[1]["name"] == "Preserve persistent-setting change evidence"
            apply_path.write_text(yaml.safe_dump(apply_tasks[:2] + [fail]))
            env = {**os.environ, "PYTHONPATH": str(fixture)}

            audit = execute("audit", "partial-audit", 4, env=env, cwd=fixture)
            assert audit["summary"]["fail"] == 1
            assert audit["summary"]["error"] == 1 and audit["summary"]["pass"] == 1
            assert audit["changed_tasks"] == 0

            applied = execute("apply", "partial-apply", 4, env=env, cwd=fixture)
            rows = {row["id"]: row for row in applied["controls"]}
            assert applied["summary"]["error"] == 1 and applied["summary"]["pass"] == 2
            assert rows["kernel.protected-hardlinks"]["changed"] is True
            assert applied["changed_tasks"] == 2
            assert remote("stat -c %a /etc/passwd").strip() == "644"
            assert remote("cat /proc/sys/fs/protected_hardlinks").strip() == "0"
            assert "M4-private-redaction-sentinel" not in json.dumps(applied)
            assert any(e["task"] == "M4 controlled failure" for e in applied["errors"])

        verified = execute("verify", "partial-state", 5)
        assert verified["summary"]["fail"] == 1 and verified["summary"]["error"] == 0
        restored = execute("apply", "recovered")
        assert restored["summary"]["pass"] == 3
        assert execute("apply", "recovered-rerun")["changed_tasks"] == 0
        result.update(
            partial_audit_distinguishes_error_and_fail=True,
            partial_apply_preserves_known_changes=True,
            independent_verification_detected_incomplete_state=True,
            private_failure_message_redacted=True,
            recovery="pass",
        )

        remote("sudo chmod 0664 /etc/passwd")
        # A normal static inventory preserves SSH configuration while changing only the role.
        unsafe = output / "unsafe-role.ini"
        fields = host.copy()
        fields["hardener_role"] = "unspecified"
        unsafe.write_text(
            args.target
            + " "
            + " ".join(
                key
                + "="
                + shlex.quote(str(value).lower() if isinstance(value, bool) else str(value))
                for key, value in fields.items()
            )
            + "\n"
        )
        try:
            refusal = execute("apply", "refused-role", 3, inv=unsafe)
            assert refusal["changed_tasks"] == 0 and not refusal["preflight_passed"]
            assert remote("stat -c %a /etc/passwd").strip() == "664"
            assert remote("sudo -n id -u").strip() == "0"
        finally:
            unsafe.unlink(missing_ok=True)
        execute("apply", "restore-role")
        final = execute("verify", "final")
        assert final["summary"]["pass"] == 3
        assert remote(preserved_command) == preserved
        result.update(
            unsafe_role_refused_without_changes=True,
            ssh_and_administrative_access_preserved=True,
            final_verification="pass",
            high_impact_control_test="not_applicable",
        )
    finally:
        remote("sudo chmod " + original_mode + " /etc/passwd")
        remote(
            "sudo /usr/bin/python3 -c "
            + shlex.quote(f"from pathlib import Path; Path({SYSCTL!r}).write_text({original!r})")
        )
        remote("sudo sysctl -w fs.protected_hardlinks=" + original_live)
    (output / "integration-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
