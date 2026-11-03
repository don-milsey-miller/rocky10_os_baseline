"""M2 tests for a snapshotted disposable guest. Run from the development guest."""

import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

from vs1 import run

from hardener.cli import inventory_target
from hardener.validation import load_catalog, load_profile

PROFILE = Path("profiles/examples/server-five-controls.yaml")
SYSCTL = "/etc/sysctl.d/99-rocky10-hardener.conf"
LATE = "/etc/sysctl.d/zz-hardener-test.conf"
EARLY = "/etc/sysctl.d/60-hardener-test.conf"
DNF = "/etc/dnf/dnf.conf"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", default="reports/m2")
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    inventory = inventory_target(args.inventory, args.target, os.environ.copy())
    profile, _ = load_profile(PROFILE, load_catalog())
    hosts = json.loads(run(["ansible-inventory", "-i", str(inventory), "--list"]))["_meta"][
        "hostvars"
    ]
    host = hosts[args.target]
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
    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        parser.error("Use a new, empty output directory for each integration run")
    output.mkdir(parents=True, exist_ok=True)
    commands = []

    def remote(command):
        return run(ssh + [command])

    def python(code):
        return remote("sudo /usr/bin/python3 -c " + shlex.quote(code))

    def write(path, text):
        python(f"from pathlib import Path; Path({path!r}).write_text({text!r})")

    def remove(path):
        python(f"from pathlib import Path; Path({path!r}).unlink(missing_ok=True)")

    def state():
        code = """
import hashlib, json, pathlib, stat, subprocess
paths = ['/etc/passwd', '/etc/group', '/etc/dnf/dnf.conf',
         '/etc/sysctl.d/99-rocky10-hardener.conf', '/etc/sysctl.d/60-hardener-test.conf',
         '/etc/sysctl.d/zz-hardener-test.conf', '/etc/systemd/system/debug-shell.service']
result = {}
for name in paths:
    path = pathlib.Path(name)
    if path.exists():
        info = path.stat()
        result[name] = [hashlib.sha256(path.read_bytes()).hexdigest(),
                        info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
    else:
        result[name] = None
result['packages'] = sorted(subprocess.check_output(
    ['rpm','-qa','--qf','%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'],text=True).splitlines())
result['hardlinks'] = pathlib.Path('/proc/sys/fs/protected_hardlinks').read_text().strip()
result['symlinks'] = pathlib.Path('/proc/sys/fs/protected_symlinks').read_text().strip()
result['debug'] = subprocess.check_output(
    ['systemctl','show','debug-shell.service','-p','ActiveState','-p','UnitFileState'],text=True)
print(json.dumps(result))
"""
        return json.loads(python(code))

    def execute(mode, name, expected=0, source=PROFILE):
        argv = [
            "hardener",
            mode,
            "--profile",
            str(source),
            "--inventory",
            str(inventory),
            "--target",
            args.target,
            "--output",
            str(output / name),
        ]
        commands.append({"argv": argv, "expected_exit": expected})
        run(argv, expected)
        return json.loads((output / name / "report.json").read_text())

    def inject(cid):
        if cid == "files.passwd-permissions":
            remote("sudo chmod 0664 /etc/passwd")
        elif cid == "kernel.protected-hardlinks":
            write(SYSCTL, "fs.protected_hardlinks = 0\n")
            remote("sudo sysctl -w fs.protected_hardlinks=0")
        elif cid == "services.debug-shell-disabled":
            remote(
                "sudo systemctl unmask debug-shell.service && sudo systemctl unmask --runtime debug-shell.service && sudo systemctl start debug-shell.service"
            )
        elif cid == "packages.telnet-client-absent":
            remote("sudo dnf -y install telnet")
        elif cid == "packages.local-signature-check":
            text = remote("sudo cat /etc/dnf/dnf.conf")
            text = re.sub(r"(?im)^\s*localpkg_gpgcheck\s*=.*\n?", "", text)
            write(DNF, text.replace("[main]", "[main]\nlocalpkg_gpgcheck=False", 1))

    result = {}
    execute("preflight", "preflight")
    remote("test -f /home/zero/m2-fixtures/hardener-test-dependent-1-1.noarch.rpm")
    remote("rpm -q telnet")
    write(
        EARLY, "# Disposable earlier setting, preserved by the engine\nfs.protected_hardlinks=0\n"
    )
    remove(SYSCTL)
    for cid in [
        "files.passwd-permissions",
        "services.debug-shell-disabled",
        "packages.local-signature-check",
    ]:
        inject(cid)
    remote("sudo sysctl -w fs.protected_hardlinks=0")
    original_dnf = remote("sudo cat /etc/dnf/dnf.conf")
    initial = state()
    try:
        audit = execute("audit", "before", 5)
        assert audit["summary"]["fail"] == 5 and audit["changed_tasks"] == 0
        assert state() == initial, "Audit changed managed state"

        write(LATE, "fs.protected_hardlinks=0\n")
        before = state()
        refusal = execute("apply", "refused-sysctl-conflict", 3)
        assert refusal["changed_tasks"] == 0 and state() == before
        remove(LATE)
        result["later_sysctl_conflict_refused"] = True

        write(DNF, original_dnf + "\n[hardener-test]\nlocalpkg_gpgcheck=False\n")
        before = state()
        refusal = execute("apply", "refused-dnf-ambiguity", 3)
        assert refusal["changed_tasks"] == 0 and state() == before
        write(DNF, original_dnf)
        result["ambiguous_dnf_configuration_refused"] = True

        remote("sudo rpm -i /home/zero/m2-fixtures/hardener-test-dependent-1-1.noarch.rpm")
        before = state()
        refusal = execute("apply", "refused-package-dependency", 3)
        assert refusal["changed_tasks"] == 0 and state() == before
        remote("sudo rpm -e hardener-test-dependent")
        result["dependent_package_removal_refused"] = True

        first = execute("apply", "apply")
        assert first["summary"]["pass"] == 5
        assert all(row["changed"] is True for row in first["controls"])
        after = state()
        assert initial["/etc/passwd"][0] == after["/etc/passwd"][0]
        assert initial["/etc/group"] == after["/etc/group"]
        assert initial[EARLY] == after[EARLY]
        assert initial["symlinks"] == after["symlinks"]
        removed = set(initial["packages"]) - set(after["packages"])
        assert len(removed) == 1 and next(iter(removed)).startswith("telnet-")
        assert not set(after["packages"]) - set(initial["packages"])
        clean_dnf = lambda s: re.sub(r"(?im)^\s*localpkg_gpgcheck\s*=.*\n?", "", s)
        assert clean_dnf(original_dnf) == clean_dnf(remote("sudo cat /etc/dnf/dnf.conf"))
        result["only_telnet_removed"] = True
        result["unrelated_state_preserved"] = True

        verified = execute("verify", "after")
        assert verified["summary"]["pass"] == 5 and verified["changed_tasks"] == 0
        second = execute("apply", "second-apply")
        assert second["summary"]["pass"] == 5 and second["changed_tasks"] == 0
        assert state() == after
        result["five_controls_verified"] = True
        result["second_apply_changed_tasks"] = 0

        probe = subprocess.run(
            ssh
            + [
                (
                    "sudo dnf -y --disablerepo='*' --setopt=plugins=0 install "
                    "/home/zero/m2-fixtures/hardener-signature-probe-1-1.noarch.rpm"
                )
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        message = (probe.stdout + probe.stderr).lower()
        assert probe.returncode != 0 and ("not signed" in message or "gpg check failed" in message)
        absent = subprocess.run(
            ssh + ["rpm -q hardener-signature-probe"], capture_output=True, text=True, check=False
        )
        assert absent.returncode == 1 and "not installed" in absent.stdout
        result["unsigned_local_rpm_rejected"] = True

        # A local unit must not be destroyed to make room for a mask.
        mask_path = "/etc/systemd/system/debug-shell.service"
        remove(mask_path)
        write(
            mask_path,
            "[Unit]\nDescription=Disposable custom unit\n[Service]\nExecStart=/usr/bin/sleep infinity\n",
        )
        remote("sudo systemctl daemon-reload")
        before = state()
        refusal = execute("apply", "refused-custom-debug-unit", 3)
        assert refusal["changed_tasks"] == 0 and state() == before
        result["custom_debug_unit_preserved"] = True
        remove(mask_path)
        remote("sudo systemctl daemon-reload && sudo systemctl mask --runtime debug-shell.service")
        runtime = execute("audit", "runtime-mask-audit", 5)
        assert runtime["summary"]["fail"] == 1
        persistent = execute("apply", "runtime-mask-apply")
        assert persistent["summary"]["pass"] == 5
        assert (
            next(
                row
                for row in persistent["controls"]
                if row["id"] == "services.debug-shell-disabled"
            )["changed"]
            is True
        )
        result["runtime_mask_made_persistent"] = True

        with tempfile.TemporaryDirectory() as tmp:
            excluded_path = Path(tmp) / "excluded.yaml"
            result["exclusions"] = {}
            for cid in [item["id"] for item in profile["controls"]]:
                inject(cid)
                excluded = json.loads(json.dumps(profile))
                for item in excluded["controls"]:
                    if item["id"] == cid:
                        item.update(enabled=False, reason="M2 exclusion proof")
                excluded_path.write_text(json.dumps(excluded))
                before = state()
                report = execute("apply", "excluded-" + cid, source=excluded_path)
                assert report["summary"]["excluded"] == 1 and report["summary"]["pass"] == 4
                assert report["changed_tasks"] == 0 and state() == before
                record = next(row for row in report["controls"] if row["id"] == cid)
                assert record["reason"] == "M2 exclusion proof"
                result["exclusions"][cid] = "pass"
                execute("apply", "restore-" + cid)

            inject("packages.local-signature-check")
            omitted = json.loads(json.dumps(profile))
            omitted["controls"] = [
                row for row in omitted["controls"] if row["id"] != "packages.local-signature-check"
            ]
            excluded_path.write_text(json.dumps(omitted))
            before = state()
            report = execute("apply", "omitted-control", source=excluded_path)
            assert report["summary"]["pass"] == 4 and report["changed_tasks"] == 0
            assert state() == before
            result["omitted_control_untouched"] = True
            execute("apply", "restore-omitted")

        old_boot = remote("cat /proc/sys/kernel/random/boot_id").strip()
        subprocess.run(
            ssh + ["sudo systemctl reboot"], capture_output=True, check=False, timeout=15
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            check = subprocess.run(
                ssh + ["cat /proc/sys/kernel/random/boot_id"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if check.returncode == 0 and check.stdout.strip() != old_boot:
                break
            time.sleep(2)
        else:
            raise AssertionError("Test guest did not return from reboot")
        rebooted = execute("verify", "after-reboot")
        assert rebooted["summary"]["pass"] == 5 and rebooted["changed_tasks"] == 0
        result["five_controls_survive_reboot"] = True
        remove(EARLY)
        final = execute("verify", "final")
        assert final["summary"]["pass"] == 5
        result["final_verification"] = "pass"
    finally:
        # Stop the temporary unauthenticated console even when a test fails.
        subprocess.run(
            ssh + ["sudo systemctl stop debug-shell.service"],
            capture_output=True,
            check=False,
            timeout=15,
        )
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (output / "integration-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
