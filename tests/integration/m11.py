"""Exercise approved audit/integrity policy in a disposable Rocky KVM target."""

import copy
import shlex
import subprocess
import time
import uuid
from pathlib import Path

import yaml
from lab import GuestLab


class SecurityLab(GuestLab):
    def __init__(self, description):
        super().__init__(description)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            ready = subprocess.run(
                self.ssh + ["sudo -n id -u"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if ready.returncode == 0 and ready.stdout.strip() == "0":
                break
            time.sleep(2)
        else:
            raise AssertionError("Snapshot guest did not become reachable")

    def managed_state(self):
        return self.python("""from pathlib import Path
import hashlib,json,stat
paths=[Path('/etc/selinux/config'),Path('/etc/audit/auditd.conf'),Path('/etc/aide-rocky10.conf')]
for directory,pattern in [('/etc/audit/rules.d','*.rules'),('/etc/rsyslog.d','*.conf'),('/etc/systemd/system','rocky10-aide.*'),('/var/lib/aide','rocky10.*'),('/boot/loader/entries','*.conf')]:
    paths+=list(Path(directory).glob(pattern))
rows={}
for p in paths:
    if p.is_file():
        st=p.stat()
        rows[str(p)]=[hashlib.sha256(p.read_bytes()).hexdigest(),st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)]
print(hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest())
""").strip()

    def collector(self, command):
        argv = self.ssh[:-1] + ["zero@192.0.2.30", command]
        return self.run(argv)

    def checksum(self, path):
        return self.python(
            "from pathlib import Path; import hashlib; print(hashlib.sha256(Path("
            + repr(path)
            + ").read_bytes()).hexdigest())"
        ).strip()

    def marker_receipt(self, name):
        marker = "m11-" + name + "-" + uuid.uuid4().hex
        self.remote("logger -p local6.notice -t rocky10-m11 " + shlex.quote(marker))
        for _ in range(60):
            code = (
                "from pathlib import Path; p=Path('/var/log/m11-collector.log'); print("
                + repr(marker)
                + " in p.read_text() if p.exists() else False)"
            )
            if self.collector("sudo python3 -c " + shlex.quote(code)).strip() == "True":
                return True
            time.sleep(1)
        raise AssertionError("Collector did not receive the unique source marker")


def load_profile():
    return yaml.safe_load(Path("profiles/examples/server-security-lab.yaml").read_text())


def main():
    lab = SecurityLab(__doc__)
    full = load_profile()
    # The snapshot has installed prerequisites and deliberately permissive SELinux.
    # Keep auditing live while making its boot enablement noncompliant.
    lab.remote("sudo systemctl start auditd; sudo systemctl disable auditd audit-rules")
    all_rules = lab.remote("sudo auditctl -l")
    assert all_rules.strip() == "No rules", "Restore m11-prepared before each lifecycle"
    unrelated = "/etc/audit/rules.d/50-m11-preserved.rules"
    lab.write(unrelated, "-w /etc/hostname -p wa -k m11_preserved\n")
    lab.remote(
        "sudo chmod 640 " + unrelated + "; sudo auditctl -w /etc/hostname -p wa -k m11_preserved"
    )
    preserved = lab.checksum(unrelated)
    initial_state = lab.managed_state()
    audit = lab.execute("audit", "before", full, 5)
    assert lab.managed_state() == initial_state
    assert audit["changed_tasks"] == 0
    assert audit["summary"]["fail"] == 11 and audit["summary"]["pass"] == 1, audit["summary"]
    before = lab.checksum("/etc/audit/auditd.conf")
    subset = copy.deepcopy(full)
    subset["controls"] = [
        c
        for c in subset["controls"]
        if c["id"] not in ("audit.privilege-use", "audit.immutable-rules")
    ]
    next(c for c in subset["controls"] if c["id"] == "audit.identity-changes")["enabled"] = False
    result = lab.execute("apply", "excluded-and-omitted", subset, 5)
    statuses = {c["id"]: c["status"] for c in result["controls"]}
    assert statuses["audit.identity-changes"] == "excluded"
    assert statuses["audit.early-boot"] == "fail"
    assert not any(c["status"] in ("error", "unsupported") for c in result["controls"])
    assert (
        lab.python(
            "from pathlib import Path; print(any(Path('/etc/audit/rules.d').glob('*identity-changes*')) or any(Path('/etc/audit/rules.d').glob('*privilege-use*')))"
        ).strip()
        == "False"
    )
    assert lab.checksum("/etc/audit/auditd.conf") != before
    lab.reboot()
    # All audit groups must verify before the immutable finalizer runs.
    applied = lab.execute("apply", "all-selected", full)
    assert applied["summary"]["pass"] == 12, applied
    applied_state = lab.managed_state()
    assert lab.execute("verify", "verified", full)["changed_tasks"] == 0
    assert lab.managed_state() == applied_state
    repeat = lab.execute("apply", "repeat", full)
    assert repeat["changed_tasks"] == 0
    assert lab.checksum(unrelated) == preserved
    assert "m11_preserved" in lab.remote("sudo auditctl -l")
    events = {}
    for kind, command in [
        ("identity_changes", "sudo touch /etc/group"),
        ("privilege_use", "sudo /usr/bin/su -s /bin/sh nobody -c /usr/bin/true"),
        ("security_config_changes", "sudo touch /etc/sudoers"),
        ("session_events", "sudo touch /var/log/wtmp"),
    ]:
        lab.remote(command)
        time.sleep(0.3)
        code = (
            "import subprocess; r=subprocess.run(['/usr/sbin/ausearch','--input','/var/log/audit/audit.log','-k',"
            + repr("r10_" + kind)
            + ",'--raw'],capture_output=True,text=True); print(r.returncode == 0 and 'type=SYSCALL' in r.stdout)"
        )
        events[kind] = lab.python(code).strip() == "True"
        assert events[kind], kind
    lab.remote(
        "sudo python3 -c "
        + shlex.quote("import os; [os.utime('/etc/group',None) for _ in range(20)]")
    )
    assert "lost 0" in lab.remote("sudo auditctl -s")
    assert lab.marker_receipt("before-reboot")
    # Kernel denies rule replacement after finalization.
    denied = subprocess.run(
        lab.ssh + ["sudo auditctl -w /etc/hosts -p wa -k m11_denied"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert denied.returncode != 0 and "m11_denied" not in lab.remote("sudo auditctl -l")
    lab.reboot()
    assert lab.execute("verify", "reboot-verify", full)["summary"]["pass"] == 12
    assert lab.execute("apply", "reboot-repeat", full)["changed_tasks"] == 0
    assert lab.marker_receipt("after-reboot")
    lab.remote("sudo systemctl start rocky10-aide.service")
    assert (
        lab.remote("systemctl show rocky10-aide.service -p ExecMainStatus --value").strip() == "0"
    )
    assert lab.remote("sudo -n id -u").strip() == "0"
    lab.finish(
        {
            "controls_verified": 12,
            "initial_failures": 11,
            "audit_events": events,
            "zero_change_repeat": True,
            "audit_verify_configuration_unchanged": True,
            "reboot_persistence": True,
            "excluded_omitted_untouched": True,
            "unrelated_rules_preserved": True,
            "immutable_kernel_denial": True,
            "collector_receipt_before_after_reboot": True,
            "scheduled_integrity_check": True,
            "lost_audit_events": 0,
        }
    )


if __name__ == "__main__":
    main()
