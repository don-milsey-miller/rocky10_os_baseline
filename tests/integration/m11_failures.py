"""Bounded failure fixtures after M11 acceptance. Restore the accepted snapshot afterward."""

import copy
import shlex
import subprocess
import time
import uuid

from m11 import SecurityLab, load_profile


def main():
    lab = SecurityLab(__doc__)
    full = load_profile()
    entries = {c["id"]: c for c in full["controls"]}

    def profile(*ids):
        return {**full, "controls": [copy.deepcopy(entries[cid]) for cid in ids]}

    def selected_hashes():
        return lab.python("""from pathlib import Path
import hashlib,json
paths=[Path('/etc/selinux/config'),Path('/etc/audit/auditd.conf'),Path('/etc/aide-rocky10.conf'),Path('/var/lib/aide/rocky10.db.gz'),Path('/etc/rsyslog.d/00-rocky10-remote-tls.conf')]
paths+=list(Path('/etc/audit/rules.d').glob('*.rules'))
print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()},sort_keys=True))
""")

    cases = []

    def refuse(name, chosen):
        before = selected_hashes()
        result = lab.execute("apply", name, chosen, 3)
        assert result["changed_tasks"] == 0 and before == selected_hashes()
        assert lab.remote("sudo -n id -u").strip() == "0"
        cases.append(name)

    def altered(name, path, addition, chosen):
        original = lab.remote("sudo cat " + path)
        try:
            lab.write(path, original + addition)
            refuse(name, chosen)
        finally:
            lab.write(path, original)

    audit = profile("audit.service-enabled", "audit.identity-changes")
    altered(
        "audit-suppression", "/etc/audit/rules.d/50-m11-preserved.rules", "-a never,task\n", audit
    )
    altered(
        "audit-duplicate",
        "/etc/audit/auditd.conf",
        "\nnum_logs = 3\n",
        profile("audit.service-enabled", "audit.storage-policy"),
    )
    threshold = profile("audit.service-enabled", "audit.storage-policy")
    threshold["controls"][1]["parameters"]["admin_space_left_mib"] = 75
    refuse("crossed-thresholds", threshold)
    for name, chosen, changes in [
        ("untrusted-peer", profile("logging.remote-tls"), {"peer_name": "wrong.lab.test"}),
        ("changed-integrity-scope", profile("integrity.aide-scheduled"), {"paths": ["/etc"]}),
    ]:
        chosen["controls"][0]["parameters"].update(changes)
        refuse(name, chosen)
    drop = "/etc/rsyslog.d/99-m11-unknown.conf"
    try:
        lab.write(drop, "stop\n")
        refuse("unknown-log-routing", profile("logging.remote-tls"))
    finally:
        lab.remove(drop)
    path = "/etc/audit/rules.d/70-rocky10-identity-changes.rules"
    original = lab.remote("sudo cat " + path)
    try:
        lab.remove(path)
        refuse("immutable-persistent-drift", audit)
    finally:
        lab.write(path, original)
        lab.remote("sudo chmod 640 " + path + "; sudo restorecon " + path)
    for unit, chosen in [
        ("rsyslog.service", profile("logging.remote-tls")),
        ("auditd.service", profile("audit.service-enabled")),
        ("rocky10-aide.service", profile("integrity.aide-scheduled")),
    ]:
        directory = "/etc/systemd/system/" + unit + ".d"
        lab.remote("sudo install -d -m 755 " + directory)
        try:
            lab.write(directory + "/m11-unsafe.conf", "[Service]\nRestart=no\n")
            lab.remote("sudo systemctl daemon-reload")
            refuse("custom-unit-" + unit, chosen)
        finally:
            lab.remove(directory + "/m11-unsafe.conf")
            lab.remote("sudo rmdir " + directory + "; sudo systemctl daemon-reload")
    # Reject unsafe links without changing the original file inode.
    path = "/etc/audit/rules.d/70-rocky10-identity-changes.rules"
    lab.remote("sudo mv " + path + " " + path + ".saved; sudo ln -s " + path + ".saved " + path)
    try:
        refuse("linked-audit-rules", audit)
    finally:
        lab.remote("sudo rm " + path + "; sudo mv " + path + ".saved " + path)
    malformed = "/etc/selinux/targeted/policy/policy.99"
    try:
        lab.write(malformed, "invalid compiled policy\n")
        refuse(
            "invalid-compiled-selinux-policy",
            profile("selinux.targeted-policy", "selinux.enforcing"),
        )
    finally:
        lab.remove(malformed)
    try:
        lab.remote("sudo grubby --update-kernel=ALL --args=enforcing=0")
        refuse("selinux-boot-bypass", profile("selinux.targeted-policy", "selinux.enforcing"))
    finally:
        lab.remote("sudo grubby --update-kernel=ALL --remove-args=enforcing")
    database_path = "/var/lib/aide/rocky10.db.gz"
    lab.remote("sudo mv " + database_path + " " + database_path + ".saved")
    try:
        refuse("missing-trusted-baseline", profile("integrity.aide-scheduled"))
    finally:
        lab.remote("sudo mv " + database_path + ".saved " + database_path)
    altered(
        "alternate-log-startup",
        "/etc/sysconfig/rsyslog",
        '\nSYSLOGD_OPTIONS="-f /tmp/m11-unknown.conf"\n',
        profile("logging.remote-tls"),
    )
    # Native disk-full behavior on an isolated 2 MiB target tmpfs.
    original = lab.remote("sudo cat /etc/audit/auditd.conf")
    directory = "/run/m11-audit-budget"
    lab.remote("sudo install -d -m 700 " + directory)
    lab.remote(
        "sudo mount -t tmpfs -o size=2m,mode=0700,context=system_u:object_r:auditd_log_t:s0 tmpfs "
        + directory
    )
    stamp = lab.remote("date +%s").strip()
    try:
        lab.write(
            "/etc/audit/auditd.conf",
            original.replace("/var/log/audit/audit.log", directory + "/audit.log"),
        )
        lab.remote("sudo auditctl --signal reload")
        time.sleep(1)
        assert (
            lab.python(
                "from pathlib import Path; print(Path("
                + repr(directory + "/audit.log")
                + ").exists())"
            ).strip()
            == "True"
        )
        lab.python("""import errno,os
from pathlib import Path
assert os.path.ismount('/run/m11-audit-budget')
with Path('/run/m11-audit-budget/filler').open('wb',buffering=0) as stream:
    try:
        while True: stream.write(b'x'*4096)
    except OSError as exc:
        assert exc.errno==errno.ENOSPC
""")
        lab.remote("sudo auditctl -m m11-storage-full")
        time.sleep(1)
        journal = lab.remote("sudo journalctl -u auditd --since=@" + stamp + " --no-pager")
        assert any(word in journal.lower() for word in ("disk full", "no space", "disk space")), (
            journal
        )
        assert lab.remote("systemctl is-active auditd").strip() == "active"
        assert lab.remote("sudo -n id -u").strip() == "0"
    finally:
        lab.write("/etc/audit/auditd.conf", original)
        lab.remote("sudo auditctl --signal reload")
        time.sleep(1)
        lab.remote("sudo auditctl --signal resume")
        lab.remote("sudo umount " + directory)
        lab.remote("sudo rmdir " + directory)
    lab.remote("sudo auditctl -m m11-storage-recovered")
    assert (
        lab.execute(
            "verify", "storage-recovered", profile("audit.service-enabled", "audit.storage-policy")
        )["summary"]["pass"]
        == 2
    )
    # An incorrect certificate from the real collector must stop delivery.
    certificate = lab.collector("sudo cat /etc/pki/rsyslog/server.pem")
    lab.collector(
        "sudo openssl req -new -key /etc/pki/rsyslog/server.key -out /root/m11-pki/wrong.csr -subj /CN=wrong.lab.test"
    )
    lab.collector(
        "sudo openssl x509 -req -in /root/m11-pki/wrong.csr -CA /etc/pki/rsyslog/lab-ca.pem -CAkey /root/m11-pki/ca.key -CAcreateserial -out /root/m11-pki/wrong.pem -days 1 -sha256"
    )
    try:
        lab.collector(
            "sudo cp /root/m11-pki/wrong.pem /etc/pki/rsyslog/server.pem; sudo systemctl restart rsyslog"
        )
        lab.execute("verify", "collector-wrong-certificate", profile("logging.remote-tls"), 5)
        marker = "m11-rejected-" + uuid.uuid4().hex
        lab.remote("logger -p local6.notice -t rocky10-m11 " + marker)
        time.sleep(3)
        query = (
            "from pathlib import Path; print("
            + repr(marker)
            + " in Path('/var/log/m11-collector.log').read_text())"
        )
        assert lab.collector("sudo python3 -c " + shlex.quote(query)).strip() == "False"
    finally:
        restore = (
            "from pathlib import Path; Path('/etc/pki/rsyslog/server.pem').write_text("
            + repr(certificate)
            + ")"
        )
        lab.collector(
            "sudo python3 -c " + shlex.quote(restore) + "; sudo systemctl restart rsyslog"
        )
    # Native sender retries after trust is restored, including its queued marker.
    assert lab.marker_receipt("collector-recovered")
    assert (
        lab.execute("verify", "collector-recovered", profile("logging.remote-tls"))["summary"][
            "pass"
        ]
        == 1
    )
    # Keep a changed baseline finding. Never refresh the database to make the test pass.
    database = lab.checksum("/var/lib/aide/rocky10.db.gz")
    lab.write("/srv/m11-baseline/approved.txt", "Unexpected disposable integrity change.\n")
    chosen = profile("integrity.aide-scheduled")
    assert lab.execute("audit", "integrity-alert", chosen, 5)["changed_tasks"] == 0
    assert lab.execute("verify", "integrity-alert-verify", chosen, 5)["changed_tasks"] == 0
    assert lab.execute("apply", "integrity-no-refresh", chosen, 5)["changed_tasks"] == 0
    assert database == lab.checksum("/var/lib/aide/rocky10.db.gz")
    failed = subprocess.run(
        lab.ssh + ["sudo systemctl start rocky10-aide.service"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode != 0
    assert (
        lab.remote("systemctl show rocky10-aide.service -p Result --value").strip() == "exit-code"
    )
    lab.finish(
        {
            "zero_write_refusals": cases,
            "bounded_tmpfs_disk_full": True,
            "audit_recovered": True,
            "wrong_certificate_rejected": True,
            "collector_recovered": True,
            "integrity_alert_and_failed_service": True,
            "trusted_baseline_unchanged": True,
            "restore_snapshot_required": True,
        }
    )


if __name__ == "__main__":
    main()
