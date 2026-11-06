"""M7 live lifecycle and refusal tests. Restore m6-verified before each full run."""

import copy
import shlex
import subprocess
from pathlib import Path

from lab import GuestLab

FIXTURES = Path("/home/zero/m7-fixtures")
REPO = "/etc/yum.repos.d/hardener-m7.repo"
LOG = "/var/log/hardener-m7-probe.log"
JOURNAL = "/etc/systemd/journald.conf.d/99-rocky10-hardener.conf"
ROTATION = "/etc/logrotate.d/90-rocky10-hardener"
PARAMETERS = {
    "packages.repository-signature-check": {"repositories": ["hardener-m7"]},
    "packages.repository-tls-verification": {"repositories": ["hardener-m7"]},
    "packages.repository-metadata-signature": {"repositories": ["hardener-m7"]},
    "time.approved-sources": {"sources": ["2.rocky.pool.ntp.org"], "source_type": "pool"},
    "logging.journal-retention": {"max_use_mib": 128, "keep_free_mib": 256, "retention_days": 7},
    "logging.logfile-permissions": {"paths": [LOG], "mode": "0640"},
    "logging.rotation-policy": {
        "paths": [LOG],
        "mode": "0640",
        "frequency": "daily",
        "retain": 3,
        "reopen": "none",
    },
}
IDS = sorted(
    [
        *PARAMETERS,
        "time.chrony-enabled",
        "logging.journal-persistent",
        "services.avahi-disabled",
        "services.cups-disabled",
    ]
)
REPO_TEXT = """[hardener-m7]
name=Disposable M7
baseurl=https://127.0.0.1:8443/repo
enabled=1
gpgcheck=0
repo_gpgcheck=0
sslverify=0
sslcacert=/home/zero/m7-fixtures/tls.crt
gpgkey=file:///home/zero/m7-fixtures/repo-key.asc
skip_if_unavailable=0
[hardener-m7-unselected]
name=Retained disabled fixture
baseurl=https://127.0.0.1:8443/repo
enabled=0
gpgcheck=0
repo_gpgcheck=0
sslverify=0
"""


def main():
    lab = GuestLab(__doc__)
    baseline = lab.profile(["files.passwd-permissions"])
    lab.execute("preflight", "target-guard", baseline)
    assert (FIXTURES / "repo/repodata/repomd.xml.asc").is_file()
    absent = lab.profile(["services.avahi-disabled", "services.cups-disabled"])
    report = lab.execute("audit", "services-absent", absent)
    assert report["summary"]["not_applicable"] == 2
    # Exercise service provisioning separately from approved-source configuration.
    lab.remote("sudo rpm -e chrony")
    clock_service = lab.profile(["time.chrony-enabled"])
    assert lab.execute("audit", "chrony-package-absent", clock_service, 5)["summary"]["fail"] == 1
    assert lab.execute("apply", "chrony-install", clock_service)["summary"]["pass"] == 1
    assert lab.execute("apply", "chrony-install-idempotent", clock_service)["changed_tasks"] == 0
    lab.remote("sudo dnf -y install avahi cups")
    lab.remote("mkdir -m 700 /home/zero/m7-fixtures")
    host = lab.ssh[-1]
    for name in [
        "repo",
        "no-advisory",
        "tls.crt",
        "tls.key",
        "repo-key.asc",
        "server.py",
        "hardener-m7-probe-1-1.noarch.rpm",
    ]:
        lab.run(
            [
                "scp",
                "-qr",
                "-P",
                lab.ssh[-2],
                str(FIXTURES / name),
                host + ":/home/zero/m7-fixtures/",
            ]
        )
    lab.write(
        "/etc/systemd/system/hardener-m7-repository.service",
        """[Unit]
Description=Disposable M7 repository
After=network.target
[Service]
User=zero
ExecStart=/usr/bin/python3 /home/zero/m7-fixtures/server.py
[Install]
WantedBy=multi-user.target
""",
    )
    lab.remote("sudo systemctl daemon-reload && sudo systemctl enable --now hardener-m7-repository")
    lab.remote("sudo rpm -i /home/zero/m7-fixtures/hardener-m7-probe-1-1.noarch.rpm")
    lab.write(REPO, REPO_TEXT)
    lab.write(LOG, "M7 disposable log content\n")
    lab.remote("sudo chmod 0666 " + LOG)
    lab.remote("sudo systemctl enable --now avahi-daemon.socket cups.socket cups.path")
    lab.remote("sudo systemctl disable --now chronyd")
    lab.write(
        "/etc/chrony.conf",
        "# retained marker\ndriftfile /var/lib/chrony/drift\npool bad.invalid iburst\n",
    )
    lab.python(
        "from pathlib import Path; Path('/etc/systemd/journald.conf.d').mkdir(mode=0o755,exist_ok=True)"
    )
    lab.remove(JOURNAL)
    lab.remove(ROTATION)
    lab.remote("sudo systemctl restart systemd-journald")
    profile = lab.profile(IDS, PARAMETERS)
    installed = lab.remote("rpm -qa | sort")
    untouched = lab.remote("sha256sum /etc/passwd /etc/dnf/dnf.conf /etc/yum.repos.d/rocky.repo")
    content = lab.remote("sudo sha256sum " + LOG)
    before = lab.execute("audit", "noncompliant", profile, 5)
    assert before["summary"]["fail"] == len(IDS) and before["changed_tasks"] == 0

    def refused(name, selected=profile):
        result = lab.execute("apply", name, selected, 3)
        assert result["changed_tasks"] == 0
        assert lab.remote("sudo stat -c %a " + LOG).strip() == "666"
        assert lab.remote("sudo sha256sum " + LOG) == content

    # Every preflight runs before any selected remediation.
    lab.write(
        "/etc/systemd/journald.conf.d/zz-hardener-m7-conflict.conf", "[Journal]\nStorage=volatile\n"
    )
    refused("refused-later-journal-policy")
    lab.remove("/etc/systemd/journald.conf.d/zz-hardener-m7-conflict.conf")
    budget = copy.deepcopy(profile)
    next(c for c in budget["controls"] if c["id"] == "logging.journal-retention")["parameters"][
        "keep_free_mib"
    ] = 1048576
    refused("refused-impossible-log-budget", budget)
    lab.remote("sudo setfacl -m u:65534:r-- " + LOG)
    refused("refused-log-acl")
    lab.remote("sudo setfacl -b " + LOG)
    lab.remote("sudo chmod 0666 " + LOG)
    lab.write("/etc/logrotate.d/zz-hardener-m7-conflict", LOG + " {\n daily\n rotate 2\n}\n")
    refused("refused-duplicate-rotation")
    lab.remove("/etc/logrotate.d/zz-hardener-m7-conflict")
    lab.write("/etc/systemd/system/avahi-daemon.service", "[Service]\nExecStart=/usr/bin/true\n")
    lab.remote("sudo systemctl daemon-reload")
    refused("refused-custom-service")
    lab.remove("/etc/systemd/system/avahi-daemon.service")
    lab.remote("sudo systemctl daemon-reload")
    original_clock = lab.remote("sudo cat /etc/chrony.conf")
    lab.write("/etc/chrony.conf", original_clock + "include /etc/chrony-extra.conf\n")
    refused("refused-time-include")
    lab.write("/etc/chrony.conf", original_clock)

    # Metadata verification must reject a genuine signature mismatch.
    metadata = "/home/zero/m7-fixtures/repo/repodata/repomd.xml"
    lab.python(
        "from pathlib import Path; p=Path("
        + repr(metadata)
        + ");p.write_bytes(p.read_bytes()+b'\\n')"
    )
    refused("refused-tampered-metadata")
    lab.python(
        "from pathlib import Path; p=Path("
        + repr(metadata)
        + ");p.write_bytes(p.read_bytes()[:-1])"
    )

    excluded = copy.deepcopy(profile)
    for entry in excluded["controls"]:
        entry["enabled"] = False
    result = lab.execute("apply", "all-excluded", excluded)
    assert result["summary"]["excluded"] == len(IDS) and result["changed_tasks"] == 0
    assert lab.remote("sudo stat -c %a " + LOG).strip() == "666"
    assert lab.execute("apply", "all-omitted", baseline)["changed_tasks"] == 0

    applied = lab.execute("apply", "selected-apply", profile)
    assert applied["summary"]["pass"] == len(IDS)
    assert lab.remote("rpm -qa | sort") == installed
    assert (
        lab.remote("sha256sum /etc/passwd /etc/dnf/dnf.conf /etc/yum.repos.d/rocky.repo")
        == untouched
    )
    assert lab.remote("sudo sha256sum " + LOG) == content
    current_repo = lab.remote("sudo cat " + REPO)
    assert (
        current_repo.split("[hardener-m7-unselected]")[1]
        == REPO_TEXT.split("[hardener-m7-unselected]")[1]
    )
    assert "# retained marker" in lab.remote("sudo cat /etc/chrony.conf")
    assert lab.execute("verify", "independent-verify", profile)["summary"]["pass"] == len(IDS)
    assert lab.execute("apply", "idempotent", profile)["changed_tasks"] == 0

    # Detect an unapproved source added only to the running daemon.
    clock = lab.profile(["time.chrony-enabled", "time.approved-sources"], PARAMETERS)
    lab.remote("sudo chronyc add server 127.0.0.2")
    assert lab.execute("verify", "unapproved-runtime-time-source", clock, 5)["summary"]["fail"] == 1
    lab.execute("apply", "repair-runtime-time-source", clock)
    assert lab.execute("apply", "clock-idempotent-after-repair", clock)["changed_tasks"] == 0

    # Unsigned package rejection uses the configured repository, not a local-install override.
    trial = subprocess.run(
        lab.ssh
        + ["sudo dnf -y --disablerepo='*' --enablerepo=hardener-m7 install hardener-m7-probe-2-1"],
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert trial.returncode != 0 and "not signed" in (trial.stdout + trial.stderr).lower()
    assert lab.remote("rpm -q --qf '%{VERSION}' hardener-m7-probe").strip() == "1"

    assessment = lab.profile(
        ["packages.security-update-status"],
        {"packages.security-update-status": {"repositories": ["hardener-m7"]}},
    )
    pending = lab.execute("audit", "security-update-pending", assessment, 5)
    assert pending["summary"]["fail"] == 1 and pending["changed_tasks"] == 0
    # The test fixture upgrades explicitly. The assessment never performs a transaction.
    lab.remote("sudo rpm -U /home/zero/m7-fixtures/repo/hardener-m7-probe-2-1.noarch.rpm")
    assert lab.execute("verify", "security-update-clear", assessment)["summary"]["pass"] == 1

    # Missing advisory metadata is an inspection error, never a clean result.
    lab.write(REPO, current_repo.replace("8443/repo", "8443/no-advisory"))
    missing = lab.execute("audit", "missing-advisory-metadata", assessment, 4)
    assert missing["summary"]["error"] == 1 and missing["changed_tasks"] == 0
    lab.write(REPO, current_repo)

    # A native HTTPS request must reject the untrusted lab certificate.
    lab.write(
        REPO,
        current_repo.replace("/home/zero/m7-fixtures/tls.crt", "/etc/pki/tls/certs/ca-bundle.crt"),
    )
    tls = lab.profile(
        ["packages.repository-metadata-signature"],
        {"packages.repository-metadata-signature": {"repositories": ["hardener-m7"]}},
    )
    failed_tls = lab.execute("apply", "refused-untrusted-tls", tls, 3)
    assert failed_tls["changed_tasks"] == 0
    lab.write(REPO, current_repo)

    # A changed on-disk journal policy cannot pass until journald reloads it.
    lab.remote("sudo touch " + JOURNAL)
    unloaded = lab.execute(
        "verify", "journal-restart-pending", lab.profile(["logging.journal-persistent"]), 5
    )
    assert unloaded["summary"]["fail"] == 1
    lab.execute("apply", "journal-reload", lab.profile(["logging.journal-persistent"]))
    # Real rotation exercises only the selected disposable log stanza.
    lab.remote("sudo logrotate --force --state /var/tmp/hardener-m7-rotation.state " + ROTATION)
    assert lab.remote("sudo stat -c %a " + LOG).strip() == "640"
    assert "M7 disposable log content" in lab.remote("sudo cat " + LOG + ".1")
    marker = "hardener-m7-persistent-marker"
    lab.remote("logger -t hardener-m7 " + shlex.quote(marker))
    lab.remote("sudo journalctl --sync")
    lab.reboot()
    assert marker in lab.remote("sudo journalctl -b -1 -t hardener-m7 --no-pager")
    lab.remote("chronyc waitsync 60 0.1 0 1")
    after = lab.execute("verify", "after-reboot", profile)
    assert after["summary"]["pass"] == len(IDS)
    assert lab.execute("apply", "after-reboot-idempotent", profile)["changed_tasks"] == 0
    assert lab.remote("sudo -n id -u").strip() == "0"
    lab.finish(
        {
            "controls": len(IDS) + 1,
            "lifecycle": True,
            "no_collateral_packages": True,
            "unsafe_preflights": 8,
            "signed_metadata": True,
            "unsigned_package_rejected": True,
            "untrusted_tls_rejected": True,
            "advisory_before_after": True,
            "real_rotation": True,
            "journal_survives_reboot": True,
            "reboot_verified": True,
            "idempotent": True,
        }
    )


if __name__ == "__main__":
    main()
