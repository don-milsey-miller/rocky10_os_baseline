"""M8 real access-policy lifecycle. Restore m7-verified before each full run."""

import copy
import hashlib
import secrets

from m8_protocols import AccessLab

SSH = "/etc/ssh/sshd_config.d/00-rocky10-hardener.conf"
FIXTURE = "/etc/ssh/sshd_config.d/90-hardener-m8-fixture.conf"
SUDO = "/etc/sudoers.d/80-hardener-m8-fixture"
PARAMETERS = {
    "auth.ssh-access-policy": {"users": ["zero", "m8admin", "m8empty", "root"], "groups": []},
    "auth.ssh-forwarding-policy": {
        "tcp": "no",
        "streamlocal": "no",
        "agent": False,
        "x11": False,
        "tunnel": False,
    },
    "auth.ssh-session-limits": {
        "max_auth_tries": 2,
        "max_sessions": 2,
        "max_startups": 3,
        "login_grace_seconds": 30,
        "idle_session_seconds": 30,
    },
    "auth.sudo-authentication": {"users": ["m8admin"]},
    "auth.sudo-timeout": {"users": ["m8admin"], "minutes": 0},
}
IDS = [
    "auth.ssh-config-permissions",
    "auth.ssh-hostkey-permissions",
    "auth.ssh-empty-passwords",
    "auth.ssh-hostbased-auth",
    "auth.ssh-root-login",
    "auth.ssh-password-login",
    "auth.ssh-access-policy",
    "auth.ssh-forwarding-policy",
    "auth.ssh-session-limits",
    "auth.sudo-config-permissions",
    "auth.sudo-use-pty",
    "auth.sudo-authentication",
    "auth.sudo-timeout",
]
NONCOMPLIANT = """# retained SSH marker
PermitEmptyPasswords yes
HostbasedAuthentication yes
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
AllowAgentForwarding yes
X11Forwarding yes
PermitTunnel yes
MaxAuthTries 6
MaxSessions 10
MaxStartups 10:30:100
LoginGraceTime 120
ChannelTimeout none
"""


def main():
    lab = AccessLab(__doc__)
    try:
        exercise(lab)
    finally:
        lab.close()


def exercise(lab):
    lab.execute("preflight", "target-guard", lab.profile(["files.passwd-permissions"]))
    password = secrets.token_urlsafe(24)
    for user in ["m8admin", "m8denied", "m8empty", "m8outside", "m8group"]:
        group = " -G wheel" if user in ["m8admin", "m8group"] else ""
        lab.remote(f"sudo useradd -m -s /bin/bash{group} {user}")
        lab.python(
            "from pathlib import Path; import pwd,os; "
            f"p=Path('/home/{user}/.ssh');p.mkdir(mode=0o700);"
            f"q=p/'authorized_keys';q.write_text({lab.public_key + chr(10)!r});q.chmod(0o600);"
            f"u=pwd.getpwnam({user!r});os.chown(p,u.pw_uid,u.pw_gid);os.chown(q,u.pw_uid,u.pw_gid)"
        )
        lab.remote(f"sudo restorecon -RF /home/{user}/.ssh")
    lab.run(lab.ssh + ["sudo chpasswd"], input="m8admin:" + password + "\n")
    lab.remote("sudo passwd -d m8empty")
    root_original = lab.python(
        "from pathlib import Path;p=Path('/root/.ssh/authorized_keys');"
        "import json;print(json.dumps(p.read_text() if p.exists() else None))"
    )
    import json

    root_original = json.loads(root_original)
    lab.python(
        "from pathlib import Path;"
        "p=Path('/root/.ssh');p.mkdir(mode=0o700,exist_ok=True);q=p/'authorized_keys';"
        f"q.write_text({(root_original or '') + chr(10) + lab.public_key + chr(10)!r});q.chmod(0o600)"
    )
    lab.remote("sudo restorecon -RF /root/.ssh")
    lab.write(FIXTURE, "# disposable protocol fixture\nPerSourcePenalties no\n")
    lab.write(SSH, NONCOMPLIANT)
    lab.remote("sudo chmod 0644 /etc/ssh/sshd_config /etc/ssh/ssh_host_rsa_key")
    lab.reload_ssh()
    original_sudo = (
        "# retained sudo marker\nDefaults !use_pty\n"
        "Defaults:m8admin timestamp_timeout=5\n"
        "m8admin ALL=(ALL) NOPASSWD: ALL\n"
    )
    lab.write(SUDO, original_sudo)
    lab.remote("sudo chmod 0440 " + SUDO)
    lab.remote("sudo visudo -c")
    lab.remote("sudo chmod 0644 /etc/sudoers /etc/sudo.conf")
    profile = lab.profile(IDS, PARAMETERS)
    untouched = lab.remote("sudo sha256sum /etc/ssh/ssh_host_*_key /etc/sudoers.d/90-lab-zero")
    labels = lab.remote("sudo stat -c '%n %C' /etc/ssh/ssh_host_*_key /etc/ssh/sshd_config")
    assert lab.connection("root", "id -u").stdout.strip() == "0"
    assert lab.connection("m8admin", secret=password).returncode == 0
    assert lab.connection("m8empty", secret="").returncode == 0
    offered = lab.connection(extra=["-vv", "-o", "PreferredAuthentications=hostbased"])
    assert any(
        "Authentications that can continue:" in line and "hostbased" in line
        for line in offered.stderr.splitlines()
    )
    assert lab.connection("m8denied").returncode == 0
    assert lab.connection(keys=[*lab.bad_keys, lab.key]).returncode == 0
    lab.forwarding(True)
    assert lab.execute("audit", "noncompliant", profile, 5)["summary"]["fail"] == len(IDS)

    lab.execute("preflight", "valid-candidate", profile)

    def refused(name, candidate=profile):
        result = lab.execute("apply", name, candidate, 3)
        assert result["changed_tasks"] == 0
        assert lab.remote("sudo cat " + SSH) == NONCOMPLIANT
        assert (
            lab.remote("sudo sha256sum /etc/ssh/ssh_host_*_key /etc/sudoers.d/90-lab-zero")
            == untouched
        )

    early = "/etc/ssh/sshd_config.d/00-aaa-m8.conf"
    lab.write(early, "PermitRootLogin yes\n")
    refused("refused-earlier-ssh-policy")
    lab.remove(early)
    lab.write(FIXTURE, "PerSourcePenalties no\nMatch User m8denied\n X11Forwarding no\n")
    refused("refused-match")
    lab.write(FIXTURE, "PerSourcePenalties no\n")
    lab.remote("sudo setfacl -m u:65534:r-- /etc/ssh/ssh_host_rsa_key")
    refused("refused-hostkey-acl")
    lab.remote("sudo setfacl -b /etc/ssh/ssh_host_rsa_key")
    lab.remote("sudo chmod 0644 /etc/ssh/ssh_host_rsa_key")
    denied = copy.deepcopy(profile)
    next(c for c in denied["controls"] if c["id"] == "auth.ssh-access-policy")["parameters"][
        "users"
    ] = ["m8admin"]
    refused("refused-administrator-exclusion", denied)
    selected_recovery = copy.deepcopy(profile)
    next(c for c in selected_recovery["controls"] if c["id"] == "auth.sudo-authentication")[
        "parameters"
    ]["users"] = ["zero", "m8admin"]
    refused("refused-recovery-sudo-change", selected_recovery)
    group = copy.deepcopy(profile)
    next(c for c in group["controls"] if c["id"] == "auth.sudo-authentication")["parameters"][
        "users"
    ] = ["m8admin", "m8group"]
    lab.write(SUDO, original_sudo + "%wheel ALL=(ALL) NOPASSWD: ALL\n")
    refused("refused-group-only-sudo-grant", group)
    lab.write(SUDO, original_sudo)
    lab.write(SUDO, original_sudo + "Defaults:m8denied !use_pty\n")
    refused("refused-scoped-no-pty")
    lab.write(SUDO, original_sudo)
    subjects = copy.deepcopy(profile)
    next(c for c in subjects["controls"] if c["id"] == "auth.sudo-timeout")["parameters"][
        "users"
    ] = ["m8group"]
    refused("refused-timeout-subject-mismatch", subjects)

    # Remove the deliberate group-only NOPASSWD conflict before remediation.
    original_sudo = original_sudo.replace("%wheel ALL=(ALL) NOPASSWD: ALL\n", "")
    lab.write(SUDO, original_sudo)
    excluded = copy.deepcopy(profile)
    for entry in excluded["controls"]:
        entry["enabled"] = False
    assert lab.execute("apply", "excluded", excluded)["changed_tasks"] == 0
    assert (
        lab.execute("apply", "omitted", lab.profile(["files.passwd-permissions"]))["changed_tasks"]
        == 0
    )
    assert lab.execute("apply", "selected-apply", profile)["summary"]["pass"] == len(IDS)
    assert lab.execute("verify", "independent-verify", profile)["summary"]["pass"] == len(IDS)
    assert lab.execute("apply", "idempotent", profile)["changed_tasks"] == 0
    assert (
        lab.remote("sudo sha256sum /etc/ssh/ssh_host_*_key /etc/sudoers.d/90-lab-zero") == untouched
    )
    assert lab.remote("sudo stat -c '%n %C' /etc/ssh/ssh_host_*_key /etc/ssh/sshd_config") == labels
    assert lab.remote("sudo cat " + SUDO) == original_sudo.replace("NOPASSWD:", "PASSWD:")
    assert "# retained SSH marker" in lab.remote("sudo cat " + SSH)
    assert lab.connection(command="sudo -n id -u").stdout.strip() == "0"
    assert lab.connection("m8admin").returncode == 0
    assert lab.connection("m8admin", secret=password).returncode != 0
    assert lab.connection("root").returncode != 0
    assert lab.connection("m8denied").returncode != 0
    failures = lab.connection(keys=[*lab.bad_keys, lab.key])
    assert failures.returncode != 0 and "Too many authentication failures" in failures.stderr
    offered = lab.connection(extra=["-vv", "-o", "PreferredAuthentications=hostbased"])
    methods = [
        line for line in offered.stderr.splitlines() if "Authentications that can continue:" in line
    ]
    assert methods and all("hostbased" not in line for line in methods)
    # Isolate empty-password rejection from the independent password-login policy.
    installed_ssh = lab.remote("sudo cat " + SSH)
    lab.write(SSH, installed_ssh.replace("PasswordAuthentication no", "PasswordAuthentication yes"))
    lab.reload_ssh()
    assert lab.connection("m8admin", secret=password).returncode == 0
    assert lab.connection("m8empty", secret="").returncode != 0
    lab.execute(
        "apply",
        "restore-password-login-policy",
        lab.profile(
            [
                "auth.ssh-config-permissions",
                "auth.ssh-hostkey-permissions",
                "auth.ssh-password-login",
            ]
        ),
    )
    lab.forwarding(False)
    lab.startup_limit(3)
    lab.session_limit(2)
    idle = lab.idle_limit(30)
    assert lab.connection("m8admin", "sudo -k -n id -u").returncode != 0
    wrong = lab.connection("m8admin", "sudo -S -p '' id -u", input="incorrect-fixture-password\n")
    assert wrong.returncode != 0
    correct = lab.connection("m8admin", "sudo -S -p '' id -u", input=password + "\n")
    assert correct.returncode == 0 and correct.stdout.strip() == "0"
    cache = lab.connection(
        "m8admin",
        "sudo -k; sudo -S -p '' id -u; sudo -n id -u; result=$?; exit $result",
        input=password + "\n",
    )
    assert cache.returncode != 0 and cache.stdout.strip() == "0"
    pty = lab.connection(command="tty; sudo -n tty", extra=["-tt"])
    devices = [line.strip() for line in pty.stdout.splitlines() if line.startswith("/dev/")]
    assert len(devices) == 2 and devices[0] != devices[1]

    access_ids = [
        "auth.ssh-config-permissions",
        "auth.ssh-hostkey-permissions",
        "auth.ssh-access-policy",
    ]
    group_parameters = copy.deepcopy(PARAMETERS)
    group_parameters["auth.ssh-access-policy"] = {
        "users": ["zero", "m8admin", "m8outside"],
        "groups": [],
    }
    lab.execute("apply", "allow-outside-user", lab.profile(access_ids, group_parameters))
    assert lab.connection("m8outside").returncode == 0
    group_parameters["auth.ssh-access-policy"]["groups"] = ["wheel"]
    lab.execute("apply", "restrict-outside-group", lab.profile(access_ids, group_parameters))
    assert lab.connection("m8outside").returncode != 0
    final_parameters = copy.deepcopy(PARAMETERS)
    final_parameters["auth.ssh-access-policy"] = {"users": ["zero", "m8admin"], "groups": ["wheel"]}
    final_parameters["auth.ssh-session-limits"]["idle_session_seconds"] = 300
    final = lab.profile(IDS, final_parameters)
    lab.execute("apply", "final-policy", final)
    lab.remote("sudo touch " + SSH)
    assert lab.execute("verify", "reload-pending", final, 5)["summary"]["fail"] >= 1
    lab.execute("apply", "repair-unloaded-policy", final)
    removed = "/etc/ssh/sshd_config.d/00-aaa-m8-removed.conf"
    lab.write(removed, "PermitEmptyPasswords yes\n")
    lab.remote("sudo chmod 0600 " + removed)
    lab.reload_ssh()
    lab.remove(removed)
    # On-disk policy is compliant again, but the daemon still has the deleted override.
    pending = lab.profile(
        ["auth.ssh-config-permissions", "auth.ssh-hostkey-permissions", "auth.ssh-empty-passwords"]
    )
    assert (
        lab.execute("verify", "removed-dropin-reload-pending", pending, 5)["summary"]["fail"] == 1
    )
    lab.execute("apply", "repair-removed-dropin", pending)
    if root_original is None:
        lab.remove("/root/.ssh/authorized_keys")
    else:
        lab.write("/root/.ssh/authorized_keys", root_original)
    lab.remove(FIXTURE)
    lab.remote("sudo usermod -L m8empty")
    lab.reload_ssh()
    lab.execute("verify", "fixture-cleaned", final)
    lab.reboot()
    lab.execute("verify", "after-reboot", final)
    assert lab.execute("apply", "after-reboot-idempotent", final)["changed_tasks"] == 0
    assert lab.connection("m8admin", "sudo -S -p '' id -u", input=password + "\n").returncode == 0
    assert lab.connection(command="sudo -n id -u").stdout.strip() == "0"
    for evidence in lab.output.rglob("*"):
        if evidence.is_file():
            assert password.encode() not in evidence.read_bytes(), "Credential leaked to evidence"
    lab.finish(
        {
            "controls": len(IDS),
            "lifecycle": True,
            "unsafe_preflights": 8,
            "private_hostkeys_unchanged": True,
            "selinux_labels_preserved": True,
            "root_key_denied": True,
            "empty_password_rejected_independently": True,
            "hostbased_method_removed": True,
            "password_login_denied": True,
            "user_and_group_allowlists": True,
            "tcp_forwarding_denied": True,
            "authentication_attempt_limit": True,
            "startup_limit": 3,
            "session_limit": 2,
            "idle_disconnect_seconds": idle,
            "sudo_password_verified": True,
            "sudo_zero_minute_cache": True,
            "sudo_pty": True,
            "fresh_recovery_access": True,
            "reboot_verified": True,
            "idempotent": True,
            "recovery_sudo_hash": hashlib.sha256(untouched.encode()).hexdigest(),
        }
    )


if __name__ == "__main__":
    main()
