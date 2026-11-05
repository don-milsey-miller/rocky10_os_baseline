"""M10 disposable local identity lifecycle. Requires the identity-ready snapshot."""

import copy
import json
import secrets
import subprocess
from pathlib import Path

import yaml
from lab import GuestLab

PROBE = "/run/hardener-m10-pam.py"
PRIVATE = Path.home() / ".cache/m10-fixture.json"
DATABASES = ["/etc/passwd", "/etc/shadow", "/etc/group"]


class IdentityLab(GuestLab):
    def install_probe(self):
        self.write(PROBE, Path(__file__).with_name("m10_pam_probe.py").read_text())
        self.remote("sudo chmod 0755 " + PROBE)

    def pam(self, user, operation="authenticate", password=""):
        request = {
            "service": "login",
            "user": user,
            "operation": operation,
            "password": password,
        }
        result = subprocess.run(
            self.ssh + [f"sudo -u {user} /usr/bin/python3 {PROBE}"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, "Native PAM probe failed without usable evidence"
        return json.loads(result.stdout)

    def password(self, old, new):
        result = subprocess.run(
            self.ssh + ["sudo -u m10human /usr/bin/passwd"],
            input=old + "\n" + new + "\n" + new + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result.returncode

    def su(self, actor, password):
        result = subprocess.run(
            self.ssh + [f"sudo -u {actor} /usr/bin/su m10human -c /usr/bin/id"],
            input=password + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result.returncode

    def managed_state(self):
        return self.python(
            "from pathlib import Path;import hashlib,json,os;"
            "paths=[Path(p) for p in ['/etc/passwd','/etc/shadow','/etc/group',"
            "'/etc/security/pwquality.conf','/etc/security/pwhistory.conf','/etc/security/faillock.conf',"
            "'/etc/pam.d/su','/etc/authselect/authselect.conf']];"
            "paths+=list(Path('/etc/authselect').glob('*-auth'));"
            "paths+=list(Path('/etc/profile.d').glob('zz-rocky10-hardener-*.sh'));"
            "result={str(p):[hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mode,"
            "p.stat().st_uid,p.stat().st_gid] for p in paths if p.is_file()};"
            "result['home_mode']=Path('/home/m10human').stat().st_mode;"
            "print(json.dumps(result,sort_keys=True))"
        )

    def stable_accounts(self):
        # Exclude selected fixture identities. Compare actual password fields only inside guest.
        return self.python(
            "from pathlib import Path;import hashlib,json;"
            "print(json.dumps({p:hashlib.sha256(('\\n'.join(r for r in Path(p).read_text().splitlines() "
            "if not r.startswith(('m10human:', 'm10service:')))).encode()).hexdigest() "
            f"for p in {DATABASES!r}" + "}))"
        )


def main():
    lab = IdentityLab(__doc__)
    profile = yaml.safe_load(Path("profiles/examples/server-identity-lab.yaml").read_text())
    passwords = json.loads(PRIVATE.read_text())
    original = passwords["m10human"]
    lab.install_probe()
    unchanged = lab.stable_accounts()
    service_pid = lab.remote("sudo systemctl show -p MainPID --value hardener-m10-service").strip()
    lab.python(
        "from pathlib import Path;import os,pwd;"
        "p=Path('/home/m10human/preserved-content');p.write_text('preserve contents and metadata\\n');"
        "u=pwd.getpwnam('m10human');os.chown(p,u.pw_uid,u.pw_gid);p.chmod(0o664)"
    )
    child = lab.remote("sudo stat -c '%u:%g:%a:%s' /home/m10human/preserved-content")

    assert lab.pam("m10human", password=original) == {"authentication": 0, "account": 0}
    assert lab.su("m10deny", original) == 0
    initial_state = lab.managed_state()
    before = lab.execute("audit", "before", profile, 5)
    assert lab.managed_state() == initial_state
    assert before["summary"]["fail"] == 10 and before["changed_tasks"] == 0
    lab.execute("preflight", "preflight", profile)
    excluded = copy.deepcopy(profile)
    for entry in excluded["controls"]:
        entry["enabled"] = False
        entry["reason"] = "Disposable exclusion proof"
    assert lab.execute("apply", "excluded", excluded)["changed_tasks"] == 0
    assert (
        lab.execute("apply", "omitted", lab.profile(["files.passwd-permissions"]))["changed_tasks"]
        == 0
    )
    assert lab.managed_state() == initial_state
    assert lab.execute("apply", "first-apply", profile)["summary"]["pass"] == 10
    applied_state = lab.managed_state()
    assert lab.execute("verify", "verify", profile)["summary"]["pass"] == 10
    assert lab.managed_state() == applied_state
    assert lab.execute("apply", "repeat-apply", profile)["changed_tasks"] == 0
    assert lab.stable_accounts() == unchanged, "Unselected account database entries changed"
    assert lab.remote("sudo systemctl is-active hardener-m10-service").strip() == "active"
    assert (
        lab.remote("sudo systemctl show -p MainPID --value hardener-m10-service").strip()
        == service_pid
    )
    assert lab.remote("sudo stat -c '%u:%g:%a:%s' /home/m10human/preserved-content") == child
    assert (
        lab.remote("sudo cat /home/m10human/preserved-content").strip()
        == "preserve contents and metadata"
    )
    assert lab.remote("sudo -n id -u").strip() == "0"
    print("Configuration lifecycle and preservation passed", flush=True)
    weak = lab.password(original, secrets.token_urlsafe(18)[:13])
    assert weak != 0, "Weak password unexpectedly accepted"
    current = secrets.token_urlsafe(18)[:14]
    assert lab.password(original, current) == 0
    passwords["m10human"] = current
    cache = PRIVATE.with_name("m10-current.json")
    cache.write_text(json.dumps(passwords))
    cache.chmod(0o600)
    assert lab.pam("m10human", password=current) == {"authentication": 0, "account": 0}
    assert lab.password(current, original) != 0
    # Native pam_pwhistory includes the current password among the retained entries.
    for _ in range(3):
        replacement = secrets.token_urlsafe(24)
        assert lab.password(current, replacement) == 0
        current = replacement
    assert lab.password(current, original) != 0, "Five-password history boundary not enforced"
    replacement = secrets.token_urlsafe(24)
    assert lab.password(current, replacement) == 0
    current = replacement
    assert lab.password(current, original) == 0, "Password older than five entries remained blocked"
    current = original
    passwords["m10human"] = current
    cache.write_text(json.dumps(passwords))
    assert lab.su("m10allow", current) == 0
    assert lab.su("m10deny", current) != 0
    print("Native password quality, history and su passed", flush=True)
    lab.remote("sudo faillock --user m10human --reset")
    for _ in range(4):
        assert lab.pam("m10human", password="wrong-disposable-password")["authentication"] != 0
    assert lab.pam("m10human", password=current) == {"authentication": 0, "account": 0}
    for _ in range(5):
        assert lab.pam("m10human", password="wrong-disposable-password")["authentication"] != 0
    assert lab.pam("m10human", password=current)["authentication"] != 0
    assert lab.remote("sudo -n id -u").strip() == "0"
    for _ in range(5):
        assert lab.pam("m10allow", password="wrong-exempt-fixture-password")["authentication"] != 0
    assert lab.pam("m10allow", password=passwords["m10allow"]) == {
        "authentication": 0,
        "account": 0,
    }, "Recovery group was not exempt from lockout"
    # Explicit administrator unlock must restore password authentication.
    lab.remote("sudo faillock --user m10human --reset")
    assert lab.pam("m10human", password=current) == {"authentication": 0, "account": 0}
    # Native account management proves expiration and inactivity enforcement.
    lab.remote("sudo chage -d $(date -d '91 days ago' +%F) m10human")
    assert lab.pam("m10human", "account")["account"] == 12
    lab.remote("sudo chage -d $(date -d '121 days ago' +%F) m10human")
    assert lab.pam("m10human", "account")["account"] != 0
    lab.remote("sudo chage -d $(date +%F) m10human")
    assert lab.pam("m10human", password=current) == {"authentication": 0, "account": 0}
    service = subprocess.run(
        lab.ssh + ["sudo su - m10service -c /usr/bin/true"],
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert service.returncode != 0
    assert lab.remote("sudo -u m10service /usr/bin/id -un").strip() == "m10service"
    print("Lockout, unlock, expiration, inactivity and service checks passed", flush=True)
    lab.reboot()
    lab.install_probe()
    assert lab.execute("verify", "after-reboot", profile)["summary"]["pass"] == 10
    assert lab.execute("apply", "repeat-after-reboot", profile)["changed_tasks"] == 0
    assert lab.pam("m10human", password=current) == {"authentication": 0, "account": 0}
    assert lab.remote("sudo systemctl is-active hardener-m10-service").strip() == "active"
    assert lab.stable_accounts() == unchanged, "Unselected account database entries changed"
    # Keep the current random fixture password private for optional timed probes.
    passwords["m10human"] = current
    cache = PRIVATE.with_name("m10-current.json")
    cache.write_text(json.dumps(passwords))
    cache.chmod(0o600)
    lab.finish(
        {
            "controls": 10,
            "real_password_authentication": True,
            "weak_password_denied": True,
            "history_reuse_denied": True,
            "lockout_and_admin_unlock": True,
            "allowed_and_denied_su": True,
            "expiration_and_inactivity": True,
            "service_job_preserved": True,
            "unselected_identities_unchanged": True,
            "reboot_verified": True,
            "zero_change_reruns": True,
        }
    )


if __name__ == "__main__":
    main()
