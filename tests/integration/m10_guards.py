"""Refuse unsafe M10 changes before any selected policy writes."""

import copy
from pathlib import Path

import yaml
from m10_identity import IdentityLab


def main():
    lab = IdentityLab(__doc__)
    base = yaml.safe_load(Path("profiles/examples/server-identity-lab.yaml").read_text())
    entries = {c["id"]: c for c in base["controls"]}
    cases = []

    def profile(cid, changes=None):
        entry = copy.deepcopy(entries[cid])
        entry["parameters"].update(changes or {})
        return {**base, "controls": [entry]}

    def refuse(name, selected):
        before = lab.managed_state()
        result = lab.execute("apply", name, selected, 3)
        assert result["changed_tasks"] == 0 and lab.managed_state() == before
        assert lab.remote("sudo -n id -u").strip() == "0"
        cases.append(name)

    for name, cid, params in [
        ("root-aging", "auth.password-aging", {"users": ["root"]}),
        ("recovery-home", "accounts.home-permissions", {"users": ["zero"]}),
        ("missing-account", "auth.inactive-account-lock", {"users": ["m10absent"]}),
        ("human-as-service", "accounts.system-login-disabled", {"users": ["m10human"]}),
        ("nonexempt-recovery", "auth.failed-login-lockout", {"exempt_group": "m10deny"}),
        ("su-excluded-recovery", "auth.su-access-policy", {"group": "m10deny"}),
    ]:
        refuse(name, profile(cid, params))

    def altered_file(name, cid, path, addition):
        original = lab.remote("sudo cat " + path)
        try:
            lab.write(path, original + addition)
            refuse(name, profile(cid))
        finally:
            lab.write(path, original)

    altered_file(
        "duplicate-quality", "auth.password-quality", "/etc/security/pwquality.conf", "\nminlen=8\n"
    )
    altered_file(
        "root-lockout",
        "auth.failed-login-lockout",
        "/etc/security/faillock.conf",
        "\neven_deny_root\n",
    )
    altered_file(
        "custom-su", "auth.su-access-policy", "/etc/pam.d/su", "\n# unreviewed custom stack\n"
    )
    altered_file(
        "custom-user-startup", "auth.default-umask", "/home/m10human/.bashrc", "\numask 000\n"
    )
    altered_file(
        "tampered-authselect",
        "auth.password-history",
        "/etc/pam.d/system-auth",
        "\npassword requisite pam_deny.so\n",
    )
    altered_file(
        "custom-passwd-entry",
        "auth.password-history",
        "/etc/pam.d/passwd",
        "\n# unreviewed password entry point\n",
    )
    altered_file(
        "custom-su-login-entry",
        "auth.su-access-policy",
        "/etc/pam.d/su-l",
        "\n# unreviewed login entry point\n",
    )
    altered_file(
        "custom-skeleton",
        "auth.default-umask",
        "/etc/skel/.bashrc",
        "\n# unreviewed startup skeleton\n",
    )
    drop = "/etc/security/pwquality.conf.d/00-m10-fixture.conf"
    try:
        lab.write(drop, "minlen=8\n")
        refuse("quality-drop-in", profile("auth.password-quality"))
    finally:
        lab.remove(drop)
    try:
        lab.remote("sudo chmod 0666 /etc/security/pwhistory.conf")
        refuse("unsafe-policy-mode", profile("auth.password-history"))
    finally:
        lab.remote("sudo chmod 0644 /etc/security/pwhistory.conf")
    try:
        lab.remote("sudo setfacl -m u:65534:rx /home/m10human")
        refuse("home-acl", profile("accounts.home-permissions"))
    finally:
        lab.remote("sudo setfacl -b /home/m10human; sudo chmod 0700 /home/m10human")
    original = lab.remote("sudo authselect current --raw").strip()
    try:
        lab.remote("sudo authselect select sssd --force")
        refuse("domain-profile", profile("auth.password-quality"))
    finally:
        lab.remote("sudo authselect select " + original + " --force")
    # A reviewed su rule insertion must retain the existing safe file group.
    su_path = "/etc/pam.d/su"
    original_su = lab.remote("sudo cat " + su_path)
    original_gid = lab.remote("sudo stat -c %g " + su_path).strip()
    fixture_gid = lab.remote("id -g m10human").strip()
    try:
        lab.write(
            su_path,
            "".join(
                row
                for row in original_su.splitlines(keepends=True)
                if "# rocky10-hardener-su" not in row
            ),
        )
        lab.remote("sudo chgrp " + fixture_gid + " " + su_path)
        result = lab.execute("apply", "safe-group-preserved", profile("auth.su-access-policy"))
        assert result["summary"]["pass"] == 1
        assert lab.remote("sudo stat -c %g " + su_path).strip() == fixture_gid
    finally:
        lab.write(su_path, original_su)
        lab.remote("sudo chgrp " + original_gid + " " + su_path)
    assert lab.execute("verify", "restored-policy", base)["summary"]["pass"] == 10
    lab.finish(
        {
            "zero_write_refusals": len(cases),
            "cases": cases,
            "fresh_access_preserved": True,
            "safe_file_group_preserved": True,
        }
    )


if __name__ == "__main__":
    main()
