"""M6 file and kernel tests. Requires a snapshotted disposable Rocky guest."""

import json

from lab import GuestLab

FILES = {
    "files.group-permissions": [("/etc/group", "0644")],
    "files.shadow-permissions": [("/etc/shadow", "0000")],
    "files.gshadow-permissions": [("/etc/gshadow", "0000")],
    "files.account-backup-permissions": [
        ("/etc/passwd-", "0644"),
        ("/etc/group-", "0644"),
        ("/etc/shadow-", "0000"),
        ("/etc/gshadow-", "0000"),
    ],
}
KERNEL = {
    "kernel.protected-symlinks": ("fs.protected_symlinks", "1"),
    "kernel.randomize-address-space": ("kernel.randomize_va_space", "2"),
    "kernel.suid-dumpable": ("fs.suid_dumpable", "0"),
    "kernel.protected-fifos": ("fs.protected_fifos", "2"),
    "kernel.protected-regular": ("fs.protected_regular", "2"),
    "kernel.dmesg-restrict": ("kernel.dmesg_restrict", "1"),
    "kernel.kptr-restrict": ("kernel.kptr_restrict", "2"),
    "kernel.ptrace-scope": ("kernel.yama.ptrace_scope", "1"),
    "kernel.unprivileged-bpf-disabled": ("kernel.unprivileged_bpf_disabled", "2"),
}
MANAGED = "/etc/sysctl.d/99-rocky10-hardener.conf"
LATE = "/etc/sysctl.d/zz-hardener-m6-test.conf"


def main():
    lab = GuestLab(__doc__)
    ids = sorted(FILES | KERNEL)
    profile = lab.profile(ids)
    lab.execute("preflight", "preflight", profile)
    lab.remote("command -v setfacl")
    paths = [p for rows in FILES.values() for p, _ in rows]

    # Hashes remain private. No identity database bytes are emitted.
    def content_hashes():
        return lab.python(
            "import hashlib,json; from pathlib import Path; print(json.dumps({"
            f"p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in {paths!r}" + "}))"
        )

    original_hashes = content_hashes()
    original_config = lab.remote("sudo cat " + MANAGED)
    original_modes = json.loads(
        lab.python(
            "import os,stat,json; print(json.dumps({"
            f"p:stat.S_IMODE(os.stat(p).st_mode) for p in {paths!r}" + "}))"
        )
    )
    original_live = {
        cid: lab.remote("sudo sysctl -n " + key).strip() for cid, (key, _) in KERNEL.items()
    }
    unrelated = lab.remote(
        "sudo stat -c '%u:%g:%a' /etc/passwd; sha256sum /etc/passwd /etc/dnf/dnf.conf; cat /proc/sys/fs/protected_hardlinks"
    )
    lab.remote("sudo test ! -e " + LATE)

    def inject(cid):
        if cid in FILES:
            for path, mode in FILES[cid]:
                lab.remote("sudo chmod " + ("0664" if mode == "0644" else "0640") + " " + path)
        else:
            key, desired = KERNEL[cid]
            wrong = "1" if desired == "0" else "0"
            lab.remote("sudo sysctl -w " + key + "=" + wrong)

    def state(cid):
        if cid in FILES:
            return lab.python(
                "import os,stat,json; print(json.dumps(["
                f"(p,stat.S_IMODE(os.lstat(p).st_mode)) for p in {[p for p, _ in FILES[cid]]!r}"
                + "]))"
            )
        return lab.remote("sudo sysctl -n " + KERNEL[cid][0])

    try:
        for cid in ids:
            inject(cid)
        before = lab.execute("audit", "before", profile, 5)
        assert before["summary"]["fail"] == len(ids) and before["changed_tasks"] == 0
        assert content_hashes() == original_hashes

        lab.write(LATE, "kernel.randomize_va_space=0\n")
        snapshot = {cid: state(cid) for cid in ids}
        blocked = lab.execute("apply", "refused-later-conflict", profile, 3)
        assert blocked["changed_tasks"] == 0
        assert snapshot == {cid: state(cid) for cid in ids}
        lab.remove(LATE)

        lab.remote("sudo setfacl -m u:65534:r-- /etc/group")
        custom_acl = lab.remote("sudo getfacl -cp /etc/group")
        try:
            blocked = lab.execute("apply", "refused-custom-acl", profile, 3)
            assert blocked["changed_tasks"] == 0
            assert lab.remote("sudo getfacl -cp /etc/group") == custom_acl
        finally:
            lab.remote("sudo setfacl -b /etc/group")

        applied = lab.execute("apply", "apply", profile)
        assert applied["summary"]["pass"] == len(ids)
        assert lab.execute("verify", "after", profile)["summary"]["pass"] == len(ids)
        assert lab.execute("apply", "rerun", profile)["changed_tasks"] == 0
        assert content_hashes() == original_hashes
        assert (
            lab.remote(
                "sudo stat -c '%u:%g:%a' /etc/passwd; sha256sum /etc/passwd /etc/dnf/dnf.conf; cat /proc/sys/fs/protected_hardlinks"
            )
            == unrelated
        )
        for cid in ids:
            inject(cid)
            before = state(cid)
            excluded = lab.profile([cid])
            excluded["controls"][0].update(enabled=False, reason="M6 exclusion test")
            report = lab.execute("apply", "excluded-" + cid, excluded)
            assert report["changed_tasks"] == 0 and report["summary"]["excluded"] == 1
            assert state(cid) == before
            assert (
                lab.execute("apply", "restore-" + cid, lab.profile([cid]))["summary"]["pass"] == 1
            )
        inject("kernel.protected-symlinks")
        before = state("kernel.protected-symlinks")
        lab.execute("apply", "omitted", lab.profile(["files.group-permissions"]))
        assert state("kernel.protected-symlinks") == before
        lab.execute("apply", "restore-omitted", lab.profile(["kernel.protected-symlinks"]))
        # Backup-only paths can be safely isolated without removing active databases.
        backups = [path for path, _ in FILES["files.account-backup-permissions"]]
        for path in backups:
            lab.remote(
                "sudo test ! -e " + path + ".m6-saved && sudo mv " + path + " " + path + ".m6-saved"
            )
        try:
            empty = lab.execute(
                "audit", "backups-absent", lab.profile(["files.account-backup-permissions"])
            )
            assert empty["summary"]["not_applicable"] == 1
            lab.execute(
                "apply", "backups-absent-apply", lab.profile(["files.account-backup-permissions"])
            )
            for path in backups:
                lab.remote("sudo test ! -e " + path)
            lab.remote("sudo ln -s /etc/passwd /etc/passwd-")
            try:
                refusal = lab.execute("apply", "refused-backup-symlink", profile, 3)
                assert refusal["changed_tasks"] == 0
            finally:
                lab.remove("/etc/passwd-")
        finally:
            for path in backups:
                lab.remote("sudo mv " + path + ".m6-saved " + path)
        lab.reboot()
        final = lab.execute("verify", "after-reboot", profile)
        assert final["summary"]["pass"] == len(ids)
        assert content_hashes() == original_hashes
        assert lab.execute("apply", "after-reboot-rerun", profile)["changed_tasks"] == 0
        lab.finish(
            {
                "m6": "pass",
                "controls": len(ids),
                "content_preserved": True,
                "all_exclusions": True,
                "omission": True,
                "late_conflict_refused": True,
                "backup_absence": True,
                "custom_acl_preserved": True,
                "backup_symlink_refused": True,
                "reboot_persistence": True,
                "idempotence": True,
            }
        )
    except BaseException:
        lab.remove(LATE)
        lab.write(MANAGED, original_config)
        for cid, value in original_live.items():
            lab.remote("sudo sysctl -w " + KERNEL[cid][0] + "=" + value)
        for path, mode in original_modes.items():
            lab.python(f"import os; os.chmod({path!r},{mode})")
        raise


if __name__ == "__main__":
    main()
