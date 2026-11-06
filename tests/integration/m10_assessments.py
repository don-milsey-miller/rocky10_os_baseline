"""M10 read-only assessment acceptance with isolated disposable database fixtures."""

from lab import GuestLab

IDS = [
    "accounts.unique-identities",
    "accounts.root-only-uid-zero",
    "accounts.no-empty-passwords",
    "accounts.root-path-integrity",
]
BACKUP = "/run/hardener-m10-assessment"
FILES = ["/etc/passwd", "/etc/shadow", "/etc/group"]


def fingerprint(lab):
    return lab.python(
        "import hashlib,json;from pathlib import Path;"
        f"print(json.dumps({{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in {FILES!r}}}))"
    )


def main():
    lab = GuestLab(__doc__)
    lab.execute("preflight", "platform-guard", lab.profile(["files.passwd-permissions"]))
    before = fingerprint(lab)
    lab.python(
        "from pathlib import Path;import shutil;"
        f"b=Path({BACKUP!r});b.mkdir(mode=0o700);"
        f"[shutil.copy2(p,b/Path(p).name) for p in {FILES!r}]"
    )
    try:
        # Account records are locked and use nologin. No existing account is modified.
        lab.python(
            "from pathlib import Path;"
            "p=Path('/etc/passwd');p.write_text(p.read_text()+"
            "'m10probe:x:45001:45001::/nonexistent:/sbin/nologin\\n"
            "m10alias:x:45001:45001::/nonexistent:/sbin/nologin\\n"
            "m10rootprobe:x:0:0::/nonexistent:/sbin/nologin\\n');"
            "p=Path('/etc/group');p.write_text(p.read_text()+"
            "'m10probe:x:45001:\\nm10alias:x:45001:\\n');"
            "p=Path('/etc/shadow');p.write_text(p.read_text()+"
            "'m10probe:!:20000:0:99999:7:::\\n"
            "m10alias::20000:0:99999:7:::\\n"
            "m10rootprobe:!:20000:0:99999:7:::\\n')"
        )
        fixture = fingerprint(lab)
        profile = lab.profile(IDS[:3])
        for mode in ("audit", "verify"):
            report = lab.execute(mode, "unsafe-" + mode, profile, 5)
            assert report["changed_tasks"] == 0 and report["summary"]["fail"] == 3
            assert fingerprint(lab) == fixture
        # Assessment-only controls must reject apply before target writes.
        from hardener.validation import ValidationError, load_catalog, validate

        try:
            validate(profile, load_catalog(), mode="apply")
        except ValidationError:
            pass
        else:
            raise AssertionError("Assessment-only apply unexpectedly accepted")
        assert fingerprint(lab) == fixture
    finally:
        lab.python(
            "from pathlib import Path;import shutil;"
            f"b=Path({BACKUP!r});"
            f"[Path(p).write_bytes((b/Path(p).name).read_bytes()) for p in {FILES!r}];"
            "shutil.rmtree(b)"
        )
    assert fingerprint(lab) == before
    healthy = lab.execute("verify", "restored-identities", lab.profile(IDS[:3]))
    assert healthy["summary"]["pass"] == 3 and healthy["changed_tasks"] == 0
    # Missing root PATH entries are real findings, not grounds to alter root's profile.
    result = lab.execute("verify", "root-path-observed", lab.profile([IDS[3]]), 5)
    assert result["summary"]["fail"] == 1 and result["changed_tasks"] == 0
    assert lab.remote("sudo -n id -u").strip() == "0"
    lab.finish(
        {
            "assessment_controls": 4,
            "unsafe_identity_findings": 3,
            "audit_verify_zero_writes": True,
            "original_databases_restored": True,
            "root_path_existing_finding": True,
            "fresh_admin_access": True,
        }
    )


if __name__ == "__main__":
    main()
