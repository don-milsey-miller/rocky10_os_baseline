"""Manage supported local PAM policy through authselect and native configuration."""

import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIG = {
    "password-quality": Path("/etc/security/pwquality.conf"),
    "password-history": Path("/etc/security/pwhistory.conf"),
    "failed-login-lockout": Path("/etc/security/faillock.conf"),
}
FEATURE = {"password-history": "with-pwhistory", "failed-login-lockout": "with-faillock"}
ALLOWED_FEATURES = {
    "with-pwhistory",
    "with-faillock",
    "without-nullok",
    "without-lastlog-showfailed",
}


def run(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        env={**os.environ, "LC_ALL": "C"},
    )


def safe(path):
    info = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o022
        or "system.posix_acl_access" in os.listxattr(path)
    ):
        raise ValueError("Unsafe policy file")
    for parent in path.parents:
        meta = parent.stat()
        if meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError("Unsafe policy directory")


def vendor_file(path, content=None):
    safe(path)
    data = run(
        ["/usr/bin/rpm", "-qf", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", str(path)]
    ).stdout
    rows = dict(line.split("\t", 1) for line in data.splitlines() if "\t" in line)
    raw = path.read_bytes() if content is None else content.encode()
    if rows.get(str(path)) != hashlib.sha256(raw).hexdigest():
        raise ValueError("Modified vendor authentication template")


def consumer_text(service, text):
    """Allow only our reviewed su insertion when checking vendor entry points."""
    if service != "su":
        return text
    marker = "# rocky10-hardener-su"
    rows = text.splitlines(keepends=True)
    managed = [row for row in rows if marker in row]
    if len(managed) > 1 or any(
        not re.fullmatch(
            r"auth required pam_wheel\.so use_uid group=[a-z_][a-z0-9_-]{0,31} # rocky10-hardener-su\n",
            row,
        )
        for row in managed
    ):
        raise ValueError("Unrecognized managed su policy")
    if managed:
        index = rows.index(managed[0])
        if index == 0 or " ".join(rows[index - 1].split()) != "auth sufficient pam_rootok.so":
            raise ValueError("Unexpected su policy order")
    return "".join(row for row in rows if marker not in row)


def active(text):
    return [
        " ".join(row.split("#", 1)[0].split())
        for row in text.splitlines()
        if row.split("#", 1)[0].strip()
    ]


def generated_matches(name, actual, rendered):
    rows = rendered.splitlines()
    if not rows or rows[0] != f"File /etc/pam.d/{name}:":
        return False
    return active(actual) == active("\n".join(rows[1:]))


def validate_generated(features):
    for name in ("system-auth", "password-auth", "postlogin"):
        vendor_file(Path("/usr/share/authselect/default/local") / name)
        rendered = run(["/usr/bin/authselect", "test", "local", *features, "--" + name]).stdout
        if not generated_matches(name, (Path("/etc/pam.d") / name).read_text(), rendered):
            raise ValueError("Generated PAM stack differs from its native profile")


def settings(text):
    values = {}
    for row in active(text):
        match = re.fullmatch(r"([a-z_]+)(?:\s*=\s*([A-Za-z0-9_-]+))?", row)
        if not match or match[1] in values:
            raise ValueError("Ambiguous authentication configuration")
        values[match[1]] = match[2] if match[2] is not None else True
    return values


def desired(kind, parameters):
    if kind == "password-quality":
        return {
            "minlen": str(parameters["minimum_length"]),
            "dcredit": "0",
            "ucredit": "0",
            "lcredit": "0",
            "ocredit": "0",
            "enforcing": "1",
        }
    if kind == "password-history":
        return {"remember": str(parameters["remember"])}
    if kind == "failed-login-lockout":
        return {
            "deny": str(parameters["attempts"]),
            "fail_interval": str(parameters["interval_seconds"]),
            "unlock_time": str(parameters["unlock_seconds"]),
            "admin_group": parameters["exempt_group"],
            "local_users_only": True,
        }
    raise ValueError("Unknown authentication policy")


def edit(text, values):
    current = settings(text)
    if set(current) - set(values):
        raise ValueError("Unmodeled local authentication options")
    comments = [row for row in text.splitlines() if not row.split("#", 1)[0].strip()]
    return (
        "\n".join(
            comments
            + [key if value is True else f"{key} = {value}" for key, value in values.items()]
        )
        + "\n"
    )


def stack(kind, features):
    expected = {
        "password-quality": ["password requisite pam_pwquality.so"],
        "password-history": ["password requisite pam_pwhistory.so use_authtok"],
        "failed-login-lockout": [
            "auth required pam_faillock.so preauth silent",
            "auth required pam_faillock.so authfail",
            "account required pam_faillock.so",
        ],
    }[kind]
    module = {
        "password-quality": "pam_pwquality.so",
        "password-history": "pam_pwhistory.so",
        "failed-login-lockout": "pam_faillock.so",
    }[kind]
    enabled = kind not in FEATURE or FEATURE[kind] in features
    for name in ("system-auth", "password-auth"):
        rows = active((Path("/etc/pam.d") / name).read_text())
        found = [row for row in rows if module in row.split()]
        if found != (expected if enabled else []):
            raise ValueError("Unsupported effective PAM module arguments")
    return enabled


def inspect(kind, parameters, administrator):
    run(["/usr/bin/authselect", "check"])
    current = run(["/usr/bin/authselect", "current", "--raw"]).stdout.split()
    if not current or current[0] != "local" or set(current[1:]) - ALLOWED_FEATURES:
        raise ValueError("Only the supported local authselect profile is allowed")
    # Domain enrollment and alternate identity providers must not be silently replaced.
    for service in ("sssd", "winbind"):
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            raise ValueError("Domain-managed identity is outside local policy")
    validate_generated(current[1:])
    for service in ("login", "passwd", "sshd", "sudo", "sudo-i", "su", "su-l"):
        path = Path("/etc/pam.d") / service
        vendor_file(path, consumer_text(service, path.read_text()))
    enabled = stack(kind, current[1:])
    path = CONFIG[kind]
    safe(path)
    values = desired(kind, parameters)
    text = path.read_text()
    candidate = edit(text, values)
    if kind == "password-quality":
        for drop in Path("/etc/security/pwquality.conf.d").glob("*.conf"):
            safe(drop)
            if active(drop.read_text()):
                raise ValueError("Resolve password quality drop-ins explicitly")
    if kind == "failed-login-lockout":
        group = grp.getgrnam(parameters["exempt_group"])
        account = pwd.getpwnam(administrator)
        if group.gr_gid not in os.getgrouplist(administrator, account.pw_gid):
            raise ValueError("The recovery identity must be exempt from lockout")
    if kind == "password-history":
        history = Path("/etc/security/opasswd")
        if history.exists() or history.is_symlink():
            safe(history)
            if history.stat().st_mode & 0o077:
                raise ValueError("Password history database must be private")
    evidence = {
        "matches": enabled and settings(text) == values,
        "profile": "local",
        "module_enabled": enabled,
        "policy": settings(text),
    }
    return evidence, candidate, enabled


def replace(path, text):
    info = path.stat()
    attrs = {key: os.getxattr(path, key) for key in os.listxattr(path)}
    fd, name = tempfile.mkstemp(prefix=".hardener-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, stat.S_IMODE(info.st_mode))
        os.chown(name, info.st_uid, info.st_gid)
        for key, value in attrs.items():
            os.setxattr(name, key, value)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    kind, params, administrator, mode = (
        sys.argv[1],
        json.loads(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
    )
    try:
        evidence, candidate, enabled = inspect(kind, params, administrator)
        changed = False
        if mode == "apply" and not evidence["matches"]:
            path = CONFIG[kind]
            original = path.read_text()
            try:
                if original != candidate:
                    replace(path, candidate)
                    changed = True
                if not enabled:
                    run(["/usr/bin/authselect", "enable-feature", FEATURE[kind]])
                    changed = True
                evidence, _, _ = inspect(kind, params, administrator)
                if not evidence["matches"]:
                    raise ValueError("Native verification failed")
            except (ValueError, OSError, subprocess.SubprocessError):
                replace(path, original)
                if not enabled:
                    run(["/usr/bin/authselect", "disable-feature", FEATURE[kind]])
                raise
        print(json.dumps({"supported": True, "changed": changed, **evidence}))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print(json.dumps({"supported": False, "matches": False, "changed": None}))


if __name__ == "__main__":
    main()
