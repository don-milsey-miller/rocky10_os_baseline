"""Manage explicit local Bash defaults and the stock su admission rule."""

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


def run(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
        env={**os.environ, "LC_ALL": "C"},
    )


def digest(path):
    rows = run(
        ["/usr/bin/rpm", "-qf", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", str(path)]
    ).stdout
    return dict(r.split("\t", 1) for r in rows.splitlines() if "\t" in r).get(str(path))


def safe(path, owner=0):
    info = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != owner
        or info.st_mode & 0o022
        or "system.posix_acl_access" in os.listxattr(path)
    ):
        raise ValueError("Unsafe startup file")
    return info


def su_candidate(text, group, vendor_digest):
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
        raise ValueError("Malformed managed su admission rule")
    original = "".join(row for row in rows if marker not in row)
    if hashlib.sha256(original.encode()).hexdigest() != vendor_digest:
        raise ValueError("Custom su PAM layout requires review")
    rows = original.splitlines(keepends=True)
    indices = [
        i for i, row in enumerate(rows) if " ".join(row.split()) == "auth sufficient pam_rootok.so"
    ]
    if len(indices) != 1:
        raise ValueError("Unknown root su bypass")
    rows.insert(indices[0] + 1, f"auth required pam_wheel.so use_uid group={group} {marker}\n")
    return "".join(rows)


def shell_candidate(kind, uids, params):
    action = (
        f"umask {params['mask']}"
        if kind == "default-umask"
        else (f"TMOUT={params['seconds']}\n            readonly TMOUT\n            export TMOUT")
    )
    return (
        "# Managed local interactive Bash defaults.\n"
        'if [ -n "\u0024{BASH_VERSION:-}" ]; then\n'
        "    case $- in\n"
        '        *i*) case "$(/usr/bin/id -u)" in\n'
        f"        {'|'.join(str(uid) for uid in sorted(uids))}) {action} ;;\n"
        "        esac ;;\n"
        "    esac\n"
        "fi\n"
    )


def inspect(kind, params, administrator):
    run(["/usr/bin/authselect", "check"])
    if run(["/usr/bin/authselect", "current", "--raw"]).stdout.split()[0] != "local":
        raise ValueError("Local identity profile required")
    if kind == "su-access-policy":
        group = grp.getgrnam(params["group"])
        admin = pwd.getpwnam(administrator)
        if group.gr_gid not in os.getgrouplist(administrator, admin.pw_gid):
            raise ValueError("Recovery administrator must belong to the permitted su group")
        login = Path("/etc/pam.d/su-l")
        safe(login)
        if hashlib.sha256(login.read_bytes()).hexdigest() != digest(login):
            raise ValueError("Custom su login PAM layout requires review")
        path = Path("/etc/pam.d/su")
        safe(path)
        candidate = su_candidate(path.read_text(), params["group"], digest(path))
        return (
            {"matches": path.read_text() == candidate, "group": group.gr_name, "root_bypass": True},
            path,
            candidate,
        )
    for path in (Path("/etc/profile"), Path("/etc/bashrc")):
        safe(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest(path):
            raise ValueError("Custom system shell startup requires review")
    rows = [r.split(":") for r in Path("/etc/passwd").read_text().splitlines()]
    if any(len(r) != 7 for r in rows) or len({r[2] for r in rows}) != len(rows):
        raise ValueError("Invalid local account database")
    accounts = []
    for name in params["users"]:
        selected = [r for r in rows if r[0] == name]
        if len(selected) != 1:
            raise ValueError("Select existing local human accounts")
        row = selected[0]
        if (
            name == administrator
            or not 1000 <= int(row[2]) < 65534
            or row[6] not in ("/bin/bash", "/usr/bin/bash")
        ):
            raise ValueError("Select non-recovery local human Bash accounts")
        home = Path(row[5])
        if home.parent != Path("/home") or home.name != name or home.resolve() != home:
            raise ValueError("Unsupported home layout")
        for filename in (".bash_profile", ".bashrc", ".bash_logout"):
            path = home / filename
            safe(path, int(row[2]))
            template = Path("/etc/skel") / filename
            safe(template)
            if hashlib.sha256(template.read_bytes()).hexdigest() != digest(template):
                raise ValueError("Custom skeleton startup requires review")
            if path.read_bytes() != template.read_bytes():
                raise ValueError("Custom user startup requires review")
        if (home / ".bash_login").exists() or (home / ".profile").exists():
            raise ValueError("Additional user startup requires review")
        accounts.append(row)
    directory = Path("/etc/profile.d")
    if directory.resolve() != directory:
        raise ValueError("Linked startup directory")
    for parent in (directory, *directory.parents):
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe startup directory")
    path = directory / f"zz-rocky10-hardener-{kind}.sh"
    if path.exists() or path.is_symlink():
        safe(path)
        if not path.read_text().startswith("# Managed local interactive Bash defaults.\n"):
            raise ValueError("Unowned destination")
    for other in Path("/etc/profile.d").glob("*.sh"):
        if other.name.startswith("zz-rocky10-hardener-"):
            continue
        if other.is_symlink():
            target = Path("/usr/lib/systemd/profile.d/70-systemd-shell-extra.sh")
            if (
                other != Path("/etc/profile.d/70-systemd-shell-extra.sh")
                or other.resolve() != target
                or other.lstat().st_uid != 0
            ):
                raise ValueError("Unrecognized startup symlink")
            safe(target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest(target):
                raise ValueError("Modified vendor startup target")
        else:
            safe(other)
        active = "\n".join(r.split("#", 1)[0] for r in other.read_text().splitlines())
        if re.search(r"\bumask\b|\bTMOUT\b", active):
            raise ValueError("Conflicting system shell policy")
    candidate = shell_candidate(kind, [int(r[2]) for r in accounts], params)
    installed = path.exists() and path.read_text() == candidate
    observed = []
    if installed:
        for row in accounts:
            for login in (True, False):
                result = run(
                    [
                        "/usr/sbin/runuser",
                        "-u",
                        row[0],
                        "--",
                        "/usr/bin/env",
                        "-i",
                        f"HOME={row[5]}",
                        f"USER={row[0]}",
                        f"LOGNAME={row[0]}",
                        "PATH=/usr/bin:/bin",
                        "TERM=dumb",
                        "/bin/bash",
                        "-lic" if login else "-ic",
                        (
                            "printf 'HARDENER_MASK=%s\\n' \"$(umask)\"; "
                            "printf 'HARDENER_TIMEOUT=%s\\n' \"\u0024{TMOUT-unset}\"; "
                            "declare -p TMOUT 2>/dev/null || true"
                        ),
                    ]
                )
                mask = re.findall(r"^HARDENER_MASK=([0-7]{4})$", result.stdout, re.MULTILINE)
                timeout = re.findall(r"^HARDENER_TIMEOUT=(\d+|unset)$", result.stdout, re.MULTILINE)
                match = (
                    mask == [params["mask"]]
                    if kind == "default-umask"
                    else (
                        timeout == [str(params["seconds"])]
                        and bool(
                            re.search(
                                r"^declare -[a-z]*r[a-z]* TMOUT=", result.stdout, re.MULTILINE
                            )
                        )
                    )
                )
                observed.append({"user": row[0], "login": login, "matches": bool(match)})
    return (
        {
            "matches": installed and all(r["matches"] for r in observed),
            "installed": installed,
            "sessions": observed,
        },
        path,
        candidate,
    )


def replace(path, text):
    info = path.stat() if path.exists() else None
    attrs = {key: os.getxattr(path, key) for key in os.listxattr(path)} if info else {}
    fd, name = tempfile.mkstemp(prefix=".hardener-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, stat.S_IMODE(info.st_mode) if info else 0o644)
        os.chown(name, info.st_uid if info else 0, info.st_gid if info else 0)
        for key, value in attrs.items():
            os.setxattr(name, key, value)
        os.replace(name, path)
        run(["/usr/sbin/restorecon", str(path)])
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
        evidence, path, candidate = inspect(kind, params, administrator)
        changed = False
        if mode == "apply" and not evidence["matches"]:
            original = path.read_text() if path.exists() else None
            try:
                if original != candidate:
                    replace(path, candidate)
                    changed = True
                evidence, _, _ = inspect(kind, params, administrator)
                if not evidence["matches"]:
                    raise ValueError("Effective shell policy failed")
            except (ValueError, OSError, subprocess.SubprocessError):
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    replace(path, original)
                raise
        print(json.dumps({"supported": True, "changed": changed, **evidence}))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print(json.dumps({"supported": False, "matches": False, "changed": None}))


if __name__ == "__main__":
    main()
