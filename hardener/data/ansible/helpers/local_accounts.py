"""Apply narrowly selected local account properties; never return password fields."""

import json
import os
import stat
import subprocess
import sys
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


def select_accounts(names, passwd, active, kind):
    rows = [line.split(":") for line in passwd.splitlines()]
    if any(len(row) != 7 for row in rows):
        raise ValueError("Malformed local accounts")
    if len({r[0] for r in rows}) != len(rows) or len({r[2] for r in rows}) != len(rows):
        raise ValueError("Resolve duplicate local identities before remediation")
    chosen = []
    for name in names:
        matches = [r for r in rows if r[0] == name]
        if len(matches) != 1:
            raise ValueError("Select existing local accounts")
        row = matches[0]
        uid = int(row[2])
        if name == active or uid == 0:
            raise ValueError("The recovery identity and root cannot be selected")
        if kind == "system-login-disabled":
            if not 0 < uid < 1000:
                raise ValueError("Select explicitly classified system accounts")
        elif not 1000 <= uid < 65534 or row[6] not in ("/bin/bash", "/usr/bin/bash"):
            raise ValueError("Select explicitly classified local human Bash accounts")
        chosen.append(row)
    return chosen


def safe_file(path):
    info = path.lstat()
    return (
        path.resolve() == path
        and stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and "system.posix_acl_access" not in os.listxattr(path)
    )


def home_state(row):
    path = Path(row[5])
    if not path.is_absolute() or path.parent != Path("/home") or path.name != row[0]:
        raise ValueError("Only explicit /home/account directories are supported")
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != int(row[2]):
        raise ValueError("Home ownership or directory layout requires operator review")
    for parent in path.parents:
        p = parent.stat()
        if p.st_uid != 0 or p.st_mode & 0o022:
            raise ValueError("Unsafe home ancestor")
    if "system.posix_acl_access" in os.listxattr(
        path
    ) or "system.posix_acl_default" in os.listxattr(path):
        raise ValueError("Home ACL policy requires operator review")
    return path, format(stat.S_IMODE(info.st_mode), "04o")


def inspect(kind, parameters, active):
    if run(["/usr/bin/authselect", "current", "--raw"]).stdout.split()[0] != "local":
        raise ValueError("Only the local authselect profile is supported")
    run(["/usr/bin/authselect", "check"])
    for name in ("/etc/passwd", "/etc/shadow", "/etc/group"):
        if not safe_file(Path(name)):
            raise ValueError("Unsafe local account database metadata")
    rows = select_accounts(parameters["users"], Path("/etc/passwd").read_text(), active, kind)
    shadow = [line.split(":") for line in Path("/etc/shadow").read_text().splitlines()]
    if any(len(row) != 9 for row in shadow) or len({r[0] for r in shadow}) != len(shadow):
        raise ValueError("Malformed local password database")
    by_name = {r[0]: r for r in shadow}
    evidence = []
    changes = []
    for row in rows:
        name = row[0]
        if kind == "home-permissions":
            path, mode = home_state(row)
            match = mode == parameters["mode"]
            evidence.append({"user": name, "mode": mode, "matches": match})
            if not match:
                changes.append(("chmod", str(path), parameters["mode"]))
        elif kind == "system-login-disabled":
            match = row[6] in ("/sbin/nologin", "/usr/sbin/nologin")
            evidence.append({"user": name, "login_disabled": match, "matches": match})
            if not match:
                changes.append(("shell", name))
        else:
            if name not in by_name:
                raise ValueError("Selected user lacks a local password record")
            record = by_name[name]
            if kind == "password-aging":
                values = {
                    "minimum_days": record[3],
                    "maximum_days": record[4],
                    "warning_days": record[5],
                }
                match = all(values[k] == str(parameters[k]) for k in values)
                evidence.append({"user": name, **values, "matches": match})
                if not match:
                    changes.append(("aging", name))
            elif kind == "inactive-account-lock":
                match = record[6] == str(parameters["days"])
                evidence.append({"user": name, "inactive_days": record[6], "matches": match})
                if not match:
                    changes.append(("inactive", name))
            else:
                raise ValueError("Unknown account policy")
    return {"matches": all(r["matches"] for r in evidence), "accounts": evidence}, changes


def main():
    kind, parameters, active, mode = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3], sys.argv[4]
    try:
        evidence, changes = inspect(kind, parameters, active)
        changed = False
        if mode == "apply":
            for item in changes:
                if item[0] == "chmod":
                    os.chmod(item[1], int(item[2], 8), follow_symlinks=False)
                elif item[0] == "shell":
                    run(["/usr/sbin/usermod", "--shell", "/sbin/nologin", item[1]])
                elif item[0] == "aging":
                    run(
                        [
                            "/usr/bin/chage",
                            "-m",
                            str(parameters["minimum_days"]),
                            "-M",
                            str(parameters["maximum_days"]),
                            "-W",
                            str(parameters["warning_days"]),
                            item[1],
                        ]
                    )
                else:
                    run(["/usr/bin/chage", "-I", str(parameters["days"]), item[1]])
                changed = True
            evidence, _ = inspect(kind, parameters, active)
        print(json.dumps({"supported": True, "changed": changed, **evidence}))
    except (ValueError, OSError, subprocess.SubprocessError):
        # Never print exceptions containing command output or account records.
        print(json.dumps({"supported": False, "matches": False, "changed": None}))


if __name__ == "__main__":
    main()
