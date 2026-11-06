"""Restrict only supported existing fstab mounts and explicit shared directories."""

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

MOUNTS = {
    "tmp-restrictions": "/tmp",
    "var-tmp-restrictions": "/var/tmp",
    "dev-shm-restrictions": "/dev/shm",
    "home-restrictions": "/home",
}
OPPOSITES = {"nodev": "dev", "nosuid": "suid", "noexec": "exec"}


def run(argv):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    ).stdout.strip()


def safe_file(path):
    if path.resolve() != path:
        raise ValueError("Remove symbolic links from configuration paths")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Protect configuration parent ownership and write access")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
    ):
        raise ValueError("Require a root-owned single-link configuration file")


def fstab_entry(text, target):
    entries = []
    for index, line in enumerate(text.splitlines(keepends=True)):
        row = line.split("#", 1)[0].split()
        if not row:
            continue
        if len(row) not in (4, 5, 6):
            raise ValueError("Resolve malformed fstab entries")
        if row[1] == target:
            entries.append((index, row))
    if len(entries) != 1:
        raise ValueError("Provision exactly one explicit fstab entry for the existing mount")
    index, row = entries[0]
    if row[2] not in ("tmpfs", "xfs", "ext4") or "\\" in " ".join(row):
        raise ValueError("Use a supported local mount without escaped fields")
    options = row[3].split(",")
    if any(
        x in options for x in ("bind", "rbind", "noauto", "user", "users", "owner", "nofail")
    ) or any(x.startswith("x-systemd.") for x in options):
        raise ValueError("Review bind, user, optional or custom systemd mounts separately")
    if len(options) != len(set(options)):
        raise ValueError("Resolve duplicate mount options")
    return index, row


def restrict_options(options, flags):
    if not flags or len(flags) != len(set(flags)) or set(flags) - OPPOSITES.keys():
        raise ValueError("Select distinct nodev, nosuid or noexec flags")
    result = [o for o in options.split(",") if o not in {OPPOSITES[f] for f in flags}]
    for flag in flags:
        if flag not in result:
            result.append(flag)
    return ",".join(result)


def mount_inspect(kind, parameters):
    target = MOUNTS[kind]
    path = Path("/etc/fstab")
    safe_file(path)
    if Path(target).resolve() != Path(target):
        raise ValueError("Mount target must not contain symbolic links")
    text = path.read_text()
    index, row = fstab_entry(text, target)
    requested = parameters["flags"]
    desired = restrict_options(row[3], requested)
    mounted = json.loads(
        run(["findmnt", "-J", "-M", target, "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,FSROOT"])
    )["filesystems"]
    if len(mounted) != 1 or mounted[0].get("children") or mounted[0]["fsroot"] != "/":
        raise ValueError("Require a whole existing filesystem without nested mounts")
    native = mounted[0]
    persistent = json.loads(
        run(["findmnt", "--fstab", "--evaluate", "-J", "-M", target, "-o", "SOURCE,FSTYPE"])
    )["filesystems"]
    if len(persistent) != 1 or any(native[k] != persistent[0][k] for k in ("source", "fstype")):
        raise ValueError("Resolve live and persistent mount source drift")
    unit = run(["systemd-escape", "--path", "--suffix=mount", target])
    fragment = run(["systemctl", "show", unit, "-p", "FragmentPath", "--value"])
    dropins = run(["systemctl", "show", unit, "-p", "DropInPaths", "--value"])
    if fragment != "/run/systemd/generator/" + unit or dropins:
        raise ValueError("Use the unmodified fstab-generated mount unit")
    live_options = set(native["options"].split(","))
    state = {
        "matches": desired == row[3] and set(requested) <= live_options,
        "mountpoint": target,
        "filesystem": native["fstype"],
        "required_flags": requested,
        "effective_flags": sorted(set(OPPOSITES) & live_options),
        "persistent_flags": sorted(set(OPPOSITES) & set(row[3].split(","))),
    }
    lines = text.splitlines(keepends=True)
    original = lines[index]
    # Replace only the fourth field, preserving the comment and surrounding whitespace.
    lines[index] = re.sub(r"^(\s*\S+\s+\S+\s+\S+\s+)\S+", lambda m: m[1] + desired, original)
    return state, (path, "".join(lines), target, desired)


def shared_inspect(parameters):
    paths = parameters["paths"]
    if len(set(paths)) != len(paths):
        raise ValueError("Use distinct shared directories")
    missing = []
    for value in paths:
        path = Path(value)
        if not path.is_absolute() or str(path) != value or path.resolve(strict=True) != path:
            raise ValueError("Use canonical shared directories without symbolic links")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or not info.st_mode & 0o002:
            raise ValueError("Select only existing root-owned world-writable shared directories")
        for parent in path.parents:
            item = parent.lstat()
            if item.st_uid != 0 or item.st_mode & 0o022:
                raise ValueError("Shared directory parents must be protected")
        if not info.st_mode & stat.S_ISVTX:
            missing.append(value)
    return {"matches": not missing, "directories": len(paths), "missing_sticky": missing}, missing


def main():
    kind, mode = sys.argv[1:3]
    parameters = json.loads(sys.argv[3])
    changed = False
    try:
        inspect = (
            shared_inspect
            if kind == "shared-directory-sticky"
            else lambda p: mount_inspect(kind, p)
        )
        state, plan = inspect(parameters)
        if mode == "apply" and not state["matches"]:
            if kind == "shared-directory-sticky":
                for value in plan:
                    fd = os.open(value, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        info = os.fstat(fd)
                        if info.st_uid != 0 or not info.st_mode & 0o002:
                            raise ValueError("Shared directory changed during inspection")
                        os.fchmod(fd, stat.S_IMODE(info.st_mode) | stat.S_ISVTX)
                        changed = True
                    finally:
                        os.close(fd)
            else:
                path, content, target, options = plan
                if content != path.read_text():
                    path.write_text(content)
                    changed = True
                    run(["systemctl", "daemon-reload"])
                run(["mount", "-o", "remount," + options, "--", target])
                changed = True
            state, _ = inspect(parameters)
        print(json.dumps({"supported": True, "changed": changed, **state}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "supported": False,
                    "matches": False,
                    "changed": changed,
                    "reason": "Require supported existing fstab mounts or protected explicit shared directories. Review configuration ownership, mount source and systemd overrides.",
                }
            )
        )


if __name__ == "__main__":
    main()
