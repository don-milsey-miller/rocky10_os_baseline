"""Inspect bounded network sysctls and systemd precedence without changing state."""

import fnmatch
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

PROC = Path("/proc/sys")
CONFIG = Path("/etc/sysctl.d")
POLICIES = {
    "network.ipv4-source-route-disabled": ("ipv4", "accept_source_route", "0"),
    "network.ipv6-source-route-disabled": ("ipv6", "accept_source_route", "-1"),
    "network.tcp-syncookies": ("ipv4", "tcp_syncookies", "1"),
}


def normalize(name):
    name = name.lstrip("-")
    separators = [c for c in name if c in "./"]
    return (
        name.translate(str.maketrans("./", "/.")) if separators and separators[0] == "." else name
    )


def entries(text):
    source = ""
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# /"):
            source = line[2:]
        if not line or line.startswith(("#", ";")):
            continue
        name, equal, value = line.partition("=")
        if not equal and not line.startswith("-"):
            raise ValueError("Unsupported sysctl syntax")
        result.append((source, normalize(name.strip()), value.strip() if equal else None))
    return result


def settings(cid):
    family, option, desired = POLICIES[cid]
    if option == "tcp_syncookies":
        return {f"net/{family}/{option}": desired}
    return {
        f"net/{family}/conf/{interface}/{option}": desired for interface in ["all", "default", "*"]
    }


def owns(cid, key):
    family, option, _ = POLICIES[cid]
    parts = key.split("/")
    if option == "tcp_syncookies":
        return key == f"net/{family}/{option}"
    return len(parts) == 5 and parts[:3] == ["net", family, "conf"] and parts[-1] == option


def affects(cid, key):
    """Recognize broad globs without claiming ownership of unrelated settings."""
    family, option, _ = POLICIES[cid]
    target = (
        ["net", family, option]
        if option == "tcp_syncookies"
        else ["net", family, "conf", "*", option]
    )
    parts = key.split("/")
    return len(parts) == len(target) and all(
        expected == "*" or fnmatch.fnmatchcase(expected, pattern)
        for expected, pattern in zip(target, parts, strict=True)
    )


def render(text, cid):
    if any(not owns(cid, key) for _, key, _ in entries(text)):
        raise ValueError("Managed file contains unrelated settings")
    comments = [
        line
        for line in text.splitlines()
        if not line.strip() or line.lstrip().startswith(("#", ";"))
    ]
    prefix = "\n".join(comments).rstrip()
    return (prefix + "\n" if prefix else "") + "".join(
        f"{key} = {value}\n" for key, value in settings(cid).items()
    )


def effective(rows, key):
    explicit = [value for _, name, value in rows if name == key and value is not None]
    if explicit:
        return explicit[-1]
    if any(name == key and value is None for _, name, value in rows):
        return None
    globs = [
        value for _, name, value in rows if value is not None and fnmatch.fnmatchcase(key, name)
    ]
    return globs[-1] if globs else None


def conflicts(rows, cid, managed):
    desired = POLICIES[cid][2]
    result = []
    explicit = set(settings(cid)) - {key for key in settings(cid) if "*" in key}
    for source, key, value in rows:
        if source == str(managed) or not affects(cid, key):
            continue
        if (
            not owns(cid, key)
            or Path(source).name == managed.name
            or (any(c in key for c in "*?[") and value != desired)
            or (key not in explicit and value is None)
            or (key not in explicit and not any(c in key for c in "*?[") and value != desired)
            or (Path(source).name > managed.name and value not in (None, desired))
        ):
            result.append(source)
    return sorted(set(result))


def safe_file(path):
    if not path.exists() and not path.is_symlink():
        return True
    info = path.lstat()
    return bool(
        path.resolve() == path
        and stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & 0o022
        and "system.posix_acl_access" not in os.listxattr(path, follow_symlinks=False)
    )


def safe_parent(path):
    info = path.stat()
    return bool(
        path.resolve() == path
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & 0o022
        and "system.posix_acl_access" not in os.listxattr(path)
    )


def inspect(cid, mode):
    family, option, desired = POLICIES[cid]
    managed = CONFIG / ("99-rocky10-" + cid.replace(".", "-") + ".conf")
    parent = PROC / "net" / family
    if not parent.exists():
        return {"applicable": False, "reason": family + " kernel sysctls are unavailable"}
    keys = list(settings(cid))
    if option != "tcp_syncookies":
        names = sorted(p.name for p in (parent / "conf").iterdir())
        if not {"all", "default"} <= set(names) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]+", n) for n in names
        ):
            raise ValueError("Unsupported interface names or missing defaults")
        keys = [f"net/{family}/conf/{name}/{option}" for name in names]
    config = subprocess.run(
        ["/usr/lib/systemd/systemd-sysctl", "--cat-config", "--tldr"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    rows = entries(config)
    safe = safe_file(managed) and safe_parent(managed.parent)
    content = managed.read_text() if safe and managed.exists() else ""
    try:
        proposed = render(content, cid)
    except ValueError:
        safe = False
        proposed = ""
    live = {}
    for key in keys:
        live[key] = (
            (PROC / key).read_text().strip()
            if mode == "verify"
            else subprocess.run(
                ["/usr/sbin/sysctl", "-n", key], check=True, capture_output=True, text=True
            ).stdout.strip()
        )
    persistent = {key: effective(rows, key) for key in keys}
    if option != "tcp_syncookies":
        future = f"net/{family}/conf/__hardener_future__/{option}"
        persistent["future_interfaces"] = effective(rows, future)
    blockers = conflicts(rows, cid, managed)
    return {
        "applicable": True,
        "safe": safe,
        "path": str(managed),
        "content": proposed,
        "desired": desired,
        "live": live,
        "persistent": persistent,
        "blockers": blockers,
        "matches": safe
        and not blockers
        and all(v == desired for v in [*live.values(), *persistent.values()]),
    }


if __name__ == "__main__":
    print(json.dumps(inspect(sys.argv[1], sys.argv[2])))
