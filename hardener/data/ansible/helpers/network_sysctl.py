"""Inspect bounded network sysctls and systemd precedence without changing state."""

import configparser
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
    "network.ipv4-redirects-disabled": ("ipv4", "accept_redirects", "0"),
    "network.ipv6-redirects-disabled": ("ipv6", "accept_redirects", "0"),
    "network.ipv4-send-redirects-disabled": ("ipv4", "send_redirects", "0"),
    "network.reverse-path-filter": ("ipv4", "rp_filter", None),
    "network.ip-forwarding-disabled": ("both", "forwarding", "0"),
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


def desired_value(cid, parameters=None):
    desired = POLICIES[cid][2]
    if desired is None:
        return {"strict": "1", "loose": "2"}[(parameters or {})["mode"]]
    return desired


def patterns(cid):
    family, option, _ = POLICIES[cid]
    if option == "tcp_syncookies":
        return [f"net/{family}/{option}"]
    families = ["ipv4", "ipv6"] if family == "both" else [family]
    result = [f"net/{item}/conf/*/{option}" for item in families]
    return ["net/ipv4/ip_forward", *result] if family == "both" else result


def settings(cid, parameters=None):
    result = {}
    for pattern in patterns(cid):
        for name in ["all", "default", "*"] if "*" in pattern else [None]:
            result[pattern.replace("*", name) if name else pattern] = desired_value(cid, parameters)
    return result


def owns(cid, key):
    parts = key.split("/")
    return any(
        len(parts) == len(pattern.split("/"))
        and all(
            expected == "*" or expected == actual
            for expected, actual in zip(pattern.split("/"), parts, strict=True)
        )
        for pattern in patterns(cid)
    )


def affects(cid, key):
    """Recognize broad globs without claiming ownership of unrelated settings."""
    parts = key.split("/")
    return any(
        len(parts) == len(pattern.split("/"))
        and all(
            expected == "*" or fnmatch.fnmatchcase(expected, actual)
            for expected, actual in zip(pattern.split("/"), parts, strict=True)
        )
        for pattern in patterns(cid)
    )


def render(text, cid, parameters=None):
    if any(not owns(cid, key) for _, key, _ in entries(text)):
        raise ValueError("Managed file contains unrelated settings")
    comments = [
        line
        for line in text.splitlines()
        if not line.strip() or line.lstrip().startswith(("#", ";"))
    ]
    prefix = "\n".join(comments).rstrip()
    return (prefix + "\n" if prefix else "") + "".join(
        f"{key} = {value}\n" for key, value in settings(cid, parameters).items()
    )


def effective(rows, key):
    explicit = [value for _, name, value in rows if name == key]
    if explicit:
        return explicit[-1]
    globs = [
        value for _, name, value in rows if value is not None and fnmatch.fnmatchcase(key, name)
    ]
    return globs[-1] if globs else None


def conflicts(rows, cid, managed, parameters=None):
    desired = desired_value(cid, parameters)
    result = []
    managed_keys = set(settings(cid, parameters))
    explicit = {key for key in managed_keys if "*" not in key}
    for source, key, value in rows:
        if source == str(managed) or not affects(cid, key):
            continue
        if (
            not owns(cid, key)
            or Path(source).name == managed.name
            or (
                any(c in key for c in "*?[")
                and value != desired
                and not (key in managed_keys and Path(source).name < managed.name)
            )
            or (cid == "network.ip-forwarding-disabled" and value not in (None, desired))
            or (key not in explicit and value is None)
            or (key not in explicit and not any(c in key for c in "*?[") and value != desired)
            or (Path(source).name > managed.name and value != desired)
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


def command(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def forwarding_conflicts(links, units, profiles, config):
    """Refuse observed router/container ownership instead of dismantling it."""
    reasons = []
    for link in links:
        kind = link.get("linkinfo", {}).get("info_kind")
        if kind not in (None, "dummy", "vlan", "bond", "team") or link.get("link_type") not in (
            "ether",
            "loopback",
        ):
            reasons.append("unsupported network interface: " + link["ifname"])
    for line in units.splitlines():
        name = line.split()[0] if line.split() else ""
        if re.match(
            r"(docker|containerd|crio|podman|kubelet|libvirtd|virtnetworkd|frr|zebra|bird6?|systemd-networkd)([.@-])",
            name,
        ):
            reasons.append("active routing/container/network service: " + name)
    for uuid, fields in profiles.items():
        if (
            len(fields) != 3
            or fields[0] == "shared"
            or fields[2] == "shared"
            or fields[1] not in ("-1", "0", "2")
        ):
            reasons.append("forwarding-capable NetworkManager profile: " + uuid)
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(config)
    for section in parser.sections():
        if section == "connection" or section.startswith("connection."):
            value = parser.get(section, "ipv4.forwarding", fallback="-1")
            if value not in ("-1", "0", "2", "default", "no", "auto"):
                reasons.append("NetworkManager forwarding default: " + section)
    return sorted(set(reasons))


def inspect_forwarding_owner():
    command("/usr/bin/systemctl", "is-active", "NetworkManager.service")
    links = json.loads(command("/usr/sbin/ip", "-j", "-d", "link", "show"))
    units = command(
        "/usr/bin/systemctl",
        "list-units",
        "--type=service",
        "--type=socket",
        "--state=active",
        "--no-legend",
        "--plain",
        "--no-pager",
    )
    units += command(
        "/usr/bin/systemctl",
        "list-unit-files",
        "--type=service",
        "--type=socket",
        "--state=enabled,enabled-runtime",
        "--no-legend",
        "--no-pager",
    )
    profiles = {}
    for uuid in command("/usr/bin/nmcli", "-g", "UUID", "connection", "show").splitlines():
        if not re.fullmatch(r"[a-fA-F0-9-]{36}", uuid):
            raise ValueError("Unexpected NetworkManager profile identifier")
        profiles[uuid] = command(
            "/usr/bin/nmcli",
            "-g",
            "ipv4.method,ipv4.forwarding,ipv6.method",
            "connection",
            "show",
            "uuid",
            uuid,
        ).splitlines()
    config = command("/usr/sbin/NetworkManager", "--print-config")
    return forwarding_conflicts(links, units, profiles, config)


def inspect(cid, mode, parameters=None):
    parameters = parameters or {}
    family, option, _ = POLICIES[cid]
    desired = desired_value(cid, parameters)
    if (
        option in ("accept_redirects", "send_redirects", "forwarding")
        and parameters.get("network_role") != "non-routing"
    ):
        raise ValueError("Explicit non-routing network role is required")
    if option == "forwarding" and parameters.get("container_networking") != "absent":
        raise ValueError("Explicit absence of container networking is required")
    managed = CONFIG / ("99-rocky10-" + cid.replace(".", "-") + ".conf")
    families = ["ipv4", "ipv6"] if family == "both" else [family]
    available = [item for item in families if (PROC / "net" / item).exists()]
    if not available:
        return {"applicable": False, "reason": family + " kernel sysctls are unavailable"}
    keys = []
    future = []
    for pattern in patterns(cid):
        if pattern.split("/")[1] not in available:
            continue
        if "*" not in pattern:
            keys.append(pattern)
            continue
        parent = PROC / pattern.split("/*/")[0]
        names = sorted(p.name for p in parent.iterdir())
        if not {"all", "default"} <= set(names) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]+", name) for name in names
        ):
            raise ValueError("Unsupported interface names or missing defaults")
        keys.extend(pattern.replace("*", name) for name in names)
        future.append(pattern.replace("*", "__hardener_future__"))
    rows = entries(command("/usr/lib/systemd/systemd-sysctl", "--cat-config", "--tldr"))
    safe = safe_file(managed) and safe_parent(managed.parent)
    content = managed.read_text() if safe and managed.exists() else ""
    try:
        proposed = render(content, cid, parameters)
    except ValueError:
        safe = False
        proposed = ""
    live = {
        key: (PROC / key).read_text().strip()
        if mode == "verify"
        else command("/usr/sbin/sysctl", "-n", key).strip()
        for key in keys
    }
    persistent = {key: effective(rows, key) for key in keys}
    for key in future:
        label = (
            "future_interfaces" if len(future) == 1 else "future_interfaces_" + key.split("/")[1]
        )
        persistent[label] = effective(rows, key)
    blockers = conflicts(rows, cid, managed, parameters)
    preserve = {}
    if option == "forwarding":
        blockers.extend(inspect_forwarding_owner())
        # Linux 6.12 resets this unselected setting when global IPv4 forwarding changes.
        if live.get("net/ipv4/ip_forward") not in (None, "0"):
            key = "net/ipv4/conf/all/accept_redirects"
            preserve[key] = (PROC / key).read_text().strip()
    return {
        "applicable": True,
        "safe": safe,
        "path": str(managed),
        "content": proposed,
        "desired": desired,
        "live": live,
        "persistent": persistent,
        "blockers": blockers,
        "preserve": preserve,
        "address_families": available,
        "matches": safe
        and not blockers
        and all(v == desired for v in [*live.values(), *persistent.values()]),
    }


if __name__ == "__main__":
    print(
        json.dumps(
            inspect(sys.argv[1], sys.argv[2], json.loads(sys.argv[3]) if len(sys.argv) > 3 else {})
        )
    )
