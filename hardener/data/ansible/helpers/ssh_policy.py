"""Inspect standard Rocky sshd layouts and validate isolated policy candidates."""

import grp
import ipaddress
import json
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAIN = Path("/etc/ssh/sshd_config")
DROP = Path("/etc/ssh/sshd_config.d")
MANAGED = DROP / "00-rocky10-hardener.conf"
CRYPTO = "/etc/crypto-policies/back-ends/opensshserver.config"


def run(argv):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "LC_ALL": "C"},
    )


def lines(text):
    return [
        shlex.split(line, comments=True)
        for line in text.splitlines()
        if shlex.split(line, comments=True)
    ]


def metadata(path, desired):
    path = Path(path)
    if not os.path.lexists(path):
        return {"path": str(path), "safe": False, "matches": False, "exists": False}
    info = path.lstat()
    safe = path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    safe = safe and "system.posix_acl_access" not in os.listxattr(path, follow_symlinks=False)
    mode = format(stat.S_IMODE(info.st_mode), "04o")
    return {
        "path": str(path),
        "safe": safe,
        "exists": True,
        "mode": mode,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "matches": safe and info.st_uid == 0 and info.st_gid == 0 and mode == desired,
    }


def edit(text, desired):
    """Update selected directives in place so independent controls do not reorder."""
    rendered = {}
    for key, value in desired.items():
        if isinstance(value, list):
            line = key + " " + " ".join(value) + "\n" if value else None
        else:
            line = key + " " + str(value) + "\n"
        rendered[key.lower()] = line
    output = []
    seen = set()
    for line in text.splitlines(keepends=True):
        words = shlex.split(line, comments=True)
        key = words[0].lower() if words else None
        if key not in rendered:
            output.append(line)
        else:
            if key not in seen and rendered[key] is not None:
                output.append(rendered[key])
            seen.add(key)
    result = "".join(output)
    for key, line in rendered.items():
        if key not in seen and line is not None:
            if result and not result.endswith("\n"):
                result += "\n"
            result += line
    return result


def parse_effective(text):
    result = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key in {"hostkey", "allowusers", "allowgroups"}:
            result.setdefault(key, []).extend(shlex.split(value))
        else:
            result[key] = value.strip()
    return result


def matches(effective, desired):
    for key, value in desired.items():
        actual = effective.get(key.lower(), [] if isinstance(value, list) else None)
        if isinstance(value, list):
            if sorted(actual) != sorted(value):
                return False
        elif key.lower() == "maxstartups" and str(value).isdigit():
            parts = str(actual).split(":")
            if actual != str(value) and not (
                len(parts) == 3 and parts[0] == parts[2] == str(value)
            ):
                return False
        elif actual != str(value):
            return False
    return True


def context_arg(context):
    user = context["user"]
    source, source_port, target, target_port = context["connection"]
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", user):
        raise ValueError("Unsupported administrative username")
    ipaddress.ip_address(source)
    ipaddress.ip_address(target)
    if not source_port.isdigit() or not target_port.isdigit():
        raise ValueError("Invalid connection context")
    return f"user={user},host={source},addr={source},laddr={target},lport={target_port}"


def admin_allowed(effective, context):
    user = context["user"]
    if effective.get("pubkeyauthentication") != "yes":
        return False
    if user == "root" and effective.get("permitrootlogin") == "no":
        return False
    if effective.get("allowusers") and user not in effective["allowusers"]:
        return False
    if effective.get("allowgroups"):
        account = pwd.getpwnam(user)
        groups = {grp.getgrgid(gid).gr_name for gid in os.getgrouplist(user, account.pw_gid)}
        if not groups.intersection(effective["allowgroups"]):
            return False
    return True


def configuration_changed_at(paths):
    # Directory metadata also detects a removed drop-in whose old timestamp vanished.
    watched = [DROP, *paths]
    if Path(CRYPTO).exists():
        watched.append(Path(CRYPTO))
    return max(
        max(path.stat().st_mtime, path.stat().st_ctime, path.lstat().st_ctime) for path in watched
    )


def inspect(desired, context, candidate=False):
    paths = [MAIN, *sorted(DROP.glob("*.conf"))]
    metadata_rows = [metadata(path, "0600") for path in paths]
    if any(not row["safe"] for row in metadata_rows):
        return {
            "layout_supported": False,
            "files_supported": True,
            "keys_supported": False,
            "safe": False,
            "files": metadata_rows,
            "keys": [],
            "effective": {},
            "matches": False,
            "loaded": False,
            "active": False,
            "candidate_valid": False,
            "administrator_allowed": False,
        }
    content = {path: path.read_text() for path in paths}
    includes_ok = True
    has_match = False
    for path, text in content.items():
        for words in lines(text):
            key = words[0].lower()
            has_match |= key == "match"
            if key == "include":
                allowed = [str(DROP / "*.conf")] if path == MAIN else [CRYPTO]
                includes_ok &= words[1:] == allowed
    main_includes = [row for row in lines(content[MAIN]) if row[0].lower() == "include"]
    includes_ok &= len(main_includes) == 1
    state = run(
        [
            "/usr/bin/systemctl",
            "show",
            "sshd.service",
            "-p",
            "MainPID",
            "-p",
            "ActiveState",
            "-p",
            "ExecStart",
            "-p",
            "FragmentPath",
            "-p",
            "DropInPaths",
            "-p",
            "User",
            "-p",
            "Group",
            "-p",
            "Environment",
            "-p",
            "EnvironmentFiles",
        ]
    )
    state.check_returncode()
    unit = dict(line.split("=", 1) for line in state.stdout.splitlines())
    options = [
        line.strip()
        for line in Path("/etc/sysconfig/sshd").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    supported = (
        includes_ok
        and not has_match
        and unit["FragmentPath"] == "/usr/lib/systemd/system/sshd.service"
        and not unit["DropInPaths"]
        and not unit["Environment"]
        and unit["EnvironmentFiles"] == "/etc/sysconfig/sshd (ignore_errors=yes)"
        and "argv[]=/usr/sbin/sshd -D $OPTIONS ;" in unit["ExecStart"]
        and options in ([], ['OPTIONS=""'], ["OPTIONS=''"])
    )
    native = run(["/usr/sbin/sshd", "-T", "-C", context_arg(context)])
    native.check_returncode()
    effective = parse_effective(native.stdout)
    key_rows = [metadata(path, "0600") for path in effective.get("hostkey", [])]
    key_rows = [row for row in key_rows if row["exists"]]
    root_service = unit["User"] in ("", "root", "0") and unit["Group"] in ("", "root", "0")
    keys_supported = root_service and bool(key_rows) and effective.get("hostkeyagent") == "none"
    keys_supported &= all(Path(row["path"]).parent == Path("/etc/ssh") for row in key_rows)
    newest = configuration_changed_at(paths)
    journal = run(
        [
            "/usr/bin/journalctl",
            "-b",
            "-u",
            "sshd.service",
            "_PID=" + str(int(unit["MainPID"])),
            "--grep=^Server listening on",
            "--output=json",
            "--no-pager",
            "-n",
            "2",
        ]
    )
    journal.check_returncode()
    loaded_at = max(
        (
            int(
                json.loads(line).get(
                    "_SOURCE_REALTIME_TIMESTAMP", json.loads(line)["__REALTIME_TIMESTAMP"]
                )
            )
            / 1e6
            for line in journal.stdout.splitlines()
            if line.startswith("{")
        ),
        default=0,
    )
    safe = all(row["safe"] for row in metadata_rows)
    safe &= DROP.resolve() == DROP and DROP.is_dir() and DROP.stat().st_uid == 0
    safe &= not (DROP.stat().st_mode & 0o022)
    result = {
        "layout_supported": supported,
        "files_supported": supported and root_service,
        "keys_supported": bool(keys_supported and supported),
        "safe": bool(safe),
        "files": metadata_rows,
        "keys": key_rows,
        "effective": {key: effective.get(key.lower()) for key in desired},
        "matches": matches(effective, desired),
        "loaded": loaded_at >= newest,
        "active": unit["ActiveState"] == "active",
        "candidate_valid": False,
        "administrator_allowed": admin_allowed(effective, context),
    }
    if candidate and supported and safe:
        proposed = edit(content.get(MANAGED, ""), desired)
        with tempfile.TemporaryDirectory(prefix="hardener-sshd-") as temporary:
            root = Path(temporary)
            drop = root / "sshd_config.d"
            drop.mkdir(mode=0o700)
            for path, text in content.items():
                if path != MAIN:
                    (drop / path.name).write_text(text)
            (drop / MANAGED.name).write_text(proposed)
            main = root / "sshd_config"
            main.write_text(content[MAIN].replace(str(DROP / "*.conf"), str(drop / "*.conf")))
            syntax = run(["/usr/sbin/sshd", "-t", "-f", str(main)])
            evaluated = run(["/usr/sbin/sshd", "-T", "-f", str(main), "-C", context_arg(context)])
            proposed_state = parse_effective(evaluated.stdout)
            result["candidate_effective"] = {
                key: proposed_state.get(key.lower()) for key in desired
            }
            result["candidate_valid"] = syntax.returncode == 0 and evaluated.returncode == 0
            result["candidate_valid"] &= matches(proposed_state, desired)
            result["administrator_allowed"] = admin_allowed(proposed_state, context)
            if result["candidate_valid"]:
                result["candidate"] = proposed
    return result


if __name__ == "__main__":
    print(
        json.dumps(
            inspect(json.loads(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[3] == "candidate")
        )
    )
