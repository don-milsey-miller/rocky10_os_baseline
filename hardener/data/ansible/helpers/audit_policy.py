"""Bounded audit policy with persistent and loaded-rule verification."""

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

GROUPS = {
    "identity-changes": [
        ("/etc/passwd", "wa"),
        ("/etc/group", "wa"),
        ("/etc/shadow", "wa"),
        ("/etc/gshadow", "wa"),
    ],
    "privilege-use": [("/usr/bin/sudo", "x"), ("/usr/bin/su", "x")],
    "security-config-changes": [
        ("/etc/selinux", "wa"),
        ("/etc/audit", "wa"),
        ("/etc/sudoers", "wa"),
        ("/etc/ssh/sshd_config", "wa"),
    ],
    "session-events": [("/run/utmp", "wa"), ("/var/log/wtmp", "wa"), ("/var/log/btmp", "wa")],
}
RULES = Path("/etc/audit/rules.d")
CONFIG = Path("/etc/audit/auditd.conf")


def run(argv, allowed=(0,)):
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode not in allowed:
        raise ValueError("Native audit inspection or operation failed")
    return result.stdout.strip()


def safe(path, missing=False):
    if missing and not path.exists() and not path.is_symlink():
        safe_directory(path.parent)
        return
    info = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or "system.posix_acl_access" in os.listxattr(path)
    ):
        raise ValueError("Restore safe audit file metadata")
    safe_directory(path.parent)


def safe_directory(path):
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Restore safe audit directory metadata")


def active_lines(text):
    return [
        row.split("#", 1)[0].strip() for row in text.splitlines() if row.split("#", 1)[0].strip()
    ]


def settings(text):
    values = {}
    for line in active_lines(text):
        match = re.fullmatch(r"([a-z][a-z0-9_]+)\s*=\s*(\S+)", line)
        if not match or match[1] in values:
            raise ValueError("Review duplicate or unknown audit configuration syntax")
        values[match[1]] = match[2]
    return values


def canonical_rule(line):
    parts = shlex.split(line)
    if len(parts) != 6 or parts[0] != "-w" or parts[2] != "-p" or parts[4] != "-k":
        raise ValueError("Review unsupported audit rule")
    if not parts[1].startswith("/") or not set(parts[3]) <= set("rwxa") or not parts[3]:
        raise ValueError("Review malformed audit watch")
    return (parts[1].rstrip("/"), "".join(sorted(set(parts[3]))), parts[5])


def desired_rules(kind):
    key = "r10_" + kind.replace("-", "_")
    return [
        "-w " + path + " -p " + permissions + " -k " + key for path, permissions in GROUPS[kind]
    ]


def rule_path(kind):
    return RULES / ("70-rocky10-" + kind + ".rules")


def boot_args(text):
    rows = re.findall(r'^args="(.*)"$', text, re.MULTILINE)
    if not rows:
        raise ValueError("No supported kernel entries")
    return rows


def audit_boot_enabled(text, backlog=None):
    parts = shlex.split(text)
    return [part for part in parts if part.startswith("audit=")] == ["audit=1"] and (
        backlog is None
        or [part for part in parts if part.startswith("audit_backlog_limit=")]
        == ["audit_backlog_limit=" + str(backlog)]
    )


def storage_values(parameters):
    if parameters["admin_space_left_mib"] >= parameters["space_left_mib"]:
        raise ValueError("Administrative threshold must be below warning threshold")
    return {
        "max_log_file": str(parameters["max_log_file_mib"]),
        "num_logs": str(parameters["num_logs"]),
        "max_log_file_action": "ROTATE",
        "space_left": str(parameters["space_left_mib"]),
        "admin_space_left": str(parameters["admin_space_left_mib"]),
        **{
            name: parameters[name].upper()
            for name in (
                "space_left_action",
                "admin_space_left_action",
                "disk_full_action",
                "disk_error_action",
            )
        },
    }


def enabled(unit):
    return run(["/usr/bin/systemctl", "is-enabled", unit], (0, 1)) == "enabled"


def audit_state():
    state = {}
    for row in run(["/usr/sbin/auditctl", "-s"]).splitlines():
        parts = row.split()
        if len(parts) >= 2:
            state[parts[0]] = parts[1]
    if not {"enabled", "pid", "lost"} <= state.keys():
        raise ValueError("Incomplete kernel audit status")
    return state


def native_daemon(kernel_pid, unit_pid, commandline):
    return kernel_pid == unit_pid and commandline == [b"/usr/sbin/auditd", b""]


def inspect_rules():
    safe_directory(RULES)
    for path in RULES.glob("*.rules"):
        safe(path)
        for line in active_lines(path.read_text()):
            if path.name == "audit.rules" and line in (
                "-D",
                "-b 8192",
                "--backlog_wait_time 60000",
                "-f 1",
            ):
                continue
            if path.name == "99-rocky10-immutable.rules" and line == "-e 2":
                continue
            canonical_rule(line)  # Suppression, deletion and unmanaged finalization are refused.
    safe(Path("/etc/audit/audit.rules"))
    runtime = run(["/usr/sbin/auditctl", "-l"])
    return {canonical_rule(line) for line in runtime.splitlines() if line and line != "No rules"}


def loaded_config(pid):
    # A daemon start after the file, or a successful reconfiguration after it,
    # proves native parsing. Reading prior events does not emit new audit events.
    modified = CONFIG.stat().st_mtime
    boot = next(
        int(r.split()[1])
        for r in Path("/proc/stat").read_text().splitlines()
        if r.startswith("btime ")
    )
    process = Path("/proc/" + pid + "/stat").read_text().rsplit(")", 1)[1].split()
    start = boot + int(process[19]) / os.sysconf("SC_CLK_TCK")
    if start >= modified:
        return True
    for path in Path("/var/log/audit").glob("audit.log*"):
        if path.stat().st_mtime < modified:
            continue
        events = run(
            ["/usr/sbin/ausearch", "--input", str(path), "-m", "DAEMON_CONFIG", "--raw"], (0, 1)
        )
        if any(
            float(match[1]) >= max(modified, boot)
            and "op=reconfigure" in match[2]
            and ("res=success" in match[2] or "res=1" in match[2])
            for match in re.finditer(
                r"^type=DAEMON_CONFIG msg=audit\(([0-9.]+):[0-9]+\):(.*)", events, re.MULTILINE
            )
        ):
            return True
    return False


def inspect(kind, parameters):
    dump = run(["/usr/bin/rpm", "-q", "--dump", "audit", "audit-rules"])
    packaged = {r.split()[0]: r.split()[3] for r in dump.splitlines()}
    for name in ("auditd.service", "audit-rules.service"):
        path = Path("/usr/lib/systemd/system") / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != packaged.get(str(path)):
            raise ValueError("Restore native audit service units")
    run(["/usr/bin/rpm", "-q", "audit"])
    for unit in ("auditd.service", "audit-rules.service"):
        if run(["/usr/bin/systemctl", "show", unit, "-p", "DropInPaths", "--value"]):
            raise ValueError("Review customized audit service units")
        fragment = run(["/usr/bin/systemctl", "show", unit, "-p", "FragmentPath", "--value"])
        if fragment != "/usr/lib/systemd/system/" + unit:
            raise ValueError("Review replaced audit service units")
    state = audit_state()
    if int(state["pid"]) > 0:
        unit_pid = run(["/usr/bin/systemctl", "show", "auditd", "-p", "MainPID", "--value"])
        commandline = Path("/proc/" + state["pid"] + "/cmdline").read_bytes().split(bytes([0]))
        if not native_daemon(state["pid"], unit_pid, commandline):
            raise ValueError("Review alternate audit daemon ownership or configuration")
    if kind == "service-enabled":
        ok = (
            enabled("auditd")
            and enabled("audit-rules")
            and int(state["pid"]) > 0
            and state["enabled"] in ("1", "2")
        )
        return {
            "matches": ok,
            "kernel_enabled": state["enabled"],
            "daemon_running": int(state["pid"]) > 0,
        }, None
    if kind == "early-boot":
        args = boot_args(run(["/usr/sbin/grubby", "--info=ALL"]))
        persistent = all(audit_boot_enabled(row, parameters["backlog_limit"]) for row in args)
        current = audit_boot_enabled(Path("/proc/cmdline").read_text(), parameters["backlog_limit"])
        return {
            "matches": persistent and current and int(state["lost"]) == 0,
            "lost_events": int(state["lost"]),
            "persistent": persistent,
            "effective": current,
        }, None
    if int(state["pid"]) <= 0 or state["enabled"] not in ("1", "2"):
        raise ValueError("Enable native audit service first")
    if kind == "storage-policy":
        safe(CONFIG)
        config = settings(CONFIG.read_text())
        if (
            config.get("log_file") != "/var/log/audit/audit.log"
            or config.get("write_logs", "").lower() != "yes"
        ):
            raise ValueError("Require the standard local audit log")
        desired = storage_values(parameters)
        persistent = all(config.get(k, "").upper() == v.upper() for k, v in desired.items())
        effective = loaded_config(state["pid"])
        return {
            "matches": persistent and effective,
            "persistent": persistent,
            "effective": effective,
        }, desired
    loaded = inspect_rules()
    if kind == "immutable-rules":
        path = RULES / "99-rocky10-immutable.rules"
        safe(path, missing=True)
        persistent = path.exists() and active_lines(path.read_text()) == ["-e 2"]
        return {
            "matches": persistent and state["enabled"] == "2",
            "persistent": persistent,
            "kernel_enabled": state["enabled"],
        }, path
    expected = desired_rules(kind)
    path = rule_path(kind)
    safe(path, missing=True)
    for name, _ in GROUPS[kind]:
        if not Path(name).exists():
            raise ValueError("Required watched object is missing")
    if path.exists() and active_lines(path.read_text()) != expected:
        raise ValueError("Review drift in owned audit rule group")
    persistent = path.exists() and active_lines(path.read_text()) == expected
    missing = [rule for rule in expected if canonical_rule(rule) not in loaded]
    if state["enabled"] == "2" and (missing or not persistent):
        raise ValueError("Immutable audit rules require snapshot recovery or reviewed reboot")
    return {
        "matches": persistent and not missing,
        "persistent": persistent,
        "missing_rules": len(missing),
        "lost_events": int(state["lost"]),
    }, (path, expected, missing)


def write_new(path, content):
    safe(path, missing=True)
    if path.exists():
        if path.read_text() == content:
            return False
        raise ValueError("Do not overwrite an existing owned rule file")
    with path.open("x") as stream:
        os.chmod(path, 0o640)
        stream.write(content)
    run(["/usr/sbin/restorecon", str(path)])
    return True


def apply(kind, parameters):
    state, plan = inspect(kind, parameters)
    if state["matches"]:
        return False
    changed = False
    if kind == "service-enabled":
        run(["/usr/bin/systemctl", "enable", "auditd", "audit-rules"])
        run(["/usr/bin/systemctl", "start", "auditd"])
        if audit_state()["enabled"] == "0":
            run(["/usr/sbin/auditctl", "-e", "1"])
        return True
    if kind == "early-boot":
        if not state["persistent"]:
            run(
                [
                    "/usr/sbin/grubby",
                    "--update-kernel=ALL",
                    "--remove-args=audit audit_backlog_limit",
                    "--args=audit=1 audit_backlog_limit=" + str(parameters["backlog_limit"]),
                ]
            )
            return True
        return False  # A pending reboot is a failed effective-state check, never success.
    if kind == "storage-policy":
        text = CONFIG.read_text()
        if not state["persistent"]:
            for key, value in plan.items():
                pattern = r"^\s*" + key + r"\s*=.*$"
                if re.search(pattern, text, re.MULTILINE):
                    text = re.sub(pattern, key + " = " + value, text, flags=re.MULTILINE)
                else:
                    text += "\n" + key + " = " + value + "\n"
            CONFIG.write_text(text)
            changed = True
        run(["/usr/sbin/auditctl", "--signal", "reload"])
        for _ in range(30):
            time.sleep(0.1)
            if inspect(kind, parameters)[0]["matches"]:
                return True
        raise ValueError("Audit daemon did not acknowledge reconfiguration")
    if kind == "immutable-rules":
        changed = write_new(plan, "-e 2\n")
        run(["/usr/sbin/augenrules"])
        if state["kernel_enabled"] != "2":
            run(["/usr/sbin/auditctl", "-e", "2"])
            changed = True
        return changed
    path, expected, missing = plan
    changed = write_new(path, "\n".join(expected) + "\n")
    run(["/usr/sbin/augenrules"])
    for rule in missing:
        run(["/usr/sbin/auditctl", *shlex.split(rule)])
        changed = True
    return changed


def main():
    kind, parameters, mode = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
    changed = False
    try:
        state, _ = inspect(kind, parameters)
        if mode == "apply":
            changed = apply(kind, parameters)
            state, _ = inspect(kind, parameters)
        print(json.dumps({"supported": True, "changed": changed, **state}))
    except (ValueError, OSError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "supported": False,
                    "matches": False,
                    "changed": None if mode == "apply" else False,
                }
            )
        )


if __name__ == "__main__":
    main()
