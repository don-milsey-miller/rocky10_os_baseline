"""Inspect SELinux independently of remediation; refuse disabled policy migration."""

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path


def run(argv):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    ).stdout.strip()


def config_values(text):
    result = {}
    for row in text.splitlines():
        row = row.split("#", 1)[0].strip()
        if not row:
            continue
        match = re.fullmatch(r"(SELINUX|SELINUXTYPE)=([a-z]+)", row)
        if not match or match[1] in result:
            raise ValueError("Review unknown or duplicate SELinux configuration")
        result[match[1]] = match[2]
    if set(result) != {"SELINUX", "SELINUXTYPE"}:
        raise ValueError("Restore explicit SELinux mode and policy")
    if result["SELINUX"] not in ("enforcing", "permissive", "disabled") or result[
        "SELINUXTYPE"
    ] not in ("targeted", "minimum", "mls"):
        raise ValueError("Unknown SELinux mode or policy")
    return result


def boot_permits(text):
    for token in shlex.split(text):
        if token in ("selinux", "enforcing"):
            return False
        if token.startswith(("selinux=", "enforcing=")) and token not in (
            "selinux=1",
            "enforcing=1",
        ):
            return False
    return True


def policy_digest(path):
    result = subprocess.run(
        ["/usr/bin/checkpolicy", "-b", "-M", "-C", "-o", "/dev/stdout", str(path)],
        capture_output=True,
        check=False,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode or not result.stdout:
        raise ValueError("Cannot inspect loaded policy semantics")
    return hashlib.sha256(result.stdout).hexdigest()


def loaded_targeted():
    candidates = [
        p
        for p in Path("/etc/selinux/targeted/policy").glob("policy.*")
        if re.fullmatch(r"policy\.[0-9]+", p.name)
    ]
    if not candidates:
        raise ValueError("Compiled targeted policy is missing")
    selected = max(candidates, key=lambda p: int(p.suffix[1:]))
    safe(selected)
    return policy_digest(selected) == policy_digest(Path("/sys/fs/selinux/policy"))


def unconfined(text):
    rows = [row.split() for row in text.splitlines() if row.strip()]
    if any(len(row) != 2 or len(row[0].split(":")) < 3 for row in rows):
        raise ValueError("Cannot inspect process contexts")
    return sum(row[0].split(":")[2] == "unconfined_service_t" for row in rows)


def safe(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe SELinux policy parent")
    info = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or "system.posix_acl_access" in os.listxattr(path)
    ):
        raise ValueError("Restore safe SELinux configuration metadata")


def inspect(kind):
    mode = run(["/usr/sbin/getenforce"])
    if mode == "Disabled":
        raise ValueError("Disabled SELinux requires reviewed relabel and reboot")
    if kind == "no-unconfined-services":
        count = unconfined(run(["/usr/bin/ps", "-eo", "label=,comm="]))
        return {"matches": count == 0, "unconfined_processes": count}, None
    path = Path("/etc/selinux/config")
    safe(path)
    values = config_values(path.read_text())
    if values["SELINUX"] == "disabled" or not loaded_targeted():
        raise ValueError("Policy migration requires reviewed relabel and reboot")
    run(["/usr/bin/rpm", "-q", "selinux-policy-targeted"])
    boot = run(["/usr/sbin/grubby", "--info=ALL"])
    args = re.findall(r'^args="(.*)"$', boot, re.MULTILINE)
    if (
        not args
        or not all(boot_permits(a) for a in args)
        or not boot_permits(Path("/proc/cmdline").read_text())
    ):
        raise ValueError("Remove SELinux boot bypasses through reviewed boot maintenance")
    key, desired = ("SELINUX", "enforcing") if kind == "enforcing" else ("SELINUXTYPE", "targeted")
    return {
        "matches": values[key] == desired
        and (mode == "Enforcing" if kind == "enforcing" else True),
        "runtime_mode": mode,
        "loaded_policy": "targeted",
        "persistent_value": values[key],
    }, (path, key, desired)


def main():
    kind, mode = sys.argv[1:3]
    changed = False
    try:
        state, plan = inspect(kind)
        if mode == "apply" and not state["matches"]:
            if plan is None:
                raise ValueError("Assessment cannot remediate")
            path, key, desired = plan
            old = path.read_text()
            updated = re.sub(r"^" + key + r"=[a-z]+", key + "=" + desired, old, flags=re.MULTILINE)
            if updated != old:
                # Existing validated inode retains ownership, mode and label.
                path.write_text(updated)
                changed = True
            if kind == "enforcing" and state["runtime_mode"] != "Enforcing":
                run(["/usr/sbin/setenforce", "1"])
                changed = True
            state, _ = inspect(kind)
        print(json.dumps({"supported": True, "changed": changed, **state}))
    except (ValueError, OSError, subprocess.SubprocessError):
        print(json.dumps({"supported": False, "matches": False, "changed": changed}))


if __name__ == "__main__":
    main()
