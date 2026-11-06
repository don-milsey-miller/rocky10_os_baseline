"""BIOS boot protection and explicit crypto policy with reboot evidence."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def run(argv, allowed=(0,), input=None):
    result = subprocess.run(
        argv,
        check=False,
        input=input,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode not in allowed:
        raise ValueError("Native command failed")
    return result.stdout.strip()


def safe(path, missing=False, private=False):
    path = Path(path)
    if path.resolve() != path:
        raise ValueError("Symbolic configuration paths are unsupported")
    for parent in path.parents:
        if parent.exists():
            st = parent.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError("Unsafe configuration parent")
    if missing and not path.exists():
        return
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("Unsafe configuration ownership, links or writes")
    if private and (stat.S_IMODE(st.st_mode) != 0o600 or st.st_gid != 0):
        raise ValueError("Secret references require root-only 0600 files")
    if "system.posix_acl_access" in os.listxattr(path):
        raise ValueError("Configuration ACL requires review")


WRITE_OCCURRED = False


def write(path, text, mode=0o644):
    global WRITE_OCCURRED
    path = Path(path)
    safe(path, missing=True)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, name = tempfile.mkstemp(prefix=".rocky10-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            os.fchmod(output.fileno(), mode)
            output.write(text)
        os.replace(name, path)
        WRITE_OCCURRED = True
        run(["restorecon", str(path)])
    finally:
        if os.path.exists(name):
            os.unlink(name)


def file_matches(path, text, mode=0o644):
    path = Path(path)
    return (
        path.exists()
        and path.read_text() == text
        and stat.S_IMODE(path.stat().st_mode) == mode
        and path.stat().st_gid == 0
    )


def vendor(path):
    safe(Path(path))
    rows = run(["rpm", "-qf", "--qf", "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", str(path)])
    digests = dict(row.split("\t", 1) for row in rows.splitlines() if "\t" in row)
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() == digests.get(str(path))


import time

BOOT_FILES = ["/boot/grub2/grub.cfg", "/boot/grub2/grubenv"]


def bios():
    if Path("/sys/firmware/efi").exists() or not Path("/boot/grub2/i386-pc").is_dir():
        raise ValueError("Only the accepted BIOS GRUB layout is supported")


def private_value(path, pattern):
    path = Path(path)
    safe(path, private=True)
    value = path.read_text().strip()
    if not re.fullmatch(pattern, value):
        raise ValueError("Invalid external credential format")
    return value


def boot_files():
    bios()
    paths = [Path(p) for p in BOOT_FILES]
    paths += sorted(Path("/boot/loader/entries").glob("*.conf"))
    if Path("/boot/grub2/user.cfg").exists():
        paths.append(Path("/boot/grub2/user.cfg"))
    if len(paths) < 3:
        raise ValueError("BLS boot entries are required")
    for path in paths:
        safe(path)
    return paths


def grub_block(text):
    markers = ["### BEGIN /etc/grub.d/01_users ###", "### END /etc/grub.d/01_users ###"]
    if any(text.count(marker) != 1 for marker in markers):
        raise ValueError("Require one generated credential hook")
    block = text.split(markers[0], 1)[1].split(markers[1], 1)[0].strip()
    expected = run(["/etc/grub.d/01_users"]).strip()
    if (
        block != expected
        or text.count("set superusers=") != 1
        or text.count("password_pbkdf2 ") != 1
    ):
        raise ValueError("Review overridden GRUB authentication")
    return True


def rescue_units():
    paths = []
    for unit in ("rescue.service", "emergency.service"):
        vendor_path = "/usr/lib/systemd/system/" + unit
        if not vendor(vendor_path):
            raise ValueError("Require vendor rescue and emergency entry points")
        managed = Path("/etc/systemd/system/" + unit + ".d/50-rocky10-auth.conf")
        safe(managed, missing=True)
        allowed = str(managed) if managed.exists() else ""
        override = run(["systemctl", "show", unit, "-p", "DropInPaths", "--value"])
        if override != allowed:
            raise ValueError("Review unknown rescue overrides")
        fragment = run(["systemctl", "show", unit, "-p", "FragmentPath", "--value"])
        command = run(["systemctl", "show", unit, "-p", "ExecStart", "--value"])
        if (
            fragment != vendor_path
            or "/usr/lib/systemd/systemd-sulogin-shell " + unit.split(".")[0] not in command
        ):
            raise ValueError("Require native authenticated rescue entry points")
        paths.append(managed)
    if not vendor("/usr/lib/systemd/systemd-sulogin-shell") or not vendor("/usr/sbin/sulogin"):
        raise ValueError("Require native sulogin binaries")
    return paths


def inspect_crypto(parameters):
    policy = parameters["policy"]
    if policy not in ("DEFAULT", "FUTURE"):
        raise ValueError("Select an accepted built-in policy")
    for directory in (Path("/etc/crypto-policies/policies"), Path("/etc/crypto-policies/local.d")):
        if directory.exists() and any(p.is_file() or p.is_symlink() for p in directory.rglob("*")):
            raise ValueError("Review local cryptographic overrides")
    for name in ("config", "state/CURRENT.pol"):
        safe(Path("/etc/crypto-policies") / name)
    current = run(["update-crypto-policies", "--show"])
    if current not in ("DEFAULT", "FUTURE", "LEGACY"):
        raise ValueError("Policy migration supports reviewed built-in non-FIPS policies")
    run(["update-crypto-policies", "--check"])
    boot = time.time() - float(Path("/proc/uptime").read_text().split()[0])
    effective = Path("/etc/crypto-policies/state/CURRENT.pol").stat().st_mtime <= boot
    return {
        "matches": current == policy and effective,
        "configured_policy": current,
        "requested_policy": policy,
        "reboot_pending": not effective,
    }, policy


def inspect(kind, parameters):
    if kind == "system-policy":
        return inspect_crypto(parameters)
    bios()
    if kind == "config-permissions":
        paths = boot_files()
        matches = all(
            stat.S_IMODE(p.stat().st_mode) == 0o600 and p.stat().st_gid == 0 for p in paths
        )
        return {"matches": matches, "firmware": "bios", "files_checked": len(paths)}, paths
    if kind == "loader-authentication":
        custom = Path("/boot/grub2/custom.cfg")
        if custom.exists() or custom.is_symlink():
            raise ValueError("Review supplemental GRUB commands before boot authentication")
        for path in boot_files():
            safe(path)
        if not vendor("/etc/grub.d/01_users"):
            raise ValueError("Require the vendor GRUB authentication hook")
        run(["grub2-script-check", "/boot/grub2/grub.cfg"])
        grub_block(Path("/boot/grub2/grub.cfg").read_text())
        secret = private_value(
            parameters["hash_file"],
            r"grub\.pbkdf2\.sha512\.[1-9][0-9]{3,7}\.[A-Fa-f0-9]{128}\.[A-Fa-f0-9]{128}",
        )
        path = Path("/boot/grub2/user.cfg")
        safe(path, missing=True)
        desired = "GRUB2_PASSWORD=" + secret + "\n"
        if path.exists() and not re.fullmatch(
            r"GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.[0-9]+\.[A-Fa-f0-9]+\.[A-Fa-f0-9]+\n?",
            path.read_text(),
        ):
            raise ValueError("Review custom GRUB credential configuration")
        return {
            "matches": file_matches(path, desired, 0o600),
            "firmware": "bios",
            "vendor_authentication_hook": True,
            "credential_source": "external",
        }, (path, desired)
    if kind == "rescue-authentication":
        command_lines = [Path("/proc/cmdline").read_text()]
        command_lines += [p.read_text() for p in Path("/boot/loader/entries").glob("*.conf")]
        if any(
            re.search(r"SYSTEMD_SULOGIN_FORCE|systemd\.debug-shell|(?:^|\s)init=|rd\.break", text)
            for text in command_lines
        ):
            raise ValueError(
                "Remove boot command-line rescue bypasses through reviewed maintenance"
            )
        paths = rescue_units()
        secret = private_value(
            parameters["hash_file"],
            r"\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}",
        )
        rows = [
            r.split(":")
            for r in Path("/etc/shadow").read_text().splitlines()
            if r.startswith("root:")
        ]
        if len(rows) != 1 or len(rows[0]) != 9 or rows[0][7] not in ("", "-1"):
            raise ValueError("Review root account identity and expiry")
        desired = "[Service]\nEnvironment=SYSTEMD_SULOGIN_FORCE=0\n"
        runtime = all(
            "SYSTEMD_SULOGIN_FORCE=0"
            in run(["systemctl", "show", unit, "-p", "Environment", "--value"]).split()
            for unit in ("rescue.service", "emergency.service")
        )
        return {
            "matches": rows[0][1] == secret
            and all(file_matches(p, desired) for p in paths)
            and runtime,
            "native_sulogin": True,
            "root_credential_matches": rows[0][1] == secret,
            "forced_bypass_disabled": runtime,
        }, (paths, desired, secret, rows[0][1] != secret)
    raise ValueError("Unknown boot policy")


def main():
    kind, mode = sys.argv[1:3]
    parameters = json.loads(sys.argv[3])
    changed = False
    try:
        state, plan = inspect(kind, parameters)
        if mode == "apply" and not state["matches"]:
            if kind == "config-permissions":
                for path in plan:
                    info = path.stat()
                    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_gid != 0:
                        changed = True
                        os.chmod(path, 0o600)
                        os.chown(path, 0, 0)
                        changed = True
            elif kind == "loader-authentication":
                write(plan[0], plan[1], 0o600)
                changed = True
            elif kind == "rescue-authentication":
                paths, text, secret, password_differs = plan
                for path in paths:
                    if not file_matches(path, text):
                        write(path, text)
                        changed = True
                if password_differs:
                    changed = True
                    run(["chpasswd", "--encrypted"], input="root:" + secret + "\n")
                    changed = True
                run(["systemctl", "daemon-reload"])
            elif kind == "system-policy" and state["configured_policy"] != plan:
                changed = True
                run(["update-crypto-policies", "--set", plan])
                run(["sshd", "-t"])
                changed = True
            state, _ = inspect(kind, parameters)
        print(json.dumps({"supported": True, "changed": changed or WRITE_OCCURRED, **state}))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "supported": False,
                    "failure_type": type(error).__name__,
                    "detail": str(error)
                    if isinstance(error, ValueError)
                    else "Native inspection or mutation failed",
                    "matches": False,
                    "changed": changed or WRITE_OCCURRED,
                    "reason": "Require the accepted BIOS layout, intact native boot authentication, private external credentials or built-in crypto policy without local overrides.",
                }
            )
        )


if __name__ == "__main__":
    main()
