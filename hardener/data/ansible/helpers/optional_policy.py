"""Explicit unused-module, listener, scheduler and console notice policies."""

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


import pwd


def module_text(modules):
    if (
        not modules
        or len(modules) != len(set(modules))
        or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", m) for m in modules)
    ):
        raise ValueError("Use distinct canonical module names")
    return "".join(f"install {m} /bin/false\nblacklist {m}\n" for m in sorted(modules))


def loading_denied(text, module):
    rows = [row.strip() for row in text.splitlines() if row.strip()]
    if not rows or rows[-1] != "install /bin/false":
        return False
    for row in rows[:-1]:
        if not row.startswith("insmod /") or re.search(
            r"/" + re.escape(module).replace("_", "[-_]") + r"\.ko(?:\.|\s|$)", row
        ):
            return False
    return True


SCAN_CONTEXT = {}


def initramfs_proof(modules, prior, images=None):
    requested = sorted(set(modules))
    module_text(requested)
    images = list(Path("/boot").glob("initramfs-*.img")) if images is None else images
    if not images:
        raise ValueError("Boot images are missing")

    def digest(path):
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()

    hashes = {str(path): digest(path) for path in images}
    proof = {"modules": requested, "images": hashes, "absent": True}
    if prior == proof:
        return proof
    for initrd in images:
        listing = run(["lsinitrd", str(initrd)])
        if any(
            re.search(r"/" + re.escape(m).replace("_", "[-_]") + r"\.ko(?:\.|\s)", listing)
            for m in requested
        ):
            raise ValueError("Provision initramfs without selected unused drivers before applying")
        if digest(initrd) != hashes[str(initrd)]:
            raise ValueError("Boot image changed during inspection")
    return proof


def inspect_modules(kind, parameters):
    modules = parameters["modules"]
    desired = module_text(modules)
    filename = "99-rocky10-" + kind + ".conf"
    path = Path("/etc/modprobe.d") / filename
    dracut = Path("/etc/dracut.conf.d") / filename
    safe(path, missing=True)
    safe(dracut, missing=True)
    installed = []
    for module in modules:
        if Path("/sys/module", module).exists():
            raise ValueError(
                "An approved module is loaded. Resolve workload use without automatic unload"
            )
        name = run(["modinfo", "-F", "filename", module])
        family = "/kernel/fs/" if kind == "unused-filesystem-modules" else "/kernel/net/"
        if family not in name or not name.endswith((".ko", ".ko.xz", ".ko.zst")):
            raise ValueError("Require installed loadable modules from the selected family")
        installed.append(module)
    # Reuse only within this invocation and only after hashing every image again.
    proof = initramfs_proof(
        set(modules) | set(SCAN_CONTEXT.get("requested", [])), SCAN_CONTEXT.get("proof", {})
    )
    for directory in [
        "/etc/modprobe.d",
        "/run/modprobe.d",
        "/usr/local/lib/modprobe.d",
        "/usr/lib/modprobe.d",
    ]:
        for candidate in Path(directory).glob("*.conf"):
            if candidate == path:
                continue
            for line in candidate.read_text().splitlines():
                parts = line.split("#", 1)[0].split()
                if (
                    len(parts) >= 2
                    and parts[1].replace("-", "_") in modules
                    and parts[0] != "blacklist"
                ):
                    raise ValueError("Resolve other modprobe policy for the selected modules")
    # Modules-load explicitly requests a driver even if it is not loaded now.
    for directory in ["/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d"]:
        for candidate in Path(directory).glob("*.conf"):
            if any(
                line.split("#", 1)[0].strip().replace("-", "_") in modules
                for line in candidate.read_text().splitlines()
            ):
                raise ValueError("Remove explicit module startup requests through workload review")
    startup = [Path("/etc/dracut.conf")]
    for directory in ["/etc/dracut.conf.d", "/usr/lib/dracut/dracut.conf.d"]:
        startup += list(Path(directory).glob("*.conf"))
    for candidate in startup:
        if candidate == dracut or not candidate.exists():
            continue
        for line in candidate.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if re.match(r"omit_drivers\s*=", line) or (
                re.search(r"(?:add|force|omit)_drivers", line)
                and any(
                    re.search(r"\b" + re.escape(module) + r"\b", line.replace("-", "_"))
                    for module in modules
                )
            ):
                raise ValueError("Resolve competing initramfs driver policy")
    dracut_text = 'omit_drivers+=" ' + " ".join(sorted(modules)) + ' "\n'
    effective = all(
        loading_denied(run(["modprobe", "--dry-run", "--verbose", m], allowed=(0, 1)), m)
        for m in modules
    )
    return {
        "matches": file_matches(path, desired) and file_matches(dracut, dracut_text) and effective,
        "modules": installed,
        "loaded": False,
        "initramfs_clear": True,
        "initramfs_proof": proof,
        "loading_denied": effective,
    }, [(path, desired), (dracut, dracut_text)]


def unit_values(unit):
    text = run(
        [
            "systemctl",
            "show",
            unit,
            "-p",
            "LoadState,ActiveState,UnitFileState,Names,TriggeredBy,Triggers,FragmentPath,DropInPaths",
        ]
    )
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def inspect_listeners(parameters):
    selected = set(parameters["units"])
    protected = {
        "sshd.service",
        "sshd.socket",
        "ssh.service",
        "NetworkManager.service",
        "NetworkManager-wait-online.service",
        "network.service",
        "firewalld.service",
        "nftables.service",
        "auditd.service",
        "audit-rules.service",
        "rsyslog.service",
        "dbus.service",
        "dbus.socket",
        "dbus-broker.service",
        "crond.service",
        "atd.service",
        "systemd-journald.service",
        "systemd-logind.service",
        "systemd-udevd.service",
    }
    if not selected or selected & protected or any(u.startswith("systemd-") for u in selected):
        raise ValueError("Essential access, networking, security and scheduler units are protected")
    states = []
    for unit in sorted(selected):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,80}\.(service|socket)", unit):
            raise ValueError("Select concrete service or socket units")
        values = unit_values(unit)
        if values["LoadState"] not in ("loaded", "masked"):
            raise ValueError("Install and inspect requested units before selection")
        if values["LoadState"] == "loaded":
            if values["DropInPaths"]:
                raise ValueError("Review unit overrides")
            safe(Path(values["FragmentPath"]))
            linked = set(
                (values["TriggeredBy"] + " " + values["Triggers"] + " " + values["Names"]).split()
            )
            if linked - selected:
                raise ValueError("Select all socket activation and alias units together")
            reverse = run(
                ["systemctl", "list-dependencies", "--reverse", "--plain", "--no-legend", unit]
            )
            for dependency in reverse.splitlines():
                dependency = dependency.strip()
                if (
                    dependency.endswith(".service")
                    and dependency not in selected
                    and run(["systemctl", "is-active", dependency], allowed=(0, 3, 4)) == "active"
                ):
                    raise ValueError("An active unselected service requires this listener")
        states.append(
            {
                "unit": unit,
                "inactive": values["ActiveState"] == "inactive",
                "masked": values["UnitFileState"] == "masked",
            }
        )
    return {"matches": all(x["inactive"] and x["masked"] for x in states), "units": states}, sorted(
        selected
    )


def scheduler_text(users):
    if (
        "root" not in users
        or len(set(users)) != len(users)
        or any(not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", u) for u in users)
    ):
        raise ValueError("Explicit distinct local users including root are required")
    return "".join(u + "\n" for u in sorted(users))


def inspect_scheduler(kind, parameters):
    cron = kind == "cron-access"
    name = "cron" if cron else "at"
    run(["rpm", "-q", "cronie" if cron else "at"])
    users = parameters["users"]
    desired = scheduler_text(users)
    local = {row.split(":")[0] for row in Path("/etc/passwd").read_text().splitlines()}
    for user in users:
        if user not in local:
            raise ValueError("Scheduler admission supports explicit local users")
        pwd.getpwnam(user)
    if cron:
        jobs = {p.name for p in Path("/var/spool/cron").iterdir()}
    else:
        jobs = {row.split()[-1] for row in run(["atq"]).splitlines() if row.strip()}
    if jobs - set(users):
        raise ValueError("Policy would exclude an existing job owner")
    path = Path("/etc/" + name + ".allow")
    safe(path, missing=True)
    safe(Path("/etc/" + name + ".deny"), missing=True)
    if not vendor("/etc/pam.d/crond" if cron else "/etc/pam.d/atd"):
        raise ValueError("Review custom scheduler PAM configuration")
    return {
        "matches": file_matches(path, desired),
        "allowed_users": sorted(users),
        "existing_job_owners_preserved": True,
    }, [(path, desired)]


def banner_text(text):
    if (
        not text.strip()
        or len(text) > 2048
        or any((ord(c) < 32 and c != "\n") or ord(c) > 126 for c in text)
        or "\\" in text
    ):
        raise ValueError("Use bounded plain ASCII notice text without terminal or getty escapes")
    return text.rstrip("\n") + "\n"


def inspect(kind, parameters):
    if kind.startswith("unused-"):
        return inspect_modules(kind, parameters)
    if kind == "legacy-listeners-disabled":
        return inspect_listeners(parameters)
    if kind in ("cron-access", "at-access"):
        return inspect_scheduler(kind, parameters)
    if kind == "authorized-use-banner":
        path = Path("/etc/issue")
        safe(path)
        cockpit = Path("/etc/issue.d/cockpit.issue")
        for notice in Path("/etc/issue.d").glob("*.issue"):
            if (
                notice == cockpit
                and notice.is_symlink()
                and os.readlink(notice) == "../../run/cockpit/issue"
                and notice.lstat().st_uid == 0
            ):
                continue
            raise ValueError("Review supplemental login notices")
        desired = banner_text(parameters["text"])
        return {
            "matches": file_matches(path, desired) and not cockpit.is_symlink(),
            "notice_sha256": hashlib.sha256(desired.encode()).hexdigest(),
            "scope": "local-console",
        }, [(path, desired)]
    raise ValueError("Unknown optional policy")


def main():
    global SCAN_CONTEXT
    SCAN_CONTEXT = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    kind, mode = sys.argv[1:3]
    parameters = json.loads(sys.argv[3])
    changed = False
    try:
        state, plan = inspect(kind, parameters)
        if mode == "apply" and not state["matches"]:
            if kind == "legacy-listeners-disabled":
                for unit in sorted(plan, key=lambda u: not u.endswith(".socket")):
                    changed = True  # A failing native operation can still partially change state.
                    run(["systemctl", "disable", "--now", unit])
                    run(["systemctl", "mask", unit])
                    changed = True
            else:
                for path, text in plan:
                    if not file_matches(path, text):
                        write(path, text)
                        changed = True
                if kind == "authorized-use-banner":
                    cockpit = Path("/etc/issue.d/cockpit.issue")
                    if cockpit.is_symlink():
                        cockpit.unlink()
                        changed = True
                    run(["agetty", "--reload"])
            if kind.startswith("unused-"):
                state["verification_required"] = True
            else:
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
                    "reason": "Review selected module startup/initramfs, linked service activation, existing scheduler job owners, local PAM, or notice ownership before applying.",
                }
            )
        )


if __name__ == "__main__":
    main()
