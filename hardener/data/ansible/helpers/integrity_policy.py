"""Maintain one explicitly approved AIDE baseline without automatic refresh."""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

CONFIG = Path("/etc/aide-rocky10.conf")
DATABASE = Path("/var/lib/aide/rocky10.db.gz")
CANDIDATE = Path("/var/lib/aide/rocky10.db.new.gz")
MANIFEST = Path("/var/lib/aide/rocky10.config.sha256")
SERVICE = Path("/etc/systemd/system/rocky10-aide.service")
TIMER = Path("/etc/systemd/system/rocky10-aide.timer")


def run(argv, allowed=(0,)):
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode not in allowed:
        raise ValueError("Native integrity operation failed")
    return result


def safe(path, missing=False):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe integrity parent")
    if missing and not path.exists() and not path.is_symlink():
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
        raise ValueError("Unsafe integrity file")


def render(parameters):
    paths = parameters["paths"]
    if not paths or len(set(paths)) != len(paths):
        raise ValueError("Select unique integrity paths")
    for path in paths:
        if not re.fullmatch(r"/(?:etc|usr|opt|srv)(?:/[A-Za-z0-9_-]+)*", path):
            raise ValueError("Select bounded persistent integrity directories")
    return (
        "database_in=file:" + str(DATABASE) + "\n"
        "database_out=file:" + str(CANDIDATE) + "\n"
        "gzip_dbout=yes\nreport_url=stdout\n"
        + "".join(re.escape(path) + "(/|$) p+i+n+u+g+s+m+c+sha256\n" for path in sorted(paths))
    )


def units(schedule):
    if schedule not in ("daily", "weekly"):
        raise ValueError("Unsupported integrity schedule")
    service = (
        "[Unit]\nDescription=Verify approved Rocky server integrity baseline\n"
        "[Service]\nType=oneshot\nExecStart=/usr/sbin/aide --config="
        + str(CONFIG)
        + " --check\nUser=root\n"
    )
    timer = (
        "[Unit]\nDescription=Schedule Rocky server integrity verification\n"
        "[Timer]\nOnCalendar=" + schedule + "\nPersistent=true\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    return service, timer


def inspect(parameters):
    run(["/usr/bin/rpm", "-q", "aide"])
    desired = render(parameters)
    for unit in ("rocky10-aide.service", "rocky10-aide.timer"):
        overrides = run(
            ["/usr/bin/systemctl", "show", unit, "-p", "DropInPaths", "--value"], (0, 1, 4)
        ).stdout.strip()
        if overrides:
            raise ValueError("Review integrity service overrides before initialization")
        for directory in ("/run/systemd/system", "/usr/lib/systemd/system"):
            if (Path(directory) / unit).exists():
                raise ValueError("Review conflicting integrity service unit")

    for directory in parameters["paths"]:
        path = Path(directory)
        info = path.lstat()
        if (
            path.resolve() != path
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise ValueError("Baseline directory must exist with safe ownership")
    contents = {
        CONFIG: desired,
        SERVICE: units(parameters["schedule"])[0],
        TIMER: units(parameters["schedule"])[1],
    }
    for path in [*contents, DATABASE, CANDIDATE, MANIFEST]:
        safe(path, missing=True)
    if MANIFEST.exists() and not DATABASE.exists():
        raise ValueError(
            "Missing trusted baseline requires explicit recovery, never reinitialization"
        )
    if CANDIDATE.exists():
        raise ValueError("Review leftover candidate database before initialization")
    digest = hashlib.sha256(desired.encode()).hexdigest()
    if DATABASE.exists():
        if (
            not CONFIG.exists()
            or not MANIFEST.exists()
            or MANIFEST.read_text().strip() != digest
            or CONFIG.read_text() != desired
        ):
            raise ValueError(
                "Existing baseline scope requires explicit offline review, never automatic refresh"
            )
    elif not parameters["initialize_baseline"]:
        raise ValueError("Baseline initialization requires explicit owner approval")
    for path, text in contents.items():
        if path.exists() and path.read_text() != text:
            raise ValueError("Review existing integrity configuration before replacement")
    configured = all(path.exists() for path in contents) and DATABASE.exists()
    result = None
    scheduled = False
    if configured:
        run(["/usr/sbin/aide", "--config=" + str(CONFIG), "--config-check"])
        result = run(
            ["/usr/sbin/aide", "--config=" + str(CONFIG), "--check"], tuple(range(8))
        ).returncode
        for unit in ("rocky10-aide.service", "rocky10-aide.timer"):
            if run(
                ["/usr/bin/systemctl", "show", unit, "-p", "DropInPaths", "--value"]
            ).stdout.strip():
                raise ValueError("Review integrity service overrides")
        units_loaded = all(
            run(
                ["/usr/bin/systemctl", "show", unit, "-p", "NeedDaemonReload", "--value"]
            ).stdout.strip()
            == "no"
            for unit in ("rocky10-aide.service", "rocky10-aide.timer")
        )
        command = run(
            ["/usr/bin/systemctl", "show", "rocky10-aide.service", "-p", "ExecStart", "--value"]
        ).stdout
        units_loaded = (
            units_loaded
            and "argv[]=/usr/sbin/aide --config=/etc/aide-rocky10.conf --check ;" in command
        )
        scheduled = (
            units_loaded
            and run(
                ["/usr/bin/systemctl", "is-enabled", "rocky10-aide.timer"], (0, 1)
            ).stdout.strip()
            == "enabled"
            and run(
                ["/usr/bin/systemctl", "is-active", "rocky10-aide.timer"], (0, 3)
            ).stdout.strip()
            == "active"
            and parameters["schedule"]
            in run(["/usr/bin/systemctl", "cat", "rocky10-aide.timer"]).stdout
        )
    return (
        {
            "matches": configured and scheduled and result == 0,
            "baseline_exists": DATABASE.exists(),
            "scheduled": scheduled,
            "integrity_exit": result,
        },
        contents,
        digest,
    )


def create(path, content):
    if path.exists():
        return False
    with path.open("x") as stream:
        os.chmod(path, 0o600 if path == MANIFEST else 0o644)
        stream.write(content)
    run(["/usr/sbin/restorecon", str(path)])
    return True


def main():
    parameters, mode = json.loads(sys.argv[1]), sys.argv[2]
    changed = False
    try:
        state, contents, digest = inspect(parameters)
        if mode == "apply":
            for path, text in contents.items():
                changed = create(path, text) or changed
            if not DATABASE.exists():
                run(["/usr/sbin/aide", "--config=" + str(CONFIG), "--init"])
                safe(CANDIDATE)
                # Link creation cannot overwrite a baseline created concurrently.
                os.link(CANDIDATE, DATABASE)
                CANDIDATE.unlink()
                os.chmod(DATABASE, 0o600)
                create(MANIFEST, digest + "\n")
                changed = True
            if changed or not state["scheduled"]:
                run(["/usr/bin/systemctl", "daemon-reload"])
            if not state["scheduled"]:
                run(["/usr/bin/systemctl", "enable", "--now", "rocky10-aide.timer"])
                changed = True
            state, _, _ = inspect(parameters)
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
