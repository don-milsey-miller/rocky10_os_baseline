"""Configure authenticated TLS forwarding without embedding certificate material."""

import hashlib
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
from pathlib import Path

DROP = Path("/etc/rsyslog.d/00-rocky10-remote-tls.conf")


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
        raise ValueError("Native logging inspection failed")
    return result.stdout.strip()


def safe(path, missing=False):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unsafe logging parent")
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
        raise ValueError("Unsafe logging file")


def render(parameters):
    for name in ("host", "peer_name"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", parameters[name]):
            raise ValueError("Supply literal collector names")
    ca = parameters["ca_file"]
    if not re.fullmatch(r"/etc/pki/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.pem", ca):
        raise ValueError("Supply an external CA file under /etc/pki")
    if not 1 <= parameters["port"] <= 65535:
        raise ValueError("Invalid TLS port")
    return (
        "# Authenticated collector. Certificate material remains external.\n"
        'action(type="omfwd" name="rocky10_remote_tls" target="'
        + parameters["host"]
        + '" port="'
        + str(parameters["port"])
        + '" protocol="tcp"\n'
        '  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"\n'
        '  StreamDriverPermittedPeers="' + parameters["peer_name"] + '"\n'
        '  StreamDriver.CAFile="' + ca + '"\n'
        '  queue.type="LinkedList" queue.filename="rocky10_remote_tls"\n'
        '  queue.maxDiskSpace="100m" queue.saveOnShutdown="on" action.resumeRetryCount="-1")\n'
    )


def vendor_main():
    path = Path("/etc/rsyslog.conf")
    safe(path)
    rows = run(["/usr/bin/rpm", "-q", "--dump", "rsyslog"]).splitlines()
    expected = [row.split()[3] for row in rows if row.split()[0] == str(path)]
    if len(expected) != 1 or hashlib.sha256(path.read_bytes()).hexdigest() != expected[0]:
        raise ValueError("Review custom rsyslog main configuration and include precedence")
    for other in DROP.parent.glob("*.conf"):
        if other != DROP:
            safe(other)
            if other.name == "21-cloudinit.conf":
                packaged = run(["/usr/bin/rpm", "-q", "--dump", "cloud-init"])
                digests = {r.split()[0]: r.split()[3] for r in packaged.splitlines()}
                if hashlib.sha256(other.read_bytes()).hexdigest() == digests.get(str(other)):
                    continue
            # Unknown includes, early stops, TLS globals and additional forwards
            # can change routing. Keep their content and request explicit review.
            if any(
                line.strip() and not line.lstrip().startswith("#")
                for line in other.read_text().splitlines()
            ):
                raise ValueError("Review active rsyslog drop-ins before adding forwarding")


def empty_options(text):
    lines = [
        line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()
    ]
    return lines in (['SYSLOGD_OPTIONS=""'], ["SYSLOGD_OPTIONS=''"])


def service_policy():
    options = Path("/etc/sysconfig/rsyslog")
    safe(options)
    if not empty_options(options.read_text()):
        raise ValueError("Review alternate rsyslog startup options")
    if run(["/usr/bin/systemctl", "show", "rsyslog", "-p", "DropInPaths", "--value"]):
        raise ValueError("Review customized logging service")
    path = Path("/usr/lib/systemd/system/rsyslog.service")
    if run(["/usr/bin/systemctl", "show", "rsyslog", "-p", "FragmentPath", "--value"]) != str(path):
        raise ValueError("Review replaced logging service")
    packaged = run(["/usr/bin/rpm", "-q", "--dump", "rsyslog"])
    digests = {r.split()[0]: r.split()[3] for r in packaged.splitlines()}
    if hashlib.sha256(path.read_bytes()).hexdigest() != digests.get(str(path)):
        raise ValueError("Restore native logging service unit")


def inspect(parameters):
    run(["/usr/bin/rpm", "-q", "rsyslog", "rsyslog-gnutls"])
    desired = render(parameters)
    service_policy()
    vendor_main()
    if run(["/usr/bin/systemctl", "show", "rsyslog", "-p", "NeedDaemonReload", "--value"]) != "no":
        raise ValueError("Reload reviewed logging service units before applying")
    safe(DROP, missing=True)
    ca = Path(parameters["ca_file"])
    safe(ca)
    context = ssl.create_default_context(cafile=str(ca))
    # This is connection authentication evidence, not a log-receipt assertion.
    with (
        socket.create_connection((parameters["host"], parameters["port"]), timeout=5) as connection,
        context.wrap_socket(connection, server_hostname=parameters["peer_name"]) as secured,
    ):
        peer_verified = bool(secured.getpeercert())
    if DROP.exists() and DROP.read_text() != desired:
        raise ValueError("Review changes to an existing collector definition")
    configured = DROP.exists()
    active = run(["/usr/bin/systemctl", "is-active", "rsyslog"], (0, 3)) == "active"
    persistent = run(["/usr/bin/systemctl", "is-enabled", "rsyslog"], (0, 1)) == "enabled"
    loaded = False
    if active:
        if run(["/usr/bin/systemctl", "show", "rsyslog", "-p", "DropInPaths", "--value"]):
            raise ValueError("Review customized logging service")
        pid = run(["/usr/bin/systemctl", "show", "rsyslog", "-p", "MainPID", "--value"])
        commandline = Path("/proc/" + pid + "/cmdline").read_bytes().split(bytes([0]))
        if commandline != [b"/usr/sbin/rsyslogd", b"-n", b""]:
            raise ValueError("Review alternate running logging configuration")
        boot = next(
            int(r.split()[1])
            for r in Path("/proc/stat").read_text().splitlines()
            if r.startswith("btime ")
        )
        ticks = int(Path("/proc/" + pid + "/stat").read_text().rsplit(")", 1)[1].split()[19])
        loaded = configured and boot + ticks / os.sysconf("SC_CLK_TCK") >= max(
            DROP.stat().st_mtime, ca.stat().st_mtime
        )
        run(["/usr/sbin/rsyslogd", "-N1"])
    return {
        "matches": configured and active and persistent and loaded and peer_verified,
        "configured": configured,
        "active": active,
        "enabled": persistent,
        "configuration_loaded": loaded,
        "tls_peer_verified": peer_verified,
    }, desired


def main():
    parameters, mode = json.loads(sys.argv[1]), sys.argv[2]
    changed = False
    try:
        state, desired = inspect(parameters)
        if mode == "apply" and not state["matches"]:
            created = False
            if not DROP.exists():
                with DROP.open("x") as stream:
                    os.chmod(DROP, 0o640)
                    stream.write(desired)
                run(["/usr/sbin/restorecon", str(DROP)])
                created = True
            try:
                run(["/usr/sbin/rsyslogd", "-N1"])
            except ValueError:
                if created:
                    DROP.unlink()
                raise
            run(["/usr/bin/systemctl", "enable", "rsyslog"])
            run(["/usr/bin/systemctl", "restart", "rsyslog"])
            changed = True
            state, _ = inspect(parameters)
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
