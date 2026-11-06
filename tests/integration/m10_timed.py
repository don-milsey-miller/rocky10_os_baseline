"""Observe the approved 900-second unlock and Bash idle timeout without shortening policy."""

import json
import os
import selectors
import subprocess
import time
from pathlib import Path

from m10_identity import IdentityLab


def main():
    lab = IdentityLab(__doc__)
    lab.install_probe()
    passwords = json.loads((Path.home() / ".cache/m10-current.json").read_text())
    command = (
        "sudo -u m10human /usr/bin/env -i HOME=/home/m10human USER=m10human "
        "LOGNAME=m10human PATH=/usr/bin:/bin TERM=dumb /bin/bash --login -i"
    )
    process = subprocess.Popen(
        lab.ssh[:-1] + ["-tt", lab.ssh[-1], command],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    transcript = bytearray()
    # Keep the existing SSH channel timeout from ending this Bash-specific test.
    # Output from a background process is not input to the waiting interactive shell.
    process.stdin.write(
        b"(while /usr/bin/sleep 20; do printf 'M10_CHANNEL_HEARTBEAT\\n'; done) & "
        b"M10_HB=$!; trap 'kill \"$M10_HB\" 2>/dev/null' EXIT; "
        b"PS1='M10> '; printf 'M10_TIMER_READY\\n'\n"
    )
    process.stdin.flush()
    ready_deadline = time.monotonic() + 30
    while b"\r\nM10_TIMER_READY\r\n" not in transcript:
        assert time.monotonic() < ready_deadline, "Interactive Bash prompt did not become ready"
        for key, _ in selector.select(1):
            data = os.read(key.fd, 4096)
            assert data, "Interactive Bash exited before timer start"
            transcript.extend(data)
    shell_started = time.monotonic()
    lab.remote("sudo faillock --user m10deny --reset")
    assert lab.pam("m10deny", password=passwords["m10deny"]) == {"authentication": 0, "account": 0}
    for _ in range(5):
        assert lab.pam("m10deny", password="wrong-timed-fixture-password")["authentication"] != 0
    locked_at = time.monotonic()
    assert lab.pam("m10deny", password=passwords["m10deny"])["authentication"] != 0
    print("Approved 900-second lockout and idle timers started", flush=True)
    shell_elapsed = None
    early_checked = False
    last_update = 0
    while time.monotonic() - locked_at < 905:
        elapsed = time.monotonic() - locked_at
        if elapsed >= 60 and not early_checked:
            assert lab.pam("m10deny", password=passwords["m10deny"])["authentication"] != 0
            early_checked = True
        for key, _ in selector.select(1):
            data = os.read(key.fd, 4096)
            transcript.extend(data)
            if not data:
                selector.unregister(key.fileobj)
        if process.poll() is not None and shell_elapsed is None:
            shell_elapsed = time.monotonic() - shell_started
            assert 890 <= shell_elapsed <= 935, "Bash idle expiry outside approved interval"
        if int(elapsed) // 60 > last_update:
            last_update = int(elapsed) // 60
            print(f"Observed {last_update} minute(s); no timer values changed", flush=True)
    result = lab.pam("m10deny", password=passwords["m10deny"])
    assert result == {"authentication": 0, "account": 0}, (
        "Timed unlock did not restore authentication"
    )
    unlock_elapsed = time.monotonic() - locked_at
    if shell_elapsed is None:
        process.wait(timeout=30)
        shell_elapsed = time.monotonic() - shell_started
    assert 890 <= shell_elapsed <= 935
    remaining = process.stdout.read()
    transcript.extend(remaining)
    assert b"auto-logout" in transcript or b"timed out waiting for input" in transcript
    assert lab.remote("sudo -n id -u").strip() == "0"
    lab.finish(
        {
            "approved_seconds": 900,
            "blocked_at_60_seconds": early_checked,
            "automatic_unlock_observed_seconds": round(unlock_elapsed, 1),
            "interactive_bash_logout_seconds": round(shell_elapsed, 1),
            "administrator_access_preserved": True,
        }
    )
    process.stdin.close()
    selector.close()


if __name__ == "__main__":
    main()
