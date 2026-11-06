"""QEMU serial-console acceptance. Run only on the explicit disposable lab hypervisor."""

import argparse
import json
import re
import select
import socket
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--lab-directory", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--disposable", action="store_true", required=True)
args = parser.parse_args()
root = Path(args.lab_directory).resolve(strict=True)
qemu = json.loads((root / "test-qemu.json").read_text())
assert qemu[0] == "qemu-system-x86_64" and "rocky-m8-test" in qemu
assert str(root / "test.qcow2") in " ".join(qemu)
ssh = [
    "ssh",
    "-i",
    str(root / "lab_ed25519"),
    "-o",
    "UserKnownHostsFile=" + str(root / "dev-known-hosts"),
    "-o",
    "BatchMode=yes",
    "-p",
    "22231",
    "zero@127.0.0.1",
]
# Keep credential plaintext in process memory only. Never print the console transcript.
credentials = json.loads(
    subprocess.check_output(
        ssh + ["cat /home/zero/.local/state/rocky10-hardener/m12-credentials.json"], text=True
    )
)
for _ in range(60):
    ready = subprocess.run(
        ssh + ["ssh -o ConnectTimeout=3 zero@192.0.2.20 sudo -n id -u"],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if ready.returncode == 0 and ready.stdout.strip() == "0":
        break
    time.sleep(2)
else:
    raise AssertionError("Guest not ready for console test")
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(str(root / "test-console.sock"))
client.setblocking(False)
buffer = ""
ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def receive():
    global buffer
    if select.select([client], [], [], 0.1)[0]:
        data = client.recv(65536)
        if not data:
            raise RuntimeError("Serial console disconnected")
        buffer += data.decode(errors="replace")
        buffer = buffer[-300000:]


def send(text):
    client.sendall(text.encode())


def expect(pattern, timeout=90):
    global buffer
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        cleaned = ansi.sub("", buffer)
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if match:
            buffer = cleaned[match.end() :]
            return
        receive()
    # Do not include potentially sensitive terminal data in exceptions.
    raise AssertionError("Console did not reach expected state: " + pattern)


def shell_marker(marker):
    send("printf '" + marker + "\\n'\n")
    expect(r"(?:^|[\r\n])" + marker + r"\r?\n", 30)


subprocess.run(
    ssh + ["ssh zero@192.0.2.20 sudo systemctl reboot --no-block"],
    capture_output=True,
    check=False,
    timeout=20,
)
expect("GRUB version", 120)
send("e")
expect("Enter username", 10)
send("root\n")
expect("Enter password", 10)
send("deliberately-incorrect\n")
expect("Access denied|invalid password|authentication failed", 20)
expect("GRUB version", 20)
send("e")
expect("Enter username", 15)
send("root\n")
expect("Enter password", 10)
send(credentials["grub"] + "\n")
expect("Minimum Emacs|Ctrl-x|F10", 15)
send("\x1b")
time.sleep(1)
send("\n")
expect("Authorized laboratory access only", 120)
expect("login:", 30)


def root_login():
    send("root\n")
    expect("Password:", 15)
    send(credentials["root"] + "\n")
    time.sleep(2)
    shell_marker("M12_ROOT_LOGIN_OK")


root_login()
print("GRUB authentication and console banner passed", flush=True)
results = {"grub_wrong_rejected": True, "grub_correct_edit": True, "console_banner": True}
for target in ("rescue", "emergency"):
    send("systemctl isolate " + target + ".target\n")
    expect(r"Control-D to continue\):", 90)
    time.sleep(0.5)
    send("deliberately-incorrect\n")
    expect("Login incorrect|incorrect password|Authentication failure", 20)
    # sulogin repeats its prompt following a rejected password.
    expect(r"Control-D to continue\):", 15)
    time.sleep(0.5)
    send(credentials["root"] + "\n")
    time.sleep(2)
    shell_marker("M12_" + target.upper() + "_AUTHENTICATED")
    results[target + "_wrong_rejected"] = True
    results[target + "_correct_shell"] = True
    print(target + " authentication passed", flush=True)
    send("systemctl default\n")
    expect("Authorized laboratory access only", 90)
    expect("login:", 30)
    if target == "rescue":
        root_login()
client.close()
for _ in range(60):
    result = subprocess.run(
        ssh + ["ssh -o ControlMaster=no -o ControlPath=none zero@192.0.2.20 sudo -n id -u"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode == 0 and result.stdout.strip() == "0":
        break
    time.sleep(2)
else:
    raise AssertionError("Fresh SSH did not recover after console testing")
results["fresh_ssh_recovered"] = True
out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(results, indent=2) + "\n")
print(json.dumps(results))
