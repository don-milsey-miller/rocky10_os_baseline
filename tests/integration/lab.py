"""Small shared transport/report helpers for disposable guest integration tests."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from hardener.cli import inventory_target


class GuestLab:
    def __init__(self, description):
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--inventory", required=True)
        parser.add_argument("--target", required=True)
        parser.add_argument("--output", required=True)
        parser.add_argument("--disposable", action="store_true", required=True)
        self.args = parser.parse_args()
        self.inventory = inventory_target(self.args.inventory, self.args.target, os.environ.copy())
        self.output = Path(self.args.output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        hosts = json.loads(self.run(["ansible-inventory", "-i", str(self.inventory), "--list"]))[
            "_meta"
        ]["hostvars"]
        host = hosts[self.args.target]
        self.ssh = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-p",
            str(host.get("ansible_port", 22)),
            f"{host['ansible_user']}@{host['ansible_host']}",
        ]
        self.commands = []

    @staticmethod
    def run(argv, expected=0, **kwargs):
        result = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=600, **kwargs
        )
        if result.returncode != expected:
            raise AssertionError(
                f"{argv[0]}: expected {expected}, got {result.returncode}\n"
                f"{result.stdout}\n{result.stderr}"
            )
        return result.stdout

    def remote(self, command):
        return self.run(self.ssh + [command])

    def python(self, code):
        return self.remote("sudo /usr/bin/python3 -c " + shlex.quote(code))

    def write(self, path, content):
        return self.python(f"from pathlib import Path; Path({path!r}).write_text({content!r})")

    def remove(self, path):
        return self.python(f"from pathlib import Path; Path({path!r}).unlink(missing_ok=True)")

    @staticmethod
    def profile(ids, parameters=None):
        return {
            "schema_version": 1,
            "id": "disposable-family-test",
            "revision": 1,
            "target": {"os": "rocky", "major_version": 10, "role": "server"},
            "controls": [
                {
                    "id": cid,
                    "enabled": True,
                    **({"parameters": parameters[cid]} if parameters and cid in parameters else {}),
                }
                for cid in ids
            ],
        }

    def execute(self, mode, name, profile, expected=0):
        source = self.output / (name + ".yaml")
        source.write_text(json.dumps(profile, indent=2) + "\n")
        argv = [
            sys.executable,
            "-m",
            "hardener.cli",
            mode,
            "--profile",
            str(source),
            "--inventory",
            str(self.inventory),
            "--target",
            self.args.target,
            "--output",
            str(self.output / name),
        ]
        self.commands.append({"argv": argv, "expected_exit": expected})
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=600)
        (self.output / (name + ".log")).write_text(result.stdout + result.stderr)
        if result.returncode != expected:
            raise AssertionError(
                f"{name}: expected {expected}, got {result.returncode}\n"
                f"{result.stdout}\n{result.stderr}"
            )
        return json.loads((self.output / name / "report.json").read_text())

    def reboot(self):
        before = self.remote("cat /proc/sys/kernel/random/boot_id").strip()
        subprocess.run(
            self.ssh + ["sudo systemctl reboot"], check=False, capture_output=True, timeout=20
        )
        for _ in range(90):
            time.sleep(2)
            result = subprocess.run(
                self.ssh + ["cat /proc/sys/kernel/random/boot_id; sudo -n id -u"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            lines = result.stdout.splitlines()
            if (
                result.returncode == 0
                and len(lines) == 2
                and lines[0] != before
                and lines[1] == "0"
            ):
                return
        raise AssertionError("Guest did not recover SSH and sudo after reboot")

    def finish(self, evidence):
        (self.output / "integration-evidence.json").write_text(
            json.dumps({**evidence, "commands": self.commands}, indent=2) + "\n"
        )
        print(json.dumps(evidence), flush=True)
