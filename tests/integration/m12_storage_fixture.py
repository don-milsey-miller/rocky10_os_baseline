"""Native encrypted/plain disposable loop-image assessment. Never formats a real disk."""

import argparse
import importlib.util
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

from hardener.validation import DATA

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--disposable", action="store_true", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit("Run inside the disposable development KVM guest as root")
if subprocess.check_output(["systemd-detect-virt"], text=True).strip() != "kvm":
    raise SystemExit("KVM guest required")
spec = importlib.util.spec_from_file_location(
    "storage_assessment", DATA / "ansible/helpers/storage_assessment.py"
)
assessment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assessment)


def run(argv):
    return subprocess.run(
        argv, capture_output=True, text=True, check=True, timeout=120
    ).stdout.strip()


records = []
with tempfile.TemporaryDirectory(prefix="hardener-m12-loop-", dir="/var/tmp") as folder:
    root = Path(folder)
    image = root / "disk.img"
    with image.open("wb") as handle:
        handle.truncate(128 * 1024 * 1024)
    key = root / "key"
    key.write_bytes(os.urandom(64))
    key.chmod(0o600)
    mount = root / "mount"
    mount.mkdir()
    loop = run(["losetup", "--find", "--show", str(image)])
    assert loop.startswith("/dev/loop") and loop[9:].isdigit()
    mapping = "hardener-m12-" + uuid.uuid4().hex[:12]
    opened = False
    mounted = False
    try:
        assert run(["losetup", "--noheadings", "--output", "BACK-FILE", loop]) == str(image)
        run(["mkfs.ext4", "-F", loop])
        run(["mount", loop, str(mount)])
        mounted = True
        plain = assessment.assess("disk-encryption", {"paths": [str(mount)]})
        assert plain["matches"] is False
        partition = assessment.assess("partition-layout", {"paths": [str(mount)]})
        assert partition["matches"] is True
        run(["umount", str(mount)])
        mounted = False
        run(
            [
                "cryptsetup",
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--pbkdf",
                "pbkdf2",
                "--key-file",
                str(key),
                loop,
            ]
        )
        run(["cryptsetup", "open", "--key-file", str(key), loop, mapping])
        opened = True
        device = "/dev/mapper/" + mapping
        assert Path(device).exists()
        run(["mkfs.ext4", "-F", device])
        run(["mount", device, str(mount)])
        mounted = True
        encrypted = assessment.assess("disk-encryption", {"paths": [str(mount)]})
        assert encrypted["matches"] is True
        records = [{"plain_encryption": False, "separate_mount": True, "luks_encryption": True}]
    finally:
        if mounted:
            run(["umount", str(mount)])
        if opened:
            run(["cryptsetup", "close", mapping])
        run(["losetup", "--detach", loop])
out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps({"native_block_assessment": records, "loop_fixture_removed": True}, indent=2) + "\n"
)
print(out.read_text())
