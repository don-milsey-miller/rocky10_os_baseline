"""Read-only storage and firmware observations. Migration belongs to provisioning."""

import json
import os
import subprocess
import sys
from pathlib import Path


def run(argv):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
        env={**os.environ, "LC_ALL": "C"},
    ).stdout


def encrypted_ancestry(nodes):
    if not nodes:
        raise ValueError("Empty block-device ancestry")

    # Every backing branch must encounter a dm-crypt mapping before a physical disk.
    def protected(node, encrypted=False):
        encrypted = encrypted or node.get("type") == "crypt"
        children = node.get("children", [])
        return all(protected(child, encrypted) for child in children) if children else encrypted

    return all(protected(node) for node in nodes)


def secure_boot(efi):
    if not efi:
        return {
            "matches": False,
            "firmware": "bios",
            "secure_boot": False,
            "disposition": "Secure Boot requires UEFI provisioning. BIOS is not a successful Secure Boot result.",
        }
    raise ValueError("UEFI inspection requires a separately accepted firmware fixture")


def assess(kind, parameters):
    if kind == "secure-boot":
        efi = Path("/sys/firmware/efi")
        return secure_boot(efi.exists())
    evidence = []
    root = json.loads(run(["findmnt", "-J", "-M", "/", "-o", "MAJ:MIN"]))["filesystems"][0][
        "maj:min"
    ]
    seen_devices = {root}
    for value in parameters["paths"]:
        path = Path(value)
        if not path.is_absolute() or str(path) != value or path.resolve(strict=True) != path:
            raise ValueError("Use existing canonical paths without symbolic links")
        if not path.is_dir():
            raise ValueError("Select mounted directories")
        native = json.loads(
            run(["findmnt", "-J", "-T", value, "-o", "TARGET,SOURCE,FSTYPE,MAJ:MIN,FSROOT"])
        )["filesystems"]
        if len(native) != 1 or native[0]["fstype"] not in ("xfs", "ext4"):
            raise ValueError("Require a supported local block filesystem")
        mount = native[0]
        if kind == "partition-layout":
            matches = (
                mount["target"] == value
                and mount["fsroot"] == "/"
                and (value == "/" or mount["maj:min"] not in seen_devices)
            )
            seen_devices.add(mount["maj:min"])
        elif kind == "disk-encryption":
            nodes = json.loads(
                run(
                    [
                        "lsblk",
                        "--inverse",
                        "--json",
                        "--paths",
                        "--output",
                        "NAME,TYPE",
                        "/dev/block/" + mount["maj:min"],
                    ]
                )
            )["blockdevices"]
            matches = encrypted_ancestry(nodes)
        else:
            raise ValueError("Unknown storage assessment")
        evidence.append({"path": value, "mountpoint": mount["target"], "matches": matches})
    return {
        "matches": all(x["matches"] for x in evidence),
        "paths": evidence,
        "disposition": "Assessment only. Repartitioning or encryption migration requires an approved provisioning procedure.",
    }


def main():
    try:
        print(json.dumps(assess(sys.argv[1], json.loads(sys.argv[2]))))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "error": "Incomplete storage or firmware inspection. Check paths, block ancestry and firmware variables."
                }
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
