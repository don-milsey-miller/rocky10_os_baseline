"""Observed snapshot-recovery rehearsal and controller-local authenticated evidence."""

import hashlib
import hmac
import json
import os
import secrets
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from hardener.reporting import source_digest
from hardener.validation import DATA

MAX_AGE = 86400


class RecoveryError(ValueError):
    pass


def state_key(create=False):
    directory = Path.home() / ".local/state/rocky10-hardener"
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise RecoveryError("Run recovery-test on this controller to create recovery evidence.")
    info = directory.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RecoveryError("Recovery state directory must be owned by this user with mode 0700.")
    path = directory / "recovery.key"
    if create and not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise RecoveryError(
                    "Recovery signing key must be a private, single-link 0600 file."
                )
            key = stream.read(33)
        if len(key) != 32:
            raise RecoveryError(
                "Invalid recovery signing key. Recreate state and repeat recovery-test."
            )
        return key
    except OSError as exc:
        raise RecoveryError(
            "Recovery signing key unavailable. Repeat recovery-test on this controller."
        ) from exc


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def binding(inventory, target):
    return hashlib.sha256(Path(inventory).read_bytes() + b"\0" + target.encode()).hexdigest()


def write_receipt(path, proof):
    signature = hmac.new(state_key(create=True), canonical(proof), hashlib.sha256).hexdigest()
    with open(path, "x", encoding="utf-8") as stream:
        json.dump({"proof": proof, "signature": signature}, stream, indent=2)
        stream.write("\n")


def read_receipt(path, inventory, target):
    if not path:
        raise RecoveryError(
            "High-impact apply/preflight requires --recovery-evidence from a successful recovery-test."
        )
    try:
        with open(path, "rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("size")
        envelope = json.loads(raw)
        proof = envelope["proof"]
        expected = hmac.new(state_key(), canonical(proof), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, envelope["signature"]):
            raise ValueError("signature")
        if (
            proof["schema_version"] != 1
            or proof["binding"] != binding(inventory, target)
            or proof["engine_sha256"] != source_digest()
        ):
            raise ValueError("binding")
        age = time.time() - proof["completed_at"]
        if (
            not 0 <= age <= MAX_AGE
            or proof["outage_observed"] is not True
            or proof["marker_rolled_back"] is not True
        ):
            raise ValueError("freshness")
        if proof["before_boot"] == proof["after_boot"]:
            raise ValueError("boot")
        return proof
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RecoveryError(
            "Recovery evidence is invalid, expired, or belongs to another target/controller/engine. Repeat recovery-test."
        ) from exc


def needs_recovery(mode, controls):
    return mode in {"apply", "preflight"} and any(c["impact"] == "high" for c in controls)


def probe(inventory, target, env, nonce, prepare=False):
    variables = {
        "hardener_target": target,
        "hardener_mode": "preflight",
        "hardener_selected": [],
        "hardener_controls": [],
        "recovery_nonce": nonce,
        "recovery_prepare": prepare,
    }
    with tempfile.TemporaryDirectory(prefix="hardener-recovery-") as tmp:
        path = Path(tmp) / "vars.json"
        path.write_text(json.dumps(variables))
        result = subprocess.run(
            [
                "ansible-playbook",
                "-i",
                str(inventory),
                "--limit",
                target,
                str(DATA / "ansible/recovery.yml"),
                "--extra-vars",
                "@" + str(path),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
    try:
        evidence = json.loads(result.stdout)
        if not result.returncode and evidence.get("preflight_passed"):
            observation = evidence["recovery_observation"]
            if observation is not None:
                return observation
        if any(error.get("kind") == "unreachable" for error in evidence.get("errors", [])):
            return None
    except (ValueError, KeyError, TypeError):
        pass
    raise RecoveryError(
        "Recovery probe failed. Check guest platform, non-root SSH, sudo and the recovery marker. Raw command output is withheld."
    )


def recovered(before, after):
    return (
        after["machine_id"] == before["machine_id"]
        and after["boot_id"] != before["boot_id"]
        and after["marker_present"] is False
    )


def rehearse(inventory, target, output, env, timeout=600):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=False)
    state_key(create=True)
    nonce = secrets.token_hex(16)
    before = probe(inventory, target, env, nonce, prepare=True)
    if before is None or before.get("marker_present") is not True:
        raise RecoveryError("Could not establish the recovery challenge. No receipt was issued.")
    print(
        "RECOVERY_READY: Stop target SSH through the lab's existing administrative path. Wait for RECOVERY_OUTAGE_OBSERVED before restoring the pre-test snapshot from the hypervisor.",
        flush=True,
    )
    deadline = time.monotonic() + timeout
    outage = False
    while time.monotonic() < deadline:
        time.sleep(2)
        after = probe(inventory, target, env, nonce)
        if after is None:
            if not outage:
                print(
                    "RECOVERY_OUTAGE_OBSERVED: Restore the pre-test snapshot through the independent hypervisor path now.",
                    flush=True,
                )
            outage = True
        elif outage and recovered(before, after):
            proof = {
                "schema_version": 1,
                "binding": binding(inventory, target),
                "engine_sha256": source_digest(),
                "machine_id": before["machine_id"],
                "before_boot": before["boot_id"],
                "after_boot": after["boot_id"],
                "outage_observed": True,
                "marker_rolled_back": True,
                "completed_at": time.time(),
            }
            write_receipt(directory / "recovery.json", proof)
            print("Recovery passed. Evidence: " + str(directory / "recovery.json"), flush=True)
            return 0
    raise RecoveryError(
        "Recovery timed out. No receipt was issued. Restore the pre-test snapshot through the hypervisor, prove SSH/sudo, then repeat recovery-test."
    )
