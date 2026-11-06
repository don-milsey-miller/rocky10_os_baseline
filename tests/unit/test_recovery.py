"""Recovery evidence cannot be replaced with an acknowledgment or another target's test."""

import copy
import json
import os
from types import SimpleNamespace

import pytest

from hardener import cli, recovery
from hardener.validation import load_catalog


@pytest.fixture
def proof(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(recovery, "source_digest", lambda: "engine")
    monkeypatch.setattr(recovery.time, "time", lambda: 100000)
    inventory = tmp_path / "inventory"
    inventory.write_text("[servers]\ntest-vm ansible_host=192.0.2.20\n")
    payload = {
        "schema_version": 1,
        "binding": recovery.binding(inventory, "test-vm"),
        "engine_sha256": "engine",
        "machine_id": "a" * 32,
        "before_boot": "before",
        "after_boot": "after",
        "completed_at": 99999,
        "outage_observed": True,
        "marker_rolled_back": True,
    }
    receipt = tmp_path / "receipt.json"
    recovery.write_receipt(receipt, payload)
    return inventory, receipt, payload


def test_valid_recovery_evidence(proof):
    inventory, receipt, payload = proof
    assert recovery.read_receipt(receipt, inventory, "test-vm") == payload


@pytest.mark.parametrize(
    "field,value",
    [
        ("binding", "other"),
        ("engine_sha256", "other"),
        ("completed_at", 1),
        ("completed_at", 100001),
        ("outage_observed", False),
        ("marker_rolled_back", False),
        ("after_boot", "before"),
    ],
)
def test_reject_invalid_signed_evidence(proof, field, value):
    inventory, receipt, payload = proof
    receipt.unlink()
    payload[field] = value
    recovery.write_receipt(receipt, payload)
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")


def test_reject_tampering_and_manual_acknowledgment(proof):
    inventory, receipt, _payload = proof
    document = json.loads(receipt.read_text())
    document["proof"]["completed_at"] += 1
    receipt.write_text(json.dumps(document))
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")
    receipt.write_text('{"recovery_confirmed": true}')
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(None, inventory, "test-vm")


def test_binding_rejects_inventory_change_and_target_alias(proof):
    inventory, receipt, _ = proof
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "different-vm")
    inventory.write_text("different endpoint")
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")


def test_private_controller_key_required(proof, tmp_path):
    inventory, receipt, _ = proof
    key = tmp_path / ".local/state/rocky10-hardener/recovery.key"
    key.chmod(0o644)
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")
    key.chmod(0o600)
    original = key.with_suffix(".original")
    key.rename(original)
    key.symlink_to(original)
    with pytest.raises(recovery.RecoveryError):
        recovery.read_receipt(receipt, inventory, "test-vm")


def test_recovery_scope():
    high = [{"impact": "high"}]
    for mode in ["audit", "verify", "validate"]:
        assert not recovery.needs_recovery(mode, high)
    for mode in ["preflight", "apply"]:
        assert recovery.needs_recovery(mode, high)
        assert not recovery.needs_recovery(mode, [])
        assert not recovery.needs_recovery(mode, [{"impact": "low"}])


def test_marker_and_reboot_and_same_guest_required():
    before = {"machine_id": "a", "boot_id": "one", "marker_present": True}
    after = {"machine_id": "a", "boot_id": "two", "marker_present": False}
    assert recovery.recovered(before, after)
    for field, value in [("machine_id", "other"), ("boot_id", "one"), ("marker_present", True)]:
        assert not recovery.recovered(before, {**after, field: value})


def test_high_impact_refusal_precedes_ansible_execution(tmp_path, monkeypatch):
    inventory = tmp_path / "inventory"
    inventory.write_text("test-vm")
    monkeypatch.setattr(cli, "inventory_target", lambda *a: inventory)
    monkeypatch.setattr(cli, "run_command", lambda *a: pytest.fail("Must refuse before playbook"))
    profile = {
        "schema_version": 1,
        "id": "guard",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": "auth.ssh-config-permissions", "enabled": True}],
    }
    args = SimpleNamespace(
        mode="apply",
        target="test-vm",
        inventory=inventory,
        output=tmp_path / "report",
        recovery_evidence=None,
    )
    assert cli.execute(args, profile, "digest", load_catalog()) == 3
    result = json.loads((args.output / "report.json").read_text())
    assert result["changed_tasks"] == 0
    assert result["errors"][0]["code"] == "recovery-required"
    assert "--recovery-evidence" in result["errors"][0]["reason"]


def test_rehearsal_requires_observed_outage(proof, tmp_path, monkeypatch):
    inventory, _, _ = proof
    before = {"machine_id": "a", "boot_id": "one", "marker_present": True}
    after = {"machine_id": "a", "boot_id": "two", "marker_present": False}
    observations = iter([before, after, None, after])
    monkeypatch.setattr(recovery, "probe", lambda *a, **k: next(observations))
    monkeypatch.setattr(recovery.time, "sleep", lambda *a: None)
    out = tmp_path / "ceremony"
    assert recovery.rehearse(inventory, "test-vm", out, os.environ.copy()) == 0
    assert (out / "recovery.json").exists()


def test_timeout_issues_no_receipt(proof, tmp_path, monkeypatch):
    inventory, _, _ = proof
    before = {"machine_id": "a", "boot_id": "one", "marker_present": True}
    monkeypatch.setattr(recovery, "probe", lambda *a, **k: copy.deepcopy(before))
    out = tmp_path / "expired"
    with pytest.raises(recovery.RecoveryError, match="timed out"):
        recovery.rehearse(inventory, "test-vm", out, {}, timeout=0)
    assert not (out / "recovery.json").exists()
