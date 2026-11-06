"""Recovery and refusal-diagnostic acceptance on an explicitly disposable Rocky guest."""

import json
import time
from pathlib import Path

from lab import GuestLab

from hardener import recovery

IDS = [
    "network.ipv4-redirects-disabled",
    "network.ipv6-redirects-disabled",
    "network.ipv4-send-redirects-disabled",
    "network.reverse-path-filter",
    "network.ip-forwarding-disabled",
]
PARAMETERS = {cid: {"network_role": "non-routing"} for cid in IDS}
PARAMETERS[IDS[3]] = {"mode": "strict"}
PARAMETERS[IDS[4]]["container_networking"] = "absent"


def main():
    lab = GuestLab(__doc__)
    assert lab.args.recovery_evidence, "A real successful recovery-test receipt is required"
    receipt = Path(lab.args.recovery_evidence).resolve()
    original = json.loads(receipt.read_text())
    profile = lab.profile(IDS, PARAMETERS)

    def state():
        return lab.python(
            "import hashlib,json; from pathlib import Path; root=Path('/proc/sys/net'); names={'accept_redirects','send_redirects','rp_filter','forwarding'}; paths=[p for family in ['ipv4','ipv6'] for p in (root/family/'conf').glob('*/*') if p.name in names]; paths += [root/'ipv4/ip_forward']; paths += list(Path('/etc/sysctl.d').glob('*.conf')); paths += [Path('/etc/ssh/sshd_config'),Path('/etc/sudoers')]; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},sort_keys=True))"
        )

    def refuse(name, evidence):
        lab.args.recovery_evidence = evidence
        before = state()
        result = lab.execute("apply", name, profile, 3)
        assert result["changed_tasks"] == 0 and not result["preflight_passed"]
        assert result["errors"] and result["errors"][0].get("reason")
        assert state() == before
        return result

    refuse("missing-receipt", None)
    # Read-only inspection must remain usable without recovery authorization.
    assert lab.execute("audit", "audit-without-receipt", profile)["summary"]["pass"] == 5
    assert lab.execute("verify", "verify-without-receipt", profile)["summary"]["pass"] == 5
    manual = lab.output / "manual.json"
    manual.write_text('{"recovery_confirmed": true}')
    refuse("manual-acknowledgment", str(manual))
    tampered = lab.output / "tampered.json"
    changed = json.loads(receipt.read_text())
    changed["proof"]["completed_at"] += 1
    tampered.write_text(json.dumps(changed))
    refuse("tampered-receipt", str(tampered))
    # Negative fixtures deliberately use this controller's key to exercise semantic checks.
    for name, field, value in [
        ("expired-receipt", "completed_at", time.time() - recovery.MAX_AGE - 1),
        ("wrong-inventory", "binding", "0" * 64),
        ("wrong-engine", "engine_sha256", "0" * 64),
        ("wrong-guest", "machine_id", "0" * 32),
    ]:
        source = lab.output / (name + ".json")
        recovery.write_receipt(source, {**original["proof"], field: value})
        result = refuse(name, str(source))
        if name == "wrong-guest":
            assert "another guest" in result["errors"][-1]["reason"]

    lab.args.recovery_evidence = str(receipt)
    before = state()
    accepted = lab.execute("apply", "accepted-idempotent", profile)
    assert accepted["summary"]["pass"] == 5 and accepted["changed_tasks"] == 0
    assert state() == before
    conflict = "/etc/sysctl.d/zz-recovery-conflict.conf"
    lab.write(conflict, "# private-diagnostic-sentinel\nnet.ipv4.conf.future0.rp_filter=2\n")
    try:
        result = refuse("network-conflict", str(receipt))
        error = result["errors"][-1]
        assert error["code"] == "network-policy-conflict"
        assert error["control_id"] == "network.reverse-path-filter"
        assert conflict in str(error["details"])
        assert "private-diagnostic-sentinel" not in json.dumps(result)
        summary = (lab.output / "network-conflict/summary.txt").read_text()
        assert conflict in summary and "Reconcile" in summary
    finally:
        lab.remove(conflict)
    managed = "/etc/sysctl.d/99-rocky10-network-reverse-path-filter.conf"
    saved = lab.remote("sudo cat " + managed)
    lab.write(managed, saved + "net.ipv4.ip_local_port_range=32768 60999\n")
    try:
        result = refuse("unsafe-managed-file", str(receipt))
        assert managed in str(result["errors"][-1]["details"])
    finally:
        lab.write(managed, saved)
    assert lab.execute("verify", "final-verify", profile)["summary"]["pass"] == 5
    assert state() == before
    lab.finish(
        {
            "refusals": 9,
            "unchanged_managed_state": True,
            "read_only_without_receipt": True,
            "authenticated_recovery_accepted": True,
            "actionable_conflict_paths": True,
            "private_sentinel_absent": True,
        }
    )


if __name__ == "__main__":
    main()
