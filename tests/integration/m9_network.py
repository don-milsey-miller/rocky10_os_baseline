"""M9 baseline lifecycle on an explicitly disposable server guest."""

import copy
import json

from lab import GuestLab

IDS = [
    "network.ipv4-source-route-disabled",
    "network.ipv6-source-route-disabled",
    "network.tcp-syncookies",
]


def main():
    lab = GuestLab(__doc__)
    profile = lab.profile(IDS)
    lab.execute("preflight", "guard", profile)
    untouched = lab.remote(
        "sudo sha256sum /etc/ssh/sshd_config /etc/sudoers /etc/sysctl.d/99-rocky10-hardener.conf; sudo sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6"
    )
    lab.python(
        "from pathlib import Path; root=Path('/proc/sys'); [(p.write_text('1')) for family in ['ipv4','ipv6'] for p in (root/'net'/family/'conf').glob('*/accept_source_route')]; (root/'net/ipv4/tcp_syncookies').write_text('0')"
    )

    def state():
        return lab.python(
            "import json; from pathlib import Path; roots=[Path('/etc/sysctl.d'),Path('/proc/sys/net/ipv4/conf'),Path('/proc/sys/net/ipv6/conf')]; "
            "files=[p for root in roots for p in root.rglob('*') if p.is_file() and (root.name=='sysctl.d' or p.name=='accept_source_route')]; "
            "files.append(Path('/proc/sys/net/ipv4/tcp_syncookies')); "
            "print(json.dumps({str(p):p.read_text() for p in files},sort_keys=True))"
        )

    initial = state()
    before = lab.execute("audit", "before", profile, 5)
    assert before["summary"]["fail"] == 3 and before["changed_tasks"] == 0
    assert state() == initial
    later = "/etc/sysctl.d/zz-m9-conflict.conf"
    lab.write(later, "net.ipv6.conf.future0.accept_source_route=0\n")
    refused = lab.execute("apply", "future-conflict", profile, 3)
    assert refused["changed_tasks"] == 0
    assert lab.remote("sysctl -n net.ipv4.tcp_syncookies").strip() == "0"
    lab.remove(later)
    for name, content in [
        ("broad-glob", "net.ipv?.conf.*.accept_source_route=0\n"),
        ("excluded-future", "-net.ipv4.conf.future0.accept_source_route\n"),
    ]:
        lab.write(later, content)
        unchanged = state()
        assert lab.execute("apply", name, profile, 3)["changed_tasks"] == 0
        assert state() == unchanged
        lab.remove(later)
    managed = "/etc/sysctl.d/99-rocky10-network-tcp-syncookies.conf"
    lab.remote("sudo ln -s /etc/hostname " + managed)
    try:
        unchanged = state()
        assert lab.execute("apply", "unsafe-symlink", profile, 3)["changed_tasks"] == 0
        assert state() == unchanged
    finally:
        lab.remove(managed)
    lab.write(managed, "net.ipv4.ip_forward=0\n")
    try:
        unchanged = state()
        assert lab.execute("apply", "unrelated-managed", profile, 3)["changed_tasks"] == 0
        assert state() == unchanged
    finally:
        lab.remove(managed)
    omitted = copy.deepcopy(profile)
    omitted["controls"][-1].update(enabled=False, reason="Test exclusion")
    excluded = lab.execute("apply", "excluded-cookie", omitted)
    assert excluded["summary"]["pass"] == 2 and excluded["summary"]["excluded"] == 1
    assert lab.remote("sysctl -n net.ipv4.tcp_syncookies").strip() == "0"
    only_v6 = lab.profile([IDS[1]])
    assert lab.execute("apply", "omitted-cookie", only_v6)["changed_tasks"] == 0
    assert lab.remote("sysctl -n net.ipv4.tcp_syncookies").strip() == "0"
    applied = lab.execute("apply", "apply", profile)
    assert applied["summary"]["pass"] == 3
    unchanged = state()
    assert lab.execute("verify", "verify", profile)["summary"]["pass"] == 3
    assert state() == unchanged
    assert lab.execute("apply", "idempotent", profile)["changed_tasks"] == 0
    lab.remote("sudo ip link add m9dummy type dummy")
    try:
        assert lab.remote("sysctl -n net.ipv4.conf.m9dummy.accept_source_route").strip() == "0"
        assert lab.remote("sysctl -n net.ipv6.conf.m9dummy.accept_source_route").strip() == "-1"
        lab.remote("sudo sysctl -w net.ipv6.conf.m9dummy.accept_source_route=0")
        assert lab.execute("verify", "interface-drift", profile, 5)["summary"]["fail"] == 1
        lab.execute("apply", "repair-interface", profile)
    finally:
        lab.remote("sudo ip link delete m9dummy")
    assert (
        lab.remote(
            "sudo sha256sum /etc/ssh/sshd_config /etc/sudoers /etc/sysctl.d/99-rocky10-hardener.conf; sudo sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.disable_ipv6"
        )
        == untouched
    )
    native = lab.python(
        "import json; from pathlib import Path; print(json.dumps({str(p):p.read_text().strip() for family in ['ipv4','ipv6'] for p in (Path('/proc/sys/net')/family/'conf').glob('*/accept_source_route')}))"
    )
    observations = json.loads(native)
    assert all(value == ("-1" if "/ipv6/" in key else "0") for key, value in observations.items())
    (lab.output / "native-observations.json").write_text(native)
    lab.reboot()
    assert lab.execute("verify", "after-reboot", profile)["summary"]["pass"] == 3
    assert lab.execute("apply", "after-reboot-idempotent", profile)["changed_tasks"] == 0
    lab.finish(
        {
            "controls": 3,
            "noncompliance_detected": True,
            "unsafe_preflight_refusals": 5,
            "read_only_audit_verify": True,
            "omission": True,
            "exclusion": True,
            "new_interface_defaults": True,
            "interface_drift_detected": True,
            "unrelated_state_preserved": True,
            "reboot_verified": True,
            "idempotent": True,
        }
    )


if __name__ == "__main__":
    main()
