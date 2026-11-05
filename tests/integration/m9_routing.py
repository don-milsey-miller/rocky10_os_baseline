"""M9 host routing policy acceptance on an explicitly disposable guest."""

import copy
import json

from lab import GuestLab

IDS = [
    "network.ipv4-redirects-disabled",
    "network.ipv6-redirects-disabled",
    "network.ipv4-send-redirects-disabled",
    "network.reverse-path-filter",
    "network.ip-forwarding-disabled",
]
BASELINE = [
    "network.ipv4-source-route-disabled",
    "network.ipv6-source-route-disabled",
    "network.tcp-syncookies",
]
PARAMETERS = {cid: {"network_role": "non-routing"} for cid in IDS}
PARAMETERS[IDS[3]] = {"mode": "strict"}
PARAMETERS[IDS[4]]["container_networking"] = "absent"


def main():
    lab = GuestLab(__doc__)
    profile = lab.profile(IDS, PARAMETERS)
    lab.execute("preflight", "guard", profile)
    assert lab.execute("verify", "baseline-before", lab.profile(BASELINE))["summary"]["pass"] == 3

    def state():
        return json.loads(
            lab.python(
                "import json; from pathlib import Path; root=Path('/proc/sys/net'); "
                "names={'accept_redirects','send_redirects','rp_filter','forwarding','accept_source_route','disable_ipv6','accept_ra'}; "
                "files=[p for family in ['ipv4','ipv6'] for p in (root/family/'conf').glob('*/*') if p.name in names]; "
                "files += [root/'ipv4/ip_forward',root/'ipv4/tcp_syncookies']; "
                "files += list(Path('/etc/sysctl.d').glob('*.conf')); "
                "print(json.dumps({str(p):p.read_text() for p in files},sort_keys=True))"
            )
        )

    untouched = lab.remote(
        "sudo sha256sum /etc/ssh/sshd_config /etc/sudoers /etc/sysctl.d/99-rocky10-hardener.conf"
    )
    lab.python(
        "from pathlib import Path; root=Path('/proc/sys/net'); "
        "(root/'ipv4/ip_forward').write_text('1'); (root/'ipv6/conf/all/forwarding').write_text('1'); "
        "[(p.write_text('0' if p.name=='rp_filter' else '1')) for family in ['ipv4','ipv6'] "
        "for p in (root/family/'conf').glob('*/*') if p.name in {'accept_redirects','send_redirects','rp_filter','forwarding'}]"
    )
    before = state()
    audit = lab.execute("audit", "before", profile, 5)
    assert audit["summary"]["fail"] == 5 and audit["changed_tasks"] == 0
    assert state() == before

    def refuse(name):
        before = state()
        assert lab.execute("apply", name, profile, 3)["changed_tasks"] == 0
        assert state() == before

    conflict = "/etc/sysctl.d/10-m9-router.conf"
    lab.write(conflict, "net.ipv4.ip_forward=1\n")
    try:
        refuse("early-forwarding-conflict")
    finally:
        lab.remove(conflict)
    conflict = "/etc/sysctl.d/zz-m9-interface.conf"
    lab.write(conflict, "net.ipv4.conf.future0.rp_filter=2\n")
    try:
        refuse("future-interface-conflict")
    finally:
        lab.remove(conflict)
    lab.remote(
        "sudo nmcli connection add type ethernet ifname m9unused con-name m9-shared connection.autoconnect no ipv4.method shared ipv6.method disabled"
    )
    try:
        refuse("shared-networkmanager-profile")
    finally:
        lab.remote("sudo nmcli connection delete m9-shared")
    conflict = "/etc/NetworkManager/conf.d/99-m9-forward-test.conf"
    lab.write(conflict, "[connection]\nipv4.forwarding=1\n")
    try:
        refuse("networkmanager-forwarding-default")
    finally:
        lab.remove(conflict)
    lab.remote("sudo ip link add m9veth type veth peer name m9peer")
    try:
        refuse("container-interface")
    finally:
        lab.remote("sudo ip link delete m9veth")

    excluded = copy.deepcopy(profile)
    excluded["controls"][-1].update(enabled=False, reason="Test forwarding exclusion")
    result = lab.execute("apply", "excluded-forwarding", excluded)
    assert result["summary"]["pass"] == 4 and result["summary"]["excluded"] == 1
    assert lab.remote("sysctl -n net.ipv4.ip_forward").strip() == "1"
    omitted = copy.deepcopy(profile)
    omitted["controls"].pop()
    assert lab.execute("apply", "omitted-forwarding", omitted)["changed_tasks"] == 0
    assert lab.remote("sysctl -n net.ipv4.ip_forward").strip() == "1"

    before = state()
    only_forward = lab.profile([IDS[-1]], PARAMETERS)
    assert lab.execute("apply", "forwarding-alone", only_forward)["summary"]["pass"] == 1
    after = state()
    # Global forwarding changes must not re-enable the unselected redirect policy.
    collateral = {
        key: value
        for key, value in before.items()
        if not key.endswith(("/forwarding", "/ip_forward"))
    }
    assert all(after[key] == value for key, value in collateral.items())
    assert lab.remote("sysctl -n net.ipv4.conf.all.accept_redirects").strip() == "0"
    (lab.output / "forwarding-collateral.json").write_text(
        json.dumps({"before": before, "after": after}, indent=2) + "\n"
    )
    assert lab.execute("verify", "verify", profile)["summary"]["pass"] == 5
    assert state() == after
    assert lab.execute("apply", "idempotent", profile)["changed_tasks"] == 0

    conflict = "/etc/sysctl.d/zz-m9-exclusion.conf"
    lab.write(conflict, "-net.ipv4.conf.all.rp_filter\n")
    try:
        before = state()
        assert lab.execute("verify", "late-exclusion-audit", profile, 5)["summary"]["fail"] == 1
        assert state() == before
        refuse("late-global-exclusion")
    finally:
        lab.remove(conflict)

    loose = lab.profile([IDS[3]], {IDS[3]: {"mode": "loose"}})
    assert lab.execute("apply", "loose-mode", loose)["summary"]["pass"] == 1
    assert set(
        lab.remote(
            "sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.lo.rp_filter"
        ).splitlines()
    ) == {"2"}
    assert lab.execute("apply", "strict-mode", profile)["summary"]["pass"] == 5
    lab.remote("sudo ip link add m9dummy type dummy")
    try:
        values = lab.remote(
            "sysctl -n net.ipv4.conf.m9dummy.rp_filter net.ipv6.conf.m9dummy.accept_redirects net.ipv4.conf.m9dummy.forwarding net.ipv6.conf.m9dummy.forwarding"
        ).splitlines()
        assert values == ["1", "0", "0", "0"]
        lab.remote(
            "sudo sysctl -w net.ipv4.conf.m9dummy.rp_filter=0 net.ipv6.conf.m9dummy.accept_redirects=1 net.ipv4.conf.m9dummy.forwarding=1"
        )
        assert lab.execute("verify", "interface-drift", profile, 5)["summary"]["fail"] == 3
        assert lab.execute("apply", "interface-repair", profile)["summary"]["pass"] == 5
    finally:
        lab.remote("sudo ip link delete m9dummy")
    assert (
        lab.remote(
            "sudo sha256sum /etc/ssh/sshd_config /etc/sudoers /etc/sysctl.d/99-rocky10-hardener.conf"
        )
        == untouched
    )
    assert lab.execute("verify", "baseline-after", lab.profile(BASELINE))["summary"]["pass"] == 3
    lab.reboot()
    assert lab.execute("verify", "after-reboot", profile)["summary"]["pass"] == 5
    assert lab.execute("apply", "after-reboot-idempotent", profile)["changed_tasks"] == 0
    assert (
        lab.execute("verify", "baseline-after-reboot", lab.profile(BASELINE))["summary"]["pass"]
        == 3
    )
    lab.finish(
        {
            "controls": 5,
            "unsafe_preflights": 6,
            "audit_verify_read_only": True,
            "exclusion_and_omission": True,
            "forwarding_collateral_preserved": True,
            "strict_and_loose_modes": True,
            "new_interface_defaults": True,
            "interface_drift_repaired": True,
            "earlier_network_controls_preserved": True,
            "reboot_verified": True,
            "idempotent": True,
        }
    )


if __name__ == "__main__":
    main()
