import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from hardener.validation import DATA, ValidationError, load_catalog, validate

spec = importlib.util.spec_from_file_location(
    "network_sysctl", DATA / "ansible/helpers/network_sysctl.py"
)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
V4 = "network.ipv4-source-route-disabled"
V6 = "network.ipv6-source-route-disabled"
SYN = "network.tcp-syncookies"
MANAGED = Path("/etc/sysctl.d/99-rocky10-network-ipv4-source-route-disabled.conf")


@pytest.mark.parametrize(
    "value",
    ["net.ipv4.conf.eth0/100.accept_source_route", "net/ipv4/conf/eth0.100/accept_source_route"],
)
def test_network_key_preserves_dotted_interface(value):
    assert network.normalize(value) == "net/ipv4/conf/eth0.100/accept_source_route"


def test_ipv6_zero_is_not_routing_header_rejection():
    assert set(network.settings(V6).values()) == {"-1"}
    assert set(network.settings(V4).values()) == {"0"}
    assert network.settings(SYN) == {"net/ipv4/tcp_syncookies": "1"}


def test_last_exact_declaration_wins_over_wildcards():
    rows = network.entries(
        "# /usr/lib/sysctl.d/50-default.conf\nnet.ipv4.conf.eth0.accept_source_route=1\n"
        "# /etc/sysctl.d/99-network.conf\nnet/ipv4/conf/*/accept_source_route=0\n-net.ipv4.conf.eth0.accept_source_route\n"
    )
    assert network.effective(rows, "net/ipv4/conf/eth0/accept_source_route") is None
    assert network.effective(rows, "net/ipv4/conf/eth1/accept_source_route") == "0"
    assert network.conflicts(rows, V4, MANAGED) == [
        "/etc/sysctl.d/99-network.conf",
        "/usr/lib/sysctl.d/50-default.conf",
    ]


@pytest.mark.parametrize(
    "assignment",
    ["net.ipv4.conf.future0.accept_source_route=1", "-net.ipv4.conf.future0.accept_source_route"],
)
def test_conflicting_future_interface_is_refused_even_in_earlier_file(assignment):
    rows = network.entries("# /etc/sysctl.d/10-custom.conf\n" + assignment)
    assert network.conflicts(rows, V4, MANAGED) == ["/etc/sysctl.d/10-custom.conf"]


def test_late_glob_and_global_assignments_are_refused():
    for key in ["net.ipv4.conf.en*.accept_source_route", "net.ipv4.conf.all.accept_source_route"]:
        rows = network.entries("# /etc/sysctl.d/zz-late.conf\n" + key + "=1")
        assert network.conflicts(rows, V4, MANAGED) == ["/etc/sysctl.d/zz-late.conf"]


def test_earlier_global_can_be_overridden_without_touching_other_policy():
    rows = network.entries(
        "# /etc/sysctl.d/10-custom.conf\nnet.ipv4.conf.all.accept_source_route=1\nnet.ipv4.ip_forward=1"
    )
    assert network.conflicts(rows, V4, MANAGED) == []


def test_exclusion_prevents_glob_application():
    rows = network.entries(
        "# /etc/sysctl.d/50-default.conf\nnet.ipv4.conf.*.accept_source_route=0\n-net.ipv4.conf.eth0.accept_source_route"
    )
    assert network.effective(rows, "net/ipv4/conf/eth0/accept_source_route") is None


def test_owned_render_preserves_comments_and_is_idempotent():
    text = "# preserved operator note\nnet.ipv4.conf.all.accept_source_route=1\n"
    proposed = network.render(text, V4)
    assert proposed.startswith("# preserved operator note\n")
    assert network.render(proposed, V4) == proposed
    assert "net/ipv4/conf/default/accept_source_route = 0" in proposed
    assert "net/ipv4/conf/*/accept_source_route = 0" in proposed


def test_unrelated_setting_in_managed_file_is_never_overwritten():
    with pytest.raises(ValueError, match="unrelated"):
        network.render("net.ipv4.ip_forward=1\n", V4)


def test_managed_file_symlink_and_hardlink_are_unsafe(tmp_path):
    real = tmp_path / "real"
    real.write_text("")
    link = tmp_path / "link"
    link.symlink_to(real)
    assert not network.safe_file(link)
    link.unlink()
    link.hardlink_to(real)
    assert not network.safe_file(link)
    assert network.safe_file(tmp_path / "absent")


def test_ipv6_unavailable_has_observed_not_applicable_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(network, "PROC", tmp_path)
    result = network.inspect(V6, "verify")
    assert result == {"applicable": False, "reason": "ipv6 kernel sysctls are unavailable"}


def test_inspection_checks_each_interface_and_future_policy(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    config = tmp_path / "config"
    config.mkdir()
    monkeypatch.setattr(network, "PROC", proc)
    monkeypatch.setattr(network, "CONFIG", config)
    monkeypatch.setattr(network, "safe_file", lambda path: True)
    monkeypatch.setattr(network, "safe_parent", lambda path: True)
    for name in ["all", "default", "eth0.100"]:
        p = proc / "net/ipv4/conf" / name / "accept_source_route"
        p.parent.mkdir(parents=True)
        p.write_text("0")
    managed = config / MANAGED.name
    managed.write_text(network.render("", V4))
    output = "# " + str(managed) + "\n" + managed.read_text()
    monkeypatch.setattr(
        network.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=output)
    )
    result = network.inspect(V4, "verify")
    assert result["matches"]
    (proc / "net/ipv4/conf/eth0.100/accept_source_route").write_text("1")
    result = network.inspect(V4, "verify")
    assert not result["matches"]
    assert result["live"]["net/ipv4/conf/eth0.100/accept_source_route"] == "1"
    assert result["persistent"]["future_interfaces"] == "0"


def test_network_baseline_rejects_arbitrary_parameters():
    profile = {
        "schema_version": 1,
        "id": "unit-network",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": V4, "enabled": True, "parameters": {"command": "unsafe"}}],
    }
    catalog = load_catalog()
    with pytest.raises(ValidationError):
        validate(profile, catalog)


@pytest.mark.parametrize(
    "key",
    [
        "net.*.conf.eth*.accept_source_route",
        "net.ipv4.conf.*.accept_*",
        "net.ipv?.conf.*.accept_source_route",
    ],
)
def test_broad_globs_are_refused_without_taking_ownership(key):
    rows = network.entries("# /etc/sysctl.d/10-custom.conf\n" + key + "=0")
    assert network.conflicts(rows, V4, MANAGED) == ["/etc/sysctl.d/10-custom.conf"]
    with pytest.raises(ValueError, match="unrelated"):
        network.render(key + "=0", V4)


def test_earlier_conflicting_glob_requires_operator_reconciliation():
    rows = network.entries(
        "# /etc/sysctl.d/10-custom.conf\nnet.ipv4.conf.eth*.accept_source_route=1"
    )
    assert network.conflicts(rows, V4, MANAGED) == ["/etc/sysctl.d/10-custom.conf"]


def test_safe_file_rejects_world_writable_metadata(tmp_path):
    path = tmp_path / "policy.conf"
    path.write_text("")
    path.chmod(0o666)
    assert not network.safe_file(path)


RP = "network.reverse-path-filter"
FWD = "network.ip-forwarding-disabled"
HOST = {"network_role": "non-routing", "container_networking": "absent"}


@pytest.mark.parametrize("mode,value", [("strict", "1"), ("loose", "2")])
def test_routing_mode_is_explicit_and_applies_to_all_interfaces(mode, value):
    assert set(network.settings(RP, {"mode": mode}).values()) == {value}
    with pytest.raises(KeyError):
        network.settings(RP)


def test_identical_earlier_vendor_glob_is_overridden():
    rows = network.entries(
        "# /usr/lib/sysctl.d/50-default.conf\nnet.ipv4.conf.*.rp_filter=2\n"
        "net.ipv4.conf.default.rp_filter=2\n-net.ipv4.conf.all.rp_filter"
    )
    managed = Path("/etc/sysctl.d/99-rocky10-network-reverse-path-filter.conf")
    assert not network.conflicts(rows, RP, managed, {"mode": "strict"})
    rows += network.entries("# " + str(managed) + "\n" + network.render("", RP, {"mode": "strict"}))
    assert network.effective(rows, "net/ipv4/conf/all/rp_filter") == "1"
    assert network.effective(rows, "net/ipv4/conf/eth9/rp_filter") == "1"


@pytest.mark.parametrize(
    "key",
    [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        "net.ipv6.conf.*.forwarding",
    ],
)
def test_forwarding_conflicts_are_refused_even_before_managed_file(key):
    rows = network.entries("# /etc/sysctl.d/10-router.conf\n" + key + "=1")
    managed = Path("/etc/sysctl.d/99-rocky10-network-ip-forwarding-disabled.conf")
    assert network.conflicts(rows, FWD, managed, HOST) == ["/etc/sysctl.d/10-router.conf"]


def test_forwarding_does_not_own_redirects_or_other_network_values():
    rendered = network.render("# preserve comment\n", FWD, HOST)
    assert "net/ipv4/ip_forward = 0" in rendered
    assert "net/ipv6/conf/*/forwarding = 0" in rendered
    assert "accept_redirects" not in rendered
    with pytest.raises(ValueError, match="unrelated"):
        network.render("net.ipv4.conf.all.accept_redirects=0", FWD, HOST)


@pytest.mark.parametrize(
    "cid,parameters",
    [
        (RP, {}),
        (RP, {"mode": "disabled"}),
        ("network.ipv4-redirects-disabled", {}),
        ("network.ipv6-redirects-disabled", {"network_role": "router"}),
        ("network.ipv4-send-redirects-disabled", {}),
        (FWD, {"network_role": "non-routing"}),
        (FWD, {"network_role": "non-routing", "container_networking": "present"}),
    ],
)
def test_conditional_network_parameters_are_required(cid, parameters):
    profile = {
        "schema_version": 1,
        "id": "unit-role",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": True, "parameters": parameters}],
    }
    catalog = load_catalog()
    with pytest.raises(ValidationError):
        validate(profile, catalog)


@pytest.mark.parametrize("kind", ["bridge", "veth", "tun", "wireguard", "vxlan"])
def test_forwarding_refuses_container_and_tunnel_interfaces(kind):
    links = [{"ifname": "test0", "link_type": "ether", "linkinfo": {"info_kind": kind}}]
    assert network.forwarding_conflicts(links, "", {}, "")


@pytest.mark.parametrize(
    "unit",
    [
        "docker.service",
        "containerd.service",
        "podman.socket",
        "frr.service",
        "bird6.service",
        "systemd-networkd.service",
    ],
)
def test_forwarding_refuses_routing_and_container_services(unit):
    assert network.forwarding_conflicts([], unit + " loaded active running fixture", {}, "")


@pytest.mark.parametrize(
    "profile", [["shared", "-1", "manual"], ["manual", "-1", "shared"], ["manual", "1", "manual"]]
)
def test_forwarding_refuses_networkmanager_sharing_and_explicit_forwarding(profile):
    assert network.forwarding_conflicts([], "", {"test-uuid": profile}, "")


def test_networkmanager_global_defaults_and_supported_host_layout():
    links = [{"ifname": "ens3", "link_type": "ether"}]
    profiles = {"uuid": ["manual", "-1", "manual"]}
    assert not network.forwarding_conflicts(
        links, "sshd.service loaded active running", profiles, "[connection]\nipv4.forwarding=2\n"
    )
    assert network.forwarding_conflicts(
        links, "", profiles, "[connection.custom]\nipv4.forwarding=1\n"
    )


def test_forwarding_inspection_records_collateral_state_without_owning_it(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    config = tmp_path / "config"
    config.mkdir()
    monkeypatch.setattr(network, "PROC", proc)
    monkeypatch.setattr(network, "CONFIG", config)
    monkeypatch.setattr(network, "safe_file", lambda path: True)
    monkeypatch.setattr(network, "safe_parent", lambda path: True)
    monkeypatch.setattr(network, "inspect_forwarding_owner", list)
    paths = [
        "net/ipv4/ip_forward",
        "net/ipv4/conf/all/forwarding",
        "net/ipv4/conf/default/forwarding",
        "net/ipv4/conf/eth0/forwarding",
    ]
    for key in paths:
        p = proc / key
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("1")
    (proc / "net/ipv4/conf/all/accept_redirects").write_text("0")
    managed = config / "99-rocky10-network-ip-forwarding-disabled.conf"
    managed.write_text(network.render("", FWD, HOST))
    monkeypatch.setattr(
        network, "command", lambda *args: "# " + str(managed) + "\n" + managed.read_text()
    )
    result = network.inspect(FWD, "verify", HOST)
    assert result["address_families"] == ["ipv4"]
    assert not result["matches"]
    assert result["preserve"] == {"net/ipv4/conf/all/accept_redirects": "0"}
    assert all("accept_redirects" not in key for key in result["live"])
    for key in paths:
        (proc / key).write_text("0")
    result = network.inspect(FWD, "verify", HOST)
    assert result["matches"] and not result["preserve"]


@pytest.mark.parametrize(
    "tail,expected",
    [("-net.ipv4.conf.all.rp_filter", None), ("net.ipv4.conf.all.rp_filter=2", "2")],
)
def test_later_exact_declaration_matches_native_systemd(tail, expected):
    managed = Path("/etc/sysctl.d/99-rocky10-network-reverse-path-filter.conf")
    rows = network.entries(
        "# "
        + str(managed)
        + "\n"
        + network.render("", RP, {"mode": "strict"})
        + "# /etc/sysctl.d/zz-late.conf\n"
        + tail
    )
    assert network.effective(rows, "net/ipv4/conf/all/rp_filter") == expected
    assert network.conflicts(rows, RP, managed, {"mode": "strict"}) == [
        "/etc/sysctl.d/zz-late.conf"
    ]
    assert network.effective(rows, "net/ipv4/conf/eth0/rp_filter") == "1"
