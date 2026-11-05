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


def test_explicit_assignment_beats_later_glob_and_exclusion():
    rows = network.entries(
        "# /usr/lib/sysctl.d/50-default.conf\nnet.ipv4.conf.eth0.accept_source_route=1\n"
        "# /etc/sysctl.d/99-network.conf\nnet/ipv4/conf/*/accept_source_route=0\n-net.ipv4.conf.eth0.accept_source_route\n"
    )
    assert network.effective(rows, "net/ipv4/conf/eth0/accept_source_route") == "1"
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
