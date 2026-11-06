"""Bounded firewall policy, native verification and refusal diagnostic contracts."""

import copy
import importlib.util

import pytest

from hardener.diagnostics import firewall_diagnostic
from hardener.validation import DATA, ValidationError, load_catalog, validate

spec = importlib.util.spec_from_file_location(
    "firewall_policy", DATA / "ansible/helpers/firewall_policy.py"
)
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)
POLICY = {"ssh_port": 22, "ipv4_sources": ["192.0.2.10/32"], "ipv6_sources": ["fd90:9::10/128"]}
CONTEXT = {"connection": ["192.0.2.10", "60000", "192.0.2.20", "22"]}


def test_management_rules_are_source_bounded_and_canonical():
    rules = fw.management_rules(POLICY)
    assert len(rules) == 2
    assert all('priority="-100"' in r and 'protocol="tcp"' in r for r in rules)
    assert fw.administrator_allowed(POLICY, CONTEXT)
    assert not fw.administrator_allowed(
        POLICY, {"connection": ["192.0.2.30", "60000", "192.0.2.20", "22"]}
    )
    assert not fw.administrator_allowed(
        POLICY, {"connection": ["192.0.2.10", "60000", "192.0.2.20", "2222"]}
    )


@pytest.mark.parametrize(
    "value", ["0.0.0.0/0", "192.0.2.10/24", "fd90:9::/64", '192.0.2.10/32" accept', "224.0.0.0/8"]
)
def test_invalid_management_networks(value):
    with pytest.raises(ValueError):
        fw.management_rules({**POLICY, "ipv4_sources": [value]})


def test_explicit_workload_policy_cannot_bypass_ssh(monkeypatch):
    monkeypatch.setattr(
        fw, "service_ports", lambda services: {("22", "tcp")} if services else set()
    )
    base = {"services": [], "tcp_ports": [], "udp_ports": []}
    assert fw.workload_ports(base, POLICY) == ([], set())
    for changed in [
        {"services": ["ssh"]},
        {"tcp_ports": ["22"]},
        {"tcp_ports": ["65536"]},
        {"udp_ports": ["0"]},
        {"tcp_ports": ["80;touch /tmp/pwn"]},
    ]:
        with pytest.raises(ValueError):
            fw.workload_ports({**base, **changed}, POLICY)
    assert fw.workload_ports({**base, "tcp_ports": ["443"], "udp_ports": ["53"]}, POLICY)[1] == {
        ("443", "tcp"),
        ("53", "udp"),
    }


def test_exclusive_kernel_ownership():
    owned = [{"table": {"family": "inet", "name": "firewalld", "flags": ["owner", "persist"]}}]
    assert fw.owned_kernel(owned, True)
    assert not fw.owned_kernel(owned, False)
    assert fw.owned_kernel([], False)
    assert not fw.owned_kernel([], True)
    assert not fw.owned_kernel(owned + [{"table": {"family": "inet", "name": "foreign"}}], True)
    assert not fw.owned_kernel([{"table": {"family": "inet", "name": "firewalld"}}], True)


def native_rule(version, source, port=22):
    return {
        "rule": {
            "chain": "filter_IN_" + fw.ZONE + "_pre",
            "expr": [
                {
                    "match": {
                        "op": "==",
                        "left": {
                            "payload": {
                                "protocol": "ip" if version == 4 else "ip6",
                                "field": "saddr",
                            }
                        },
                        "right": source,
                    }
                },
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": port,
                    }
                },
                {"accept": None},
            ],
        }
    }


def test_kernel_management_verification_rejects_extra_or_missing_rules():
    rules = [native_rule(4, "192.0.2.10"), native_rule(6, "fd90:9::10")]
    assert fw.native_management(rules, POLICY)
    assert not fw.native_management(rules[:1], POLICY)
    assert not fw.native_management(rules + [native_rule(4, "192.0.2.30")], POLICY)
    changed = copy.deepcopy(rules)
    changed[0]["rule"]["expr"][-1] = {"drop": None}
    assert not fw.native_management(changed, POLICY)


def test_firewall_diagnostics_do_not_echo_unknown_text():
    result = firewall_diagnostic(
        {
            "code": "firewall-policy-conflict",
            "control_id": "firewall.inbound-policy",
            "blockers": ["runtime-drift", "private-sentinel"],
        }
    )
    assert "Runtime-only" in str(result)
    assert "private-sentinel" not in str(result)


def test_dependency_order_and_no_implicit_policy():
    catalog = load_catalog()
    profile = {
        "schema_version": 1,
        "id": "firewall",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [
            {
                "id": "firewall.inbound-policy",
                "enabled": True,
                "parameters": {
                    "interfaces": ["ens3"],
                    "services": [],
                    "tcp_ports": [],
                    "udp_ports": [],
                },
            }
        ],
    }
    with pytest.raises(ValidationError):
        validate(profile, catalog)
    profile["controls"].extend(
        [
            {"id": "firewall.management-access", "enabled": True, "parameters": POLICY},
            {
                "id": "firewall.firewalld-enabled",
                "enabled": True,
                "parameters": {
                    "owner": "firewalld",
                    "network_role": "non-routing",
                    "container_networking": "absent",
                },
            },
        ]
    )
    assert validate(profile, catalog) == [fw.OWNER, fw.MANAGEMENT, fw.INBOUND]
    del profile["controls"][0]["parameters"]["services"]
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_networkmanager_fields_are_read_by_name_not_display_order(monkeypatch):
    def native(*argv):
        if argv[:3] == ("nmcli", "-g", "UUID"):
            return "id-one"
        if argv[0] == "nmcli":
            return "connection.type:802-3-ethernet\nconnection.zone:\nipv4.method:auto\nipv6.method:auto\nipv4.forwarding:-1\nGENERAL.DEVICES:ens3\nGENERAL.STATE:activated"
        return '[{"ifname":"lo"},{"ifname":"ens3","link_type":"ether"}]'

    monkeypatch.setattr(fw, "command", native)
    assert fw.connections() == [{"uuid": "id-one", "interface": "ens3", "zone": ""}]


def test_native_management_rejects_inverted_source_match():
    rules = [native_rule(4, "192.0.2.10"), native_rule(6, "fd90:9::10")]
    rules[0]["rule"]["expr"][0]["match"]["op"] = "!="
    assert not fw.native_management(rules, POLICY)


def inbound_fixture():
    def rule(chain, expressions):
        return {"rule": {"chain": chain, "expr": expressions}}

    base = "filter_IN_" + fw.ZONE
    rules = [
        rule(base, [{"jump": {"target": base + "_" + suffix}}])
        for suffix in ["pre", "log", "deny", "allow", "post"]
    ]
    for protocol in ["icmp", "ipv6-icmp"]:
        rules.append(
            rule(
                base + "_allow",
                [
                    {
                        "match": {
                            "op": "==",
                            "left": {"meta": {"key": "l4proto"}},
                            "right": protocol,
                        }
                    },
                    {"accept": None},
                ],
            )
        )
    for interface in ["ens3", "ens4", None]:
        match = (
            [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": interface}}]
            if interface
            else []
        )
        for action in [
            {"jump": {"target": "filter_IN_policy_allow-host-ipv6"}},
            {"jump": {"target": base}},
            {"drop": None},
        ]:
            rules.append(rule("filter_INPUT_POLICIES", match + [action]))
    return rules


def test_native_inbound_requires_each_interface_and_default_drop():
    rules = inbound_fixture()
    assert fw.native_inbound(rules, [], ["ens3", "ens4"])
    assert not fw.native_inbound(rules[:-1], [], ["ens3", "ens4"])
    assert not fw.native_inbound(rules, [], ["ens3", "ens4", "ens5"])
    rules[-1]["rule"]["expr"] = [{"accept": None}]
    assert not fw.native_inbound(rules, [], ["ens3", "ens4"])


def test_native_inbound_verifies_workload_ports():
    rules = inbound_fixture()
    rules.append(
        {
            "rule": {
                "chain": "filter_IN_" + fw.ZONE + "_allow",
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                            "right": {"set": [80, 18080]},
                        }
                    },
                    {"accept": None},
                ],
            }
        }
    )
    assert fw.native_inbound(rules, [("80", "tcp"), ("18080", "tcp")], ["ens3", "ens4"])
    assert not fw.native_inbound(rules, [], ["ens3", "ens4"])
