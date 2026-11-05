"""Bounded firewalld host policy. No provisioning or competing firewall ownership."""

import fcntl
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

ZONE = "rocky10-hardener"
DESCRIPTION = "Managed Rocky 10 host firewall"
CONFIG = Path("/etc/firewalld")
ZONE_FILE = CONFIG / "zones" / (ZONE + ".xml")
RUN = Path("/run/rocky10-hardener-firewall")
UNIT = "rocky10-hardener-firewall-rollback"
OWNER = "firewall.firewalld-enabled"
MANAGEMENT = "firewall.management-access"
INBOUND = "firewall.inbound-policy"


def command(*argv, codes=(0,)):
    result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=40)
    if result.returncode not in codes:
        raise RuntimeError("Native firewall inspection or operation failed: " + Path(argv[0]).name)
    return result.stdout.strip()


def safe(path, directory=False):
    if not path.exists() and not path.is_symlink():
        return True
    info = path.lstat()
    return bool(
        path.resolve() == path
        and (
            stat.S_ISDIR(info.st_mode)
            if directory
            else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        )
        and info.st_uid == 0
        and info.st_gid == 0
        and not info.st_mode & 0o022
        and "system.posix_acl_access" not in os.listxattr(path, follow_symlinks=False)
    )


def config_values():
    result = {}
    for line in (CONFIG / "firewalld.conf").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            if key.strip() in result:
                raise ValueError("Duplicate firewalld setting")
            result[key.strip()] = value.strip()
    return result


def normalize(settings):
    result = dict(settings)
    for key in ["version", "short", "description", "interfaces"]:
        result.pop(key, None)
    if result.get("target") == "{chain}_{zone}":
        result["target"] = "default"
    return {
        k: sorted(v, key=lambda x: json.dumps(x, sort_keys=True)) if isinstance(v, list) else v
        for k, v in result.items()
    }


def disk_zone(name):
    from firewall.client import FirewallClientZoneSettings
    from firewall.core.io.zone import zone_reader

    local = CONFIG / "zones" / (name + ".xml")
    path = local if local.exists() else Path("/usr/lib/firewalld/zones") / (name + ".xml")
    if not path.exists():
        return None
    result = FirewallClientZoneSettings().getSettingsDict()
    result.update(zone_reader(path.name, str(path.parent)).export_config_dict())
    return result


def client():
    from firewall.client import FirewallClient

    for _ in range(30):
        instance = FirewallClient()
        if instance.connected:
            return instance
        time.sleep(0.2)
    raise RuntimeError("firewalld D-Bus is unavailable")


def management_rules(parameters):
    port = parameters["ssh_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Explicit SSH port is invalid")
    rules = []
    for version, field in [(4, "ipv4_sources"), (6, "ipv6_sources")]:
        if not parameters[field] or len(parameters[field]) > 32:
            raise ValueError("Explicit sources for both IP families are required")
        for value in parameters[field]:
            network = ipaddress.ip_network(value, strict=True)
            if (
                network.version != version
                or not network.prefixlen
                or network.is_multicast
                or network.is_unspecified
            ):
                raise ValueError("Management sources must be bounded canonical networks")
            rules.append(
                f'rule priority="-100" family="ipv{version}" source address="{network}" port port="{port}" protocol="tcp" accept'
            )
    return sorted(set(rules))


def administrator_allowed(parameters, context):
    source, _, _, destination_port = context["connection"]
    address = ipaddress.ip_address(source)
    field = "ipv4_sources" if address.version == 4 else "ipv6_sources"
    return int(destination_port) == parameters["ssh_port"] and any(
        address in ipaddress.ip_network(n) for n in parameters[field]
    )


def service_ports(services):
    import xml.etree.ElementTree as ET

    ports = set()
    for service in services:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", service):
            raise ValueError("Invalid service")
        path = Path("/usr/lib/firewalld/services") / (service + ".xml")
        if not safe(path) or not path.is_file():
            raise ValueError("Unsupported service")
        for child in ET.parse(path).getroot():
            if child.tag in {"short", "description"}:
                continue
            if (
                child.tag != "port"
                or child.attrib.get("protocol") not in {"tcp", "udp"}
                or not child.attrib.get("port", "").isdigit()
            ):
                raise ValueError("Only simple vendor TCP/UDP services are supported")
            ports.add((str(int(child.attrib["port"])), child.attrib["protocol"]))
    return ports


def workload_ports(parameters, management):
    ports = service_ports(parameters["services"])
    explicit = set()
    for protocol in ["tcp", "udp"]:
        for value in parameters[protocol + "_ports"]:
            if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or not 1 <= int(value) <= 65535:
                raise ValueError("Invalid workload port")
            explicit.add((value, protocol))
    if (str(management["ssh_port"]), "tcp") in ports | explicit:
        raise ValueError("Workload rules must not bypass management source restrictions")
    return sorted(explicit), ports | explicit


def connections():
    result = []
    for uuid in command("nmcli", "-g", "UUID", "connection", "show").splitlines():
        fields = [
            "connection.type",
            "GENERAL.DEVICES",
            "connection.zone",
            "ipv4.method",
            "ipv6.method",
            "ipv4.forwarding",
            "GENERAL.STATE",
        ]
        output = command(
            "nmcli", "--terse", "--fields", ",".join(fields), "connection", "show", uuid
        )
        named = dict(line.split(":", 1) for line in output.splitlines())
        values = [named[field].replace("\\:", ":") for field in fields]
        if values[0] == "loopback":
            continue
        if (
            len(values) != 7
            or values[0] != "802-3-ethernet"
            or values[3] == "shared"
            or values[4] == "shared"
            or values[5] not in {"-1", "0", "2"}
            or values[6] != "activated"
        ):
            raise ValueError("Unsupported NetworkManager connection")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", values[1]) or values[2] not in {
            "",
            "public",
            ZONE,
        }:
            raise ValueError("Unsupported NetworkManager interface or zone")
        result.append({"uuid": uuid, "interface": values[1], "zone": values[2]})
    links = json.loads(command("ip", "-j", "-d", "link", "show"))
    interfaces = set()
    for link in links:
        if link["ifname"] == "lo":
            continue
        if (
            link.get("link_type") != "ether"
            or link.get("linkinfo", {}).get("info_kind") is not None
        ):
            raise ValueError("Unsupported network link")
        interfaces.add(link["ifname"])
    if interfaces != {c["interface"] for c in result}:
        raise ValueError("Every interface must have one active Ethernet connection")
    return result


def kernel_rules():
    return json.loads(command("nft", "-j", "list", "ruleset"))["nftables"]


def owned_kernel(items, active):
    tables = [x["table"] for x in items if "table" in x]
    if not active:
        return not tables
    return (
        len(tables) == 1
        and tables[0]["family"] == "inet"
        and tables[0]["name"] == "firewalld"
        and "owner" in tables[0].get("flags", [])
    )


def native_management(items, expected):
    rules = [
        x["rule"]
        for x in items
        if "rule" in x and x["rule"]["chain"] == "filter_IN_" + ZONE + "_pre"
    ]
    observed = set()
    for rule in rules:
        source = port = None
        family = None
        if not any("accept" in e for e in rule["expr"]):
            return False
        for expr in rule["expr"]:
            match = expr.get("match", {})
            if match and match.get("op") != "==":
                return False
            payload = match.get("left", {}).get("payload", {})
            if payload.get("field") == "saddr" and payload.get("protocol") in {"ip", "ip6"}:
                family = 4 if payload["protocol"] == "ip" else 6
                right = match["right"]
                if isinstance(right, dict) and "prefix" in right:
                    source = str(
                        ipaddress.ip_network(f"{right['prefix']['addr']}/{right['prefix']['len']}")
                    )
                elif isinstance(right, str):
                    source = str(ipaddress.ip_network(right))
            if payload.get("field") == "dport" and payload.get("protocol") == "tcp":
                port = str(match["right"])
        if source is None or port is None:
            return False
        observed.add((family, source, port))
    desired = {
        (version, str(ipaddress.ip_network(n)), str(expected["ssh_port"]))
        for version, field in [(4, "ipv4_sources"), (6, "ipv6_sources")]
        for n in expected[field]
    }
    return observed == desired and len(rules) == len(desired)


def native_inbound(items, ports, interfaces):
    rules = [x["rule"] for x in items if "rule" in x]
    zone_rules = [r for r in rules if r["chain"] == "filter_IN_" + ZONE]
    if [r["expr"] for r in zone_rules] != [
        [{"jump": {"target": "filter_IN_" + ZONE + "_" + suffix}}]
        for suffix in ["pre", "log", "deny", "allow", "post"]
    ]:
        return False
    observed_ports = set()
    protocols = set()
    for rule in [r for r in rules if r["chain"] == "filter_IN_" + ZONE + "_allow"]:
        if not any("accept" in e for e in rule["expr"]):
            return False
        recognized = False
        for expr in rule["expr"]:
            match = expr.get("match", {})
            if match and match.get("op") != "==":
                return False
            left, right = match.get("left", {}), match.get("right")
            payload = left.get("payload", {})
            if payload.get("field") == "dport" and payload.get("protocol") in {"tcp", "udp"}:
                values = right.get("set", []) if isinstance(right, dict) else [right]
                observed_ports.update((str(p), payload["protocol"]) for p in values)
                recognized = True
            if left.get("meta", {}).get("key") == "l4proto" and right in {"icmp", "ipv6-icmp"}:
                protocols.add(right)
                recognized = True
        if not recognized:
            return False
    # firewalld 2.4 dispatches through policy chains. The DROP follows each
    # managed-zone jump, including the unqualified default-zone path.
    dispatch = [r["expr"] for r in rules if r["chain"] == "filter_INPUT_POLICIES"]
    expected_paths = {interface: [] for interface in interfaces}
    expected_paths[None] = []
    for expressions in dispatch:
        interface = None
        if len(expressions) == 2:
            match = expressions[0].get("match", {})
            if match.get("op") != "==" or match.get("left") != {"meta": {"key": "iifname"}}:
                return False
            interface = match.get("right")
        elif len(expressions) != 1:
            return False
        if not isinstance(interface, (str, type(None))) or interface not in expected_paths:
            return False
        expected_paths[interface].append(expressions[-1])
    expected = [
        {"jump": {"target": "filter_IN_policy_allow-host-ipv6"}},
        {"jump": {"target": "filter_IN_" + ZONE}},
        {"drop": None},
    ]
    return (
        observed_ports == set(ports)
        and protocols == {"icmp", "ipv6-icmp"}
        and all(path == expected for path in expected_paths.values())
    )


def blocked(active, enabled, blockers):
    return {
        "active": active,
        "enabled": enabled,
        "blockers": sorted(set(blockers)),
        "matches": False,
        "native_verified": False,
        "zone_bound": False,
        "zone": None,
        "profiles": [],
        "default": "unverified",
        "expected_rules": [],
        "explicit_ports": [],
    }


def inspect(cid, plan, context, mode="audit", pending_allowed=False):
    blockers = []
    active = command("systemctl", "is-active", "firewalld", codes=(0, 3, 4)) == "active"
    enabled = command("systemctl", "is-enabled", "firewalld", codes=(0, 1, 3, 4)) == "enabled"
    if (
        command("systemctl", "is-active", UNIT + ".timer", codes=(0, 3, 4)) == "active"
        and not pending_allowed
    ):
        blockers.append("pending-rollback")
    if (
        not safe(CONFIG, True)
        or not safe(RUN, True)
        or (RUN.exists() and any(not safe(p) for p in RUN.iterdir()))
    ):
        blockers.append("unsafe-files")
    if blockers and "unsafe-files" in blockers:
        return blocked(active, enabled, blockers)
    allowed = {
        CONFIG / "firewalld.conf",
        CONFIG / "firewalld.conf.old",
        ZONE_FILE,
        ZONE_FILE.with_suffix(".xml.old"),
    }
    for path in CONFIG.rglob("*"):
        if not safe(path, path.is_dir()) or (not path.is_dir() and path not in allowed):
            blockers.append("unmanaged-configuration")
    if blockers and "unmanaged-configuration" in blockers:
        return blocked(active, enabled, blockers)
    config = config_values()
    if (
        config.get("FirewallBackend", "nftables") != "nftables"
        or config.get("NftablesTableOwner", "yes") != "yes"
        or config.get("CleanupOnExit", "yes") != "yes"
        or config.get("NftablesFlowtable", "off") != "off"
        or config.get("DefaultZone", "public") not in {"public", ZONE}
    ):
        blockers.append("backend-configuration")
    unit = command("systemctl", "show", "firewalld", "-p", "FragmentPath", "-p", "DropInPaths")
    if "FragmentPath=/usr/lib/systemd/system/firewalld.service" not in unit or not unit.endswith(
        "DropInPaths="
    ):
        blockers.append("service-override")
    units = (
        command("systemctl", "list-units", "--state=active", "--no-legend", "--no-pager")
        + "\n"
        + command(
            "systemctl",
            "list-unit-files",
            "--state=enabled,enabled-runtime",
            "--no-legend",
            "--no-pager",
        )
    )
    if any(
        re.match(
            r"(?:nftables|ip6?tables|docker|containerd|podman|crio|kubelet|libvirtd|virtnetworkd|frr|bird6?|zebra|systemd-networkd)[.@-]",
            line.strip(),
        )
        for line in units.splitlines()
    ):
        blockers.append("competing-owner")
    for path in [Path("/proc/net/ip_tables_names"), Path("/proc/net/ip6_tables_names")]:
        if path.exists() and path.read_text().strip():
            blockers.append("legacy-firewall")
    for path in [
        Path("/proc/sys/net/ipv4/ip_forward"),
        Path("/proc/sys/net/ipv6/conf/all/forwarding"),
    ]:
        if not path.exists() or path.read_text().strip() != "0":
            blockers.append("routing-role")
    if (
        not Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").exists()
        or Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() != "0"
    ):
        blockers.append("ipv6-disabled")
    try:
        profiles = connections()
    except ValueError:
        profiles = []
        blockers.append("network-layout")
    items = kernel_rules()
    if not owned_kernel(items, active):
        blockers.append("foreign-kernel-rules")
    management = plan.get(MANAGEMENT)
    expected_rules = []
    if management:
        try:
            expected_rules = management_rules(management)
            if mode == "preflight" and not administrator_allowed(management, context):
                blockers.append("administrator-excluded")
        except (ValueError, KeyError):
            blockers.append("management-policy")
    inbound = plan.get(INBOUND)
    explicit_ports, all_ports = [], set()
    if inbound:
        try:
            explicit_ports, all_ports = workload_ports(inbound, management)
            if set(inbound["interfaces"]) != {p["interface"] for p in profiles}:
                blockers.append("interface-coverage")
        except (ValueError, KeyError, TypeError):
            blockers.append("workload-policy")
    current = disk_zone(ZONE)
    default = config.get("DefaultZone", "public")
    native = False
    bound = False
    if active:
        f = client()
        if (
            f.getDefaultZone() != default
            or set(f.getZones()) != set(f.config().getZoneNames())
            or set(f.getPolicies()) != set(f.config().getPolicyNames())
        ):
            blockers.append("runtime-drift")
        if f.getIPSets() or f.config().getIPSetNames() or f.getAllRules() or f.getAllPassthroughs():
            blockers.append("direct-or-ipset")
        if set(f.getActivePolicies()) - {"allow-host-ipv6"}:
            blockers.append("custom-policy")
        for name in f.getPolicies():
            if (
                f.getPolicySettings(name).getSettingsDict()
                != f.config().getPolicyByName(name).getSettings().getSettingsDict()
            ):
                blockers.append("runtime-drift")
        for name in f.getZones():
            live = f.getZoneSettings(name).getSettingsDict()
            permanent = f.config().getZoneByName(name).getSettings().getSettingsDict()
            disk = disk_zone(name)
            expected_interfaces = {
                p["interface"] for p in profiles if (p["zone"] or default) == name
            }
            if (
                normalize(live) != normalize(permanent)
                or normalize(permanent) != normalize(disk)
                or set(live["interfaces"]) != expected_interfaces
                or permanent["interfaces"]
            ):
                blockers.append("runtime-drift")
            if live["sources"]:
                blockers.append("source-binding")
            if name == ZONE:
                current = live
                if (
                    live["description"] != DESCRIPTION
                    or live["masquerade"]
                    or live["forward_ports"]
                    or live["source_ports"]
                    or live["icmp_blocks"]
                    or live["icmp_block_inversion"]
                    or live["ingress_priority"]
                    or live["egress_priority"]
                ):
                    blockers.append("unmanaged-zone")
                if any(
                    not re.fullmatch(
                        r'rule priority="-100" family="ipv[46]" source address="[0-9a-fA-F:./]+" port port="[0-9]+" protocol="tcp" accept',
                        r,
                    )
                    for r in live["rules_str"]
                ):
                    blockers.append("unmanaged-zone")
        bound = any((p["zone"] or default) == ZONE for p in profiles)
        native = owned_kernel(items, True)
        if cid == MANAGEMENT and current and bound:
            native = native and native_management(items, management)
        if cid == INBOUND:
            native = (
                native
                and native_management(items, management)
                and native_inbound(items, all_ports, inbound["interfaces"])
            )
    else:
        managed_bound = default == ZONE or any(p["zone"] == ZONE for p in profiles)
        if managed_bound:
            source = ipaddress.ip_address(context["connection"][0])
            port = context["connection"][3]
            permitted = False
            for rule in current.get("rules_str", []) if current else []:
                match = re.fullmatch(
                    r'rule priority="-100" family="ipv[46]" source address="([0-9a-fA-F:./]+)" port port="([0-9]+)" protocol="tcp" accept',
                    rule,
                )
                if match and match[2] == port and source in ipaddress.ip_network(match[1]):
                    permitted = True
            if not current or current.get("description") != DESCRIPTION or not permitted:
                blockers.append("unsafe-bootstrap")
        elif default != "public" or int(context["connection"][3]) != 22:
            blockers.append("unsafe-bootstrap")
    if cid == OWNER:
        matches = active and enabled
    elif cid == MANAGEMENT:
        matches = bool(current and sorted(current["rules_str"]) == expected_rules)
    else:
        matches = bool(
            current
            and current["target"] == "DROP"
            and set(current["services"]) == set(inbound["services"])
            and {tuple(p) for p in current["ports"]} == set(explicit_ports)
            and set(current["protocols"]) == {"icmp", "ipv6-icmp"}
            and not current["forward"]
            and default == ZONE
            and all(p["zone"] == ZONE for p in profiles)
        )
    if mode == "verify":
        matches = matches and native
    return {
        "active": active,
        "enabled": enabled,
        "blockers": sorted(set(blockers)),
        "matches": bool(matches and not blockers),
        "native_verified": native,
        "zone_bound": bound,
        "zone": current,
        "profiles": profiles,
        "default": default,
        "expected_rules": expected_rules,
        "explicit_ports": explicit_ports,
    }


def begin(cid, plan, context):
    state = inspect(cid, plan, context, "preflight")
    if state["blockers"]:
        raise ValueError("Unsafe firewall preflight")
    backup = {
        "control": cid,
        "plan": plan,
        "active": state["active"],
        "enabled": state["enabled"],
        "default": state["default"],
        "profiles": state["profiles"],
        "zone": ZONE_FILE.read_text() if ZONE_FILE.exists() else None,
    }
    (RUN / "rollback-result.json").unlink(missing_ok=True)
    (RUN / "backup.json").write_text(json.dumps(backup))
    (RUN / "backup.json").chmod(0o600)
    command(
        "systemd-run",
        "--quiet",
        "--collect",
        "--unit=" + UNIT,
        "--on-active=120s",
        "--timer-property=AccuracySec=1s",
        "/usr/bin/python3",
        str(RUN / "helper.py"),
        "rollback",
    )


def apply(cid, plan):
    backup = json.loads((RUN / "backup.json").read_text())
    if backup["control"] != cid or backup["plan"] != plan:
        raise ValueError("Firewall transaction mismatch")
    if cid == OWNER:
        command("systemctl", "enable", "--now", "firewalld")
        client()
        return
    from firewall.client import FirewallClientZoneSettings

    f = client()
    if ZONE in f.config().getZoneNames():
        settings = f.config().getZoneByName(ZONE).getSettings()
    else:
        settings = FirewallClientZoneSettings()
        settings.setDescription(DESCRIPTION)
        settings.setShort("Managed host firewall")
        settings.setTarget("default")
    if cid == MANAGEMENT:
        settings.setRichRules(management_rules(plan[MANAGEMENT]))
    else:
        ports, _ = workload_ports(plan[INBOUND], plan[MANAGEMENT])
        settings.setTarget("DROP")
        settings.setServices(sorted(plan[INBOUND]["services"]))
        settings.setPorts(ports)
        settings.setProtocols(["icmp", "ipv6-icmp"])
        settings.setForward(False)
    if ZONE in f.config().getZoneNames():
        f.config().getZoneByName(ZONE).update(settings)
    else:
        f.config().addZone(ZONE, settings)
    f.reload()
    if cid == INBOUND:
        if f.getDefaultZone() != ZONE:
            f.setDefaultZone(ZONE)
        for profile in backup["profiles"]:
            command("nmcli", "connection", "modify", profile["uuid"], "connection.zone", ZONE)
        for interface in plan[INBOUND]["interfaces"]:
            if f.getZoneOfInterface(interface) != ZONE:
                f.changeZoneOfInterface(ZONE, interface)


def rollback():
    backup = json.loads((RUN / "backup.json").read_text())
    if backup["active"]:
        command("systemctl", "start", "firewalld")
        f = client()
        if f.getDefaultZone() != backup["default"]:
            f.setDefaultZone(backup["default"])
        for profile in backup["profiles"]:
            command(
                "nmcli", "connection", "modify", profile["uuid"], "connection.zone", profile["zone"]
            )
        if backup["zone"] is None:
            ZONE_FILE.unlink(missing_ok=True)
        else:
            ZONE_FILE.write_text(backup["zone"])
            ZONE_FILE.chmod(0o644)
        f.reload()
        for profile in backup["profiles"]:
            zone = profile["zone"] or backup["default"]
            if f.getZoneOfInterface(profile["interface"]) != zone:
                f.changeZoneOfInterface(zone, profile["interface"])
    else:
        command("systemctl", "stop", "firewalld")
    command("systemctl", "enable" if backup["enabled"] else "disable", "firewalld")
    command("systemctl", "stop", UNIT + ".timer", codes=(0, 5))
    (RUN / "rollback-result.json").write_text(
        json.dumps({"restored": True, "control": backup["control"]})
    )
    (RUN / "rollback-result.json").chmod(0o600)


def main():
    action = sys.argv[1]
    if action == "rollback":
        with open(RUN / "lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rollback()
        return
    cid, plan, context = sys.argv[2], json.loads(sys.argv[3]), json.loads(sys.argv[4])
    if action in {"audit", "verify", "preflight"}:
        print(json.dumps(inspect(cid, plan, context, action)))
        return
    fd = os.open(RUN / "lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == "begin":
            begin(cid, plan, context)
        elif action == "apply":
            apply(cid, plan)
        elif action == "commit":
            backup = json.loads((RUN / "backup.json").read_text())
            if backup["control"] != cid or backup["plan"] != plan:
                raise ValueError("Firewall transaction mismatch")
            if not inspect(cid, plan, context, "verify", pending_allowed=True)["matches"]:
                raise ValueError("Native verification failed. Timed rollback remains armed.")
            command("systemctl", "stop", UNIT + ".timer")
        else:
            raise ValueError("Unsupported firewall operation")
    print(json.dumps({"completed": action}))


if __name__ == "__main__":
    main()
