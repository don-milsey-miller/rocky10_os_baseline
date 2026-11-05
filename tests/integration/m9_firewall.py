"""M9 firewall lifecycle on three explicitly disposable dual-stack KVM guests."""

import copy
import json
import secrets
import shlex
import socket
import time
from pathlib import Path

from lab import GuestLab

from hardener.validation import parse_yaml

TARGET4, TARGET6 = "192.0.2.20", "fd90:9::20"
PROBE_SSH = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
    "-p",
    "22233",
    "zero@10.0.2.2",
]
ZONE = "rocky10-hardener"
LISTENER = r"""
import socket,threading,time

def serve(family,port,udp=False):
    s=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port))
    if not udp:s.listen(32)
    while True:
        if udp:
            data,peer=s.recvfrom(256);s.sendto(data,peer)
        else:
            peer,_=s.accept();peer.sendall(b'm9-firewall\n');peer.close()
for family in [socket.AF_INET,socket.AF_INET6]:
    for port in [80,18080,18081]:threading.Thread(target=serve,args=(family,port),daemon=True).start()
    threading.Thread(target=serve,args=(family,19090,True),daemon=True).start()
while True:time.sleep(1)
"""


def reach(address, port, udp=False):
    with socket.socket(
        socket.AF_INET6 if ":" in address else socket.AF_INET,
        socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
    ) as stream:
        stream.settimeout(1)
        try:
            stream.connect((address, port))
            if udp:
                token = secrets.token_bytes(16)
                stream.send(token)
                return stream.recv(256) == token
            return bool(stream.recv(128))
        except OSError:
            return False


def main():
    lab = GuestLab(__doc__)
    assert lab.args.recovery_evidence, "Run the observed recovery rehearsal first"
    profile = parse_yaml(Path("profiles/examples/server-firewall-lab.yaml").read_bytes())
    evidence = {}

    def state():
        return lab.python(
            "import hashlib,json,subprocess; from pathlib import Path; paths=[p for root in ['/etc/firewalld','/etc/NetworkManager/system-connections'] for p in Path(root).rglob('*') if p.is_file() and not p.name.endswith('.old')]; print(json.dumps({'files':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'nft':subprocess.check_output(['nft','-j','list','ruleset'],text=True),'nm':subprocess.check_output(['nmcli','-t','-f','UUID,TYPE,DEVICE','connection','show'],text=True)},sort_keys=True))"
        )

    def refuse(name, selected=profile):
        before = state()
        report = lab.execute("apply", name, selected, 3)
        assert report["changed_tasks"] == 0 and not report["preflight_passed"]
        assert report["errors"][-1].get("reason")
        assert state() == before
        return report

    def firewall(*arguments):
        return lab.remote("sudo firewall-cmd " + shlex.join(arguments))

    def traffic(name, workloads=False):
        observed = {}
        for address in [TARGET4, TARGET6]:
            assert reach(address, 22), (name, "development SSH", address)
            for port, udp in [(80, False), (18080, False), (18081, False), (19090, True)]:
                allowed = workloads and port != 18081
                result = reach(address, port, udp)
                assert result == allowed, (name, address, port, result, allowed)
                observed[f"dev/{address}/{port}"] = result
        code = """import socket,json,secrets
result={}
for address in ['192.0.2.20','fd90:9::20']:
 for port,udp in [(22,False),(80,False),(18080,False),(18081,False),(19090,True)]:
  with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
   s.settimeout(1)
   try:
    s.connect((address,port))
    if udp:
     token=secrets.token_bytes(16);s.send(token);ok=s.recv(256)==token
    else:ok=bool(s.recv(128))
   except OSError:ok=False
   result[address+'/'+str(port)]=ok
print(json.dumps(result))"""
        result = json.loads(lab.run(PROBE_SSH + ["python3 -c " + shlex.quote(code)]))
        for key, allowed in result.items():
            port = int(key.rsplit("/", 1)[1])
            assert allowed == (workloads and port in {80, 18080, 19090}), (
                name,
                "probe",
                key,
                allowed,
            )
        observed.update({"probe/" + k: v for k, v in result.items()})
        evidence[name] = observed

    before = state()
    assert lab.execute("audit", "before", profile, 5)["summary"]["fail"] == 3
    assert lab.execute("verify", "before-verify", profile, 5)["summary"]["fail"] == 3
    assert state() == before
    bad = copy.deepcopy(profile)
    bad["controls"][1]["parameters"]["ipv4_sources"] = ["192.0.2.30/32"]
    refuse("administrator-excluded", bad)
    bad = copy.deepcopy(profile)
    bad["controls"][2]["parameters"]["interfaces"] = ["ens4"]
    refuse("incomplete-interfaces", bad)
    bad = copy.deepcopy(profile)
    bad["controls"][2]["parameters"]["services"] = ["ssh"]
    refuse("ssh-service-bypass", bad)
    bad = copy.deepcopy(profile)
    bad["controls"][2]["parameters"]["tcp_ports"] = ["22"]
    refuse("ssh-port-bypass", bad)
    lab.remote("sudo nft add table inet m9foreign")
    try:
        refuse("foreign-native-table")
    finally:
        lab.remote("sudo nft delete table inet m9foreign")
    lab.remote("sudo systemctl enable nftables")
    try:
        refuse("competing-enabled-manager")
    finally:
        lab.remote("sudo systemctl disable nftables")
    foreign = "/etc/firewalld/zones/m9-foreign.xml"
    lab.write(foreign, '<?xml version="1.0"?><zone><short>Fixture</short></zone>\n')
    try:
        refuse("foreign-zone")
    finally:
        lab.remove(foreign)
    lab.write("/var/tmp/m9-zone-fixture.xml", '<?xml version="1.0"?><zone/>\n')
    lab.remote("sudo ln -s /var/tmp/m9-zone-fixture.xml /etc/firewalld/zones/rocky10-hardener.xml")
    try:
        refuse("unsafe-zone-link")
    finally:
        lab.remove("/etc/firewalld/zones/rocky10-hardener.xml")
        lab.remove("/var/tmp/m9-zone-fixture.xml")
    applied = lab.execute("apply", "apply", profile)
    assert applied["summary"]["pass"] == 3 and applied["changed_tasks"] > 0
    assert lab.execute("verify", "after", profile)["summary"]["pass"] == 3
    assert lab.execute("apply", "idempotent", profile)["changed_tasks"] == 0
    lab.write("/var/tmp/m9-firewall-listeners.py", LISTENER)
    lab.remote(
        "sudo systemd-run --quiet --collect --unit=m9-firewall-listeners /usr/bin/python3 /var/tmp/m9-firewall-listeners.py"
    )
    try:
        time.sleep(1)
        traffic("ssh-only")
        workload = copy.deepcopy(profile)
        workload["controls"][2]["parameters"].update(
            services=["http"], tcp_ports=["18080"], udp_ports=["19090"]
        )
        assert lab.execute("apply", "workload-apply", workload)["summary"]["pass"] == 3
        traffic("allowed-workloads", True)
        rule = 'rule priority="-100" family="ipv6" source address="fd90:9::10/128" port port="22" protocol="tcp" accept'
        firewall("--permanent", "--zone=" + ZONE, "--remove-rich-rule=" + rule)
        firewall("--zone=" + ZONE, "--remove-rich-rule=" + rule)
        partial = copy.deepcopy(profile)
        partial["controls"][2].update(enabled=False, reason="Preserve unselected workload policy")
        assert lab.execute("apply", "management-only-repair", partial)["summary"]["pass"] == 2
        traffic("unselected-workloads-preserved", True)
        omitted = copy.deepcopy(profile)
        omitted["controls"].pop()
        baseline = state()
        assert lab.execute("apply", "inbound-omitted", omitted)["changed_tasks"] == 0
        assert state() == baseline
        firewall("--zone=" + ZONE, "--add-port=18081/tcp")
        try:
            refuse("runtime-only-rule", workload)
        finally:
            firewall("--zone=" + ZONE, "--remove-port=18081/tcp")
        firewall("--permanent", "--zone=" + ZONE, "--add-port=18081/tcp")
        try:
            refuse("permanent-only-rule", workload)
        finally:
            firewall("--permanent", "--zone=" + ZONE, "--remove-port=18081/tcp")
        firewall("--zone=trusted", "--add-source=192.0.2.30/32")
        firewall("--permanent", "--zone=trusted", "--add-source=192.0.2.30/32")
        try:
            refuse("source-zone-bypass", workload)
        finally:
            firewall("--zone=trusted", "--remove-source=192.0.2.30/32")
            firewall("--permanent", "--zone=trusted", "--remove-source=192.0.2.30/32")
            # Remove only this fixture's new override, restoring the vendor zone.
            lab.remove("/etc/firewalld/zones/trusted.xml")
            lab.remove("/etc/firewalld/zones/trusted.xml.old")
        firewall("--zone=" + ZONE, "--add-port=18081/tcp")
        firewall("--permanent", "--zone=" + ZONE, "--add-port=18081/tcp")
        assert reach(TARGET4, 18081)
        assert lab.execute("audit", "managed-drift-audit", workload, 5)["summary"]["fail"] == 1
        assert lab.execute("apply", "managed-drift-repair", workload)["summary"]["pass"] == 3
        traffic("drift-repaired", True)
        assert lab.execute("apply", "restore-ssh-only", profile)["summary"]["pass"] == 3
        traffic("restored-ssh-only")
        lab.remote("sudo systemctl stop m9-firewall-listeners.service")
        lab.reboot()
        assert lab.execute("verify", "after-reboot", profile)["summary"]["pass"] == 3
        assert lab.execute("apply", "after-reboot-idempotent", profile)["changed_tasks"] == 0
        lab.remote(
            "sudo systemd-run --quiet --collect --unit=m9-firewall-listeners /usr/bin/python3 /var/tmp/m9-firewall-listeners.py"
        )
        time.sleep(1)
        traffic("after-reboot-traffic")
        # Arm the same recovery helper, then simulate a failed runtime SSH change.
        # No controller command restores policy. The guest timer must recover it.
        plan = {item["id"]: item["parameters"] for item in profile["controls"]}
        context = {"connection": ["192.0.2.10", "1", TARGET4, "22"]}
        helper = "/run/rocky10-hardener-firewall/helper.py"
        # /run is empty after reboot. Stage the already-tested helper for this failure fixture.
        source = Path("hardener/data/ansible/helpers/firewall_policy.py").read_text()
        lab.python(
            "from pathlib import Path; p=Path('/run/rocky10-hardener-firewall'); p.mkdir(mode=0o700,exist_ok=True)"
        )
        lab.write(helper, source)
        lab.remote("sudo chmod 0600 " + helper)
        rule4 = 'rule priority="-100" family="ipv4" source address="192.0.2.10/32" port port="22" protocol="tcp" accept'
        code = (
            "import subprocess; subprocess.run("
            + repr(
                [
                    "/usr/bin/python3",
                    helper,
                    "begin",
                    "firewall.inbound-policy",
                    json.dumps(plan),
                    json.dumps(context),
                ]
            )
            + ",check=True); subprocess.run("
            + repr(["firewall-cmd", "--zone=" + ZONE, "--remove-rich-rule=" + rule4])
            + ",check=True)"
        )
        lab.python(code)
        assert not reach(TARGET4, 22)
        assert reach(TARGET6, 22)
        print("Timed rollback: new IPv4 SSH blocked, waiting for guest timer", flush=True)
        start = time.monotonic()
        while time.monotonic() - start < 160 and not reach(TARGET4, 22):
            time.sleep(2)
        assert reach(TARGET4, 22), "Guest timer did not recover administrative access"
        recovered = json.loads(
            lab.remote("sudo cat /run/rocky10-hardener-firewall/rollback-result.json")
        )
        assert recovered["restored"] and lab.remote("sudo -n id -u").strip() == "0"
        evidence["timed_rollback"] = {
            "restored": True,
            "elapsed_seconds": round(time.monotonic() - start, 1),
        }
        assert lab.execute("verify", "after-timed-rollback", profile)["summary"]["pass"] == 3
        assert lab.execute("apply", "final-idempotent", profile)["changed_tasks"] == 0
        traffic("final-traffic")
    finally:
        lab.remote("sudo systemctl stop m9-firewall-listeners.service")
        lab.remove("/var/tmp/m9-firewall-listeners.py")
    lab.finish(
        {
            "checks": evidence,
            "zero_write_refusals": 11,
            "both_families": True,
            "reboot_and_repeat": True,
        }
    )


if __name__ == "__main__":
    main()
