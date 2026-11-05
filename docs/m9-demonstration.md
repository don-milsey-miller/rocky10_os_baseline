# M9 network and firewall

This record covers the first M9 batch of three baseline network controls.
The [host-policy batch](m9-routing-demonstration.md) adds five validated network controls
and corrects exact-exclusion precedence in the shared helper. Three firewall controls remain planned.
The disposable-lab policy is approved: firewalld owns filtering, only the development
guest may initiate SSH, both IP families remain enabled, and the target has no routing
or container-networking role. Production policy still requires explicit site values.
The first batch does not implement that firewall policy.

## Implemented behavior

| Control | Effective and persistent policy | Compatibility |
| --- | --- | --- |
| network.ipv4-source-route-disabled | Set accept_source_route to 0 for all, default, and every current interface, with a boot wildcard for future interfaces. | Exclude when an application requires IPv4 source routing. |
| network.ipv6-source-route-disabled | Set accept_source_route to -1 for all, default, and every current interface, with a boot wildcard for future interfaces. | Rejects type 2 routing headers used by IPv6 mobility. |
| network.tcp-syncookies | Set net.ipv4.tcp_syncookies to 1. | SYN backlog fallback does not replace capacity planning. |

The example is [server-network-baseline.yaml](../profiles/examples/server-network-baseline.yaml).
These controls accept no parameters. They leave forwarding, redirect policy, firewall
services, and IPv6 enablement untouched. The kernel defines IPv6 values below zero as
routing-header rejection. Zero still accepts type 2 headers.
[Kernel network parameters](https://docs.kernel.org/networking/ip-sysctl.html)

Each control owns one root-owned 0644 file named
`/etc/sysctl.d/99-rocky10-<control-id-with-dots-replaced-by-hyphens>.conf`.
Existing comments are preserved. Unrelated assignments in that file, unsafe links,
unsafe ownership or permissions, and ACL-bearing managed files are refused.
The engine never rewrites other sysctl configuration files or reloads all sysctls.
It activates only the selected noncompliant keys.

Preflight reads systemd's ordered, directory-shadowed configuration. Explicit
interface assignments override wildcards. Conflicting assignments to an interface
are refused even if that interface does not exist yet. Later conflicting globals,
later global/default exclusions, interface exclusions, conflicting wildcard policies, and broad patterns extending
outside a control's ownership require operator reconciliation. This conservative
refusal avoids choosing precedence for competing wildcard policies.
[systemd sysctl configuration](https://www.freedesktop.org/software/systemd/man/devel/sysctl.d.html)

Audit reads native sysctl output. Verification reads `/proc/sys` directly and checks
persistent policy separately. Both inspect every current interface and the defaults
for future interfaces. Missing address-family kernel sysctls produce an observed
`not_applicable` result. An inspection failure is an error. Fresh SSH and sudo are
checked before and after apply, with multiplexing disabled.

## Disposable reproduction and recovery

Run inside the development Rocky guest with its virtual environment activated:

```bash
source .venv/bin/activate
python tests/integration/m9_network.py --inventory inventory.local.ini --target test-vm --output reports/m9/network-a --disposable
```

Prepare a target with the verified M8 state and a stopped-disk snapshot before running.
The suite deliberately changes the three selected settings and creates temporary
configuration and interface fixtures. Use a new output directory for every run.
Restore the same baseline and repeat. Keep inventories, keys, VM disks and runtime
reports outside Git.

The local lab uses three real Rocky Linux 10.2 KVM guests on WSL 2: development,
target, and a separate traffic-probe/regression guest. A private bridge joins their
secondary interfaces with IPv4 and IPv6. Their original NAT adapters retain package
access and host SSH forwarding. Host bridge forwarding exceptions are scoped to
traffic entering and leaving that lab bridge. No guest hardening runs on WSL itself.

The tested host lifecycle helper is outside the repository at
`/home/milsy/rocky10-m8-lab/labctl.py`. It cleanly shuts down a guest before changing
its qcow2 snapshot, then starts it with its saved QEMU arguments. Its network helper
recreates the private bridge, taps and scoped host rules. The saved baseline is
`m9-network-ready` on the target. Recovery from the host is:

```bash
sudo python3 /home/milsy/rocky10-m8-lab/labctl.py test restore m9-network-ready
```

Wait for guest boot to finish, then prove a fresh SSH connection and `sudo -n id -u`
from the development guest. Restoring this disposable snapshot rolls back every disk
change since it was saved. On another hypervisor, use its equivalent stopped-guest
snapshot restoration. There is no general engine rollback facility.

## Validation record

First-batch acceptance completed on 2026-11-05, version 0.9.0rc1.
Implementation commit: `10bde31996e11aa49d2f1f23fbdd9e238ef428bb`.
Engine SHA-256: `a1482a2b2706ac34d4311fa5a217f0ebe727de404203d65f44e138bb8cc29c9f`.

| Check | Result |
| --- | --- |
| Python unit tests | 164 passed |
| Editor unit tests | 31 passed |
| Browser tests | 9 passed, including network selection, exclusion and round-trip export |
| Ruff and Ansible syntax | Passed |
| Initial guest lifecycle | Passed, including reboot and zero-change reruns |
| Expanded lifecycle | Two complete runs from the same offline snapshot |
| Unsafe preflight cases | Five zero-change refusals per run: future-interface conflict, broad wildcard, excluded future interface, symlink, unrelated managed-file content |
| Read-only and selection behavior | Audit/verify made no writes, exclusions and omission preserved the unselected value |
| Interface behavior | New-interface defaults, live interface drift detection and repair passed |
| Browser-to-engine | Exact downloaded YAML applied and verified with zero changes |
| Combined state | All 46 controls verified after reboot, all 45 remediable controls repeated with zero changes |
| Administrative access | Fresh IPv4 and IPv6 SSH/sudo passed, IPv6 remained enabled and forwarding unchanged |
| Regression | VS1, VS2, VS4 and VS5 passed |
| Installed wheel and publication assets | Passed |

Private evidence is in `reports/m9/network-b`, `reports/m9/network-c`, and
`reports/m9/combined`, with exact profiles, commands, digests and native observations.
The earlier `network-a` run covers the initial implementation. It is not counted as
one of the two expanded-suite acceptance runs. The initial test invocation failed
before target execution because the virtual environment was not activated. A regression
attempt also stopped because its restored baseline lacked the documented RPM fixture.
Both setup issues were corrected before acceptance.

The unchanged browser download SHA-256 is
`fd4b56a3e0b2cd36d15b1d607f62cd7c66bbcf07149c62773973704260a1080f`.
Combined apply excludes the existing assessment-only update check. Combined verify
includes it against the disposable signed repository. This is the historical
first-batch record. See the [firewall record](m9-firewall-demonstration.md) for current 54-control acceptance.

## Subsequent M9 acceptance

The [host-policy batch](m9-routing-demonstration.md) completed the five remaining
network controls. The [firewall batch](m9-firewall-demonstration.md) completed
ownership, management access and inbound policy. All eleven M9 controls are validated.
The SSH-only lab values remain explicit test policy, not production defaults.
