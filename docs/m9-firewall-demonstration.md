# M9 firewall acceptance

This batch completes the three firewall controls following the eight network controls.
Both baseline-restored acceptance runs and the combined catalog checks passed.
The approved disposable policy uses firewalld, permits new remote SSH connections only from
the development guest, keeps IPv4 and IPv6 enabled, and has no routing or container role.
Production operators must supply their own reviewed values.

## Selection and effective behavior

| Control | Required parameters | Behavior |
| --- | --- | --- |
| firewall.firewalld-enabled | owner: firewalld, network_role: non-routing, container_networking: absent | Enables and starts the provisioned daemon after ownership and layout checks. |
| firewall.management-access | ssh_port, ipv4_sources, ipv6_sources | Stages source-bounded TCP allowances in the managed zone. Requires the ownership control. |
| firewall.inbound-policy | interfaces, services, tcp_ports, udp_ports | Binds every current interface and the default zone, permits the explicit workloads, and drops other new inbound application connections. Requires management access. |

The [lab profile](../profiles/examples/server-firewall-lab.yaml) selects all three.
Management staging alone does not restrict the existing public zone. Reports expose
`zone_bound` so a staged allowance cannot be mistaken for an enforced inbound policy.
Select inbound policy to bind the managed zone. SSH source networks are required for
both families. The current administrator's source and server port must be included.
Workload services or ports cannot reopen that SSH port to arbitrary sources.

All lists are explicit. Empty workload lists mean no additional inbound application
services. TCP and UDP ports are decimal strings between 1 and 65535. Service names
must resolve to simple vendor TCP/UDP definitions. Port ranges, helpers, service
includes and destination-qualified services are outside this implementation.
Established traffic, loopback and ICMP remain available. Vendor IPv6 host discovery
policy remains active. This is an inbound host policy, not an egress filter.

The managed zone is `rocky10-hardener`. Persistent interface assignment uses each
NetworkManager connection UUID. Runtime checks inspect actual devices, including
cloud profiles bound by MAC address. Verification separately checks the live nftables
management rules, workload ports, interface dispatch and final drops. Configuration
files or Ansible changed counts alone do not establish a pass.

## Supported layout and refusals

Provision `firewalld`, `python3-firewall` and `nftables` through the guest's approved
package process before selecting these controls. The engine does not provision them.
The validated layout is Rocky 10.2 with firewalld 2.4.3-4.el10_2 and nftables
1.1.5-6.el10_2, ordinary NetworkManager Ethernet connections, native nftables backend,
and exclusive firewalld table ownership. Other native rule layouts are not claimed.
The acceptance kernel is 6.12.0-211.73.1.el10_2.x86_64, installed by firewall package dependencies before the baseline snapshot. NetworkManager is 1.56.0-1.el10.

Preflight refuses foreign nftables tables, competing active or enabled managers,
legacy tables, custom local firewall configuration, source-bound zones, direct rules,
ipsets, unsupported policies, unsafe file ownership/links, routing/container layouts,
incomplete interface coverage and an excluded current administrator. It also refuses
runtime/permanent/disk disagreement. Operators must reconcile that disagreement before
apply. The engine never makes an unexplained runtime-only rule disappear by reloading.
Supported managed-policy drift can be repaired when runtime and permanent states agree.
Known service and layout guards supplement the required operator role declarations.
They do not discover every custom startup script or future workload.

Refusals retain bounded actionable reason codes through the
[diagnostic mechanism](recovery-enforcement.md). Arbitrary native command output and
unknown diagnostic text are not copied into public report reasons. Audit and verify
remain read-only and do not require a recovery receipt.

## Recovery

Every selected firewall change requires a valid, recent
[observed recovery receipt](recovery-enforcement.md) bound to the engine, controller,
inventory and target. Preserve the independent hypervisor recovery route throughout.
Each changing control saves its prior firewall state and arms a guest-local 120-second
systemd rollback timer before mutation. A fresh SSH connection with noninteractive
sudo and native verification must succeed before the timer is cancelled.

The rollback restores the prior managed zone, default zone, NetworkManager zone
assignments, runtime bindings, and daemon activation/enabling state. It owns only this
firewall transaction. It is not a general operating-system rollback mechanism.
The transient timer and its files live under `/run` and do not survive reboot.
Do not reboot or power off during a pending transaction. If the guest or its recovery
service cannot run, restore the saved stopped-disk snapshot through the hypervisor.
Ordinary reboot acceptance occurs only after the transaction has committed.

## Reproduction

Use three disposable KVM guests: a development controller, the target and a separate
unauthorized probe. The fixture uses development addresses `192.0.2.10` and
`fd90:9::10`, target addresses `192.0.2.20` and `fd90:9::20`, and probe addresses
`192.0.2.30` and `fd90:9::30`. The probe's administrative transport is independent
of the target firewall. This suite deliberately changes policy and briefly blocks new
IPv4 administration to test the guest timer. Run only on the disposable lab.

Save the prepared baseline with firewalld installed but disabled and inactive, then:

```bash
source .venv/bin/activate
hardener recovery-test --inventory inventory.local.m9.ini --target test-vm --output reports/m9-firewall/recovery
# Follow RECOVERY_READY, stop target sshd, wait for RECOVERY_OUTAGE_OBSERVED,
# then restore the saved baseline independently through the hypervisor.
python tests/integration/m9_firewall.py --disposable --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m9-firewall/recovery/recovery.json --output reports/m9-firewall/acceptance
```

For this approved WSL-hosted KVM lab, the independent restoration command is:

```bash
sudo python3 /home/milsy/rocky10-m8-lab/labctl.py test restore m9-firewall-ready
```

Run only lifecycle/network plumbing on the hypervisor. All framework execution and
target changes occur inside the guests. Wait for fresh target SSH and sudo after
boot before starting a suite. Restore the same baseline and use a new output directory
for the repeated run. Keep inventory, receipts, keys, snapshots and raw reports private.
After inbound policy applies, the host-forwarded target SSH port is intentionally
blocked. Use the approved development guest path or the independent hypervisor route.

## Validation record

Acceptance completed on 2026-11-05 for version 0.9.0rc1.
Implementation commit: `25630ef365cb078997ba658793a536ffaf4ee7f0`.
Engine SHA-256: `7907bc82343413ad728f386b8a9fe6fd1e36bb9ec54c2f16bc39e0cc377e3dc5`.
The three Rocky 10.2 KVM guests ran under the approved WSL 2 hypervisor. No framework
hardening was applied to the Windows host, WSL host or office bare-metal server.

| Check | Result |
| --- | --- |
| Python unit tests | 232 passed |
| Editor unit and browser tests | 31 and 11 passed |
| Ruff, Ansible syntax, wheel installation and release checks | Passed |
| Recovery enforcement | Final-engine rehearsals `recovery-d` and `recovery-e` observed SSH loss and independent snapshot restoration before issuing receipts |
| Complete firewall lifecycle | `acceptance-a` and `acceptance-b` passed from the same `m9-firewall-ready` snapshot |
| Unsafe preflights | 11 zero-write refusals in each run, including policy exclusions, incomplete interfaces, global SSH bypass, foreign ownership, unsafe files and runtime/permanent drift |
| Traffic | Both families tested from the permitted controller and separate unauthorized probe, with positive TCP/service/UDP workloads and denied SSH/unselected ports |
| Selection and drift | Read-only audit/verify, explicit exclusion, omission, management-only repair and owned-policy drift repair passed |
| Reboot persistence | Native verification, permitted/blocked traffic and zero-change apply passed after reboot in both runs |
| Timed rollback | New IPv4 SSH was deliberately blocked, IPv6 remained reachable, and the guest timer restored access in 120.7 and 120.8 seconds without a controller repair command |
| Combined catalog | All 54 catalog entries verified, all 53 remediable controls applied with zero changes |
| Exact browser download | Applied and verified unchanged, with zero changes |
| Original regressions | VS1, VS2, VS4 and VS5 passed on the separate regression guest |
| Source checkpoint CI | Passed (run `42101939033`) |

The combined profile retains the signed disposable repository for the assessment-only
security-update check. Apply omits that assessment. This proves the control against the
fixture, not a claim that every installed OS package is free of security updates.
The final guest retains the approved SSH-only application policy and both IP families.
Fresh IPv4 and IPv6 SSH with noninteractive sudo passed after the combined checks.
The accepted continuation snapshot is `m9-accepted`. It was saved after acceptance,
and fresh SSH/sudo succeeded on both families after its automatic restart. Use
`m9-firewall-ready`, not the accepted snapshot, to reproduce the deliberately
noncompliant lifecycle tests.

Private evidence is under `reports/m9-firewall/acceptance-a`, `acceptance-b`, `combined`,
`recovery-d`, `recovery-e`, and `vs1`, `vs2`, `vs4`, `vs5`. Reports preserve commands,
profile digests, engine digests, control results and bounded refusal reasons.
Unchanged browser download SHA-256: `49c4b148d837a1679ad9f35df97d3227da40b46e1f795abc95fb17a1a898e395`.

Prototype attempts are retained separately and are not counted as final acceptance.
Native tests exposed MAC-bound NetworkManager profiles, named-field ordering,
canonical rich-rule ordering, and firewalld 2.4 policy-chain drop placement. Their
checks were corrected before the final engine checkpoint. A diagnostic lifecycle run
stopped on its own leftover fixture zone, which cleanup now removes. A subsequent
attempt started before guest boot completed. Neither is counted as a final run.
The completed milestone covers all eleven M9 controls. M10 through M13 remain.

## Behavior references

- [firewalld runtime and permanent operations](https://firewalld.org/documentation/man-pages/firewall-cmd.html)
- [Rich-rule priorities and source selection](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html)
- [Reload behavior](https://firewalld.org/documentation/howto/reload-firewalld.html)
- [Native D-Bus zone API](https://firewalld.org/documentation/man-pages/firewalld.dbus.html)
- [Zone configuration](https://firewalld.org/documentation/man-pages/firewalld.zone.html)
