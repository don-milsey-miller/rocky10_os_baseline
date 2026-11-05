# M9 host routing policy

This batch adds five independently selectable controls to the three baseline
network controls. Eight of eleven M9 controls are now validated. Firewall ownership, management
access and inbound policy remain planned.

## Controls and explicit parameters

| Control | Required policy | Effective state |
| --- | --- | --- |
| network.ipv4-redirects-disabled | network_role: non-routing | accept_redirects=0 for IPv4 all, default and every current interface |
| network.ipv6-redirects-disabled | network_role: non-routing | accept_redirects=0 for IPv6 all, default and every current interface |
| network.ipv4-send-redirects-disabled | network_role: non-routing | send_redirects=0 for IPv4 all, default and every current interface |
| network.reverse-path-filter | mode: strict or loose | rp_filter=1 or 2 respectively for IPv4 all, default and every current interface |
| network.ip-forwarding-disabled | network_role: non-routing and container_networking: absent | ip_forward=0 and forwarding=0 for every available family, including all/default/current interfaces |

No role or reverse-path mode is assumed when parameters are missing. The explicit
[disposable host profile](../profiles/examples/server-network-host-lab.yaml) uses
strict reverse-path filtering for the lab's directly connected management path.
Production operators must choose a mode appropriate to their routes. A strict
setting may reject legitimate asymmetric traffic. This batch does not certify an
arbitrary multi-homed or asymmetric production topology.

The controls reuse bounded per-control files in `/etc/sysctl.d`, explicit all/default
values and wildcards for future interfaces. They do not alter unrelated configuration
files. Runtime apply uses native sysctl. Independent verification reads `/proc/sys`
and separately evaluates persistent policy. IPv6 remains enabled, and the controls
do not change the configured IPv6 router-advertisement setting.
[Linux network parameters](https://docs.kernel.org/networking/ip-sysctl.html)

## Forwarding side effects and workload guards

On the tested Rocky kernel, changing global IPv4 forwarding from 1 to 0 also sets
`net.ipv4.conf.all.accept_redirects` to 1. The control captures that value immediately
before changes, restores it after the forwarding transition when necessary, and
independently checks the preserved result. It does not acquire ownership of redirect
policy. Native network-namespace probes and a forwarding-only guest apply verify
this behavior. The same probe found no additional non-forwarding interface sysctl changes for
the IPv6 transition in the tested configuration.
[Linux 6.12 forwarding implementation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/devinet.c)

Forwarding remediation supports the tested NetworkManager-managed host layout.
It refuses observed routing/container ownership rather than disabling those workloads:

- Shared IPv4 or IPv6 NetworkManager profiles, including inactive profiles.
- Explicit forwarding-enabled profiles or global connection defaults.
- Known routing/container services and sockets that are active or enabled.
- Bridges, veth pairs, tunnels and unsupported interface types.
- Conflicting persistent forwarding assignments, including earlier files and the
  IPv4 global alias. A boot-time forwarding transition can otherwise undo another policy.

Plain Ethernet, loopback, dummy, VLAN, bond and team interfaces are accepted by the
layout guard. Their workload compatibility still requires the operator's explicit
non-routing declaration. Missing inspection capabilities produce an error, not a
not-applicable result. These guards do not discover every possible custom service or
startup script. Unexpected post-boot changes must be reconciled before claiming a pass.
[NetworkManager IPv4 forwarding behavior](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html)

## Persistent precedence correction

An additional native systemd probe showed that a later exact exclusion cancels an
earlier explicit assignment. The parser now uses the last exact declaration,
including exclusions. Apply refuses a later exclusion of a managed global or default
key. A live test confirms that verification fails even while the current kernel
value is correct, then confirms a zero-write apply refusal.

An earlier identical wildcard can be superseded by the managed file. This supports
Rocky's vendor reverse-path defaults without rewriting vendor files. Different
conflicting wildcard patterns and broad patterns outside the control's scope still
require operator reconciliation. Explicit interface assignments and future-interface
exclusions remain guarded.
[systemd sysctl configuration](https://www.freedesktop.org/software/systemd/man/devel/sysctl.d.html)

## Reproduction and recovery

Use a disposable Rocky Linux 10.2 KVM server with the first M9 batch already verified.
Save its stopped-disk snapshot, then run inside the development guest:

```bash
source .venv/bin/activate
python tests/integration/m9_routing.py --inventory inventory.local.ini --target test-vm --output reports/m9-routing/host-a --disposable
```

Restore the same snapshot before repeating with a new output directory. The suite
intentionally enables forwarding and weakens the selected settings. It creates and
removes an inactive sharing profile, temporary configuration and temporary interfaces.
It never activates the sharing profile. Preserve the original host lifecycle path.
For this local lab, recovery to the first-batch state is:

```bash
sudo python3 /home/milsy/rocky10-m8-lab/labctl.py test restore m9-baseline-accepted
```

That helper shuts down the guest before restoring its qcow2 snapshot. Wait for boot,
then prove fresh SSH and noninteractive sudo. Use the equivalent stopped-guest
snapshot recovery procedure on another hypervisor. Inventory, keys, reports and
recovery scripts remain outside Git. See the [first-batch lab record](m9-demonstration.md)
for topology and the local network startup helper.

## Validation record

Acceptance completed on 2026-11-05 for version 0.9.0rc1.
Implementation commit: `ca4dbc33718f87e913016d6f65c1f30f734b2245`.
Engine SHA-256: `23e97a8b775711e420b0961cd8a4b13162457c25e86280d295d8fb4859f931df`.
The tested guest runs Rocky 10.2, kernel 6.12.0-211.16.1.el10_2.0.1 and
NetworkManager 1.56.0-1.el10 under KVM hosted by WSL 2.

| Check | Result |
| --- | --- |
| Python unit tests | 197 passed |
| Editor unit and browser tests | 31 and 10 passed |
| Ruff and Ansible syntax | Passed |
| Corrected routing lifecycle | Two full runs from the same offline snapshot |
| Unsafe preflights | Six zero-write refusals per run: early forwarding conflict, future-interface conflict, sharing profile, forwarding default, container interface, later exact exclusion |
| Selection and read-only behavior | Exclusion and omission preserved forwarding, audit/verify made no writes |
| Forwarding collateral | Forwarding-only apply preserved all captured non-forwarding state, including redirect acceptance |
| Reverse-path modes | Strict and loose modes independently verified |
| Interface lifecycle | New-interface defaults and drift detection/repair passed |
| Reboot | All five new and three earlier network controls passed, repeated apply made zero changes |
| Earlier network regression | Full original three-control suite passed with the corrected shared helper |
| Browser-to-engine | Exact downloaded host profile applied and verified unchanged |
| Combined catalog | All 51 controls verified after reboot, all 50 remediable controls repeated with zero changes |
| Administrative access | Fresh IPv4 and IPv6 SSH/sudo passed, IPv6 stayed enabled |
| Original regression gates | VS1, VS2, VS4 and VS5 passed during the batch |

Private evidence is under `reports/m9-routing/host-c`, `host-d`,
`baseline-regression-b` and `combined`. Reports retain commands, profiles, engine
digests and control evidence. Native kernel and systemd probes are saved alongside
them. Browser download SHA-256: `ac4adb2407ce9abfb985ccd273b2806215f04bcf5de583d7666eae0c04cba914`.

Earlier runs `host-a` and `host-b` passed before the exclusion-precedence correction.
They are not counted as acceptance runs of the final implementation. A browser test
initially compared the displayed enum label with its internal HTML value. Its export
was correct, and the assertion was fixed. The first original-network regression
attempt encountered an existing managed file while creating its symlink fixture.
The fixture now saves and restores that original content. The corrected suite passed.

The full-catalog apply excludes the assessment-only update check. Verification
includes it against the signed disposable repository. Packaging and GitHub CI are
recorded against the published checkpoint. No firewall-completion claim is made.

Current-engine reproduction additionally requires `--recovery-evidence` from a successful
[recovery rehearsal](recovery-enforcement.md). Historical acceptance above predates this
enforcement. Run the rehearsal before the integration suite and pass its receipt to the
suite command. The receipt must match the inventory, target, controller and engine.
