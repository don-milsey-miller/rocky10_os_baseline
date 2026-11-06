# M8 SSH and sudo policy

Version 0.8.0rc1 adds thirteen independently selectable server controls.
Production profiles must supply access identities, forwarding choices, session
limits, sudo subjects, and cache duration. The example
[access profile](../profiles/examples/server-access-lab.yaml) names disposable
lab identities and is not a production policy.

## Supported behavior

SSH configuration and existing private host keys become root-owned mode 0600.
Contents and existing security labels are preserved. The helper inspects native
`sshd -T -C` output for the actual administrative connection and validates a full
isolated candidate with `sshd -t` before replacement. The normal Rocky wildcard
drop-in layout is supported. Active Match blocks, custom includes, service
overrides, unsafe links or ACLs, and conflicting earlier settings require review.

The separate authentication controls set PermitEmptyPasswords, HostbasedAuthentication,
and PermitRootLogin to no. The password-login control disables both password and
keyboard-interactive authentication. Access lists use exact local user/group names.
The forwarding control explicitly sets TCP, Unix socket, agent, X11 and tunnel
permissions. Session policy sets MaxAuthTries, MaxSessions, MaxStartups,
LoginGraceTime and ChannelTimeout for session channels, using the session* pattern
to cover the extended shell, command and subsystem names in OpenSSH 9.9. An idle limit is actual
channel inactivity, not a client-liveness probe.

All SSH policy controls depend on configuration and host-key protection.
Selected directives are updated in place in `00-rocky10-hardener.conf`.
Unselected directives remain. Native current-process journal evidence must show
that sshd loaded the configuration after its most recent modification. Missing
load evidence fails verification and triggers reload during apply.

Sudo configuration, including an existing `/etc/sudo.conf`, becomes root-owned
mode 0440. Policy changes require the standard local files source and complete
native `cvtsudoers` evaluation plus `visudo -c` validation. PTY policy is explicit.
Scoped exceptions that disable it are refused.

Authentication changes only retag existing direct unrestricted local administrator
grants to PASSWD. They never add a grant or copy group privileges. Group-only
passwordless access, command restrictions, unsupported tags/scopes, domain sudo
sources, special authentication defaults, and the active recovery identity are
refused. Timeout subjects must also be selected for authentication policy.
Existing unselected subjects and command grants remain unchanged.

Every access-changing control checks a new public-key SSH connection with
multiplexing disabled and noninteractive sudo before and after remediation.
Failure of that probe stops subsequent writes. Configuration syntax checks cannot
prove arbitrary production MFA, identity-provider, or workload compatibility.

## Reproduction and recovery

Restore the stopped disposable test guest to the preceding M7 snapshot, start it,
and run from the development guest:

```bash
python tests/integration/m8.py --inventory inventory.local.ini --target test-vm --output reports/m8/run-a --disposable
```

The test creates isolated users and a temporary root-key fixture, deliberately
weakens selected settings, then exercises refusal and remediation. Passwords
are generated in memory and passed through stdin or the private SSH askpass
environment. No credentials enter profiles, command arguments, or reports.
The temporary root key and testing-only source-penalty override are removed
before final verification and reboot. Restore the M7 snapshot before repeating.

Keep the pre-change KVM snapshot and a tested host lifecycle path. On loss of
guest access, shut down the disposable VM through libvirt, confirm it is stopped,
restore the verified snapshot, start it, and prove a new SSH/sudo connection.
For manual rollback with working recovery access, restore the saved original
selected configuration files and metadata, run `sshd -t` and `visudo -c`,
reload sshd, and test a separate administrative connection before closing recovery
access. The engine does not provide a general transaction rollback.

## Validation record

M8 acceptance completed on 2026-11-05 for version 0.8.0rc1. Tests used the saved
implementation from commit `ae83d04`, with no engine changes during the local resume.
Its SHA-256 remains
`8adaa98a342bbe85f7f51e23e5e335a24b543463abd6946a88a72320f842a0e6`.

| Check | Result |
| --- | --- |
| Python unit tests | 144 passed |
| Editor unit and browser tests | 31 and 8 passed |
| Ruff and Ansible syntax | Passed |
| M7 baseline recreation | Full suite passed, including reboot and no-change rerun |
| M8 lifecycle | Two complete runs from the same offline snapshot |
| Unsafe-policy preflights | Eight zero-change refusals per run |
| Native access probes | Authentication, user/group restrictions, forwarding denial, connection/session limits, idle disconnect, sudo password/cache/PTY behavior passed |
| Reload evidence | Edited configuration and deleted drop-in detected, then repaired |
| Browser-to-engine | Exact downloaded access profile applied and verified without editing |
| Combined catalog | 42 remediable controls applied and all 43 verified, including update assessment |
| Combined persistence | All 43 verified after reboot, with zero-change apply reruns before and after reboot |
| Regression | VS1, VS2, VS4, VS5 and extended M5 access-loss/dependency suite passed |
| Recovery | SSH stopped deliberately, offline snapshot restored, fresh SSH/sudo and marker rollback verified |
| Packaging and publication checks | Installed-wheel smoke, release assets and Git-history credential-pattern/path scan passed |

Private evidence is under `reports/m8/local-run-d`, `reports/m8/local-run-e`,
`reports/m8/local-combined` and `reports/local-resume`. Reports retain exact commands,
profile digests, engine digest and native observations. The two M8 runs produced
matching final control statuses and expectations. Each post-reboot apply made zero
changes. Native idle disconnection measured 30.0 and 29.8 seconds for a 30-second policy.

The browser download SHA-256 is
`24a15591a8920d6381f17b537503e307fe12a2173acb9c49331b465c194404a8`.
Combined apply explicitly excludes the assessment-only update control. Combined
verify enables it against the signed disposable M7 repository after its fixture update.

The interrupted office runs and local attempts `local-run-a` and `local-run-b` are
not acceptance passes. The local failures identified a missing M7 HTTPS fixture and
an already-enabled sudo PTY policy in the initial test baseline. Both were corrected
before the two complete runs. The engine's platform and safety guards were unchanged.

### Local KVM reproduction

Separate development and target guests run under QEMU/KVM hosted by Ubuntu 24.04 on
WSL 2. They boot Rocky's kernel and report `kvm`. A third disposable guest runs the
older regression suites independently. WSL is only the hypervisor host.

The image is `Rocky-10-GenericCloud-Base-10.2-20260525.0.x86_64.qcow2` from
[Rocky's image repository](https://download.rockylinux.org/pub/rocky/10/images/x86_64/).
Its verified SHA-256 is
`9fc9e9ff16888bb68ac39b0392e25c9c92684d50c85f1cce6ab549363bbc4b48`.
The tested kernel is `6.12.0-211.16.1.el10_2.0.1.x86_64`, with OpenSSH 9.9p1 and sudo 1.9.17.
Development uses Python 3.12, Node.js 22 and the pinned repository dependencies.

Prepare key-authenticated `zero` administration, verified SSH host keys, an explicit
server inventory and a recovery grant in `/etc/sudoers.d/90-lab-zero`. This cloud image
places its default user's sudo grant after the include directive. In the disposable
fixture, preserve that grant in a separate drop-in so the include remains last.
Validate the policy with `visudo -c` and prove a fresh administrative connection.

Rebuild the M2/M7 package and HTTPS fixtures using the existing test instructions.
Run the M7 suite and establish the file/kernel baseline before saving the pre-M8
snapshot. The current general profile enables some M8 controls, so remove its managed
SSH and sudo-PTY settings from this disposable starting fixture. The M8 forwarding
probe requires the M7 HTTPS fixture to be running.

With the target shut down, create QEMU disk snapshots using
`qemu-img snapshot -c SNAPSHOT DISK.qcow2` and restore them using
`qemu-img snapshot -a SNAPSHOT DISK.qcow2`. Start the guest and prove fresh SSH/sudo
after restoration. The tested local snapshot is `local-m7-for-m8`. Run the M8 command
above twice with separate output directories, restoring this snapshot between runs.
Keep VM disks, inventories, keys and generated reports outside Git.

References: [OpenSSH daemon](https://man.openbsd.org/sshd),
[OpenSSH configuration](https://man.openbsd.org/sshd_config),
[upstream sudo policy manual](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in).

The native idle probe caught the difference between the documented session name
and the extended runtime channel names. The wildcard is checked against
[OpenSSH 9.9 session handling](https://github.com/openssh/openssh-portable/blob/V_9_9_P1/session.c)
and validated with a real inactive channel before publication.

Current-engine reproduction additionally requires `--recovery-evidence` from a successful
[recovery rehearsal](recovery-enforcement.md). Historical acceptance above predates this
enforcement. Run the rehearsal before the integration suite and pass its receipt to the
suite command. The receipt must match the inventory, target, controller and engine.
