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

Work stopped at the owner's request on 2026-11-03. This is an unfinished M8
checkpoint, not a completed release. The test guest was restored to the preceding
verified M7 snapshot after the active read-only check finished. No validation
driver remains running.

The saved engine digest is
`8adaa98a342bbe85f7f51e23e5e335a24b543463abd6946a88a72320f842a0e6`.

Completed checks:

- 144 Python tests, Ruff lint/format checks, and Ansible syntax validation passed.
- The rebuilt offline editor passed 31 unit tests and 8 browser tests.
- The final-d guest run detected all thirteen noncompliant controls, refused all
  eight unsafe policies with zero changes, applied and independently verified all
  thirteen controls, and repeated apply with zero changes.
- Native probes passed root/password/empty-password rejection, removal of the
  host-based method, user/group access restrictions, TCP forwarding rejection,
  authentication-attempt and connection/session limits, actual idle-channel
  expiry, password-required sudo, zero-minute caching, and separate sudo PTYs.
- Focused checks demonstrated deleted-drop-in reload detection, reload repair,
  reboot verification, and zero-change reapplication.

The final-d run stopped at a manual fixture reload because its next TCP connection
arrived before sshd reopened the listener. The harness now waits for fresh SSH/sudo
after each manual reload. The subsequent final-e run was deliberately interrupted
at a completed read-only refusal check when the owner requested a stopping point.
Neither run is counted as a complete acceptance pass.

Remaining before M8 completion:

1. Run the full M8 suite twice from the M7 snapshot using the saved engine.
2. Run the browser-exported access profile unchanged against the guest and verify
   the combined 43-control profile.
3. Exercise SSH-loss snapshot recovery and the extended M5 stop-after-access-loss
   fixture. Rerun original VS1, VS2, VS4 and VS5 regression.
4. Rebuild and check the exact final package, complete CI/publication validation,
   archive final evidence, and promote the coverage status.

The earlier installed-wheel smoke test passed before the final helper changes.
It does not establish packaging validation for this checkpoint. Private evidence
under `reports/m8` records both successful probes and incomplete attempts.
Resume instructions and scripts remain in the development guest.

References: [OpenSSH daemon](https://man.openbsd.org/sshd),
[OpenSSH configuration](https://man.openbsd.org/sshd_config),
[upstream sudo policy manual](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in).

The native idle probe caught the difference between the documented session name
and the extended runtime channel names. The wildcard is checked against
[OpenSSH 9.9 session handling](https://github.com/openssh/openssh-portable/blob/V_9_9_P1/session.c)
and validated with a real inactive channel before publication.
