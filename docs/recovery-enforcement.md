# Recovery enforcement and refusal diagnostics

High-impact `apply` and `preflight` require evidence from an observed snapshot-recovery
rehearsal. This is enforced before any selected control writes. `audit`, `verify`,
profile validation, excluded controls and profiles containing only lower-impact
controls do not require a receipt. There is no acknowledgment or force bypass.
The selected target must remain a Rocky Linux 10 KVM server.

## Rehearsal on a disposable guest

This operation intentionally tests loss of administrative SSH. Arrange an independent
hypervisor administrative session and a known stopped-disk snapshot before starting.
The snapshot must predate the rehearsal. Do not save a new snapshot after the challenge
marker has been written. The framework does not provision guests, manage the hypervisor,
stop SSH, or restore snapshots. Those actions remain explicit operator/harness operations.

Inside the development guest, with the tested virtual environment active:

```bash
hardener recovery-test --inventory inventory.local.ini --target test-vm --output reports/recovery-a
```

1. The engine checks the supported platform, a non-root public-key SSH login, root
   escalation, and fresh connections with strict host-key verification. It writes a
   random root-owned challenge marker under `/var/lib` and prints `RECOVERY_READY`.
2. In the existing disposable-target administrative session, stop `sshd.service`.
   Wait for the engine to print `RECOVERY_OUTAGE_OBSERVED`. Restoring too early does
   not satisfy the test.
3. Through the independent hypervisor session, stop the guest cleanly and restore
   the known snapshot. Start the guest. Do not delete the marker manually.
4. The engine must observe restored non-root SSH/sudo, the same machine identity,
   a different boot ID, and absence of its marker. A reboot that retains the marker
   cannot pass. A different guest cannot pass. The rehearsal waits about ten minutes,
   then fails without issuing a receipt if the required sequence is incomplete.
5. Use the emitted receipt for high-impact operations:

```bash
hardener preflight --profile profiles/examples/server-network-host-lab.yaml --inventory inventory.local.ini --target test-vm --recovery-evidence reports/recovery-a/recovery.json --output reports/preflight
hardener apply --profile profiles/examples/server-network-host-lab.yaml --inventory inventory.local.ini --target test-vm --recovery-evidence reports/recovery-a/recovery.json --output reports/apply
```

For the current local lab, the independently exercised host route is the stopped-disk
QEMU restore in the M9 demonstration documents. Keep that route available throughout
remediation. The ceremony demonstrates out-of-band guest restoration independently of
the target SSH service. It does not add a second SSH account or claim to validate every
production console, cloud recovery service, or topology.

If a rehearsal fails, restore the known snapshot and prove fresh SSH/sudo before retrying
with a new output directory. Failed rehearsals can leave their marker. Snapshot recovery
removes it. Normal apply never restores a disk automatically.

## Receipt contract and trust boundary

The receipt is authenticated using a controller-local random key at
`~/.local/state/rocky10-hardener/recovery.key`. The directory must be owned by the current
user with mode 0700. The key must be a private, regular, single-link 0600 file. Keep the
key and all runtime evidence out of Git. The receipt has a 24-hour validity limit and
binds the inventory bytes, target alias, engine digest, and observed machine identity.
Changing inventory, engine or controller requires another rehearsal. Before remediation,
the target's actual machine identity is checked again. Missing, altered, expired or
mismatched evidence produces a nonzero preflight refusal with zero control writes.

The controller user, installed engine, inventory and hypervisor operator are trusted.
The receipt is evidence of the engine's observed rehearsal, not protection against an
operator who controls and rewrites that engine or its signing key. The 24-hour bound is
not a guarantee that infrastructure cannot subsequently fail. Preserve the tested route
and snapshot, and rerun the rehearsal after recovery infrastructure changes. Ordinary
reboots do not by themselves invalidate the receipt.

## Actionable refusals

Reports retain static assertion reasons only when the exact message is present in the
packaged task allowlist. Rendered messages, arbitrary module messages, stderr and
inventory values are not copied into errors. Network preflight failures additionally
record a control ID, stable `network-policy-conflict` code and bounded conflict details.
These identify configuration paths, interface/service ownership, or NetworkManager
profile UUIDs. Unsafe managed files include the expected managed path and properties to
inspect. Arbitrary connection-section names and unrecognized diagnostic text are replaced
with generic inspection instructions. JSON and text reports contain the same reasons.

Integration suites using `GuestLab` accept `--recovery-evidence`. Obtain real rehearsal
evidence before running M8/M9 suites that include high-impact controls. Reuse it only
while its target/controller/engine bindings and age remain valid.

## Acceptance record

Acceptance completed on 2026-11-05 in the disposable Rocky Linux 10.2 KVM lab.
Implementation commit: `b7268a6c1923f2b68c22b4ceadd9c824aa52b7f8`.
Engine SHA-256: `41937cae7a438cca45882cc6caff8061006e7b6bf7dafea44e5e6590035791c3`.

| Check | Result |
| --- | --- |
| Python / editor / browser tests | 217 / 31 / 10 passed |
| Lint, formatting and both Ansible playbooks | Passed |
| Observed recovery | Two rehearsals on the final engine, each observing SSH loss and restoration from the same stopped-disk baseline |
| Receipt enforcement | Missing, manual acknowledgment, tampered, expired, wrong inventory, wrong engine and wrong guest evidence all refused |
| Refusal acceptance | Two final runs, nine zero-write refusals each, with managed-state comparisons |
| Read-only operations | Audit and verify passed without recovery evidence |
| Diagnostics | Conflicting and unsafe managed paths reported, private test sentinel withheld |
| Combined state | 51 controls verified, 50 remediable controls repeated with zero changes |
| Original regressions | VS1, VS2, VS4 and VS5 passed |
| Installed wheel and release assets | Passed |
| Implementation CI | Passed (run `42088853381`) |

Final private evidence is under `reports/m9-recovery/rehearsal-c`, `rehearsal-d`,
`guards-b`, `guards-c`, the combined reports and `regression`. `acceptance.json`
indexes the results. The combined apply explicitly excludes the assessment-only
update control. Verification includes it against the signed disposable repository.

The initial rehearsal stopped without issuing a receipt because the observation fact
was hidden from the callback. Only bounded observation facts are now exposed to its
allowlist. The prototype rehearsal/guard run predates the final assertion allowlist
and is not counted as final acceptance. The first VS2 regression attempt stopped
at its required installed-Telnet fixture check. The fixture was restored and the
complete suite passed in `regression/vs2-final`.

The subsequent [firewall acceptance](m9-firewall-demonstration.md) validates M9
firewall ownership, management access and inbound policy with this enforcement. The recovery procedure is validated for the described disposable KVM
snapshot route. It is not a general production recovery certification.
