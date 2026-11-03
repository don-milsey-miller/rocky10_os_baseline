# M2 demonstration

Executed on 2026-11-03 using the separate Rocky Linux 10.2 development and test
KVM guests. Engine version: 0.2.0. Profile:
`profiles/examples/server-five-controls.yaml`, revision 1.

The four new controls join the existing account-file control. All five are
implemented and selectable. The one-control example is retained at revision 2.

## Executed checks

| Check | Result |
| --- | --- |
| Unit tests | 59 passed |
| Original M1 regression suite | Passed on the final source/profile |
| Installed wheel, outside source checkout | All five controls independently verified |
| Ruff and Ansible syntax checks | Passed |
| Initial audit with five deliberately noncompliant controls | Five failures, no changes |
| Combined apply and independent verification | Five passes |
| Second identical apply | Five passes, zero changed tasks |
| Reboot, followed by independent verification | Five passes |
| Each of five explicit exclusions | Excluded state unchanged, reason retained |
| Omitted signature control | Unchanged |
| Later sysctl conflict | Whole apply refused before writes |
| Ambiguous DNF configuration | Whole apply refused before writes |
| Package requiring Telnet | Whole apply refused, no package removed |
| Custom debug-shell unit | Preserved, whole apply refused |
| Runtime-only debug-shell mask | Detected and made persistent |
| Unsigned local RPM through DNF | Rejected, package remained absent |
| Unrelated state | Account content, group metadata, earlier sysctl file, other kernel setting, other DNF settings, and other installed packages preserved |

The full five-control lifecycle passed initially and again after restoring the
`m2-test-ready` snapshot. The final run includes the custom-unit and runtime-mask
tests. Its evidence is under `reports/m2-final2/`.

Exact final integration command:

```bash
source .venv/bin/activate
python tests/integration/vs2.py --inventory inventory.local.ini --target test-vm --disposable --output reports/m2-final2
```

The output includes before/apply/after/second-apply/after-reboot/final reports,
refusal and exclusion reports, `commands.json`, and
`integration-evidence.json`. Generated reports and RPMs remain outside Git.

The installed wheel and source checkout have the same engine source digest:
`ba311de823b150954f353f7836f67fa05cac80ed4eda6045f4956ea45b78fe23`.

See [test reproduction](m2-testing.md) and [control behavior](m2-controls.md).
The profile editor and release-readiness work remain separate milestones.
No hosted CI run or open-source release is claimed. The project remains
unlicensed by owner choice.
