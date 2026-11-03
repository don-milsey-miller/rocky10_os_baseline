# M0 and M1 demonstration

Executed 2026-11-03 on separate Rocky Linux 10.2 KVM development/test guests.
The owner approved the five controls, schema v1, and snapshot/console recovery
procedure before implementation.

| Control ID | Agreed behavior | Availability |
| --- | --- | --- |
| files.passwd-permissions | /etc/passwd root:root, 0644 | Implemented and VM-tested |
| kernel.protected-hardlinks | Persistent and running fs.protected_hardlinks=1 | Planned |
| services.debug-shell-disabled | debug-shell.service stopped and masked | Planned |
| packages.telnet-client-absent | telnet absent, dependencies preserved | Planned |
| packages.local-signature-check | Effective DNF localpkg_gpgcheck=True | Planned |

## Executed evidence

Serial-console login and sudo returned UID 0. The clean-m0 internal snapshot
was restored successfully. A marker created afterward disappeared, SSH
continued working, and /etc/passwd returned to root:root, 0644.

The standalone lifecycle used `profiles/examples/server-minimal.yaml` unchanged:

```bash
source .venv/bin/activate
python tests/integration/vs1.py --inventory inventory.local.ini --target test-vm --disposable
```

The script records each exact CLI invocation and expected exit behavior in
source. Individual commands are also in the README.

| Check | Observed result |
| --- | --- |
| Audit after injecting mode 0664 | fail, exit 5, zero changes |
| First apply | pass, one changed task |
| Independent verify | 0:0:644:regular file:1, pass |
| Second apply | pass, zero changed tasks |
| Second verify | pass |
| Account-file content and sampled unrelated state | Preserved |
| Explicitly excluded control | Mode stayed 0664, zero changes |
| Missing server-role declaration | Preflight refused, zero changes |
| Missing privilege escalation | Preflight refused, zero changes |
| Final apply and verify | pass, mode restored to 0644 |

Reports are generated under `reports/vs1/`, including before, apply, after,
second-apply, second-verify, exclusion, refused-role, refused-privilege, and
final reports. They are evidence artifacts, not tracked repository content.

The initial fact-collection compatibility error was corrected by selecting
Ansible's supported `virtual` fact subset. The full live lifecycle passed
after that correction.

Unit tests and static checks cover malformed/unsafe YAML, schema types, duplicate
and unknown controls, unsupported targets, parameters, dependencies/conflicts,
unavailable implementations, offline validation, literal targets, report
serialization/status/exit behavior, redaction, and read-only task constraints.

No high-impact control, editor, five-control remediation, or release test is
claimed complete. The next milestone implements the remaining four controls
after this one-control handoff.

Final unit run: 40 tests passed. Ruff checks and Ansible syntax check passed.
The built wheel installed into a separate environment and validated the profile
outside the source checkout. No hosted CI run is claimed.
