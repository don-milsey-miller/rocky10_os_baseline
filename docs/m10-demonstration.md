# M10 local authentication and account policy

M10 is complete for the approved local-only disposable policy. Ten remediation
controls and four assessments are implemented. The catalog now contains 68
controls: 63 remediable and five assessment-only.

## Approved disposable policy

The owner approved local-only testing on 2026-11-05. The
[identity lab profile](../profiles/examples/server-identity-lab.yaml) selects ten
remediating controls. All parameters are explicit. These values are not production
defaults and the engine does not create accounts or group memberships.

| Control | Selected behavior |
| --- | --- |
| auth.password-quality | Minimum 14 characters, no character-class length credits, native enforcement enabled. Other vendor quality checks still apply. |
| auth.password-history | Native pam_pwhistory retained-entry count of 5. |
| auth.failed-login-lockout | 5 failures within 900 seconds, automatic unlock after 900 seconds. Root and the wheel recovery group remain exempt. |
| auth.password-aging | Selected human account: minimum 0 days, maximum 90 days, warning 14 days. |
| auth.inactive-account-lock | Selected human account: deny authentication 30 days after password expiry. |
| auth.default-umask | Initial 0027 mask for selected new interactive Bash sessions. |
| auth.shell-idle-timeout | Read-only 900-second TMOUT for selected new interactive Bash prompts. |
| auth.su-access-policy | Permit non-root su callers only from wheel, retaining the vendor root bypass. |
| accounts.system-login-disabled | Set only the selected disposable service account shell to nologin. |
| accounts.home-permissions | Set only the selected human home directory to 0700, without changing children or ownership. |

The local PAM password rules cover the supported system-auth and password-auth
stacks. Account lifecycle, Bash and home changes select named accounts. Root and
the connected recovery identity cannot be selected for those account mutations.
Existing administrator and service account records remain unchanged.

Native password history saves the current password before checking a replacement.
It counts toward the five retained entries. The acceptance test checks both
rejection within that set and acceptance after an entry leaves it. Failed su
authentication can add a failure to the target account's tally. Independent
threshold tests reset their fixture counters explicitly.

TMOUT measures waiting at an interactive Bash prompt. It is not a running-command
deadline, an SSH daemon timeout, or a policy for other shells. Umask is a startup
default that users may subsequently change. Existing shell processes are not
rewritten. Faillock uses the native volatile tally directory, so reboot clears
failure counters. No persistent-lockout claim is made.

## Supported layout and refusals

The tested platform uses the vendor local authselect profile. Native authselect
checks, complete active-stack comparison against authselect test output, and
package digests validate generated stacks, their templates, and the
login, passwd, sshd, sudo, sudo-i, su and su-l entry points. The reviewed managed
su insertion is the only accepted vendor-file deviation.

Domain profiles, active domain providers, unknown features, custom PAM entry
points, duplicate configuration keys, unsafe ownership/modes/links, password-quality
drop-ins, root lockout options and a nonexempt recovery identity are refused.
The engine uses authselect features rather than rewriting generated PAM files.

Bash controls require stock system and selected-user startup files, including
vendor-verified skeleton templates. The standard systemd startup symlink is
checked against its expected destination and packaged content. Custom startup
policy requires operator review.

Account controls require explicit local identities and refuse duplicate names or
UIDs. Human accounts must have ordinary Bash logins and UID from 1000 through 65533.
The service-shell control accepts explicitly selected accounts with UID 1–999.
Home directories must be ordinary /home/account directories with matching owners
and no ACLs. The engine never recursively changes their contents.

High-impact apply/preflight requires a recent engine- and target-bound
[recovery receipt](recovery-enforcement.md). Fresh independent SSH/sudo is checked
after each changed control. PAM and session-file changes restore their previous
selected configuration on local verification failure. Keep independent snapshot
recovery available throughout.

## Four assessment controls

The [assessment profile](../profiles/examples/server-account-assessment.yaml)
checks duplicate local identities, UID-zero ownership, empty/missing password
records, and root login PATH integrity. These controls never delete, renumber,
lock or repair accounts. Apply is rejected offline.

The accepted M9 guest includes two missing root PATH directories:
 /root/.local/bin and /root/bin. The PATH assessment reports a finding.
This is an explicit assessment disposition, not a successful remediation or a
reason to change root's startup configuration automatically. Combined verification
must retain that finding separately from passing controls.

## Reproduction

Use the approved isolated Rocky KVM lab. The development guest is the controller,
the target is the disposable identity guest, and a separate guest runs original
regressions. Keep credentials, inventory, raw reports and snapshots private.

From the prior M9 baseline, with no m10 fixture users:

    source .venv/bin/activate
    python tests/integration/m10_prepare.py --inventory inventory.local.m9.ini --target test-vm --output reports/m10/prepare --disposable

Save the stopped-disk target snapshot as m10-identity-ready using the independent
hypervisor route. In this lab the existing lifecycle command is:

    sudo python3 /home/milsy/rocky10-m8-lab/labctl.py test save m10-identity-ready

Run the engine recovery rehearsal, stop target SSH when RECOVERY_READY appears,
and restore that snapshot only after RECOVERY_OUTAGE_OBSERVED. Then run:

    hardener recovery-test --inventory inventory.local.m9.ini --target test-vm --output reports/m10/recovery
    python tests/integration/m10_identity.py --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m10/recovery/recovery.json --output reports/m10/lifecycle --disposable
    python tests/integration/m10_guards.py --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m10/recovery/recovery.json --output reports/m10/guards --disposable

Restore the same snapshot and repeat the lifecycle with a new output directory.
The receipt remains usable only while its engine, inventory, target and controller
bindings and validity period remain satisfied. After the final rebooted lifecycle:

    python tests/integration/m10_timed.py --inventory inventory.local.m9.ini --target test-vm --output reports/m10/timed --disposable

The timed suite waits the full approved 900 seconds. A background output-only
heartbeat keeps the existing SSH channel timeout from ending the Bash test.
It sends no input to the waiting shell and does not change SSH policy. Do not reboot the guest,
change authentication policy or reset its counters during that observation.
Fixture passwords travel through stdin and stay in private controller cache files,
outside reports and Git. The test service executes directly under its selected
service identity to prove that disabling its login shell does not stop the job.

## Review corrections

Review found that authselect check alone did not reject an appended generated PAM
rule. The engine now compares every active row of system-auth, password-auth and
postlogin with freshly rendered native profile output. It also verifies packaged
PAM entry points and shell skeleton files. The accepted tampered-stack and custom
entry-point cases refuse all writes.

Session-policy replacement now retains the existing safe file owner, group and
mode. A live su insertion with a nondefault safe group verifies group preservation.

Early harness runs are not acceptance evidence. Corrections replaced an
unprivileged PAM password-update probe with the real passwd command, isolated
su/login failure counters, matched the native five-entry history boundary, and
fixed a newline assertion. Early guard runs exposed the generated-stack gap above.
Final acceptance must use the corrected engine and fresh snapshot-restored runs.

## Validation record

Accepted on 2026-11-05 in Rocky Linux 10.2 x86_64 KVM guests. Development used
Python 3.12.13, Ansible Core 2.19.15 and Node 22.23.2. Target native packages were
authselect 1.5.2-1.el10, PAM 1.6.1-9.el10, libpwquality 1.4.5-12.el10,
shadow-utils 4.15.0-11.el10 and Bash 5.2.26-6.el10.

Engine SHA-256: c67721f6033a7968561ec51cee349d8d74911ea47bb6dc787526fb4bd6e45284.
The recovery receipt and all final lifecycle, guard, assessment, editor and
combined reports bind to this engine. Private evidence is under reports/m10-live.

| Evidence | Result |
| --- | --- |
| recovery-f | Observed SSH loss, independent stopped-disk snapshot restoration, changed boot identity, rolled-back marker and restored administrator access. |
| lifecycle-f and lifecycle-g | Two independent restores of m10-identity-ready. Ten initial failures, selected apply and verify pass, zero-change repeat apply, exclusions and omission preserve managed state, real password/authentication checks pass, rebooted verify and repeat apply pass. |
| Native credentials | 13-character replacement rejected, 14-character replacement accepted, reuse inside five retained entries rejected and an aged-out entry accepted. Four failures permit a correct login, five block it, wheel exemption and administrator unlock work. |
| Native account behavior | Allowed/denied su, password expiry, post-expiry inactivity, nologin denial, unchanged home children, unselected account records and running service job all pass. |
| guards-final | 18 unsafe-input cases refuse all policy writes. Fresh administrator access remains available. A safe nondefault su file group is preserved across replacement. |
| timed-final | Correct credentials remained blocked at 60 seconds. Automatic unlock observed at 906.5 seconds. Interactive Bash auto-logout observed at 900.0 seconds. Approved 900-second values were unchanged. |
| assessments-final | Unsafe identity fixtures fail audit and verify with zero writes. Original databases restore exactly. Three restored identity assessments pass and the existing root PATH finding remains visible. |
| browser-apply and browser-verify | Unchanged browser-downloaded YAML passes all ten selected controls with zero changes. |
| combined/apply | All 63 remediable controls pass with zero changes. Five assessments are explicitly excluded from apply. |
| combined/verify | 67 pass, one root PATH finding, zero changes. Exit 5 correctly retains that finding. |
| regression-final | Original VS1, VS2, VS4 and VS5 pass on the separate regression guest. |
| checks-final | 281 Python tests, 31 editor tests, 12 browser tests, Ruff, both Ansible syntax checks, wheel installation and release checks pass. |

Browser-export SHA-256: f1d529e14281ae4de042906ebfa9d85eada33ad85ce9c0192103f6dfc3c059f5.
Fresh IPv4 and IPv6 administrative SSH/sudo passed after combined verification.
The accepted target is saved as m10-accepted. No domain-managed authentication,
production rollout or later milestone is claimed. M11 through M13 remain unstarted.

## Behavior references

- [Authselect and domain-managed authentication](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [Native password-history processing order](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.6.1/modules/pam_pwhistory/pam_pwhistory.c)
- [Native retained-entry handling](https://raw.githubusercontent.com/linux-pam/linux-pam/v1.6.1/modules/pam_pwhistory/opasswd.c)
- Rocky guest manuals: pwquality.conf(5), pwhistory.conf(5), faillock.conf(5), chage(1).
