# M10 historical review checkpoint

This document records checkpoint 651c036 before the owner approved the disposable
identity policy. It is historical, not the current milestone status. See
[M10 acceptance](m10-demonstration.md) for the subsequent implementation and evidence.

At that checkpoint M10 was incomplete. Four assessment-only controls had guest evidence. The ten
remediating controls are drafts with implemented set to false, so the CLI and editor
cannot execute or select them. Unit tests and read-only audit do not establish
remediation acceptance.

## Completed assessment slice

| Control | Evidence |
| --- | --- |
| accounts.unique-identities | Duplicate local user IDs and group IDs detected in isolated fixtures. |
| accounts.root-only-uid-zero | Locked, noninteractive UID-zero alias detected. |
| accounts.no-empty-passwords | Isolated empty shadow password detected without recording password fields. |
| accounts.root-path-integrity | Native root login PATH inspection found two missing directories. |

All three deliberately unsafe identity states failed audit and verify with zero
changed tasks. Original passwd, shadow and group bytes were restored, then the
three identity assessments passed. Assessment-only apply is rejected offline.
Fresh administrative SSH and sudo worked afterward.

Root PATH contains /root/.local/bin and /root/bin, which do not exist in the
accepted M9 guest. The assessment reports failure. It does not create directories
or rewrite root startup files. This is not a successful hardening result.

Use [the assessment profile](../profiles/examples/server-account-assessment.yaml)
with audit or verify. A failed assessment returns exit code 5.

Reproduce only on a disposable Rocky 10 KVM guest matching the saved
m10-review-baseline snapshot. The suite temporarily adds locked/noninteractive
identity records and one empty-password fixture. Never run against production.

    source .venv/bin/activate
    python tests/integration/m10_assessments.py --inventory inventory.local.m9.ini --target test-vm --output reports/m10/assessments --disposable

The suite restores original database bytes in a finally block. Independent snapshot
recovery remains available if the controller or guest fails. The current lab uses
the previously approved WSL KVM host solely for guest lifecycle operations.

## Draft remediation contract

| Controls | Required selection or values |
| --- | --- |
| auth.password-quality | Minimum length. Character credits disabled and native enforcement enabled. |
| auth.password-history | Number of prior passwords remembered. |
| auth.failed-login-lockout | Attempts, counting interval, timed unlock and existing recovery-exempt group. |
| auth.password-aging | Explicit human accounts, minimum/maximum days and warning interval. |
| auth.inactive-account-lock | Explicit human accounts and days after password expiry. |
| auth.default-umask, auth.shell-idle-timeout | Explicit human Bash accounts and mask or prompt idle seconds. |
| auth.su-access-policy | Existing permitted local group containing the connected administrator. |
| accounts.system-login-disabled | Explicit service accounts with UID between 1 and 999. |
| accounts.home-permissions | Explicit human accounts and nonrecursive 0700 or 0750 home mode. |

PAM quality and history apply across the local system-auth and password-auth
stacks, not to a per-user list. Existing passwords are not rotated. Native root
password-change exceptions remain. Lockout requires root and a recovery group to
remain exempt. Domain profiles, custom PAM stacks, unmodeled configuration and
conflicting password-quality drop-ins are refused.

Account changes refuse root and the connected recovery identity. Home permissions
require ordinary /home/account directories without ACLs. Bash defaults require
stock system and user startup files. TMOUT covers idle prompts, not running
programs, other shells or existing sessions. Umask is an initial default a user
can subsequently change.

Native read-only audit exercised all ten draft inspectors before their execution
gates were disabled. Each recognized the current guest layout. No remediation
was run. These reports are review evidence, not acceptance.

## Pending decision and exit tests

At that checkpoint Q1 remained the owner's identity policy decision required by the approved server
controls plan. Proposed disposable-lab values are 14-character passwords,
5-password history, 5 failures within 15 minutes, unlock after 15 minutes,
root and wheel exempt, maximum password age 90 days, minimum age zero,
14-day warning, 30-day password-expiry inactivity, Bash umask 027, 15-minute
prompt idle timeout, and wheel-only su. Account changes should target newly
created disposable human/service fixtures. Home mode and classifications must
be explicit in the lab profile. These are proposed values, not approved policy
or production defaults.

Before enabling the ten drafts, complete:

- Approved identity profile and isolated fixtures.
- Real allowed/denied password changes, history reuse, login, lockout and unlock.
- Allowed/denied su and expired/inactive human-account behavior.
- Service job continuity and fresh independent administrative SSH/sudo.
- Safe preflight refusals, unchanged exclusions and omitted controls.
- Recovery bound to the final engine, zero-change repeat apply, reboot persistence,
  and repeated snapshot-restored lifecycle.
- Combined prior-control regression, unchanged editor export and packaging.

The first assessment attempt expected exit 1 for noncompliance. The engine correctly
returned 5, the fixture databases were restored, and corrected run assessments-b
passed. The initial shell inspector rejected Rocky's vendor systemd startup symlink.
It now validates that specific link and packaged destination. Subsequent read-only
audit recognized the supported layout.

## References

- [Authselect profiles and domain-managed configuration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- Native Rocky guest manuals: pwquality.conf(5), pwhistory.conf(5), faillock.conf(5).

Validation on 2026-11-05 passed 278 Python tests, 31 editor unit tests, 11 browser tests,
Ruff, Ansible syntax, wheel installation and release scans. Final-engine assessment
acceptance is reports/m10/assessments-c. Engine SHA-256: e6f266c9479709a3f6c1613909ed37a3b9a180979a49da80a1918c9fc188a305.
The earlier assessments-b run predates the final draft execution gates.
No mutating authentication lifecycle, lockout/recovery acceptance, M10 reboot test,
or combined milestone regression has run.
