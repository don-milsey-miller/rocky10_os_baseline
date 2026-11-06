# Remaining server controls implementation plan

Status: Implementation authorized on 2026-11-03. Milestones are delivered sequentially with recorded acceptance evidence. Broad server coverage with workload-dependent controls explicitly optional, selected by the owner on 2026-11-03.

Start with M5 engine prerequisites, then deliver small tested control batches through M12. M13 closes coverage and release validation. Preserve the five existing behaviors and schema compatibility wherever possible. This plan authorizes no target hardening by itself.

## Review findings

| Code | Finding | Evidence and consequence |
| --- | --- | --- |
| F1 | The original specification ends at a five-control release. No larger approved inventory exists. | The new scope below defines the expansion. Completion means covering the agreed inventory, not every possible server security setting. |
| F2 | M1 through M4 provide the necessary catalog, CLI, reports, editor, packaging, and VM recovery foundation. | Reviewed main commit dfe7268bfc54b853ef6357e8925ba490fbcb51b8. Its tree matches v0.4.0rc1 at 8df10a38f01a12de01087c01d7009a2435c22343. Existing milestone evidence is in the demonstration documents and project journal. |
| F3 | Parameters and dependency execution need completion before more complex controls. | [CLI execution](../hardener/cli.py) copies catalog metadata into Ansible variables but omits selected profile parameter values. [Validation](../hardener/validation.py) checks dependency selection, then returns alphabetical order. These limitations do not affect the five fixed, independent controls. |
| F4 | Failure handling and preflight need expansion for access-changing controls. | [Control execution](../hardener/data/ansible/control.yml) rescues a failed control and continues. [Preflight](../hardener/data/ansible/preflight.yml) runs shared prerequisites for every mode. New dependent controls must not run after a prerequisite fails, and remediation-only refusals must not hide inspectable audit results. |
| F5 | Packaging and editor contracts need targeted updates as the catalog grows. | [Wheel smoke test](../tests/integration/package_smoke.py) asserts exactly five catalog entries. The editor supports scalar parameter fields and preserves complex values through YAML import. The profile schema limits selections to 100 entries and YAML input to 64 KiB. The proposed inventory has 97 new IDs, or 102 including the existing five. Before supporting a profile containing all entries, raise the selection limit to a bounded 128 and test the CLI/editor boundary. Retain the 64 KiB limit unless measured serialized profiles exceed it. |
| F6 | Validation coverage is strong for the existing slice, but new behavior still needs guest evidence. | All 64 Python tests passed again in rocky10-dev during this review. Existing recorded M4 evidence includes 26 editor unit tests, six browser tests, and VS1, VS2, VS4, VS5. Browser and VM mutation suites were not rerun for this planning change. |

## Scope decisions

| Code | Decision |
| --- | --- |
| D1 | Cover server security broadly. Workload-dependent settings remain optional and individually selectable. |
| D2 | Keep stable, project-owned domain.name IDs. Preserve the existing five IDs and example profiles unchanged. Write original metadata and implementations. |
| D3 | Develop and test inside Rocky 10 KVM guests. Retain the current KVM-only target guard. The hypervisor is used only for guest lifecycle and recovery. |
| D4 | Maintain an explicit general-server profile and separate optional examples for access, network, identity, logging, and storage policies. Each profile is complete YAML. Do not add profile inheritance or automatic merging. |
| D5 | Inventory entries below are proposed controls, not implemented catalog entries. Before each batch, settle exact expected states, applicability, parameters, evidence, and recovery steps. Publish a control as implemented only after its guest tests pass. |
| D6 | Keep provisioning, repartitioning, secret generation, domain enrollment, application hardening, and production rollout outside the engine. Preserve the existing project-license decision. |

The existing baseline remains files.passwd-permissions, kernel.protected-hardlinks, services.debug-shell-disabled, packages.telnet-client-absent, and packages.local-signature-check.

## Delivery sequence

M means milestone. Implement sequentially in batches of roughly three to six controls. Split large milestones into multiple reviewed commits or pull requests.

| Milestone | Deliverable | Entry dependency | Specific exit evidence |
| --- | --- | --- | --- |
| M5 | Engine prerequisites and frozen first-batch behavior | Reviewed M4 baseline | Parameter propagation and defaults work end to end. Dependencies run in order, cycles fail offline, failed dependencies prevent downstream writes. Existing five-control tests remain green. |
| M6 | Account-file protection and kernel safeguards | M5 | First six controls below pass the complete lifecycle, exclusions, conflict tests, content preservation, and persistence checks. |
| M7 | Package trust, service exposure, time and local logging | M6 | No collateral package removals. Time and log behavior are observed, including retention after reboot and approved configuration precedence. |
| M8 | SSH and privilege escalation | M7 plus access policy | Syntax checks pass. A new independent administrative SSH connection and sudo work after every access change. Unsafe fixtures leave configuration unchanged. |
| M9 | Network settings and guest firewall | M8 plus network policy | Approved connections succeed, disallowed new connections fail, and runtime and rebooted firewall states agree. |
| M10 | Authentication and local account policy | M8 plus identity policy | Test users demonstrate allowed and denied authentication, lockout and recovery. Existing administrative and service access survives. |
| M11 | Mandatory access control, auditing and integrity | M7 plus logging and workload policies | SELinux effective state, generated audit events, log handling, integrity alerts, and recovery are verified. M9 is required for remote collector connectivity. |
| M12 | Filesystems, boot and optional service restrictions | Earlier applicable milestones plus storage policy | Effective mount and boot state survives reboot. Conditional controls preserve required workloads. Manual items have explicit dispositions. |
| M13 | Combined regression and release candidate | M6 through M12 coverage reconciled | Fresh-checkout build, installed wheel, editor round trip, full guest regression, repeat snapshot run, recovery, and publication checks pass on the exact release commit. |

## M5 engine prerequisites

| Action | Change | Required tests |
| --- | --- | --- |
| A1 | Resolve each selected control's explicit parameter values and documented defaults into a separate effective-parameters object passed to Ansible. Never overwrite the parameter schema. Require site-specific values when no safe default exists. | Omitted/default/override values, false and zero, invalid types and bounds, no cross-control leakage, and a parameterized fixture control executed in the disposable guest. |
| A2 | Resolve dependencies with deterministic topological ordering and reject cycles offline. After failed apply or failed verification, mark dependents skipped with a reason and return nonzero. Stop further writes after loss of administrative access. | Reverse lexical dependency order, chains, cycles, missing dependencies, failure propagation, retained partial evidence, and independent-control behavior. |
| A3 | Separate inspection prerequisites from apply-only safety checks. Retain target, transport and privilege guards for all remote modes. Run all apply prerequisites before the first write. | Audit can describe an unsafe-to-remediate state. Apply refuses that same state without changes. Unsupported targets still fail before execution. |
| A4 | Compare installed catalog IDs and packaged assets with the source catalog instead of a hard-coded count. Keep the original five-control profile test intact. Expand the profile selection bound to 128 when promoting this inventory, with 128/129 boundary tests shared by CLI and editor. | Added and omitted packaged entries are detected. Existing profiles retain identical selected controls. |
| A5 | Add only the shared mechanisms demanded by new controls: effective-state parsing, per-control applicability, restart/reboot evidence, and safe configuration validation. | Missing features differ from failed inspections. Pending restart/reboot never passes as effective. Audit/verify leave managed state unchanged. |

Use existing task organization and small Python helpers. Do not build a generic plugin system or rewrite the engine. Add secret-redaction tests when authentication and logging controls introduce new evidence fields. Keep credential material outside profiles, logs, and Git.

## Proposed control inventory

The inventory contains 97 proposed IDs in addition to the existing five. Each ID below identifies one independently selectable behavior once implemented. Related IDs share a row only to keep the inventory readable. Exact values remain subject to the batch behavior review. Baseline candidates still require explicit selection. Conditional controls are excluded from the general-server profile.

### M6 account files and kernel

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| files.group-permissions | Protect group-file ownership and mode while preserving bytes, ACL policy, and account entries. | Baseline candidate |
| files.shadow-permissions | Restrict password-database metadata using Rocky-supported access requirements. Never include file content in reports. | Baseline candidate |
| files.gshadow-permissions | Restrict group-password database metadata without exposing secrets. | Baseline candidate |
| kernel.protected-symlinks | Enforce the supported symlink protection setting in running and persistent state. | Baseline candidate |
| kernel.randomize-address-space | Enforce full supported address-space randomization. | Baseline candidate |
| kernel.suid-dumpable | Disable ordinary privileged-process dumps using the supported kernel value. | Baseline candidate |
| files.account-backup-permissions | Protect existing account-database backups without inventing missing files. | Baseline candidate |
| kernel.protected-fifos, kernel.protected-regular | Apply separately selectable restrictions on unsafe file creation in shared directories. | Conditional on application compatibility |
| kernel.dmesg-restrict, kernel.kptr-restrict | Restrict kernel log and address exposure. | Conditional on monitoring and diagnostic needs |
| kernel.ptrace-scope, kernel.unprivileged-bpf-disabled | Restrict tracing and unprivileged BPF where the running kernel supports the policy. | Conditional on application and observability needs |

The first implementation batch is the first six IDs in this table. Resolve exact file ownership/modes from the supported Rocky guest and package behavior before changing them. Reuse the current single-link regular-file checks and sysctl precedence handling.

### M7 packages services time and logging

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| packages.repository-signature-check | Require package signature verification for enabled, approved repositories. Inspect per-repository overrides. | Baseline candidate |
| packages.repository-tls-verification | Require certificate verification for approved HTTPS repositories. Preserve operator trust configuration. | Conditional on repository policy |
| packages.repository-metadata-signature | Require signed repository metadata only where the approved repository publishes it. | Conditional |
| packages.security-update-status | Identify outstanding security updates and record operator maintenance disposition. | Assessment initially |
| services.avahi-disabled, services.cups-disabled | Disable discovery and printing services only when the server has no requirement for them. | Conditional |
| time.chrony-enabled, time.approved-sources | Maintain time synchronization and restrict configured sources to the operator's approved set. | Baseline candidates with supplied sources |
| logging.journal-persistent, logging.journal-retention | Retain local logs across boots with explicit disk and retention budgets. | Baseline candidates |
| logging.logfile-permissions, logging.rotation-policy | Protect applicable log files and rotate file-based logs without interfering with service-owned access. | Conditional on installed logging stack |

Do not invent time servers, repository keys, log budgets, or automatic update windows. An unreachable time source is not a verified synchronization result.

### M8 SSH and privilege escalation

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| auth.ssh-config-permissions, auth.ssh-hostkey-permissions | Protect daemon configuration and host keys, preserving required service ownership and labels. | Baseline candidates |
| auth.ssh-empty-passwords, auth.ssh-hostbased-auth | Reject empty-password and host-based authentication. | Baseline candidates |
| auth.ssh-root-login | Require named administrative access in place of direct root login. | Conditional on verified alternate access |
| auth.ssh-password-login | Restrict password authentication when the chosen key or MFA path works. | Conditional |
| auth.ssh-access-policy | Restrict admitted users or groups using supplied policy. | Conditional |
| auth.ssh-forwarding-policy | Limit tunnel and forwarding features required by the workload. | Conditional |
| auth.ssh-session-limits | Apply supplied authentication, connection, and idle-session limits. | Conditional |
| auth.sudo-config-permissions, auth.sudo-use-pty | Protect sudo policy and use a pseudo-terminal where supported. | Baseline candidates |
| auth.sudo-authentication, auth.sudo-timeout | Enforce approved authentication requirements and cached-credential limits. | Conditional on automation and recovery access |

Implement configuration syntax validation before replacement, preserve unrelated directives, and check applicable Include and Match behavior. OpenSSH supports effective configuration tests with connection-specific Match evaluation through sshd -T -C. Configuration checks do not replace a new login test. [OpenSSH daemon documentation](https://man.openbsd.org/sshd)

Keep a tested console path and snapshot. Prove a new connection with SSH connection multiplexing disabled. Do not remove the lab's only privilege-escalation path.

### M9 network and firewall

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| network.ipv4-source-route-disabled, network.ipv6-source-route-disabled | Reject source-routed traffic for each supported address family. | Baseline candidates |
| network.ipv4-redirects-disabled, network.ipv6-redirects-disabled | Restrict redirect acceptance using the chosen server network role. | Conditional |
| network.ipv4-send-redirects-disabled | Disable redirect transmission where the guest is not a router. | Conditional |
| network.tcp-syncookies | Enable supported TCP SYN flood mitigation. | Baseline candidate |
| network.reverse-path-filter | Apply routing-compatible source validation. | Conditional on asymmetric routing and multi-homing |
| network.ip-forwarding-disabled | Disable forwarding only for non-routing, non-container-networking guests. | Conditional |
| firewall.firewalld-enabled | Establish firewalld as the approved guest firewall owner. | Conditional on existing firewall ownership |
| firewall.management-access, firewall.inbound-policy | Preserve explicit administrative sources and enforce supplied inbound service/port rules. | Conditional, high impact |

Inventory IPv4, IPv6, zones, interfaces, sources, container rules, runtime-only rules, and existing native nftables management before writing. Do not disable IPv6 globally or run competing firewall managers. Require an approved management path and workload port list.

A firewalld reload replaces runtime configuration with permanent configuration and can discard runtime-only rules. Check both states and refuse unexplained drift before applying changes. [firewalld reload behavior](https://firewalld.org/documentation/howto/reload-firewalld.html)

Stage management allowance before restrictions, verify from a new connection, and test blocked traffic from a separate disposable guest. Use narrowly scoped recovery for a failed change rather than introducing general OS transaction machinery.

### M10 authentication and account policy

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| auth.password-quality, auth.password-history | Apply approved local password rules through the supported authentication stack. | Conditional |
| auth.failed-login-lockout | Apply approved attempt thresholds, unlock behavior, and recovery exclusions. | Conditional, high impact |
| auth.password-aging, auth.inactive-account-lock | Enforce the supplied lifecycle policy only for identified human accounts. | Conditional |
| auth.default-umask, auth.shell-idle-timeout | Apply defaults to the intended interactive login paths. | Conditional on application compatibility |
| auth.su-access-policy | Restrict account switching according to approved administrative groups. | Conditional |
| accounts.system-login-disabled | Prevent interactive login for explicitly identified service accounts without breaking jobs. | Conditional |
| accounts.home-permissions | Protect approved local users' home directories without recursive ownership changes. | Conditional |
| accounts.unique-identities, accounts.root-only-uid-zero, accounts.no-empty-passwords | Identify account conflicts and unsafe authentication records without automatically deleting or renumbering accounts. | Assessment initially |
| accounts.root-path-integrity | Check privileged command-search paths for unsafe directories and ownership. | Assessment initially |

Detect and validate authselect state before editing. Preserve domain-managed authentication and refuse unknown custom PAM layouts. RHEL 10 documents local, sssd, and winbind profiles and advises against changing profiles established by domain enrollment. Treat this as implementation guidance and verify actual behavior on Rocky guests. [Authentication configuration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)

Do not force password rotation intervals, lock privileged identities, alter service-account shells, or impose domain policy without the relevant operator decision. Test isolated users, successful login, rejection, unlock, and administrator recovery.

### M11 SELinux audit and integrity

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| selinux.enforcing, selinux.targeted-policy | Require the chosen supported mandatory-access-control state in both runtime and boot configuration. | Baseline candidates with workload validation |
| selinux.no-unconfined-services | Detect services outside the intended confinement policy. | Assessment initially |
| audit.service-enabled, audit.early-boot | Enable auditing and required early-boot coverage. | Baseline candidates |
| audit.storage-policy | Apply supplied retention, space thresholds, and failure actions. | Conditional, high impact |
| audit.identity-changes, audit.privilege-use, audit.security-config-changes, audit.session-events | Install separate original rule groups and prove events are recorded. | Baseline candidates with volume testing |
| audit.immutable-rules | Lock rule changes only after all selected rules are loaded and verified. | Conditional, last audit action, reboot recovery |
| integrity.aide-scheduled | Initialize an operator-approved integrity baseline and schedule checks. Never refresh a trusted baseline silently. | Conditional |
| logging.remote-tls | Forward logs to a supplied authenticated collector and verify receipt. | Conditional |

Do not force a disabled SELinux installation directly into enforcing without a tested relabel and reboot procedure. Check loaded audit rules and real events, not just files. Test audit storage failure without filling the development guest. Keep sensitive event payloads out of public evidence.

Audit services, persistent rules, remote TLS logging, and journald are documented in [RHEL 10 risk reduction and recovery operations](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/risk_reduction_and_recovery_operations/index). Validate Rocky package and command differences during implementation.

### M12 storage boot and remaining conditional controls

| Proposed IDs | Intended outcome | Selection |
| --- | --- | --- |
| filesystem.tmp-restrictions, filesystem.var-tmp-restrictions, filesystem.dev-shm-restrictions | Enforce selected mount flags only on supported existing mounts after compatibility checks. | Conditional, high impact |
| filesystem.home-restrictions | Restrict existing home mounts according to workload policy. | Conditional |
| filesystem.shared-directory-sticky | Protect explicitly approved shared writable directories. No blanket recursive changes. | Conditional |
| filesystem.world-writable-review, filesystem.unowned-files-review, filesystem.privileged-files-review | Review unsafe metadata and unexpected privileged files within bounded local filesystems. | Assessment initially |
| kernel.unused-filesystem-modules, kernel.unused-network-protocols | Disable explicitly approved unused modules without unloading active dependencies. | Conditional |
| services.legacy-listeners-disabled | Disable explicitly named obsolete listeners and socket activation units after checking workload dependencies. | Conditional |
| services.cron-access, services.at-access | Restrict scheduler access while preserving required jobs. | Conditional |
| boot.config-permissions, boot.loader-authentication, boot.rescue-authentication | Protect boot configuration and require approved access controls on tested firmware layouts. | Conditional, high impact |
| crypto.system-policy | Apply an operator-selected supported cryptographic policy and verify affected services after required restarts. | Conditional |
| login.authorized-use-banner | Install operator-supplied notice text without exposing system details. | Conditional |
| storage.partition-layout, storage.disk-encryption, boot.secure-boot | Assess requested layout and boot protection. Remediation remains in provisioning or an explicit migration procedure. | Manual/provisioning |

The current tested lab uses BIOS. Add a disposable UEFI fixture before claiming UEFI boot-control support. Boot passwords, encryption keys, private certificates, and similar secrets belong in trusted external facilities, never exported profile YAML.

Use system-wide crypto policy guidance as a starting point, then test actual application compatibility on Rocky. Do not silently choose a stricter policy or claim cryptographic certification. [RHEL 10 cryptographic policy documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/using-system-wide-cryptographic-policies)

## Assessment and applicability contract

| Action | Rule |
| --- | --- |
| A6 | Keep assessment/manual entries in the coverage inventory until a narrow audit-only capability is implemented and tested. The current engine requires audit, apply, and verify for implemented controls. Do not publish fake no-op remediations as success. |
| A7 | When adding audit-only execution, expose supported modes consistently in catalog, validator, CLI, reports, and editor. Reject apply selections containing assessment-only controls before any writes. Preserve old schema/profile behavior or version the contract explicitly. |
| A8 | Report not_applicable only when observed target facts establish that a control does not apply. A missing required package, denied inspection, failed prerequisite, deferred implementation, or owner exclusion is not not_applicable. |
| A9 | Record each inventory item's status as planned, implemented, assessment, manual/provisioning, or excluded with a reason. Reconcile against this inventory at every milestone. No silent omissions. |

## Acceptance gate for every control batch

| Gate | Required evidence |
| --- | --- |
| A10 | Original metadata, stable ID, supported platform, expected state, bounded parameters, dependencies/conflicts, operational impact, exact recovery steps, and authoritative behavior references. |
| A11 | Unit/schema tests for parsers, defaults and overrides, invalid inputs, precedence, applicability, dependency behavior, report redaction, and failure paths. Validate Ansible syntax and read-only behavior. |
| A12 | Disposable guest test: deliberately noncompliant state, audit failure, selected apply, independent verify, zero-change second apply, explicit exclusion, omission, and preservation of unrelated content/configuration. |
| A13 | Unsafe preflight fixtures block all selected writes. Partial failures return nonzero and retain evidence. Dependency failures cannot lead to downstream changes. Access controls additionally require fresh SSH/sudo and console recovery tests. |
| A14 | Persistent settings pass after reboot. Restart/reboot-pending state remains fail with an actionable reason until effective-state verification succeeds. Restore a baseline and repeat the integration scenario. |
| A15 | Rebuild the editor from the same catalog. Import/export preserves parameters and exclusions. Run the exported YAML unchanged through the CLI. Add bounded list editing only where real approved parameters require it. |
| A16 | Build/install the wheel independently, confirm all new metadata/tasks are packaged, run CI and original regression suites, review publication assets, and record exact commit, commands, versions, digests, and evidence paths. Keep inventories and runtime reports outside Git. |

Use existing VS1, VS2, VS4, and VS5 as regression tests. Add focused integration suites per control family rather than extending one unmanageable script. Increase the fixed execution timeout only when measured workloads require it, with bounded timeout/failure tests.

## Decisions needed before affected batches

These decisions do not block M5 or preparation of the first M6 batch.

| Code | Owner input | Needed before |
| --- | --- | --- |
| Q2 | Administrative users/groups, key or MFA method, allowed SSH sources, sudo automation needs, and tested recovery identity. | M8 |
| Q3 | Server workload roles, exposed services, routing/container needs, IPv6 requirements, and firewall ownership. | M9 |
| Q4 | Resolved for M10 disposable testing on 2026-11-05: local-only fixtures and the explicit [approved policy](m10-demonstration.md#approved-disposable-policy). Production identity values still require owner selection. | M10 |
| Q5 | Resolved for disposable testing: M7 time/logging values and the owner-approved M11 SELinux, audit storage, immutable rules, AIDE scope and TLS collector policy on 2026-11-05. See the [M11 policy](m11-demonstration.md#approved-disposable-policy). Production values still require owner selection. | Relevant M7 and M11 controls |
| Q6 | Approved for the disposable lab: dedicated restricted temporary mounts, executable restricted home, explicit unused modules/listeners, preserved scheduler jobs, authenticated BIOS/rescue access, DEFAULT crypto and the approved notice. Production values remain explicit. | M12 complete |

## Completion and handoff

M13 is complete when every agreed inventory entry has implemented guest evidence or an explicit assessment/manual/exclusion disposition, and all supported profile combinations exercised by the release test matrix pass. Conditional controls require their own representative fixtures. Untested identity providers, firmware layouts, architectures, or workload combinations remain documented support limits.

For each milestone, publish the reviewed source and concise demonstration record to GitHub, save private evidence separately, and append the project journal. Maintain a branch per implementation batch and preserve the tested release candidate as the regression reference.

M5 through M11 are implemented and validated, including all thirteen SELinux, audit, integrity and TLS logging controls. See [control coverage](control-coverage.md) for all 102 agreed IDs. The owner approved explicit disposable-lab policies for validation, with production-specific values remaining required in profiles.

M8 acceptance completed on 2026-11-05 using local Rocky Linux 10.2 KVM guests hosted by WSL 2. M9 first-batch acceptance is recorded in the [M9 validation record](m9-demonstration.md#validation-record). The [M9 host-policy record](m9-routing-demonstration.md#validation-record) covers the five additional network controls. The [M9 firewall record](m9-firewall-demonstration.md#validation-record) completes the three remaining M9 controls with repeated dual-stack traffic, reboot and recovery acceptance. M10 is complete under the owner-approved disposable local identity policy. Its [acceptance record](m10-demonstration.md#validation-record) covers ten remediation controls, four assessments, repeated snapshot lifecycles, native authentication and actual 900-second timers. The root PATH assessment retains one finding without automatic repair. M11 is complete under the approved disposable security policy. Its [acceptance record](m11-demonstration.md#validation-record) covers twelve remediations, one assessment, repeated snapshot lifecycles, real audit events, bounded storage failure, rotation, integrity alerts and authenticated collector receipt. Combined verification passes 79 controls and retains the existing root PATH and deliberate unconfined-service findings. All 75 remediable controls repeat with zero changes. M12 is complete under approved Q6. Its [acceptance record](m12-demonstration.md#validation-record) covers fifteen remediations and six assessments, two restored-snapshot lifecycles, native boot and rescue authentication, scheduler and TLS workloads, unsafe-preflight refusals, and partial-failure reporting. Combined verification passes 98 controls with four documented findings. All 90 remediations repeat with zero changes. The M13 release matrix and tagged-candidate acceptance are documented in [the release record](m13-release-readiness.md). The owner approved an SSH-only disposable lab with firewalld ownership, development-guest-only administrative sources, both IP families enabled, and no routing or container workload. Production profiles still require explicit site values.

High-impact changes require recent target-bound evidence from
an observed out-of-band recovery rehearsal and reports bounded actionable preflight
refusals. See [recovery enforcement and acceptance](recovery-enforcement.md).
