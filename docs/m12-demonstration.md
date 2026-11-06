# M12 storage, boot and optional policies

The owner approved Q6 for disposable Rocky Linux 10.2 KVM guests. The scope is
15 explicit remediations and six read-only assessments. Production policy values
remain operator decisions. UEFI remains unsupported by the accepted BIOS slice.

## Supported behavior

| Controls | Behavior and limits |
| --- | --- |
| Temporary and home mounts | Require existing whole XFS/ext4/tmpfs mounts, a unique fstab entry, matching live and persistent sources, and native mount management. Preserve unrelated options, fields, comments and data. Whole root-owned loop-image fixtures are supported. No partitioning, migration, bind mounts or custom mount units. |
| Shared directories | Add the sticky bit only to explicit root-owned writable directories. No recursive edits. |
| Unused filesystem and network modules | Require explicit installed, unloaded modules absent from every initramfs. Deny future loading and add dracut omissions. Never unload a live driver or rebuild a boot image. Competing startup policy is refused. |
| Obsolete listeners | Require explicit service/socket activation and alias selection, no unknown overrides, and no active unselected dependent service. Essential access, networking, security and scheduler services are protected. Stop, disable and mask only selected units. |
| Cron and at | Require explicit existing local users including root. Preserve current jobs and deny a policy that excludes an existing job owner. Validate native scheduler PAM configuration. |
| Boot file permissions | Protect BIOS grub.cfg, grubenv, BLS entries and an existing user.cfg with root ownership and mode 0600. Preserve their bytes. |
| Boot editing | Require an intact vendor GRUB authentication hook and an external root-only PBKDF2 credential file. Refuse supplemental custom.cfg commands. Protect editing and the GRUB command line while permitting normal boot. |
| Rescue and emergency | Require native sulogin entry points, no bypass parameters or unknown overrides, and an external root-only SHA-512 credential file. Set the approved root credential and explicitly disable forced sulogin bypass. |
| Crypto policy | Support explicit DEFAULT or FUTURE with no custom policy or local overrides. FIPS transitions are outside this scope. Changed policy remains a finding until reboot. Validate real SSH and TLS compatibility in the fixture. |
| Console notice | Install bounded operator-provided ASCII in /etc/issue. Remove only the known native Cockpit supplemental URL symlink. Refuse unknown supplemental notices. SSH banners are a separate policy. |

The module inspector hashes every complete boot image before reusing an inspection
within an Ansible run. A changed image or requested module set invalidates that
proof. It has no persistent cache. Concurrent image replacement fails closed.

Credentials stay outside Git, profile YAML and reports. The example profile contains
only target-local credential paths. Native failures report bounded diagnostics and
retain whether a partial write occurred. Preflight runs before any selected mutation.

The six assessments retain the scope and native fixture evidence in the historical
[M12 assessment checkpoint](m12-review.md). Partition layout is evaluated against
explicit requested mounts. Encryption requires dm-crypt ancestry, without claiming
key-management or algorithm acceptance. BIOS produces a Secure Boot provisioning
finding. No encryption migration or firmware changes occur.

## Reproduction

Run inside the development guest with an explicit disposable inventory. The fixture
preparation script creates dedicated image-backed mounts, preserves prior home and
temporary data, configures two named scheduler users, and prepares unused modules
outside the engine. Keep the accepted M11 snapshot and prepare an M12 snapshot
before testing writes.

~~~bash
. .venv/bin/activate
python tests/integration/m12_prepare.py --inventory inventory.local.m9.ini --target test-vm --output reports/m12-live/prepare-new --disposable
hardener recovery-test --inventory inventory.local.m9.ini --target test-vm --output reports/m12-live/recovery-new
python tests/integration/m12_lifecycle.py --inventory inventory.local.m9.ini --target test-vm --output reports/m12-live/lifecycle-new --recovery-evidence reports/m12-live/recovery-new/recovery.json --disposable
python tests/integration/m12_guards.py --inventory inventory.local.m9.ini --target test-vm --output reports/m12-live/guards-new --recovery-evidence reports/m12-live/recovery-new/recovery.json --disposable
~~~

Recovery requires observing a real SSH outage and restoring the named prepared
snapshot. Use the exact receipt filename emitted by the command. Restore the
prepared snapshot and repeat the lifecycle independently. The console script runs
on the disposable hypervisor and uses its serial socket, keeping credentials only
in memory. It tests incorrect and correct GRUB, rescue and emergency authentication.

The lifecycle checks audit preservation, exclusion and omission, reboot-pending
state, independent verification, zero-change repeats, mount behavior, module and
listener denial, actual cron/at execution, service continuity, TLS 1.2 and collector
receipt, and TLS 1.1 rejection.

## Recovery and support boundaries

Use snapshot restoration for this disposable fixture. Do not delete shared data or
repartition a target to recover a failed apply. Stop target activity, restore the
prepared or accepted stopped-disk snapshot through the independent hypervisor, and
prove fresh SSH plus sudo before resuming. Reapply only with a recovery receipt
bound to the current runtime. Production recovery must preserve an external root
and GRUB credential, boot access, fstab backup, scheduler lists, service activation
state, crypto policy and any managed configuration before selecting these controls.

The accepted workload uses DEFAULT, BIOS, local users, ext4 loop-image mounts,
native /dev/shm, udf, sctp, and the named disposable listener. FUTURE is an explicit
built-in policy option, but its workload compatibility is not established by the
DEFAULT fixture. UEFI, custom boot hooks, bind/remote filesystems, FIPS transitions,
remote scheduler identities, active-driver removal and storage migration remain
outside demonstrated support.

Native behavior references are available on the target through mount(8),
findmnt(8), modprobe.d(5), dracut.conf(5), systemctl(1), crontab(1), at(1),
sulogin(8), update-crypto-policies(8), issue(5), and agetty(8).
The existing [server plan](server-controls-plan.md) links the vendor boot and
cryptographic policy guidance.

## Validation record

M12 acceptance passed. Runtime version: 0.12.0rc1. Runtime SHA-256:
d4f73be6aecca314abb1347586c3f0e43e1f2b57291e94f6027477ee3a69eb4f.

| Check | Result | Private evidence under reports/m12-live |
| --- | --- | --- |
| Python, style and Ansible syntax | 446 tests, Ruff and both syntax checks passed | checks/python-runtime-final.log, checks/style-runtime-final.log, checks/syntax-runtime-final.log |
| Editor | 31 unit and 15 browser tests passed | checks/editor-final-remediation.log |
| Isolated wheel and release assets | Passed with the exact runtime digest | checks/wheel-runtime-final.log, checks/release-runtime-final.log |
| Independent recovery | Real outage observed, prepared snapshot restored, authenticated receipt passed | recovery-runtime-final/recovery.json |
| Two restored-snapshot lifecycles | Each starts with 15 findings, applies only selected controls, holds crypto pending until reboot, then verifies 15 passes and zero-change repeats | lifecycle-runtime-a, lifecycle-runtime-b |
| Native workloads | noexec, nosuid, nodev, sticky ownership, actual module/listener denial, executed cron/at jobs, retained service, TLS 1.2 and collector receipt, TLS 1.1 refusal | Both lifecycle integration-evidence.json files |
| Unsafe preflight and partial failure | Fifteen cases block all selected writes. A native remount failure retains a nonzero result and changed state. Matching banner text still removes the known native supplement. | guards-runtime-final |
| BIOS console | Wrong credentials rejected, approved credentials allow GRUB editing and rescue/emergency shells. Normal boot, notice and fresh SSH recovered. | console-runtime-final.json |
| Combined catalog | 98 passes, four findings, zero changes. All 90 remediations repeat with zero changes and twelve explicit assessment exclusions. | combined-accepted |
| Unchanged browser profile | Fifteen passes, zero changes in apply and verify | combined-accepted/browser-apply, browser-verify |
| Original regression suites | VS1, VS2, VS4 and VS5 passed on the separate probe guest | regression-runtime-final/summary.json |

The four findings are accounts.root-path-integrity, selinux.no-unconfined-services,
storage.disk-encryption and boot.secure-boot. The first two retain M11 dispositions.
The root disk remains unencrypted and the fixture remains BIOS by approved Q6.
Separate /boot, /tmp, /var/tmp and /home filesystems now pass the layout assessment.
No production migration, UEFI support or encryption-key acceptance is claimed.

The exact published commit, GitHub workflow result, private evidence archive digest
and accepted snapshots are recorded in the project journal. Reports include the
runtime digest above. Assessment helpers retain their separately recorded native
fault and LUKS fixture evidence from the earlier checkpoint. M13 release acceptance
remains separate.
