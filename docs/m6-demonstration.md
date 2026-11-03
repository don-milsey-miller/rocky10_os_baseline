# M6 account files and kernel safeguards

Version 0.6.0rc1 adds 13 server controls. Existing control IDs and profiles remain valid.

## Control behavior

| ID | Required state |
| --- | --- |
| files.group-permissions | /etc/group root:root 0644 |
| files.shadow-permissions | /etc/shadow root:root 0000 |
| files.gshadow-permissions | /etc/gshadow root:root 0000 |
| files.account-backup-permissions | Existing passwd-/group- backups root:root 0644, shadow-/gshadow- root:root 0000 |
| kernel.protected-symlinks | fs.protected_symlinks=1 |
| kernel.randomize-address-space | kernel.randomize_va_space=2 |
| kernel.suid-dumpable | fs.suid_dumpable=0 |
| kernel.protected-fifos | fs.protected_fifos=2 |
| kernel.protected-regular | fs.protected_regular=2 |
| kernel.dmesg-restrict | kernel.dmesg_restrict=1 |
| kernel.kptr-restrict | kernel.kptr_restrict=2 |
| kernel.ptrace-scope | kernel.yama.ptrace_scope=1 |
| kernel.unprivileged-bpf-disabled | kernel.unprivileged_bpf_disabled=2 |

File controls preserve bytes and refuse symlinks, multiple hard links, and custom
access ACLs before remediation. Audits use Ansible metadata. Verification uses
GNU stat or Python lstat, without reading password content into evidence.
Absent standard backups are not created and produce not_applicable when none exist.

Kernel controls update only their selected key in
/etc/sysctl.d/99-rocky10-hardener.conf and activate that key individually.
Verification reads procfs and independently reevaluates systemd's ordered
configuration. A later conflicting explicit assignment refuses the whole apply
before any changes. No sysctl --system operation is used.

The reversible BPF policy refuses an existing irreversible value of 1. Resolve
that state through an explicit recovery/reboot procedure rather than attempting
an ineffective runtime downgrade. Diagnostic restrictions and shared-directory
creation restrictions remain optional because applications can depend on them.

The catalog now permits an optional implementation.preflight reference.
The engine validates its packaged path and runs all selected additional
prerequisites before any remediation. Original controls retain their existing
preflight behavior.

## Profiles

[server-general.yaml](../profiles/examples/server-general.yaml) contains the
original five controls and the seven new baseline candidates.
[server-files-kernel.yaml](../profiles/examples/server-files-kernel.yaml) explicitly
selects all 13 M6 controls for disposable validation. Its conditional kernel
settings require workload review before use on another server.

## Testing and evidence

On 2026-11-03, the first complete guest suite verified all 13 controls after
deliberate faults, independent verification, zero-change reruns, every exclusion,
an omitted control, untouched identity-file content and unrelated state, conflict
refusal, absent backups, unsafe backup symlink refusal, and reboot persistence.

The automated checks pass 87 Python tests, 30 editor unit tests, six browser tests,
Ruff, Ansible syntax, and isolated wheel installation. Browser fixtures now refer
to stable control IDs and catalog counts instead of assuming exactly five entries.

Private reports are under reports/m6/run1/ on the development guest.
The repeat suite starts from m4-rc1-verified and adds custom ACL preservation.
Its reports are under reports/m6/from-snapshot/. The project journal records its
final result, the published commit, CI URL, and transferred evidence checksum.

## Reproduce

Use a disposable guest with snapshots, console recovery, and the existing
SSH/sudo inventory. Install the acl package inside the test guest for the
ACL fixture. It is a test dependency, not a runtime engine dependency.

```bash
# Inside the disposable test guest:
sudo dnf install -y acl

# Development guest, repository root, virtual environment active:
pytest -q
ruff check hardener tests web/prepare.py
ruff format --check hardener tests web/prepare.py
python tests/integration/m6.py --inventory inventory.local.ini --target test-vm --output reports/m6-new --disposable
```

The test temporarily changes file modes and kernel values, isolates backup files,
and reboots the guest. It leaves the selected controls hardened on success.
On a caught failure it attempts to restore original modes, persistent sysctl text,
and runtime values. The guest snapshot remains the complete recovery method.

## Restoration and behavior references

Restore the recorded file metadata or prior sysctl entries and runtime values.
Preserve unrelated keys. Restore backup names if a test was interrupted during
the absent-backup fixture. After restoration, independently audit and verify.

The file modes were checked against the Rocky guest's installed identity files.
The kernel settings follow the documented meanings of
[filesystem sysctls](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
and [kernel sysctls](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html).
Only tested Rocky 10 KVM guests are supported.
