# RHEL 10 and Rocky Linux 10 native EC2 validation

Date: 2026-11-06. **RHEL profile creation and bounded native EC2 execution are validated.
This is not full acceptance of all 102 catalog controls or configurations.**

Input: [the document comparison](rhel10-rocky10-comparison.md) at commit `950632c`.
That comparison described the earlier Rocky-only engine. This implementation adds
explicit RHEL selection without changing the intended shared hardening values.

## Validation findings

The prefix **V** identifies validation findings in this report.

1. **V1: Profiles bind to the requested distribution.** The editor creates either
   Rocky Linux 10 or RHEL 10 server profiles. Import/export preserves the selection,
   controls and parameters. Existing Rocky profiles remain valid. Native tests on
   both guests reject the opposite profile before any control changes. Reports
   identify `rhel-10-server` or `rocky-10-server` only after successful preflight.
2. **V2: AWS RHEL repository access needs vendor integration.** Its RHUI advisory
   audit failed because the original inspection skipped the vendor plugin needed
   for region resolution and identity headers. Issue #9
   records the defect. The fix permits only the installed `amazon-id` plugin when
   selected repository hosts identify AWS RHUI. Other DNF plugins remain excluded.
   TLS and package-signature settings are preserved. The audit performs no package
   transaction and keeps raw repository/identity material out of reports.
3. **V3: Defaults differ by image, despite shared policy.** Vendor repositories,
   signing keys, package builds, cloud users and supported local sudo layouts
   differ. The tested images also have different publication dates. These results
   must not be interpreted as permanent distribution defaults or a security ranking.
4. **V4: Eight controls passed apply, repeatability and reboot verification on both
   guests.** High-impact SSH apply was separately refused without a recovery receipt.
   Full recovery/restore and high-impact remediation were not exercised.

## Native test environment

Both instances ran their operating system directly on AWS. No Ubuntu controller
or nested guest was used. Each guest ran the CLI and targeted itself over SSH with
a separate temporary key and pinned local SSH host key. This validates real Ansible
SSH execution and privilege escalation, but does not test a separate controller's
network path. The workstation used SSH to operate the guests.

| Item | RHEL | Rocky |
| --- | --- | --- |
| Region and instance type | us-east-1, t2.micro | us-east-1, t2.micro |
| AMI | ami-01126d0bab29817a7 | ami-02cfb13d4cf8b7b77 |
| Image name | RHEL-10.2.0_HVM-20261020-x86_64-0-Hourly2-GP3 | Rocky-10-EC2-Base-10.2-20260525.0.x86_64 |
| Publisher account | 309956199498 | 792107900819 |
| Observed release | RHEL 10.2 | Rocky Linux 10.2 |
| Kernel | 6.12.0-211.67.1.el10_2.x86_64 | 6.12.0-211.26.1.el10_2.x86_64 |
| Virtualization / boot | Xen guest / legacy BIOS | Xen guest / legacy BIOS |
| Server boot target | multi-user.target | multi-user.target |
| SELinux / crypto policy | Enforcing / DEFAULT | Enforcing / DEFAULT |
| Test resources | 1 GiB RAM, 2 GiB temporary swap, encrypted disposable gp3 root disk | Same |

Development, test and browser dependencies were installed. No general OS update
transaction was run. These are prepared test guests, not pristine AMI measurements.
Red Hat documents its [official publisher account](https://access.redhat.com/solutions/99333)
and [AWS RHUI delivery](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/deploying_and_managing_rhel_on_amazon_web_services/index).

Preflight now admits KVM guests and EC2 Xen guests with an EC2-prefixed hypervisor
UUID. It still requires major version 10, server role, SSH, privilege escalation,
DNF and multi-user.target. UUID detection is a platform heuristic, not cryptographic
attestation. See [AWS instance identification](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html).
Bare metal, containers, other Xen identities and mismatched distributions are refused.

## Observed differences and shared behavior

| Check | RHEL result | Rocky result | Profile implication |
| --- | --- | --- | --- |
| Enabled repositories | rhel-10-baseos-rhui-rpms, rhel-10-appstream-rhui-rpms, rhui-client-config-server-10 | baseos, appstream, extras | Select actual site-approved IDs. RHEL on AWS uses RHUI, not necessarily CDN registration. |
| Distribution key file | RPM-GPG-KEY-redhat-release | Rocky key files supplied by rocky-gpg-keys | Do not copy vendor key examples between distributions. Key-file presence alone does not verify trust or fingerprint approval. |
| Package signatures and TLS | Both selected content repos enforce gpgcheck and sslverify, with HTTPS endpoints | Same for BaseOS and AppStream | Shared controls work with explicit vendor IDs. |
| Repository metadata signatures | repo_gpgcheck disabled in both selected repos | Same | Assessment fails the selected policy. This run did not force unsupported vendor metadata signatures. |
| Security-update assessment after fix | 21 pending package candidates | 63 pending package candidates | Snapshot of selected repos and installed packages. Neither assessment installed updates. Counts are not vulnerability totals. |
| Firewall packages | nftables installed, firewalld absent | nftables and firewalld absent | Provision the documented tools before selecting firewall controls. |
| Four sudo controls | fail | unsupported | The bounded parser admits the tested RHEL layout and rejects the Rocky layout. No sudo changes were made. |
| IPv4 redirect acceptance | all/default accept_redirects = 1 | Same | Both fail the intended reject-redirect policy. This is the correct setting to inspect. |
| Core-dump configuration | No active Storage assignment, ProcessSizeMax and ExternalSizeMax each 1G | Same | Configuration inspection only. No deliberate process crash was generated. |
| PAM remember argument | No match in system-auth/password-auth | Same | This targeted check is not full PAM acceptance. |
| Mail listener | No TCP port 25 listener | Same | A live mail-agent configuration was not tested. |
| Audit-log owner/group/mode | root:root, 0600 | Same | Native stat confirms the ownership/group policy for the existing audit log. |

The source comparison's wrapped commands were not executed. Native commands and
the project's independently implemented inspections were used instead. Matching
results do not validate every script or recommendation in the source documents.

## Test results and limits

| Test | Result |
| --- | --- |
| Python unit suite on native RHEL | 496 passed |
| Editor unit suite on native RHEL | 49 passed |
| Headless Chromium tests on native RHEL | 17 passed, including RHEL export/import |
| Lint and formatting | Passed |
| Ansible run and recovery syntax | Passed |
| Wheel build, isolated installed-wheel smoke, release asset checks | Passed |
| Wrong-distribution preflight | Refused on both guests, zero changes |
| Eight-control repeat apply | 8 pass on each guest, zero changed tasks |
| Eight-control verification after reboot | 8 pass on each guest, zero changed tasks |
| High-impact apply without authenticated recovery evidence | Refused on both guests, zero changes |
| Actual snapshot restore, RHEL KVM, Nitro, ARM, FIPS, UEFI/Secure Boot | Not tested |

The eight applied controls were:

- `files.passwd-permissions`
- `kernel.protected-hardlinks`
- `services.debug-shell-disabled`
- `packages.telnet-client-absent`
- `packages.local-signature-check`
- `network.ipv4-source-route-disabled`
- `network.ipv6-source-route-disabled`
- `network.tcp-syncookies`

The initial five-control apply changed three tasks on each guest. The three network
controls changed four additional tasks. The final combined repeat apply changed none.

The broader survey attempted all 102 catalog controls using the combined lab profile,
split by category with dependency closure. User selections and time sources were
adapted, and repository checks were rerun with actual vendor repository IDs after
the RHUI fix. Other lab-specific paths, collector endpoints and mount prerequisites
were retained, so survey failures are not a production compliance score.

| Survey status | RHEL | Rocky |
| --- | ---: | ---: |
| pass | 29 | 29 |
| fail | 46 | 42 |
| unsupported | 22 | 26 |
| error | 3 | 3 |
| not_applicable | 2 | 2 |
| Total unique control IDs | 102 | 102 |

The three errors on each guest are explicit missing-firewall-tool guards. Unsupported
results include bounded account/identity layouts, mount prerequisites, optional
services, AIDE and remote logging. All four status differences are sudo controls.
A missing lab logfile also fails the survey. Follow-up comparison probes use the
existing audit log and explicit temporary-directory scopes instead. The audit-log
permission probe passed on both. The temporary-directory review found 94 RHEL
entries created by the Python tests and zero on Rocky. This is test-fixture
contamination, not evidence of an operating-system default difference. Both
redirect probes failed the intended policy, consistently with the native sysctl values.

Two harness errors were corrected before final acceptance. A temporary file named
inspect.py shadowed Python's standard library during one RHEL verification. A
refusal test initially selected three non-high-impact network controls and applied
them. The corrected high-impact test uses SSH controls. The applied network controls
were included in repeatability and post-reboot verification. Neither was a framework
defect. Issue #9 is the product defect found and fixed during this work.

## Create and validate either profile

Select **Target distribution** in the offline editor, choose controls, and export
YAML. Existing selections are preserved when changing distributions. CLI examples:

```bash
hardener validate --profile profiles/examples/rhel10-server-five-controls.yaml
hardener validate --profile profiles/examples/server-five-controls.yaml

# Inventory must identify the intended disposable server and hardener_role=server.
hardener preflight --profile profiles/examples/rhel10-server-five-controls.yaml   --inventory inventory.local.ini --target test-vm --output reports/rhel/preflight
hardener audit --profile profiles/examples/rhel10-server-five-controls.yaml   --inventory inventory.local.ini --target test-vm --output reports/rhel/audit
hardener apply --profile profiles/examples/rhel10-server-five-controls.yaml   --inventory inventory.local.ini --target test-vm --output reports/rhel/apply
hardener verify --profile profiles/examples/rhel10-server-five-controls.yaml   --inventory inventory.local.ini --target test-vm --output reports/rhel/verify
```

Use the Rocky example path for a Rocky target. An operating-system switch does not
translate repository IDs, keys, users, time sources or workload policy. For AWS RHEL
advisory assessment, select the actual BaseOS/AppStream RHUI IDs listed above. For
Rocky select baseos/appstream. Preserve approved vendor authentication and trust
configuration. A wrong-distribution profile fails preflight.

Useful read-only checks for the document differences:

```bash
cat /etc/os-release
dnf repolist --enabled
ls /etc/pki/rpm-gpg
systemd-analyze cat-config systemd/coredump.conf
sysctl net.ipv4.conf.all.accept_redirects
sudo ss -H -lnt 'sport = :25'
sudo stat -Lc '%U %G %a' /var/log/audit/audit.log
grep -n remember /etc/pam.d/system-auth /etc/pam.d/password-auth
```

## Evidence and cleanup

Final runtime engine SHA-256:
`9dacf51959cf0475ea5c1bce128b875c7640d5c847b520516f291c8bc8b11a5d`.

Raw reports, commands, profile inputs, test logs and screenshots are retained in the
operator's ignored `reports/dual-os-20261106` directory. They are not published as
release assets. Temporary instances used encrypted delete-on-termination disks,
restricted SSH ingress, IMDSv2 and termination timers. The PR records final AWS
termination and security-group/key cleanup after evidence and commits are exported.

Existing internal filenames and recovery-key paths containing rocky10 remain
unchanged for compatibility. RHEL high-impact deployment still requires its own
workload review and an actual successful recovery rehearsal.
