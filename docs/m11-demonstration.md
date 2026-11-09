# M11 mandatory access control, auditing and integrity

M11 adds twelve remediable controls and one read-only assessment under the
owner-approved disposable-lab policy. The validation record below separates
successful control execution from retained assessment findings.

## Approved disposable policy

The owner approved this isolated policy on 2026-11-05. It is represented by
[the security lab profile](../profiles/examples/server-security-lab.yaml).
Production profiles require their own storage, integrity and collector values.

- SELinux uses enforcing mode and the loaded targeted policy.
- Audit files rotate at 20 MiB, retaining five files. Free-space thresholds are
  75 MiB and 50 MiB. All four selected space/error actions report to syslog.
  These warning-only actions preserve availability and can lose records if storage
  remains exhausted. They are an explicit lab policy.
- Early boot uses audit=1 and audit_backlog_limit=8192. The buffer matches the
  existing native runtime setting. Reported event loss prevents this control
  from passing. The engine never clears the loss counter to obtain a pass.
- Four original audit watch groups cover identity databases, sudo/su execution,
  security configuration and session databases.
- Immutable rules run after all seven audit prerequisites pass. A reboot remains
  the recovery path for kernel rule changes.
- AIDE checks only /srv/m11-baseline daily. Initial baseline approval is explicit.
  Neither a rerun nor an integrity finding refreshes the trusted database.
- Rsyslog forwards to the private probe collector on TLS port 6514. Its certificate
  must match logs.lab.test and the externally provisioned CA file. The sender queue
  is bounded at 100 MiB. No private key or certificate contents enter profiles.

## Supported behavior and limits

The tested platform is the existing Rocky Linux 10.2 x86_64 KVM lab. The development
guest runs the CLI. The target receives changes. The probe guest hosts the private
collector and is restored separately when running original regression fixtures.

SELinux disabled-to-enabled migration and changing the loaded policy require a
separately reviewed relabel/reboot procedure. The enforcing control requires the
targeted-policy control. The engine converts both the compiled targeted policy and /sys/fs/selinux/policy
to native CIL with checkpolicy and compares their semantics. It does not infer
the loaded policy from sestatus, which reads the configured name. Unmatched
runtime policy requires review. Neither control generates confinement policy or
changes vendor permissive types. The unconfined-service control is an assessment.

Audit rules use separate owned files. Existing unrelated supported watches remain.
Suppression rules, unmanaged finalizers, custom audit service units and unsafe
files are refused. A stopped auditing subsystem must first be enabled with the
service control before applying dependent groups. Existing immutable drift requires
reviewed reboot or snapshot recovery.

The kernel audit receiver must match the native systemd auditd process and
standard command line. Alternate daemon ownership or configuration is refused.
Storage verification reads native successful reconfiguration events or proves
that the daemon started after its configuration. It does not equate a signal being
sent with successful reload. Early-boot verification compares every boot entry,
the running command line and the lost-event counter.

AIDE uses its own configuration, database and systemd timer. Existing database
scope, conflicting unit content, unsafe paths and leftover candidate databases
require review. Findings cause audit/verify/apply to fail without replacing the
baseline. The check service exposes a failing exit status and journal alert.

TLS verification checks native configuration, running service state and a
certificate-validated peer connection. End-to-end receipt is additionally proven
by unique source markers inspected on the collector during integration. It is not
a promise of continuous collector ingestion. Stock rsyslog and its vendor-verified
cloud-init routing file are supported. The forwarding action precedes cloud-init's
local stop rule. Other active routing overrides, alternate startup options and nonstandard running
command lines require review.

High-impact preflight/apply requires a current engine-bound recovery receipt.
Restore the guest snapshot for broad recovery. Narrow recovery consists of
restoring prior SELinux/audit settings, removing the owned audit files before
reboot if immutable, disabling rocky10-aide.timer without updating its database,
or removing the owned TLS drop-in and validating/restarting rsyslog.

## Reproduction

Prepare external prerequisites in disposable guests: audit/audit-rules,
selinux-policy-targeted, checkpolicy, AIDE, rsyslog and rsyslog-gnutls. Provision the explicit
integrity directory, lab CA and private collector outside the framework. Preserve
the initial snapshot before testing. Do not put inventories, private keys or
runtime reports in Git.

From the development guest:

    source .venv/bin/activate
    hardener recovery-test --inventory inventory.local.m9.ini --target test-vm --output reports/m11-live/recovery
    python tests/integration/m11.py --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m11-live/recovery/recovery.json --output reports/m11-live/lifecycle --disposable

When RECOVERY_READY appears, stop target SSH using the existing administrative
channel. Wait for RECOVERY_OUTAGE_OBSERVED, then restore m11-prepared through the
independent hypervisor route. Repeat the lifecycle from that same snapshot.

After saving the accepted target snapshot:

    python tests/integration/m11_rotation.py --inventory inventory.local.m9.ini --target test-vm --output reports/m11-live/rotation --disposable
    python tests/integration/m11_selinux.py --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m11-live/recovery/recovery.json --output reports/m11-live/selinux --disposable

Then run the refusal and fault suite:

    python tests/integration/m11_failures.py --inventory inventory.local.m9.ini --target test-vm --recovery-evidence reports/m11-live/recovery/recovery.json --output reports/m11-live/failures --disposable

This suite intentionally ends with an integrity finding. Restore the accepted
snapshot afterward. The disk-full fixture uses only a 2 MiB tmpfs on the disposable
target. It never fills the development guest or the target root filesystem.

## Disposable fixture preparation

Start from the accepted M10 target and the separate M9 probe baseline. Keep their
existing snapshots. The following commands are fixture provisioning, outside the
hardening CLI. Do not reuse an existing private-key directory.

On the probe guest:

    sudo dnf install -y rsyslog rsyslog-gnutls openssl
    sudo install -d -m 700 /root/m11-pki
    sudo install -d -m 755 /etc/pki/rsyslog
    sudo openssl req -x509 -newkey rsa:3072 -nodes -keyout /root/m11-pki/ca.key -out /etc/pki/rsyslog/lab-ca.pem -sha256 -days 30 -subj /CN=Rocky-M11-Lab-CA
    sudo openssl req -newkey rsa:3072 -nodes -keyout /etc/pki/rsyslog/server.key -out /root/m11-pki/server.csr -subj /CN=logs.lab.test

Create /root/m11-pki/server.ext with:

    subjectAltName=DNS:logs.lab.test
    extendedKeyUsage=serverAuth
    basicConstraints=CA:FALSE

Then sign the disposable server certificate:

    sudo openssl x509 -req -in /root/m11-pki/server.csr -CA /etc/pki/rsyslog/lab-ca.pem -CAkey /root/m11-pki/ca.key -CAcreateserial -out /etc/pki/rsyslog/server.pem -days 30 -sha256 -extfile /root/m11-pki/server.ext
    sudo chmod 600 /etc/pki/rsyslog/server.key

Create /etc/rsyslog.d/80-m11-collector.conf:

    global(DefaultNetstreamDriver="gtls"
      DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/lab-ca.pem"
      DefaultNetstreamDriverCertFile="/etc/pki/rsyslog/server.pem"
      DefaultNetstreamDriverKeyFile="/etc/pki/rsyslog/server.key")
    module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
    ruleset(name="m11_collector") {
      action(type="omfile" file="/var/log/m11-collector.log" fileCreateMode="0600")
    }
    input(type="imtcp" port="6514" ruleset="m11_collector")

This fixture authenticates the collector to the sender. It does not implement
client-certificate authentication. Permit only the isolated lab network to reach
the collector. Restore file contexts and validate/start it:

    sudo restorecon -RF /etc/pki/rsyslog /etc/rsyslog.d
    sudo rsyslogd -N1
    sudo systemctl enable --now rsyslog
    sudo systemctl restart rsyslog

On the disposable target:

    sudo dnf install -y aide rsyslog-gnutls checkpolicy
    sudo install -d -m 755 /etc/pki/rsyslog /srv/m11-baseline

Copy only the public lab-ca.pem from the probe into the target's
/etc/pki/rsyslog/lab-ca.pem with root ownership and mode 0644. Create
/srv/m11-baseline/approved.txt with a fixed harmless line, root ownership and mode
0644. Restore their contexts. Set only SELINUX=permissive in /etc/selinux/config,
leaving SELINUXTYPE=targeted, then:

    sudo setenforce 0
    sudo systemctl disable auditd audit-rules

Save stopped-disk snapshots m11-prepared on the target and m11-collector-ready on
the probe. The committed lifecycle suite restarts auditd before testing its disabled
boot enablement. Its collector helper deliberately uses the approved isolated
192.0.2.30 fixture. Adapt that test-only address if building a different lab.

## Native behavior references

Original implementation was checked against the guest's installed manual pages
and the following vendor documentation:

- [SELinux states and modes](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/changing-selinux-states-and-modes).
- [Audit and TLS logging operations](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/risk_reduction_and_recovery_operations/index).
- [AIDE integrity checking](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/checking-integrity-with-aide).
- [SELinux native policy loading](https://github.com/SELinuxProject/selinux/blob/main/libselinux/src/load_policy.c).
- [Rsyslog forwarding module](https://docs.rsyslog.com/doc/configuration/modules/omfwd.html).

## Validation record

Acceptance source: commit `81f95cac21d1f825641b76529f674b771ddba404`,
version `0.11.0rc1`. Runtime source SHA-256:
`eaeac118692911b559d2ad442ba8ea56ba6ee8ec72fb299627727c323e5fdcda`.
Documentation-only completion commits do not alter that runtime digest.
CI run `42139506965` passed for this implementation,
including editor/browser checks, installed-wheel checks and candidate artifact upload.

All native work ran inside the local Rocky Linux 10.2 KVM guests hosted by WSL 2.
The installed kernel was 6.12.0-211.73.1.el10_2.x86_64. Native packages were
audit/audit-rules 4.0.3-5.el10, AIDE 0.19.2-4.el10_2.1,
rsyslog/rsyslog-gnutls 8.2510.0-5.el10_2.2, selinux-policy-targeted
42.1.18-4.el10 and checkpolicy 3.10-1.el10.

| Executed check | Result | Private evidence under reports/m11-live |
| --- | --- | --- |
| Python, style and Ansible syntax | 342 tests passed, Ruff and both playbook syntax checks passed | checks/python-final.log, checks/ruff-final.log, checks/syntax-final.log |
| Editor unit and Chromium browser checks | 31 unit and 13 browser tests passed | checks/editor-b.log |
| Installed wheel and release assets | Build, independent wheel smoke and release checks passed | checks/build-final.log, checks/wheel-final.log, checks/release-final.log |
| Two independent snapshot lifecycles | All 12 selected controls passed, repeats changed nothing, reboot persisted, unrelated watches survived | lifecycle-g/integration-evidence.json, lifecycle-h/integration-evidence.json |
| Read-only and selection boundaries | Audit/verify preserved configuration bytes and metadata, exclusions and omissions remained untouched | lifecycle-g, lifecycle-h |
| Native audit and collector evidence | All four event groups recorded, immutable mutation denied, zero lost events, collector received markers before and after reboot | lifecycle-g, lifecycle-h |
| Audit rotation | Six native rotations retained exactly five private files and continued recording with zero loss | rotation-final/integration-evidence.json |
| SELinux assessment and persistent repair | Added unconfined fixture detected without changes, persistent targeted setting repaired, fresh administration preserved | selinux-final/integration-evidence.json |
| Unsafe configuration refusal | All 15 fixtures refused apply with no managed writes | failures-final/integration-evidence.json |
| Storage, TLS and integrity faults | Bounded disk-full warning and recovery, wrong certificate rejected and collector resumed, AIDE drift alerted without replacing its trusted baseline | failures-final/integration-evidence.json |
| Original VS1/VS2/VS4/VS5 regressions | All four suites passed on the separate probe guest | regression/summary.json |
| Unchanged browser profile through the CLI | All 12 selected controls passed apply and verify with zero changes | combined/integration-evidence.json |
| Combined catalog and fresh dual-stack administration | Apply: 75 pass, six assessments excluded, zero changes. Verify: 79 pass, two assessment findings. Fresh IPv4/IPv6 SSH and sudo passed | combined/integration-evidence.json |

The 15 refusal cases cover audit suppression and duplicates, crossed storage
thresholds, untrusted peers, changed integrity scope, unknown logging routes,
immutable persistent drift, custom auditd/rsyslog/AIDE units, linked audit rules,
invalid compiled SELinux policy, boot bypass, missing trusted baseline and
alternate logging startup.

The accepted target snapshot is `m11-accepted`. The original `m10-accepted`,
prepared `m11-prepared` and separate `m11-collector-ready` snapshots are retained.
The fault suite intentionally ends with AIDE drift. The target is restored before
the final combined checks. Current-engine recovery receipts record an observed
SSH outage followed by restoration through the independent hypervisor route.

The unconfined-service assessment reports two deliberate pre-existing fixtures:
`sleep` in `hardener-m10-service.service` and `python3` in
`hardener-m7-repository.service`. They remain for their earlier integration tests.
The existing root PATH assessment reports absent `/root/.local/bin` and
`/root/bin`. These are explicit assessment findings, not automatic repairs or
claims of a fully passing server.

Earlier prototype attempts remain in private evidence but do not count toward
acceptance. Final acceptance uses lifecycle-g/h and the final fault/rotation/
SELinux runs at the runtime digest above. The private evidence archive and its
SHA-256 are recorded in the owner's project journal. Runtime reports, inventories,
recovery material and lab credentials are excluded from Git.
