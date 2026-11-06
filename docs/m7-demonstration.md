# M7 package, service, time, and local logging controls

Release candidate: 0.7.0rc1. Validated on Rocky Linux 10.2 x86_64 KVM guests on 2026-11-03.

## Implemented behavior

The catalog adds 12 controls, bringing the total to 30. Eleven support audit, apply, and verify.
Security-update status supports audit and verify only. Selecting an assessment-only control for
apply fails offline before inventory access. Reports expose supported modes, and the offline
editor explains the restriction. Required repository IDs, source names, log paths, retention
budgets, and rotation choices have no production defaults.

| Control | Behavior and boundaries |
| --- | --- |
| packages.repository-signature-check | Enables package signature checking in explicit enabled repository sections. Preserves all other sections and options. |
| packages.repository-tls-verification | Enables certificate verification for explicit repositories whose configured base URL, mirror list, or metalink uses HTTPS. It does not convert mirror URLs or guarantee that every advertised mirror uses HTTPS. |
| packages.repository-metadata-signature | Enables metadata signature checks only after fresh metadata succeeds with configured trusted keys. Verification uses isolated temporary DNF cache, log, and key state. Default distribution repositories are not assumed to publish signed metadata. |
| packages.security-update-status | Loads fresh advisory metadata for explicit repositories, compares installed packages, and reports pending security updates. Missing advisory metadata is an error. It never installs an update or claims that unpublished advisories are absent. |
| services.avahi-disabled | Stops and persistently masks the installed daemon and activation socket. Absence is not applicable. |
| services.cups-disabled | Stops and persistently masks the installed service, socket, and path unit. Absence is not applicable. Neither service control removes packages. |
| time.chrony-enabled | Installs chrony if needed and enables its service. This control alone does not claim synchronization. Deliberately masked services require operator resolution. |
| time.approved-sources | Replaces server, pool, peer, and DHCP source-directory selection with explicit server or pool names. Validates with chronyd before replacement. Checks running original source names and synchronized selection. Refuses custom includes, reference clocks, and unsupported daemon invocation. |
| logging.journal-persistent | Sets persistent journal storage, restarts when needed, flushes volatile entries, and verifies persistent journal files. |
| logging.journal-retention | Sets explicit maximum disk use, reserved free space, and maximum retention. Requires persistent storage and refuses a budget larger than available storage. Checks that the running daemon started after configuration changes. |
| logging.logfile-permissions | Sets 0600 or 0640 on explicit existing files under /var/log. Retains content, owner, and group. Refuses symlinks, hardlinks, custom ACLs, and writable parent directories. |
| logging.rotation-policy | Writes one managed stanza for explicit existing logs. Uses the native parser against the combined configuration to reject duplicates and syntax errors. Requires the active enabled distribution timer. Retains original log ownership when creating replacements. |

Service overrides, ambiguous repository sections, unsafe managed paths, conflicting later
journal drop-ins, unsupported rotation includes, and custom time layouts refuse remediation
before any selected write. Audit and verify remain available where inspection is possible.
The engine never treats an unavailable inspection as not applicable.

The rotation policy supports daily, weekly, or monthly intervals and a bounded archive count.
It supports either a fixed rsyslog HUP action or an explicit choice to handle application
reopening externally. It does not invent arbitrary commands, recursive log discovery, or
application-specific restart logic. Logrotate is required to be provisioned and scheduled
before this control is selected. Approved time-source selection similarly expects the
distribution chrony configuration to exist. The service-only control can install chrony.

## Profiles and recovery

The general-server example includes chrony service enablement and persistent journaling.
Other new policies are explicit exclusions until the owner supplies parameters.
The operations-lab example requires the disposable integration fixtures. It is not a production
policy. For production, choose repositories, approved sources, log paths, budgets, and writer
reopening deliberately. Assessment selections belong in an audit or verify profile.

Before applying, save an offline guest snapshot and copies of the selected configuration files.
To recover repository settings, restore the selected .repo files. To restore optional services,
remove only the masks installed by this run, reload systemd, and restore prior enablement and
activation state. To recover time service, restore chrony.conf and prior service state, then
check chronyc tracking. To recover journald, restore its managed drop-in, restart the service,
and flush if persistent storage remains selected. Restore original log modes and the rotation
stanza from recorded metadata. Existing journal entries and rotated logs are not deleted.
The disposable test recovery path is snapshot reversion with a new SSH/sudo check.

## Validation method

The live suite starts from m6-verified and first proves service absence. It installs only
disposable service and repository fixtures, then makes all eleven remediable controls
noncompliant. It checks audit failure, preflight refusals without writes, exclusions and omissions,
selected apply, independent verify, repeat apply with zero changes, package and unrelated-file
preservation, runtime time-source drift, native package signature rejection, fresh advisory
before/after results, absent advisory metadata, certificate rejection, actual log rotation,
journal persistence across reboot, and administrative recovery.

The repository fixture uses two empty package versions, original advisory XML, a disposable
metadata signing key, and a local HTTPS certificate. Private keys remain outside Git and public
evidence. A deliberate fixture upgrade is separate from the read-only update assessment.
Metadata and advisory inspection creates temporary isolated cache files and removes them.
It does not modify configured repositories, installed packages, or persistent DNF caches.

The family suite is tests/integration/m7.py. Its prerequisite fixture builder is
tests/integration/m7_fixtures.py. Both require --disposable. The editor browser test exports a
bounded repository list, validates it with the CLI, imports it unchanged, and rejects duplicates.

## Acceptance results

| Check | Result |
| --- | --- |
| Python unit and schema tests | 105 passed, including DNF variable loading and latest security candidates |
| Ruff and Ansible syntax | Passed |
| Offline editor | 31 unit tests and seven browser tests passed |
| Complete M7 snapshot runs | final-b and final-c passed from m6-verified |
| Absent chrony package | Audit failed, apply installed/enabled the service, repeat apply changed nothing |
| Final combined verification | All 30 controls passed using the explicitly selected disposable repository |
| Final M7 apply | Eleven remediable controls passed, zero changed tasks |
| Browser-exported assessment | Unchanged exported YAML inspected live Rocky BaseOS/AppStream metadata and reported 56 upgrade candidates, exit 5, zero changes |
| Original VS1, VS2, VS4, VS5 | All four passed |
| Installed wheel and release assets | Installed wheel, source distribution, and publication checks passed |

The live repository check exposed a missing DNF site-variable initialization. The final
implementation loads the configured variable directories before reading repositories.
A focused unit regression and live repository assessment validate the correction.
It reports one latest security candidate per package architecture rather than counting
every intermediate version. No operating-system update transaction was performed.

The verified disposable target is saved as m7-verified before original regression tests.
Reports remain private under reports/m7 on the development guest. The project journal
records the published commit, CI result, and local evidence archive.

## Behavior references

Repository policy follows the [DNF configuration reference](https://dnf.readthedocs.io/en/latest/conf_ref.html)
and [repository metadata API](https://dnf.readthedocs.io/en/latest/api_repos.html).
Source selection and daemon syntax follow [chrony configuration](https://chrony-project.org/doc/4.8/chrony.conf.html)
and [chronyd](https://chrony-project.org/doc/4.8/chronyd.html).
The running-source check uses chronyc's original-name output and synchronization reports,
documented in [chronyc](https://chrony-project.org/doc/4.8/chronyc.html).
Storage and precedence follow [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).
Rotation syntax, dry-run behavior, and inherited ownership follow the
[upstream logrotate manual](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in).
