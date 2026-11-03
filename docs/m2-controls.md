# Five-control behavior and restoration

The approved profile is `profiles/examples/server-five-controls.yaml`.
Each control can be selected, explicitly excluded with a reason, or omitted.
The original `server-minimal.yaml` remains a one-control example.

| ID | Expected state | Operational effect |
| --- | --- | --- |
| files.passwd-permissions | /etc/passwd root:root, 0644 | Preserves account-file content |
| kernel.protected-hardlinks | Runtime and effective boot setting equal 1 | Restricts hard links to other users' files |
| services.debug-shell-disabled | Inactive, persistently masked in /etc | Removes the unauthenticated debugging console |
| packages.telnet-client-absent | Exact telnet package absent | Removes the unencrypted terminal client |
| packages.local-signature-check | DNF localpkg_gpgcheck=True | Rejects unsigned local RPM installations through ordinary DNF |

## Configuration and failure handling

Hard-link protection writes only its own setting in
`/etc/sysctl.d/99-rocky10-hardener.conf` and activates only
`fs.protected_hardlinks`. It never runs `sysctl --system`.
Inspection uses systemd's ordered, shadow-resolved configuration output.
A conflicting explicit assignment in a later file blocks the entire apply
before any control changes. Existing unrelated settings are preserved.
Verification reads procfs and reinspects persistent configuration.
The integration test also verifies the result after reboot.

The debug-shell control stops the service, creates the persistent
`/etc/systemd/system/debug-shell.service -> /dev/null` mask, and reloads
systemd only when the mask changes. A runtime-only mask does not satisfy
the control. An existing custom unit or different symlink is never overwritten.
Verification checks both the mask and systemd's effective inactive state.

Telnet removal uses `rpm --erase --test telnet` in preflight and
`rpm --erase telnet` in apply. RPM rechecks dependencies at removal time.
No dependency bypass or automatic dependency cleanup is used. A package that
requires Telnet blocks the whole apply. The direct RPM transaction does not
create a DNF history entry. This narrow command is intentional because general
package-manager removal may also remove dependent packages.
Audit uses RPM bindings and verification uses the RPM command-line query.

The signature control edits only `localpkg_gpgcheck` in the main section of
`/etc/dnf/dnf.conf`. Duplicate keys, missing main sections, inherited defaults,
and the same option in another section are refused before apply.
The file must be regular with one link. Effective state is read using DNF's
configuration API, without loading repositories or executing plugins.
The test suite also submits an unsigned local RPM and confirms DNF rejects it.
Explicit operator overrides such as `--nogpgcheck`, direct RPM operations,
custom configuration files, and third-party plugins are outside this setting's
guarantee.

All prerequisites run before any selected control changes. Audit and verify
may report noncompliance for configurations that apply refuses to overwrite.

## Restore

Use the tested guest snapshot for complete lab restoration. For a targeted
manual reversal, restore the recorded owner/group/mode, prior sysctl entry
and runtime value, prior service mask/state, Telnet package, or DNF option.
Preserve unrelated configuration and recheck effective state afterward.
There is no automatic OS rollback.

Primary behavior references:
- [systemd sysctl configuration ordering](https://www.freedesktop.org/software/systemd/man/latest/sysctl.d.html)
- [systemd configuration inspection](https://www.freedesktop.org/software/systemd/man/latest/systemd-sysctl.html)
- [RPM erase and dependency checks](https://rpm.org/docs/latest/man/rpm.8)
- [DNF configuration options](https://dnf.readthedocs.io/en/stable/conf_ref.html)
