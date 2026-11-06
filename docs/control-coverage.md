# Server control coverage

The inventory below reconciles the approved plan with implemented catalog entries.
Workload-dependent controls remain optional. A supported mode describes execution capability,
not automatic selection. M5 through M12 are complete. The catalog has 102 executable
controls: 90 remediable and twelve assessment-only. M12 covers fifteen remediations
and six assessments under the approved disposable policy. See the
[M12 acceptance record](m12-demonstration.md#validation-record). The combined run
retains root PATH, unconfined-service, root encryption and BIOS Secure Boot findings.
The first two retain their [M11 dispositions](m11-demonstration.md#validation-record).
Encryption and firmware changes remain provisioning decisions. M13 remains pending.

| ID | Milestone | Disposition | Evidence |
| --- | --- | --- | --- |
| files.group-permissions | M6 | Implemented | [M6](m6-demonstration.md) |
| files.shadow-permissions | M6 | Implemented | [M6](m6-demonstration.md) |
| files.gshadow-permissions | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.protected-symlinks | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.randomize-address-space | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.suid-dumpable | M6 | Implemented | [M6](m6-demonstration.md) |
| files.account-backup-permissions | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.protected-fifos | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.protected-regular | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.dmesg-restrict | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.kptr-restrict | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.ptrace-scope | M6 | Implemented | [M6](m6-demonstration.md) |
| kernel.unprivileged-bpf-disabled | M6 | Implemented | [M6](m6-demonstration.md) |
| packages.repository-signature-check | M7 | Implemented | [M7](m7-demonstration.md) |
| packages.repository-tls-verification | M7 | Implemented | [M7](m7-demonstration.md) |
| packages.repository-metadata-signature | M7 | Implemented | [M7](m7-demonstration.md) |
| packages.security-update-status | M7 | Assessment | [M7](m7-demonstration.md) |
| services.avahi-disabled | M7 | Implemented | [M7](m7-demonstration.md) |
| services.cups-disabled | M7 | Implemented | [M7](m7-demonstration.md) |
| time.chrony-enabled | M7 | Implemented | [M7](m7-demonstration.md) |
| time.approved-sources | M7 | Implemented | [M7](m7-demonstration.md) |
| logging.journal-persistent | M7 | Implemented | [M7](m7-demonstration.md) |
| logging.journal-retention | M7 | Implemented | [M7](m7-demonstration.md) |
| logging.logfile-permissions | M7 | Implemented | [M7](m7-demonstration.md) |
| logging.rotation-policy | M7 | Implemented | [M7](m7-demonstration.md) |
| auth.ssh-config-permissions | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-hostkey-permissions | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-empty-passwords | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-hostbased-auth | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-root-login | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-password-login | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-access-policy | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-forwarding-policy | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.ssh-session-limits | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.sudo-config-permissions | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.sudo-use-pty | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.sudo-authentication | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| auth.sudo-timeout | M8 | Implemented | [M8](m8-demonstration.md#validation-record) |
| network.ipv4-source-route-disabled | M9 | Implemented | [M9 first batch](m9-demonstration.md#validation-record) |
| network.ipv6-source-route-disabled | M9 | Implemented | [M9 first batch](m9-demonstration.md#validation-record) |
| network.ipv4-redirects-disabled | M9 | Implemented | [M9 host policy](m9-routing-demonstration.md#validation-record) |
| network.ipv6-redirects-disabled | M9 | Implemented | [M9 host policy](m9-routing-demonstration.md#validation-record) |
| network.ipv4-send-redirects-disabled | M9 | Implemented | [M9 host policy](m9-routing-demonstration.md#validation-record) |
| network.tcp-syncookies | M9 | Implemented | [M9 first batch](m9-demonstration.md#validation-record) |
| network.reverse-path-filter | M9 | Implemented | [M9 host policy](m9-routing-demonstration.md#validation-record) |
| network.ip-forwarding-disabled | M9 | Implemented | [M9 host policy](m9-routing-demonstration.md#validation-record) |
| firewall.firewalld-enabled | M9 | Implemented | [M9 firewall](m9-firewall-demonstration.md#validation-record) |
| firewall.management-access | M9 | Implemented | [M9 firewall](m9-firewall-demonstration.md#validation-record) |
| firewall.inbound-policy | M9 | Implemented | [M9 firewall](m9-firewall-demonstration.md#validation-record) |
| auth.password-quality | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.password-history | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.failed-login-lockout | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.password-aging | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.inactive-account-lock | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.default-umask | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.shell-idle-timeout | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| auth.su-access-policy | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| accounts.system-login-disabled | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| accounts.home-permissions | M10 | Implemented | [M10](m10-demonstration.md#validation-record) |
| accounts.unique-identities | M10 | Assessment | [M10](m10-demonstration.md#validation-record) |
| accounts.root-only-uid-zero | M10 | Assessment | [M10](m10-demonstration.md#validation-record) |
| accounts.no-empty-passwords | M10 | Assessment | [M10](m10-demonstration.md#validation-record) |
| accounts.root-path-integrity | M10 | Assessment | [M10](m10-demonstration.md#validation-record) |
| selinux.enforcing | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| selinux.targeted-policy | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| selinux.no-unconfined-services | M11 | Assessment | [M11](m11-demonstration.md#validation-record) |
| audit.service-enabled | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.early-boot | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.storage-policy | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.identity-changes | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.privilege-use | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.security-config-changes | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.session-events | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| audit.immutable-rules | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| integrity.aide-scheduled | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| logging.remote-tls | M11 | Implemented | [M11](m11-demonstration.md#validation-record) |
| filesystem.tmp-restrictions | M12 | Implemented | [M12](m12-demonstration.md) |
| filesystem.var-tmp-restrictions | M12 | Implemented | [M12](m12-demonstration.md) |
| filesystem.dev-shm-restrictions | M12 | Implemented | [M12](m12-demonstration.md) |
| filesystem.home-restrictions | M12 | Implemented | [M12](m12-demonstration.md) |
| filesystem.shared-directory-sticky | M12 | Implemented | [M12](m12-demonstration.md) |
| filesystem.world-writable-review | M12 | Assessment | [M12](m12-demonstration.md) |
| filesystem.unowned-files-review | M12 | Assessment | [M12](m12-demonstration.md) |
| filesystem.privileged-files-review | M12 | Assessment | [M12](m12-demonstration.md) |
| kernel.unused-filesystem-modules | M12 | Implemented | [M12](m12-demonstration.md) |
| kernel.unused-network-protocols | M12 | Implemented | [M12](m12-demonstration.md) |
| services.legacy-listeners-disabled | M12 | Implemented | [M12](m12-demonstration.md) |
| services.cron-access | M12 | Implemented | [M12](m12-demonstration.md) |
| services.at-access | M12 | Implemented | [M12](m12-demonstration.md) |
| boot.config-permissions | M12 | Implemented | [M12](m12-demonstration.md) |
| boot.loader-authentication | M12 | Implemented | [M12](m12-demonstration.md) |
| boot.rescue-authentication | M12 | Implemented | [M12](m12-demonstration.md) |
| crypto.system-policy | M12 | Implemented | [M12](m12-demonstration.md) |
| login.authorized-use-banner | M12 | Implemented | [M12](m12-demonstration.md) |
| storage.partition-layout | M12 | Assessment / provisioning | [M12](m12-demonstration.md) |
| storage.disk-encryption | M12 | Assessment / provisioning | [M12](m12-demonstration.md) |
| boot.secure-boot | M12 | Assessment / provisioning | [M12](m12-demonstration.md) |
| files.passwd-permissions | M1–M4 | Implemented | [M4](m4-release-readiness.md) |
| kernel.protected-hardlinks | M1–M4 | Implemented | [M4](m4-release-readiness.md) |
| services.debug-shell-disabled | M1–M4 | Implemented | [M4](m4-release-readiness.md) |
| packages.telnet-client-absent | M1–M4 | Implemented | [M4](m4-release-readiness.md) |
| packages.local-signature-check | M1–M4 | Implemented | [M4](m4-release-readiness.md) |
