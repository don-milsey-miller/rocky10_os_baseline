# M12 assessment checkpoint

M12 is **incomplete**. Six read-only controls are executable. Five filesystem
remediations are drafted with `implemented: false`. Ten other controls remain
planned. No mount, boot, scheduler, listener, module or crypto policy has been
applied under M12.

## Pending owner decision Q6

The proposed disposable policy is:

- Provision dedicated temporary mounts for /tmp and /var/tmp, then test
  nodev,nosuid,noexec on those mounts and /dev/shm.
- Provision an existing /home mount preserving its data and allow execution there
  while testing nodev,nosuid.
- Restrict only explicitly unused modules and listeners. Limit cron/at to root
  and named test accounts while preserving required jobs.
- Test BIOS boot editing and rescue authentication using lab credentials held
  outside Git, profiles and reports. Allow guest reboots and snapshot restoration.
- Select crypto policy DEFAULT and the notice text
  "Authorized laboratory access only."
- Keep partitioning, encryption migration and Secure Boot changes in provisioning.
  Record existing gaps. UEFI remains unsupported until a separate fixture passes.

This policy has **not been approved**. The implementation plan explicitly requires
storage/boot/workload policy before mutating acceptance. No production values are
inferred.

## Executable assessment behavior

| Control | Behavior and limit |
| --- | --- |
| filesystem.world-writable-review | Inspect explicitly selected trees for writable regular/special files and shared directories missing the sticky bit. Ignore symlink mode bits. |
| filesystem.unowned-files-review | Resolve each observed UID and GID through native NSS lookups. Report unresolved metadata without assigning ownership. |
| filesystem.privileged-files-review | Detect setuid/setgid regular files and file capabilities outside explicit approved paths. Exceptions approve paths, not file contents or integrity. |
| storage.partition-layout | Check that each requested path is a whole supported local filesystem separate from root and other requested paths. No partition creation or migration. |
| storage.disk-encryption | Require dm-crypt ancestry on every backing block-device branch. This does not assess key management, algorithms, encrypted swap or unselected paths. |
| boot.secure-boot | BIOS produces a finding with a UEFI-provisioning disposition. UEFI execution fails as unsupported by this tested slice. No firmware writes. |

Filesystem reviews require existing canonical directory paths, do not follow
symlinks, and skip other filesystems while reporting the boundary count. They
support XFS, ext4 and tmpfs metadata inspection. Explicit entry limits
are bounded at 200,000, the time limit is 30 seconds, and only the first 40 finding
paths appear in reports. Inspection failures return an error, never an empty pass.
Nested mounts should be selected separately. Other filesystem types are refused by this slice.

Storage assessments support XFS and ext4 block filesystems. The native
fixture covers ext4 on both a plain loop device and a LUKS2 mapping. The existing
guest supplies XFS partition evidence. Other layouts require separate acceptance.

All six controls reject apply before target contact. Reports contain metadata
findings rather than file contents or keys. The example is a read-only review,
not a production storage specification:
[server-storage-review.yaml](../profiles/examples/server-storage-review.yaml).

## Draft remediation scope

The four mount controls accept only explicit nodev/nosuid/noexec flag lists.
They require an already mounted whole tmpfs/XFS/ext4 filesystem, one fstab entry,
matching live/persistent sources, and an unmodified fstab-generated systemd unit.
Bind mounts, custom units/drop-ins, optional/user mounts, ambiguous entries and
source drift are refused. Changes preserve unrelated fstab fields and comments.
The shared-directory control only adds the sticky bit to explicitly named,
root-owned world-writable directories. It does not recurse.

These five drafts are unavailable in executable profiles and the editor.
Unit tests are not guest acceptance. Their promotion requires Q6, real write
refusals, effective behavior tests, reboot persistence, exclusion/omission,
snapshot repetition and fresh recovery evidence.

The remaining planned controls are kernel.unused-filesystem-modules,
kernel.unused-network-protocols, services.legacy-listeners-disabled,
services.cron-access, services.at-access, boot.config-permissions,
boot.loader-authentication, boot.rescue-authentication, crypto.system-policy
and login.authorized-use-banner.

## Reproduction and evidence

All development and native testing occurs inside Rocky Linux 10.2 KVM guests.
Use an explicit target inventory and preserve the M11 accepted snapshot.

```bash
. .venv/bin/activate
pytest -q
python tests/integration/m12_assessments.py \
  --inventory inventory.local.m9.ini --target test-vm \
  --output reports/m12-live/assessments-repeat --disposable
sudo .venv/bin/python tests/integration/m12_storage_fixture.py \
  --output reports/m12-live/native-storage-repeat.json --disposable
hardener audit --profile profiles/examples/server-storage-review.yaml \
  --inventory inventory.local.m9.ini --target test-vm \
  --output reports/m12-live/storage-review-repeat
```

The assessment fault suite creates only /srv/hardener-m12-review, refuses a
pre-existing directory, and removes its own fixture after success. A failed run
retains the fixture for inspection. It injects writable files/directories, unknown
owners, setuid and capability files, then proves audit and verify preserve
contents, metadata and extended attributes. Explicitly approved privileged paths
pass without being modified. Entry-limit exhaustion produces a control error.

The storage fixture requires root in a KVM guest. It creates a fresh 128 MiB loop
image under a private temporary directory, confirms the backing filename before
formatting, tests plain and LUKS-backed ext4, and removes the mount, mapping, loop,
image and random key afterward. It does not format any existing disk.

The unchanged browser export is checked with the CLI and audited against the
target. On the accepted M11 target, the three filesystem reviews pass. Separate
/tmp, /var/tmp and /home mounts, root encryption and Secure Boot are absent.
Those are assessment findings, not false passes or authorized migration work.

Final executed results and source identity are recorded below after validation.

## Native references

- [util-linux mount behavior](https://man7.org/linux/man-pages/man8/mount.8.html).
- [util-linux findmnt behavior](https://man7.org/linux/man-pages/man8/findmnt.8.html).
- [Kernel device-mapper crypt target](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html).
