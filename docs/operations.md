# Disposable guest operations

Development and testing are separate guests. The tested lab uses Rocky 10.2
minimal x86_64, BIOS boot, virtio disk/network, SELinux enforcing, and the
default libvirt NAT network. Development uses 2 vCPUs, 4 GiB RAM, and a 30 GiB
qcow2 disk. The test guest uses 2 vCPUs, 2 GiB RAM, and a 20 GiB qcow2 disk.

Installation media: `Rocky-10.2-x86_64-minimal.iso`.
SHA-256: `aac6ac3ce781b91a91ce78463405f66c611a5dca4b3840c79e5e01d97302f6c8`.
The local ISO matched its supplied checksum. An independent signature check
of the installation media was not performed.

SSH and sudo are prepared inside the guests. Host administration is limited
to VM lifecycle, console, disks, and snapshots. Never install or run the
hardening framework on the hypervisor.

## Recovery

The following commands are manual hypervisor management, outside the framework.
Replace the example VM and snapshot names only after verifying the intended VM.

1. Shut down the test guest cleanly using `sudo shutdown -h now` inside it.
2. On the hypervisor, confirm `virsh -c qemu:///system domstate rocky10-test`
   reports `shut off`.
3. Create a baseline with
   `virsh -c qemu:///system snapshot-create-as rocky10-test clean-m0`.
4. Start it with `virsh -c qemu:///system start rocky10-test`.
5. Exercise console login using
   `virsh -c qemu:///system console rocky10-test`.
   Verify administrative access with `sudo -n id -u`. Detach using Ctrl+].
6. Create a disposable marker inside the guest. Shut it down cleanly again.
7. Restore with
   `virsh -c qemu:///system snapshot-revert rocky10-test clean-m0`,
   start the guest, and verify the marker is absent and SSH still works.

Reset only the test guest. Development and reports remain in the development
guest. Restoring a snapshot discards all guest changes since that snapshot.

## Failure handling

A failed preflight must leave controls untouched. Fix the named prerequisite
and rerun. Preflight checks precede audit and verification too.

A control error may follow a partial change. Inspect the affected metadata
before retrying. Restore the recorded owner/group/mode manually or reset the
disposable guest to its known snapshot. There is no automatic OS rollback.

Read-only modes do not change managed configuration. SSH, sudo, and Ansible
can still create ordinary authentication logs and transient execution files.

The laboratory sudo setup is for disposable guests. Production authentication
design and access-changing controls are outside this milestone. Credentials,
private keys, runtime inventories, and generated reports are excluded from Git.
