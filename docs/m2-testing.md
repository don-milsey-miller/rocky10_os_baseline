# Reproduce the five-control guest tests

Use a separate Rocky Linux 10.2 minimal KVM server guest with verified SSH
host keys and working sudo. Take and test a snapshot first. The development
guest needs the normal test dependencies and `rpm-build`.

Build two empty, independently authored test RPMs on the development guest:

```bash
sudo dnf install -y rpm-build
source .venv/bin/activate
mkdir -p reports/m2-fixtures
rpmbuild --define "_topdir $PWD/reports/m2-fixtures" -bb tests/fixtures/hardener-test-dependent.spec
rpmbuild --define "_topdir $PWD/reports/m2-fixtures" -bb tests/fixtures/hardener-signature-probe.spec
```

Copy the resulting noarch RPMs to `/home/zero/m2-fixtures/` on the disposable
test guest. The harness uses this fixed fixture path. Install the signed
distribution `telnet` package on that guest using DNF. Shut it down cleanly,
take a `m2-test-ready` snapshot through libvirt, and restart it.

Run from the development guest's checkout:

```bash
pytest -q
ruff check hardener tests
ruff format --check hardener tests
ansible-playbook -i inventory.example.ini hardener/data/ansible/run.yml --syntax-check -e hardener_target=test-vm
python tests/integration/vs1.py --inventory inventory.local.ini --target test-vm --disposable
python tests/integration/vs2.py --inventory inventory.local.ini --target test-vm --disposable
```

VS2 deliberately changes account-file mode, hard-link protection, the DNF
setting, and debug-shell state. The temporary debug shell is unauthenticated,
so use only the isolated disposable guest. The harness stops that service
even when a test fails. It also reboots the guest and waits for a new boot ID.

The suite checks five initial failures, five verified remediations, zero
changes on the second apply, unsigned RPM rejection, preservation of unrelated
state, each individual exclusion, omission, and reboot persistence.
It also confirms that a later sysctl conflict, ambiguous DNF configuration,
a custom debug-shell unit, and a Telnet-dependent package prevent all remediation.
A runtime-only service mask is upgraded to a persistent mask.

Runtime JSON/text evidence and exact commands are under `reports/m2/`.
Generated RPMs, inventories, and reports are not committed.
Unit tests cover schema dependencies/conflicts with synthetic catalog fixtures
because the five real controls are mutually compatible.

To reproduce from the same starting state, shut down the test guest,
restore `m2-test-ready`, restart it, and rerun VS2 with
`--output reports/m2-repeat`. Each run requires a new, empty output directory. A failed suite is not a
passing milestone. Inspect its partial reports or reset the snapshot before retrying.
