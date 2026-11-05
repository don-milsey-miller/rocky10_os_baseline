# Rocky Linux 10 OS baseline

**M9 in progress:** All eight network controls are validated. All 51 catalog controls passed combined verification after reboot. Three firewall controls remain planned. See the [validation record](docs/m9-routing-demonstration.md#validation-record).

An installable, profile-driven CLI for Rocky Linux 10 **KVM server guests**.
The catalog contains 51 controls covering account files, kernel safeguards, package
trust, optional services, time, local logging, SSH, sudo, and network policy. Each can be selected or excluded.
Security-update status is assessment-only. Other implemented controls support
independent audit, apply, and verification. See the [original controls](docs/m2-controls.md),
[M6 file and kernel controls](docs/m6-demonstration.md), and
[M7 operations controls](docs/m7-demonstration.md), and
[M8 access controls](docs/m8-demonstration.md), and
[M9 baseline network controls](docs/m9-demonstration.md), and
[M9 host routing policy](docs/m9-routing-demonstration.md) for behavior and recovery.

The project currently has **no license grant**, by owner decision. This is a
release candidate, not an open-source release or certification.
See [M4 checks and complete reproduction](docs/m4-release-readiness.md).

## Install on a development guest

Tested on Rocky Linux 10.2 x86_64, Python 3.12, Ansible Core 2.19.15.
Use a separate disposable test guest and a tested snapshot recovery path.

```bash
sudo dnf install -y git python3-pip
git clone --branch codex/m9-network-firewall https://github.com/don-milsey-miller/rocky10_os_baseline.git
cd rocky10_os_baseline
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-tested.txt
pip install --no-build-isolation -e '.[test]'
cp inventory.example.ini inventory.local.ini
# Edit inventory.local.ini with the test guest address and SSH user.
```

Use SSH keys and verified host keys. The inventory user needs working Ansible
privilege escalation. The disposable lab uses passwordless sudo.
Credentials belong in SSH/Ansible facilities, never in a profile or Git.
Inventory and Ansible plugins are trusted operator configuration, not
untrusted profile input.

## Run

```bash
hardener validate --profile profiles/examples/server-five-controls.yaml
hardener preflight --profile profiles/examples/server-five-controls.yaml --inventory inventory.local.ini --target test-vm --output reports/preflight
hardener audit --profile profiles/examples/server-five-controls.yaml --inventory inventory.local.ini --target test-vm --output reports/before
hardener apply --profile profiles/examples/server-five-controls.yaml --inventory inventory.local.ini --target test-vm --output reports/apply
hardener verify --profile profiles/examples/server-five-controls.yaml --inventory inventory.local.ini --target test-vm --output reports/after
hardener apply --profile profiles/examples/server-five-controls.yaml --inventory inventory.local.ini --target test-vm --output reports/second-apply
```

Every remote operation requires an inventory file, one literal inventory host,
and an output directory. Output directories contain `report.json` and
`summary.txt`. Reusing a directory replaces its report, so use a distinct
directory when retaining evidence.

Apply prints its target and selected controls, runs read-only preflight,
then remediates only explicitly enabled controls. Independent verification
runs after apply. For the account-file control, audit uses Ansible stat and
verification uses GNU stat.
Ansible task success alone never counts as verified compliance.

Preflight checks SSH, privilege escalation, Rocky 10, KVM guest identity,
explicit server role, multi-user boot target, DNF availability, and the
selected control's prerequisites. Bare metal targets are refused.
This release candidate supports KVM guests only.

## Tests

```bash
pytest -q
ruff check hardener tests web/prepare.py
ruff format --check hardener tests web/prepare.py
ansible-playbook -i inventory.example.ini hardener/data/ansible/run.yml --syntax-check -e hardener_target=test-vm

# Only after snapshotting a disposable guest. Temporarily changes /etc/passwd mode.
python tests/integration/vs1.py --inventory inventory.local.ini --target test-vm --disposable
```

The original integration test proves before/after state, independent verification,
idempotence, unchanged account-file content and unrelated state, explicit
exclusion, and preflight refusal for missing server role or privileges.
It restores mode 0644 on exit when SSH remains available. Snapshot recovery
is the fallback, not an automatic transaction.

Exit codes: **0** successful operation, **2** invalid profile/catalog/inventory,
**3** failed preflight, **4** execution/reporting failure, **5** unmet control
state in audit, apply verification, or verify. A successful preflight does
not mean controls are compliant.

Run the [five-control integration suite](docs/m2-testing.md) for per-control
exclusions, configuration conflicts, dependency refusal, unsigned RPM rejection,
and reboot persistence. The optional [local profile editor](web/README.md)
builds to one offline HTML file and exports YAML for this same CLI. See the
[M3 editor-to-engine demonstration](docs/m3-demonstration.md).

See [profile format](docs/profile-format.md), [operations](docs/operations.md),
[architecture and authoring](docs/architecture.md), and
[M2 demonstration evidence](docs/m2-demonstration.md).

High-impact apply/preflight requires a recent target-bound recovery receipt. Follow
[recovery enforcement](docs/recovery-enforcement.md) before running access-changing profiles.
Audit and verify remain available without recovery evidence.
