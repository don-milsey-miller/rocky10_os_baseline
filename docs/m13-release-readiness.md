# M13 combined regression and release candidate

Candidate version: **0.13.0rc1**, annotated tag **v0.13.0rc1**.
The tag identifies the exact source accepted by the release matrix below. Its
annotation records the commit, runtime digest, CI URL and private evidence digest.
No release tag is issued until those gates pass on that commit.

The catalog covers all 102 agreed server IDs: 90 remediations and twelve
read-only assessments. The coverage test reconciles each catalog ID with exactly
one evidence-backed disposition in [control coverage](control-coverage.md).
No planned or silently omitted inventory entry remains. Assessment controls
cannot be selected for apply. The combined apply explicitly excludes all twelve.

## Reproduce the build

Use a Rocky Linux 10.2 x86_64 development KVM guest with Python 3.12 and Node 22.
Clone the tag into a fresh directory. Before tagging, use the candidate branch
and record its immutable commit. Never use an existing editable installation as
proof that the wheel works.

~~~bash
git clone --branch v0.13.0rc1 https://github.com/don-milsey-miller/rocky10_os_baseline.git
cd rocky10_os_baseline
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-tested.txt
pip install --no-build-isolation -e '.[test]'
pytest -q
ruff check hardener tests web/prepare.py
ruff format --check hardener tests web/prepare.py
ansible-playbook -i inventory.example.ini hardener/data/ansible/run.yml --syntax-check -e hardener_target=test-vm
ansible-playbook -i inventory.example.ini hardener/data/ansible/recovery.yml --syntax-check -e hardener_target=test-vm
(cd web && npm ci --ignore-scripts && npm run build && npm test)
(cd web && npx playwright install chromium --only-shell && npm run test:browser)
python -m build --no-isolation
python tests/integration/package_smoke.py
python tests/release_checks.py
python3 -m venv /home/zero/m13-wheel
/home/zero/m13-wheel/bin/pip install -r requirements-tested.txt
/home/zero/m13-wheel/bin/pip install --no-deps dist/*.whl
~~~

Install Chromium system libraries as described in the [editor instructions](../web/README.md).
The browser test imports the complete lab profile, excludes exactly the twelve
assessments, exports it, validates it with the CLI, and reimports the same bytes.
It saves reports/m13/browser-combined.yaml for guest acceptance.

## Disposable fixture and release matrix

The combined profile is an explicit lab fixture, not a production baseline or
a provisioner. It requires the approved [M6](m6-demonstration.md),
[M7](m7-demonstration.md), [M8](m8-demonstration.md),
[M9](m9-firewall-demonstration.md), [M10](m10-demonstration.md),
[M11](m11-demonstration.md) and [M12](m12-demonstration.md) prerequisites.
These include local test identities, a signed disposable repository, a private
dual-stack network, a separate authenticated TLS collector, an AIDE fixture,
dedicated temporary/home mounts, and external root/GRUB credentials.
Keep all private keys and credentials outside the checkout and evidence archive.

The accepted stopped-disk target snapshot is m12-accepted. Its existing native
behavior evidence remains linked from the family records. M13 reruns the combined
policy and the conditional suites listed below on the candidate runtime.
Restore m12-prepared for the M12 lifecycle and m12-accepted for combined runs.
Preserve the collector configuration when running older regressions on the
separate probe guest.

| Gate | Required result |
| --- | --- |
| Fresh-checkout Python, schema, static and editor tests | All pass on the candidate commit |
| Independent wheel | Packaged assets/digest match source, examples validate, guest execution imports from the wheel environment |
| Combined baseline audit/verify | 98 pass, exactly four named assessment findings, zero changes |
| Deliberate faults and exclusion | Account-file mode and hardlink faults are detected. Excluded faults stay unchanged. Selected remediation repairs both and preserves account-file contents |
| Complete remediation | All 90 pass, twelve explicit exclusions, zero changes on repeated apply |
| Unchanged browser YAML | Actual downloaded bytes execute in apply and verify without editing, with zero changes |
| Reboot and snapshot repetition | Complete state and fresh IPv4/IPv6 SSH/sudo survive reboot. Two independent restored-snapshot runs have equivalent outcomes |
| Recovery | Candidate runtime observes SSH outage and snapshot restoration, then issues a target-bound receipt |
| Conditional fixtures | M12 native lifecycle, unsafe-preflight and partial-failure suite, filesystem assessments and plain/LUKS storage fixture pass |
| Original regressions | VS1, VS2, VS4 and VS5 pass on the separate disposable guest |
| Publication | Tracked tree, full Git history, wheel, sdist, bundled notices and dependency inventories reviewed. GitHub checks pass on the tagged commit |

Get a new [recovery receipt](recovery-enforcement.md) using the wheel runtime.
The receipt must bind the same inventory bytes, target and runtime used below.
Changing the engine version changes the runtime digest and invalidates older receipts.

~~~bash
/home/zero/m13-wheel/bin/hardener recovery-test --inventory /absolute/inventory.local.m9.ini --target test-vm --output /absolute/reports/m13/recovery
# Observe RECOVERY_READY, stop target SSH from an existing session,
# wait for RECOVERY_OUTAGE_OBSERVED, then restore m12-accepted independently.
cd /tmp
/home/zero/m13-wheel/bin/python /absolute/checkout/tests/integration/m13.py --inventory /absolute/inventory.local.m9.ini --target test-vm --output /absolute/reports/m13/combined-a --recovery-evidence /absolute/reports/m13/recovery/recovery.json --disposable
# Independently restore m12-accepted and repeat with output combined-b.
~~~

The outside-checkout working directory prevents source-tree imports from masking
packaging defects. Each run records the imported package path, source commit,
engine digest, exact commands and browser-file hash. Unit tests make the report
gate reject omissions, duplicate IDs, unexpected findings, errors/skips,
hidden changes and stale runtimes.

Run the family and original regression commands from their linked records using
the candidate interpreter. Preserve distinct output directories. Reprepare each
suite's explicit prerequisites rather than treating fixture drift as a pass.
No failed, skipped or unexecuted suite is accepted.

## Findings and support limits

| Finding | Disposition |
| --- | --- |
| accounts.root-path-integrity | Lab root PATH has two missing directories. Assessment reports the finding. No automatic environment rewrite |
| selinux.no-unconfined-services | Two deliberate lab services are unconfined. Assessment retains the finding |
| storage.disk-encryption | Root filesystem is unencrypted. Encryption migration and key-management acceptance remain provisioning work |
| boot.secure-boot | Fixture boots BIOS. Firmware transition remains provisioning work |

These are expected findings, not control passes or a claim of universal hardening.
The gate rejects every additional finding and never permits a failed remediation.

Demonstrated support is Rocky 10.2 x86_64 KVM servers, local identities, SSH-only
dual-stack non-routing networking with firewalld ownership, BIOS boot, DEFAULT
crypto policy, the documented local filesystems and the approved test workloads.
Untested identity providers, UEFI/Secure Boot, other architectures, custom boot/PAM
stacks, remote/bind storage, routing/container workloads and FUTURE compatibility
are not established by this release. FIPS conversion, disk repartitioning,
encryption migration and active-driver removal remain outside automatic remediation.
Assessment scan roots and AIDE paths are explicit and do not claim whole-host coverage.

The project remains unlicensed by owner decision. This is a tagged evaluation
candidate, not an open-source license grant, certification, package-registry
publication, default-branch change or production deployment.
See [publication review](publication-review.md). Private inventories, raw guest
reports, recovery receipts and snapshots are retained separately. The project
journal records the final evidence archive hash and accepted snapshots.
