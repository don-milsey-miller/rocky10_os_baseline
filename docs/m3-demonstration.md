# M3 editor-to-engine demonstration

Executed on 2026-11-03 using the Rocky 10 development and disposable test guests.
Development, builds, unit tests, browser tests, and CLI execution ran in guests.
The hypervisor's operating system was not a hardening target.

## Delivered behavior

The local editor builds from the engine's authoritative catalog and profile
schema. It offers search and filters, three selection states, exclusions with
reasons, validation and warnings, typed parameter fields, YAML import, and
deterministic export. Its standalone HTML runs offline without server access.
The engine remains independently usable.

The current five controls are fixed-setting policies. VS4 therefore selects
three controls without parameters. Typed parameters, unsupported controls,
dependencies, conflicts, and high-impact warnings are covered by isolated
browser fixtures and unit tests, not invented production controls.

## Evidence

- 59 Python tests passed, along with Ruff and Ansible syntax checks.
- 26 editor unit tests passed.
- Six Chromium browser tests passed, including an offline `file://` run.
- Desktop (1440 pixels) and mobile (390 pixels) layouts were inspected.
- Browser export and import/re-export produced identical bytes.
- Two builds from the same sources produced the same HTML digest.
- Runtime dependency notices are present and content-security-policy hashes
  match the exact embedded script and style.

The downloaded profile enables account-file permissions, hard-link protection,
and disabling the debug console. It excludes Telnet removal with a reason and
omits the local RPM signature control.

The exact downloaded profile SHA-256 is:

```text
05d0443c7f2d179734aec3eab18f207e1a1970f0e4b58e86f02febca3ac10b88
```

VS4 first confirmed preflight and the verified M2 baseline, then changed only
the disposable guest's account-file mode to 0664. Audit detected one failing
control. Apply made one change. Independent verification passed all three
selected controls. A second apply reported zero changes. Account-file content,
unrelated group-file metadata, the excluded package state, and the omitted
DNF configuration remained unchanged. Reports retained the exclusion reason.
The profile bytes remained unchanged throughout the run.

## Reproduce

Use a disposable guest with a tested snapshot and console recovery path.
Start from a verified five-control M2 baseline. The integration script requires
an explicit disposable flag and restores account-file mode 0644 on exit while
SSH remains available. Snapshot recovery remains the fallback.

```bash
# Development guest, repository root, with the Python environment active:
cd web
npm ci --ignore-scripts
npm run build
npm test
npm run test:browser
cd ..
python tests/integration/vs4.py \
  --profile reports/m3/m3-browser-profile.yaml \
  --inventory inventory.local.ini --target test-vm --disposable
```

The browser test saves the profile and screenshots in `reports/m3/`.
VS4 saves JSON reports, readable summaries, command output, and
`integration-evidence.json` under `reports/m3/vs4/`.
Runtime artifacts and inventories are excluded from Git.

M3 does not change the five approved behaviors. Release readiness, CI,
fresh-checkout release smoke testing, and release publication remain M4.
No project license was added, as requested by the owner.
