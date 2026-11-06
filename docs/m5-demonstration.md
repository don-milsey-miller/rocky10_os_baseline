# M5 engine prerequisites

Version 0.5.0rc1. Implemented and validated on 2026-11-03 in Rocky 10 KVM guests.

## Behavior

The CLI resolves explicit parameter values over catalog defaults into a separate
effective_parameters object. Defaults are copied, typed, and validated without
mutating profile input or catalog schemas. Explicit zero and false survive.
Selected controls require site policy when no default exists. Excluded controls
may omit parameters. Supplied excluded parameters must still validate.

Dependencies execute before dependents in deterministic order. Offline validation
rejects cycles and missing selected dependencies. Apply skips direct and transitive
dependents after execution or verification failure. Independent controls can
continue. Loss of administrative access stops further writes. Missing evidence,
unsupported controls, and non-preflight skips cannot produce a success exit.

Platform, SSH, privilege, and server-role guards still apply to every remote
operation. Remediation-specific file/configuration checks run for preflight and
apply. Audit and verify inspect target state without inheriting apply-only
refusals. Control tasks retain responsibility for reporting unavailable features
and effective restart/reboot state when those behaviors are introduced.

The profile selection bound is now 128. The 64 KiB input bound is unchanged.
The editor shares default resolution and cycle detection behavior. Wheel smoke
tests compare the installed catalog IDs with the checkout instead of assuming
five entries. Existing five-control examples and behaviors remain unchanged.

## Validation

- 76 Python unit/schema/report tests passed.
- 30 editor unit tests and six browser tests passed.
- Ruff, Ansible syntax, clean wheel installation, and release asset checks passed.
- VS1, VS2, VS4, and VS5 passed, including exclusions, refusal before writes,
  independent verification, reboot persistence, and partial-failure recovery.
- The M5 fixture passed first against the existing disposable guest and again
  after restoring m4-rc1-verified. The final run also injected an administrative
  access-probe failure into the temporary engine and proved no further writes.

The fixture uses a temporary engine copy and a temporary directory on the test
guest. It does not add production test switches or artificial catalog controls.
It verifies defaults, explicit zero/false, no-change reruns, dependency execution
failure, failed prerequisite verification, transitive skips, independent-control
execution, recovery, and administrative-access refusal.

Private evidence is in reports/m5/ on the development guest. The complete
regression command logs are in reports/m5/regression/. Final fixture reports
and log are in reports/m5/engine-from-snapshot/ and
reports/m5/engine-from-snapshot.log. Inventories and runtime reports stay out of Git.

## Reproduce

Run from the development guest repository with its virtual environment active.
Use a separate snapshotted test guest, verified SSH keys, working sudo, and a
tested console recovery path.

```bash
pytest -q
ruff check hardener tests web/prepare.py
ruff format --check hardener tests web/prepare.py
ansible-playbook -i inventory.example.ini hardener/data/ansible/run.yml --syntax-check -e hardener_target=test-vm
python tests/integration/m5.py --inventory inventory.local.ini --target test-vm --output reports/m5-new --disposable
```

Use the existing [M4 reproduction](m4-release-readiness.md) for the original
regression suites and package/editor checks. VS2 needs the existing fixture RPMs
and the Telnet package installed before its initial audit.

## Next batch

M6 begins with /etc/group root:root 0644, /etc/shadow and /etc/gshadow root:root
0000, fs.protected_symlinks=1, kernel.randomize_va_space=2, and fs.suid_dumpable=0.
The file modes match the inspected Rocky guest defaults. The kernel settings
are explicit hardening choices. Content and unrelated configuration must remain
unchanged. Remaining M6 conditional controls follow their individual guest tests.

Default application is deliberately implemented by the framework because JSON
Schema validation does not insert defaults.
[jsonschema default behavior](https://python-jsonschema.readthedocs.io/en/stable/faq/#why-doesn-t-my-schema-s-default-property-set-the-default-on-my-instance)

Ansible blocks can isolate task errors, but unreachable hosts leave the active
host set. The callback retains error evidence in either case.
[Ansible error handling](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_error_handling.html)
