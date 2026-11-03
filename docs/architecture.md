# Architecture and control authoring

`hardener/validation.py` validates YAML, schemas, catalog metadata, references,
dependencies, and conflicts without contacting a target.
`hardener/cli.py` selects exactly one inventory host and invokes Ansible
as a subprocess. `hardener/reporting.py` creates JSON and text reports.

Schemas, original control metadata, and Ansible tasks are package data, so
a wheel installation works outside the source checkout. There is no web,
provisioning, database, or remote job service in this milestone.

Each catalog entry declares original intent, rationale, benefit, trade-off,
platform, impact, dependencies, conflicts, parameter schema, reboot requirement,
availability, and task references. References must remain within the packaged
task directory and point to existing files.

Implemented controls require separate audit, apply, and verify task files.
Audit and verify must inspect effective state without invoking mutation
handlers. Apply must be idempotent. Verification must run after apply and
cannot infer compliance from the changed flag. Failures must produce partial
evidence and nonzero exit codes. Do not enable a control until its VM tests pass.

The callback emits only controlled facts, control evidence, change counts,
and task names. It drops raw module messages, inventory values, and stderr
from reports. Error task names identify the failed prerequisite. To diagnose
an environmental failure, reproduce the named check with trusted Ansible
configuration, without publishing raw diagnostics.

The first control requires a regular, single-link /etc/passwd. It does not
edit file contents, ACL policy, account entries, password files, or other
permissions. It has no service restart or reboot requirement.

Original implementation references:
- [Ansible file module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/file_module.html)
- [Ansible stat module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/stat_module.html)
- [Ansible callback API](https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_plugins.html)

A null changed value means change evidence is unavailable after an error.
It must not be interpreted as a no-change result.

The additional M2 controls and their configuration boundaries are described in
[m2-controls.md](m2-controls.md). Read-only filter helpers interpret ordered
sysctl output and reject ambiguous DNF edits. No additional runtime dependency
or service was introduced.
