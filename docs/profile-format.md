# Profile schema v1

The authoritative JSON Schemas are shipped in `hardener/data/schemas/`.
The CLI and future editor must use this same contract. The editor does not
exist in this milestone.

Required fields are `schema_version: 1`, a stable lowercase hyphenated `id`,
positive integer `revision`, `target`, and `controls`. A human-readable
`name` is optional. The target is exactly Rocky, major version 10, role server.

Each control has a project-owned `id` and a Boolean `enabled`. Optional
`parameters` must match the catalog entry's closed JSON Schema.
An optional `reason` is preserved in exclusion reports. All current controls
have no configurable parameters. Unknown parameters are errors.

Only explicitly enabled controls are eligible for changes. Disabled controls
are reported as excluded. Omitted controls do not run. Unimplemented controls
may appear as disabled entries but cannot be enabled. Dependencies must be
enabled explicitly, and conflicts fail validation. The CLI never adds controls
on the operator's behalf.

Profiles cannot specify task paths, commands, credentials, or extra fields.
Duplicate keys, aliases, unsafe YAML tags, duplicate/unknown control IDs,
unsupported targets, and files over 64 KiB are rejected before target contact.

The engine resolves enabled controls in ID order. Reports preserve profile
order. The profile SHA-256 covers the exact input bytes, including comments
and formatting. Engine and catalog versions plus a source digest identify the
implementation used. Keep source and profiles in version control.

Example: `profiles/examples/server-minimal.yaml`.
