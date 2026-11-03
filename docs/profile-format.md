# Profile schema v1

The authoritative JSON Schemas are shipped in `hardener/data/schemas/`.
The CLI and offline editor use this same contract.

Required fields are `schema_version: 1`, a stable lowercase hyphenated `id`,
positive integer `revision`, `target`, and `controls`. A human-readable
`name` is optional. The target is exactly Rocky, major version 10, role server.

Each control has a project-owned `id` and a Boolean `enabled`. Optional
`parameters` must match the catalog entry's closed JSON Schema.
An optional `reason` is preserved in exclusion reports. Parameters may be bounded
scalars or lists. Site-specific values are required unless the catalog declares an
explicit default. Unknown parameters are errors. Excluded controls may omit parameters,
but any supplied values still validate. The editor uses one value per line for string lists.

Only explicitly enabled controls are eligible for changes. Disabled controls
are reported as excluded. Omitted controls do not run. Unimplemented controls
may appear as disabled entries but cannot be enabled. Dependencies must be
enabled explicitly, and conflicts fail validation. The CLI never adds controls
on the operator's behalf.

Profiles cannot specify task paths, commands, credentials, or extra fields.
Duplicate keys, aliases, unsafe YAML tags, duplicate/unknown control IDs,
unsupported targets, and files over 64 KiB are rejected before target contact.

The engine resolves dependencies before dependents, using ID order for ties. Reports preserve profile
order. The profile SHA-256 covers the exact input bytes, including comments
and formatting. Engine and catalog versions plus a source digest identify the
implementation used. Keep source and profiles in version control.

Examples: `profiles/examples/server-minimal.yaml` selects one control.
`profiles/examples/server-five-controls.yaml` selects the original five.
The general-server example keeps workload-dependent additions excluded.
The operations-lab example requires disposable fixtures and explicit site policies.

A profile can contain at most 128 control entries and remains limited to 64 KiB.
Assessment-only catalog entries declare `supported_modes: [audit, verify]`.
They can be exported and assessed, but selecting one for apply fails offline before
inventory access. Use a separate assessment profile when applying other controls.
