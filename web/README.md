# Local profile editor

Build on the development guest with Node.js 22 and the project's Python environment:

```bash
# From the repository root, after installing the Python project:
cd web
npm ci --ignore-scripts
npm run build
```

Open `web/dist/index.html` directly in a modern browser. Copying that one file
is sufficient. It contains the catalog, validation code, styles, and dependency
notices. No web server, network connection, account, or database is required.
The browser never connects to a target or runs the CLI. Drafts stay in memory.
Export YAML before closing or reloading the page.

The build reads the engine's catalog and profile schema using `prepare.py`.
It compiles JSON Schema validators ahead of time and bundles dependencies.
It does not fetch runtime assets. Rebuild after changing the catalog or schema.
`dist/build-manifest.json` records the engine version, catalog digest, HTML
digest, and bundled dependency names. `HARDENER_PYTHON` can override the default
`../.venv/bin/python` build interpreter.

## Editing profiles

1. Search or filter the catalog and inspect benefits, trade-offs, and requirements.
2. Choose **Include**, **Exclude**, or **Not selected** for each control.
   Exclusions may retain a reason. Nothing is included automatically.
3. Set a stable ID, optional name, and positive integer revision.
4. Resolve validation errors, review warnings, and export YAML.
5. Independently validate the exact file with `hardener validate --profile FILE`.

Import accepts a local YAML file or pasted YAML. Invalid imports leave the
current draft unchanged. Export sorts controls by ID and parameter keys
alphabetically. Include/exclude state, explicit parameter values, and reasons
round-trip. Comments and input formatting are not preserved.
The editor accepts only schema v1 Rocky 10 server profiles. Unknown fields,
duplicates, aliases, custom tags, incompatible controls, and oversized YAML
are rejected. For predictable browser parsing, input is capped at 64 KiB,
YAML directives are refused, and integers must fit JavaScript's safe integer
range. The CLI remains the validation authority.

The five approved controls have fixed settings, so they expose no parameters.
Scalar string, number, integer, boolean, and enum fields are generated from
parameter schemas. Synthetic test fixtures exercise these paths without
adding policy to the shipped catalog. Defaults are hints, not silently stored
values. Structured parameters can be edited in YAML and imported.

## Tests

```bash
npm run build
npm test
npx playwright install chromium --only-shell
npm run test:browser
```

### Browser-test resources

The single-worker browser suite checks Linux memory before launching Chromium,
including when invoked directly with `npx playwright test`. It requires at least
2 GiB combined **currently available RAM plus free swap** (`MemAvailable` +
`SwapFree` in `/proc/meminfo`). Installed RAM or allocated but used swap does not
satisfy this check. Missing or unreadable Linux memory data stops the run.

For a disposable 1 GiB test VM, provision 2 GiB swap before running the suite, or
use a larger runner with sufficient available memory. The check only reads state.
It does not configure swap or change the host. Use `free -m` to inspect resources.

This is a conservative admission budget for the tested Linux VM configuration,
not a guarantee against other processes consuming memory later. Container memory
limits are not measured. On other operating systems, the check emits a warning
and preserves the existing test behavior. It does not change the built editor or
hardening target support. See [the EC2 validation record](../docs/issue5-browser-resources.md).

On the tested Rocky 10 development guest, headless Chromium requires these OS
packages in addition to Node.js:

```bash
sudo dnf install -y nss nspr atk at-spi2-atk cups-libs libdrm \
  libXcomposite libXdamage libXrandr libgbm pango alsa-lib libxkbcommon
```

Browser tests open the built file using `file://`, test offline operation,
save an actual download, compare its semantics with a manually constructed
profile, run CLI validation, and import/re-export the same bytes.
They also check mobile layout, literal rendering of untrusted text, validation
errors, filters, unavailable controls, warnings, dependencies, and parameters.

Artifacts go to ignored `reports/m3/` and browser test results to ignored
`web/test-results/`. The test-only modified catalog stays under
`web/.generated/` and is never included in the shipped HTML.

See [the guest demonstration](../docs/m3-demonstration.md) for VS4 execution.
The project remains unlicensed. Bundled YAML and Ajv code retain their own
licenses, embedded in the HTML and copied to `dist/THIRD-PARTY-NOTICES.txt`.
