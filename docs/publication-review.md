# Publication review

The owner requested that the project remain unlicensed. No project license
is granted, and no open-source release or certification is claimed.
The M4 output is a tagged evaluation candidate in the already public repository.

## Source and assets

The source, catalog descriptions, schemas, tests, and documentation were
independently authored for this project. Primary API documentation was
consulted for tool behavior. No external guide, PDF, control table, numbering
crosswalk, credential file, source specification, or local instruction file
is included in the published tree.

M4 checks the tracked source, wheel, and source distribution for private
inventory paths, VM images, keys, reports, and common credential patterns.
The release review also scans historical Git blobs. These checks supplement
diff review and cannot prove absence of every possible secret.

Examples contain target placeholders and declarative control selections.
Runtime inventories and VM evidence stay outside Git. Candidate CI artifacts
contain no target inventory or VM reports.

## Dependencies

Python runtime and development dependencies are pinned in
`requirements-tested.txt`. Their installed metadata is recorded in
`dependency-licenses.json`, including the build backend. They are installed
separately and are not vendored into the project's wheel.

The editor lockfile's dependencies and licenses are recorded in
`web-dependency-licenses.json`. Build inspection identifies Ajv and YAML
as the only dependencies bundled into the standalone HTML. Their MIT license
texts and copyright notices are preserved in the HTML and in
`THIRD-PARTY-NOTICES.txt`. Build and browser-test tools are not bundled.
The browser binary is downloaded separately by the test tooling.

GitHub Actions are pinned to reviewed repository commits in the workflow.
Official action usage documentation is available from
[checkout](https://github.com/actions/checkout),
[setup-python](https://github.com/actions/setup-python),
[setup-node](https://github.com/actions/setup-node), and
[upload-artifact](https://github.com/actions/upload-artifact).

This is an engineering source, asset, and dependency review. It is not an
independent legal opinion or a grant of rights over dependencies. The owner's
decision to withhold a project license remains in effect. A future general
open-source release or broader dependency redistribution requires its own
license decision and review.
