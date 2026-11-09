# Release candidate workflow

Candidate version: **0.4.0rc1**, Git tag **v0.4.0rc1**.
The editor's npm package uses the equivalent **0.4.0-rc.1** version.
The project remains unlicensed by owner decision. This is an evaluation
candidate, not a general open-source release or a certification claim.

## Checks and scope

The candidate adds failure/recovery tests, clean wheel installation checks,
release asset checks, pinned CI actions, dependency inventories, and repeatable
demo instructions. It fixes one report issue: a failed Ansible module that
reports a change now contributes to the changed-task count. Control behavior
and profile/report schemas remain unchanged.

GitHub Actions runs Python unit/schema/report tests, Ruff, Ansible syntax,
editor unit/browser tests, wheel installation, and release asset checks.
The workflow has read-only repository permissions, pinned action commits,
no target credentials, and no self-hosted runner. Its uploaded artifacts
contain only the wheel, source distribution, standalone editor, build manifest,
and bundled notices. These CI results do not represent VM integration.

## Fresh checkout

Start at the root of a fresh project checkout on a Rocky 10 development guest
with Python 3.12 and Node.js 22.

```bash
sudo dnf install -y git python3-pip nodejs nodejs-npm rpm-build
git switch --detach v0.4.0rc1
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-tested.txt
pip install --no-build-isolation -e '.[test]'
pytest -q
ruff check hardener tests web/prepare.py
ruff format --check hardener tests web/prepare.py
ansible-playbook -i inventory.example.ini hardener/data/ansible/run.yml --syntax-check -e hardener_target=test-vm
cd web
npm ci --ignore-scripts
npm run build
npm test
npx playwright install chromium --only-shell
npm run test:browser
cd ..
python -m build --no-isolation
python tests/integration/package_smoke.py
python tests/release_checks.py
```

Before the tag exists, use `--branch codex/m4-release-readiness` and record
`git rev-parse HEAD`. Install the Chromium system libraries listed in
[the editor instructions](../web/README.md). The wheel smoke test creates
a separate environment, installs the wheel without editable source linkage,
checks all catalog/task assets and examples, and compares the installed
engine digest with the checkout. The source distribution includes examples,
documentation, tests, and editor source.

## Disposable VM demonstration

Prepare a separate Rocky 10 KVM server with SSH host-key verification,
working sudo, and `hardener_role=server` in a private inventory.
Complete [console and snapshot recovery](operations.md) before any mutations.
Prepare the two empty test RPMs and the signed distribution Telnet package
as described in [M2 testing](m2-testing.md). Save this clean test state as
`m2-test-ready`. Restore it before repeating the complete demonstration.

Run from the new checkout, with its environment active:

```bash
cp inventory.example.ini inventory.local.ini
# Set only the disposable guest's address, user, and required SSH settings.
python tests/integration/vs1.py --inventory inventory.local.ini --target test-vm --disposable
python tests/integration/vs2.py --inventory inventory.local.ini --target test-vm --output reports/m4/vs2 --disposable
# Browser tests above saved this exact profile without manual editing:
python tests/integration/vs4.py --profile reports/m3/m3-browser-profile.yaml --inventory inventory.local.ini --target test-vm --disposable
python tests/integration/vs5.py --inventory inventory.local.ini --target test-vm --output reports/m4/vs5 --disposable
```

VS1 checks a permission fault, repair, idempotence, exclusions, and unsafe
role/privilege refusal. VS2 covers all five controls, conflicts and dependency
refusal, each exclusion, unsigned local package rejection, and a reboot.
VS4 executes the unchanged browser download. VS5 distinguishes an execution
error from noncompliance, retains known partial changes, verifies incomplete
effective state, repairs it, and confirms a no-change rerun.

VS5 injects failure into a temporary copy of the engine on the development
guest. It does not add a failure switch to production code. Its audit report
must contain one fail, one error, one pass, and two exclusions. Its partial
apply must contain one error, two passes, and two exclusions. It returns a
nonzero exit and does not claim global success. A separate unmodified
verification detects the incomplete kernel setting. The deliberately private
module error message must not appear in the report.

No high-impact or access-changing control is in the approved catalog, so
that portion of VS5 is not applicable. Role and privilege refusals must
preserve SSH and sudo. Serial-console login and snapshot-marker restoration
are recorded separately. The harness restores the original permission mode
and hard-link setting when SSH remains available. Snapshot recovery is the
fallback if access is lost.

## Tagging and evidence

After the exact candidate passes CI and the guest demonstration:

1. Inspect the tracked diff, full-history credential-pattern scan, distribution
   contents, and [publication review](publication-review.md).
2. Record the commit, CI URL, engine/catalog/profile digests, test commands,
   guest results, recovery evidence, artifact hashes, and known limits.
3. Create an annotated `v0.4.0rc1` tag on that tested commit and push it.
4. Keep inventories, credentials, VM reports, and guest snapshots outside Git.
   Save local deliverables and update the project journal.

The tag annotation and journal record the actual CI run and guest results.
A failed or unexecuted check must remain explicitly unresolved. No package
registry upload, production rollout, project-license grant, or default-branch
change is part of this candidate.
