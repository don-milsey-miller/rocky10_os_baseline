# Issue 5 browser-test resource validation

Validated on 2026-11-06 against main commit
`ef9cdba543945d9764c9b894463bf484379d8dd2` plus this PR's test-only changes.
All EC2 instances were `t2.micro` in `us-east-1`. No nested VMs or hardening
operations were used.

## Controlled reproduction

Two instances used the same Ubuntu 24.04 image (`ami-052355af2a014bd2c`),
source commit, Python dependencies, Node 22.23.4, Playwright 1.64.1 and single-worker
browser suite. One had no swap. The other had 2 GiB swap. Memory samples and
kernel/browser logs streamed to the operator machine before tests began.

| Original suite | No swap | 2 GiB swap |
| --- | --- | --- |
| Kernel OOM kills | 2 Chromium processes | 0 |
| Lowest sampled available RAM | 15.7 MiB | 113.7 MiB |
| Highest sampled swap usage | 0 | 394.2 MiB |
| Browser result | First test failed after Chromium was killed | All 16 passed |

The no-swap kernel log recorded `global_oom` and
`Out of memory: Killed process ... (chrome-headless)` at 13:51:04 and 13:51:05 UTC.
The failed VM was terminated after evidence collection, without waiting for the
remaining tests. Memory exhaustion is confirmed in this repeat. The original
unlogged incident is not retrospectively diagnosed beyond this reproduced failure.

## Fix

Playwright global setup reads Linux `MemAvailable` and `SwapFree` before launching
Chromium. It requires at least 2 GiB combined available RAM and free swap. A refusal
reports the observed values and advises freeing memory, using a larger runner, or
provisioning 2 GiB swap on a disposable 1 GiB test VM. The setup makes no system
changes. Both npm and direct Playwright invocation use the check.

The 2 GiB threshold is a conservative admission budget, not a measured universal
minimum. It cannot guarantee against later memory pressure. Container limits are
not inspected. Non-Linux systems emit an explicit unchecked-resource warning and
retain their previous behavior.

## Validation of the fix

The same source changes were exercised on Ubuntu 24.04 and official Rocky Linux
10.2 (`ami-02cfb13d4cf8b7b77`), each directly on a `t2.micro` with 2 GiB swap.

| Check | Ubuntu 24.04 | Rocky Linux 10.2 |
| --- | --- | --- |
| Editor unit tests, including 17 new resource checks | 48 passed | 48 passed |
| Full browser suite | 16 passed, 74.335 seconds | 16 passed, 92.590 seconds |
| Source/wheel build and release asset checks | Passed | Passed |
| Built editor compared with the unmodified build | Identical SHA-256 | Identical SHA-256 |
| npm invocation after disabling swap | Exit 1, 1.525 seconds | Exit 1, 1.424 seconds |
| Direct Playwright invocation without swap | Exit 1, 1.974 seconds | Exit 1, 1.931 seconds |
| Browser processes after refusal | 0 | 0 |
| New kernel OOM kills during refusal | 0 | 0 |
| Fresh SSH and sudo after refusal | Passed | Passed |

Unit tests cover the admission boundary, available versus allocated swap,
reclaimable memory, missing/malformed/duplicate fields, invalid numeric values,
unreadable Linux memory data and the explicit non-Linux path.

Only the browser test harness and its documentation change. The hardening engine,
control catalog, profiles and generated editor are unchanged. EC2 target support
is not added. Private logs, supplemental host checks and evidence hashes are
recorded in the project journal and the PR validation summary.

## Reproduce validation

Install the project's pinned Python dependencies and Node 22, then follow
[the editor setup instructions](../web/README.md#tests). On disposable Linux test
VMs, run the full suite with adequate free RAM/swap. After the suite exits, disable
only the test VM's swap and rerun `npm run test:browser` and `npx playwright test`.
Both commands must refuse with exit 1 before any Chromium process starts. Preserve
kernel logs and verify SSH/sudo and the kernel `oom_kill` counter remain healthy.

The resource fields follow the
[Linux procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).
The entry point uses
[Playwright global setup](https://playwright.dev/docs/test-global-setup-teardown).
