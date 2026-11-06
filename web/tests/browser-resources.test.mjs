import test from "node:test";
import assert from "node:assert/strict";
import { checkBrowserResources, requireBrowserMemory, MIN_HEADROOM_KIB } from "./browser-resources.mjs";

const sample = (available, swap) => `MemTotal: 977000 kB\nMemAvailable: ${available} kB\nSwapFree: ${swap} kB\n`;

test("a small no-swap runner is refused with an actionable diagnostic", () => {
  assert.throws(() => requireBrowserMemory(sample(150 * 1024, 0)), error => {
    assert.match(error.message, /2048 MiB/);
    assert.match(error.message, /150 MiB available RAM and 0 MiB free swap/);
    assert.match(error.message, /provision 2 GiB swap/);
    assert.match(error.message, /No browser was started/);
    return true;
  });
});
test("a small runner with free swap meets the budget", () => {
  assert.deepEqual(requireBrowserMemory(sample(450 * 1024, 2 * 1024 * 1024)),
    { MemAvailable: 450 * 1024, SwapFree: 2 * 1024 * 1024 });
});
test("a sufficiently free RAM-only runner needs no swap", () => {
  assert.doesNotThrow(() => requireBrowserMemory(sample(3 * 1024 * 1024, 0)));
});
test("the exact admission boundary passes", () => {
  assert.doesNotThrow(() => requireBrowserMemory(sample(MIN_HEADROOM_KIB / 2, MIN_HEADROOM_KIB / 2)));
});
test("one KiB below the admission boundary fails", () => {
  assert.throws(() => requireBrowserMemory(sample(MIN_HEADROOM_KIB - 1, 0)), /require at least/);
});
test("allocated but consumed swap does not count as headroom", () => {
  assert.throws(() => requireBrowserMemory(sample(500 * 1024, 0) + "SwapTotal: 4194304 kB\n"), /require at least/);
});
test("reclaimable memory is counted through MemAvailable rather than MemFree", () => {
  assert.doesNotThrow(() => requireBrowserMemory(sample(MIN_HEADROOM_KIB, 0) + "MemFree: 100 kB\n"));
});
for (const [name, input] of [
  ["missing available RAM", "SwapFree: 0 kB\n"],
  ["missing free swap", "MemAvailable: 3000000 kB\n"],
  ["negative memory", sample(-1, 3000000)],
  ["nonnumeric memory", sample("NaN", 3000000)],
  ["unsafe integer", sample("9007199254740992", 0)],
  ["duplicate field", sample(3000000, 0) + "SwapFree: 0 kB\n"],
  ["wrong units", "MemAvailable: 3 GiB\nSwapFree: 0 kB\n"]
]) {
  test(`${name} fails closed`, () => assert.throws(() => requireBrowserMemory(input), /Cannot determine/));
}
test("unreadable Linux memory data fails closed", () => {
  assert.throws(() => checkBrowserResources({ platform: "linux", readMeminfo() { throw new Error("denied"); } }), /Cannot read \/proc\/meminfo/);
});
test("Linux setup evaluates the observed budget", () => {
  assert.throws(() => checkBrowserResources({ platform: "linux", readMeminfo: () => sample(100, 0) }), /require at least/);
});
test("non-Linux callers are explicitly unchecked and do not read procfs", () => {
  assert.equal(checkBrowserResources({ platform: "darwin", readMeminfo() { assert.fail("unexpected procfs read"); } }), null);
});
