import { readFileSync } from "node:fs";

// Conservative admission budget for the existing single-worker Linux suite.
export const MIN_HEADROOM_KIB = 2 * 1024 * 1024;

export function requireBrowserMemory(meminfo) {
  const fields = {};
  for (const key of ["MemAvailable", "SwapFree"]) {
    const lines = meminfo.split("\n").filter(line => line.startsWith(`${key}:`));
    const match = lines[0]?.trim().match(new RegExp(`^${key}:\\s+(\\d+)\\s+kB$`));
    const value = match ? Number(match[1]) : NaN;
    if (lines.length !== 1 || !Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Cannot determine browser-test resources: invalid ${key} in /proc/meminfo.`);
    }
    fields[key] = value;
  }
  if (fields.MemAvailable + fields.SwapFree < MIN_HEADROOM_KIB) {
    throw new Error(
      "Browser tests require at least 2048 MiB of available RAM plus free swap " +
      `before Chromium starts. Detected ${Math.floor(fields.MemAvailable / 1024)} MiB ` +
      `available RAM and ${Math.floor(fields.SwapFree / 1024)} MiB free swap. ` +
      "Free memory, use a larger runner, or provision 2 GiB swap on a disposable " +
      "1 GiB test VM. See web/README.md. No browser was started."
    );
  }
  return fields;
}

export function checkBrowserResources({
  platform = process.platform,
  readMeminfo = () => readFileSync("/proc/meminfo", "utf8")
} = {}) {
  // Preserve existing behavior on other operating systems without claiming a check.
  if (platform !== "linux") return null;
  let meminfo;
  try {
    meminfo = readMeminfo();
  } catch (cause) {
    throw new Error("Cannot read /proc/meminfo for browser-test resource preflight.", { cause });
  }
  return requireBrowserMemory(meminfo);
}

export default function browserResourceSetup() {
  const memory = checkBrowserResources();
  if (memory === null) {
    console.warn("Browser memory preflight is Linux-only. Resources were not checked on this OS.");
    return;
  }
  console.log(
    `Browser resources: ${Math.floor(memory.MemAvailable / 1024)} MiB available RAM, ` +
    `${Math.floor(memory.SwapFree / 1024)} MiB free swap.`
  );
}
