import { defineConfig } from "@playwright/test";
export default defineConfig({
  globalSetup:"./tests/browser-resources.mjs",
  testDir:"./tests/browser", workers:1, fullyParallel:false,
  use:{browserName:"chromium",headless:true,viewport:{width:1440,height:1100}},
  reporter:[["list"]], timeout:30000
});
