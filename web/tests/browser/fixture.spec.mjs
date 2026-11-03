import { test, expect } from "@playwright/test";
import { build } from "esbuild";
import Ajv2020 from "ajv/dist/2020.js";
import standaloneCode from "ajv/dist/standalone/index.js";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import path from "node:path";

// Test-only catalog mutations exercise UI paths without inventing approved controls.
test.beforeAll(async()=>{
  const schema={type:"object",additionalProperties:false,required:["count"],properties:{
    count:{type:"integer",minimum:1,maximum:10,title:"Count"},
    strict:{type:"boolean"},mode:{enum:["one","two"]},label:{type:"string",maxLength:20}}};
  const ajv=new Ajv2020({code:{source:true,esm:true}});
  await writeFile(".generated/fixture-validator.mjs",standaloneCode(ajv,ajv.compile(schema)));
  const source=`
    import {data} from "./src/core.mjs";
    import {parameterValidators} from "./.generated/validators.mjs";
    import check from "./.generated/fixture-validator.mjs";
    data.controls.find(c=>c.id==="files.passwd-permissions").parameters=${JSON.stringify(schema)};
    parameterValidators[data.controls.find(c=>c.id==="files.passwd-permissions").id]=check;
    data.controls.find(c=>c.id==="kernel.protected-hardlinks").implemented=false;
    data.controls.find(c=>c.id==="packages.local-signature-check").applies_to.major_version=9;
    data.controls.find(c=>c.id==="packages.telnet-client-absent").requires=[data.controls.find(c=>c.id==="services.debug-shell-disabled").id];
    data.controls.find(c=>c.id==="packages.telnet-client-absent").conflicts_with=[data.controls.find(c=>c.id==="files.passwd-permissions").id];
    data.controls.find(c=>c.id==="packages.telnet-client-absent").impact="high";
    data.controls.find(c=>c.id==="packages.telnet-client-absent").impact_note="Test-only high-impact warning";
    import("./src/app.mjs");
  `;
  const result=await build({stdin:{contents:source,resolveDir:process.cwd()},
    bundle:true,format:"iife",write:false,platform:"browser"});
  const script=result.outputFiles[0].text.replace(/<\/script/gi,"<\\/script");
  const style=await readFile("src/style.css","utf8");
  const hash=s=>createHash("sha256").update(s).digest("base64");
  const csp="default-src 'none'; script-src 'sha256-"+hash(script)+"'; style-src 'sha256-"+hash(style)+"'; connect-src 'none'";
  const html=(await readFile("src/index.html","utf8")).replace("{{CSP}}",csp)
    .replace("{{STYLE}}",()=>style).replace("{{SCRIPT}}",()=>script).replace("{{NOTICES}}","");
  await writeFile(".generated/fixture.html",html);
});
const url=()=>pathToFileURL(path.resolve(".generated/fixture.html")).href;
const selection=(page,id)=>page.locator('select[data-control="'+id+'"]');
test("unimplemented and inapplicable controls cannot be included",async({page})=>{
  await page.goto(url());
  for(const id of ["kernel.protected-hardlinks","packages.local-signature-check"]) {
    const control=selection(page,id);
    await expect(control.locator('option[value="enabled"]')).toHaveAttribute("disabled", "");
    await control.selectOption("excluded");
    await expect(control).toHaveValue("excluded");
  }
  await page.locator("#availability").selectOption("unavailable");
  await expect(page.locator(".control-card")).toHaveCount(2);
});
test("parameters, dependencies, conflicts and warnings block or permit export",async({page})=>{
  await page.goto(url());
  await selection(page,"files.passwd-permissions").selectOption("enabled");
  await expect(page.locator("#export")).toBeDisabled();
  await page.getByLabel("Protect account-file permissions: count").fill("3");
  await page.getByLabel("Protect account-file permissions: strict").selectOption("false");
  await page.getByLabel("Protect account-file permissions: mode").selectOption("1");
  await page.getByLabel("Protect account-file permissions: label").fill("on");
  await expect(page.locator("#export")).toBeEnabled();
  const original=await page.locator("#yaml-preview").inputValue();
  await page.locator("#open-import").click();
  await page.locator("#import-text").fill(original);
  await page.locator("#confirm-import").click();
  await expect(page.getByLabel("Protect account-file permissions: count")).toHaveValue("3");
  await expect(page.getByLabel("Protect account-file permissions: strict")).toHaveValue("false");
  await expect(page.locator("#yaml-preview")).toHaveValue(original);
  await selection(page,"packages.telnet-client-absent").selectOption("enabled");
  await expect(page.locator("#validation")).toContainText("requires services.debug-shell-disabled");
  await expect(page.locator("#validation")).toContainText("conflicts with files.passwd-permissions");
  await expect(page.locator("#validation")).toContainText("Test-only high-impact warning");
  await expect(page.locator("#export")).toBeDisabled();
  await selection(page,"files.passwd-permissions").selectOption("omit");
  await selection(page,"services.debug-shell-disabled").selectOption("enabled");
  await expect(page.locator("#export")).toBeEnabled();
  await expect(page.locator("#validation")).toContainText("Test-only high-impact warning");
});
