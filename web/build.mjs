import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import standaloneCode from "ajv/dist/standalone/index.js";
import { build } from "esbuild";

const root = path.dirname(fileURLToPath(import.meta.url));
process.chdir(root);
const python = process.env.HARDENER_PYTHON || "../.venv/bin/python";
const prep = spawnSync(python, ["prepare.py"], { stdio: "inherit" });
if (prep.status !== 0) throw new Error("Catalog preparation failed");
const data = JSON.parse(await readFile(".generated/catalog.json", "utf8"));
const ajv = new Ajv2020({ allErrors: true, ownProperties: true, strict: false,
  code: { source: true, esm: true } });
ajv.addSchema(data.profileSchema, "profile");
const exports = { profileValidator: "profile" };
data.controls.forEach((control, index) => {
  const key = "parameters" + index;
  ajv.addSchema(control.parameters, key);
  exports[key] = key;
});
let validators = standaloneCode(ajv, exports);
validators += "\nexport const parameterValidators = {\n" +
  data.controls.map((control, index) =>
    JSON.stringify(control.id) + ": parameters" + index).join(",\n") + "\n};\n";
const validatorBundle = await build({
  stdin: { contents: validators, resolveDir: root, sourcefile: "validators.mjs" },
  bundle: true, format: "esm", platform: "browser", write: false, metafile: true
});
await writeFile(".generated/validators.mjs", validatorBundle.outputFiles[0].text);
await mkdir("dist", { recursive: true });
const result = await build({ entryPoints: ["src/app.mjs"], bundle: true, write: false,
  outfile: "editor.js", format: "iife", platform: "browser", target: ["es2022"],
  minify: true, legalComments: "inline", metafile: true });
const script = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const style = await readFile("src/style.css", "utf8");
const escape = (s) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const bundled = new Set();
for (const input of Object.keys({ ...validatorBundle.metafile.inputs, ...result.metafile.inputs })) {
  const match = input.match(/node_modules\/(\.pnpm\/[^/]+\/node_modules\/)?((?:@[^/]+\/)?[^/]+)/);
  if (match) bundled.add(match[2]);
}
const notices = [];
for (const name of [...bundled].sort()) {
  const pkg = JSON.parse(await readFile("node_modules/" + name + "/package.json", "utf8"));
  let license;
  for (const filename of ["LICENSE", "LICENSE.txt", "LICENSE.md"]) {
    try { license = await readFile("node_modules/" + name + "/" + filename, "utf8"); break; }
    catch { /* Try the next standard license filename. */ }
  }
  if (!license) throw new Error("Missing bundled license for " + name);
  notices.push(name + " " + pkg.version + "\n" + license);
}
const hash = (text) => createHash("sha256").update(text).digest("base64");
const csp = "default-src 'none'; script-src 'sha256-" + hash(script) +
  "'; style-src 'sha256-" + hash(style) +
  "'; connect-src 'none'; img-src data:; base-uri 'none'; form-action 'none'; object-src 'none'";
let html = await readFile("src/index.html", "utf8");
html = html.replace("{{CSP}}", csp).replace("{{STYLE}}", () => style)
  .replace("{{NOTICES}}", () => escape(notices.join("\n\n")))
  .replace("{{SCRIPT}}", () => script);
await writeFile("dist/index.html", html);
await writeFile("dist/THIRD-PARTY-NOTICES.txt", notices.join("\n\n"));
await writeFile("dist/build-manifest.json", JSON.stringify({
  engine_version: data.engineVersion, catalog_sha256: data.catalogDigest,
  html_sha256: createHash("sha256").update(html).digest("hex"),
  dependencies: [...bundled].sort()
}, null, 2) + "\n");
console.log("Built standalone editor: " + path.join(root, "dist/index.html"));
