import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import { data, available, validateProfile, exportProfile, importProfile, normalize, parameterValue } from "../src/core.mjs";

const base = () => ({schema_version:1,id:"test-profile",name:"Test profile",revision:1,
  target:{os:"rocky",major_version:10,role:"server"},controls:[]});
const entry = (id=data.controls[0].id, enabled=true) => ({id,enabled});
const valid = (p) => assert.deepEqual(validateProfile(p).errors,[]);
test("empty selection warns and never auto-enables controls",()=>{
  const p=base(); valid(p); assert.match(validateProfile(p).warnings.join(),/no changes/);
  assert.deepEqual(importProfile(exportProfile(p)),p);
});
test("all catalog controls validate and exported YAML passes independent CLI",()=>{
  const p=base(); p.controls=data.controls.map(c=>entry(c.id));
  const yaml=exportProfile(p); valid(p);
  const result=spawnSync("../.venv/bin/python",["-c",
    "import sys; from hardener.validation import parse_yaml,validate,load_catalog; validate(parse_yaml(sys.stdin.read()),load_catalog())"],
    {input:yaml,encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
});
test("ordering and exclusions round-trip deterministically",()=>{
  const p=base(); p.controls=[entry(data.controls[4].id),{...entry(data.controls[0].id,false),reason:"on"}];
  const first=exportProfile(p); p.controls.reverse();
  assert.equal(exportProfile(p),first);
  assert.equal(exportProfile(importProfile(first)),first);
  assert.equal(importProfile(first).controls[0].reason,"on");
});
for (const [label,change] of [
  ["unknown fields",p=>p.command="id"],
  ["unsupported schema",p=>p.schema_version=2],
  ["unsupported target",p=>p.target.major_version=9],
  ["invalid ID",p=>p.id="../unsafe"],
  ["invalid revision",p=>p.revision=NaN],
  ["unsafe integer",p=>p.revision=9007199254740992],
  ["unknown control",p=>p.controls=[entry("other.control")]],
  ["duplicate controls",p=>p.controls=[entry(),entry()]],
  ["wrong enabled type",p=>p.controls=[{...entry(),enabled:"true"}]],
  ["unknown parameter",p=>p.controls=[{...entry(),parameters:{command:"id"}}]],
  ["invalid excluded parameters",p=>p.controls=[{...entry(undefined,false),parameters:{unexpected:true}}]],
]) test("rejects "+label,()=>{const p=base();change(p);assert.ok(validateProfile(p).errors.length);assert.throws(()=>exportProfile(p));});
for (const [label,raw] of [
  ["duplicate YAML keys","id: first\nid: second"],
  ["alias","name: &a hello\ncontrols: *a"],
  ["non-string key","true: value"],
  ["custom tag","!!python/object:danger {}"],
  ["multiple documents","---\na: b\n---\nc: d"],
  ["directive","%YAML 1.2\n---\na: b"],
  ["oversized input","#"+"x".repeat(65536)],
  ["deep nesting","[".repeat(100)+"0"+"]".repeat(100)],
]) test("rejects "+label,()=>assert.throws(()=>importProfile(raw)));
test("availability, dependencies, conflicts and high impact use catalog metadata",()=>{
  const controls=structuredClone(data.controls),p=base();
  p.controls=[entry(controls[0].id)];
  controls[0].implemented=false;
  assert.equal(available(controls[0],p.target),false);
  assert.match(validateProfile(p,controls).errors.join(),/unavailable/);
  controls[0].implemented=true;controls[0].applies_to.major_version=9;
  assert.match(validateProfile(p,controls).errors.join(),/unavailable/);
  controls[0].applies_to.major_version=10;
  controls[0].requires=[controls[1].id];
  assert.match(validateProfile(p,controls).errors.join(),/requires/);
  p.controls.push(entry(controls[1].id));
  assert.deepEqual(validateProfile(p,controls).errors,[]);
  controls[0].conflicts_with=[controls[1].id];
  assert.match(validateProfile(p,controls).errors.join(),/conflicts/);
  controls[0].impact="high";controls[0].reboot_required=true;
  assert.equal(validateProfile(p,controls).warnings.length,2);
});
test("typed parameters validate without coercion or invented defaults",()=>{
  const controls=structuredClone(data.controls),p=base(),id=controls[0].id;
  const schema={type:"object",additionalProperties:false,required:["port"],properties:{
    port:{type:"integer",minimum:1,maximum:65535},strict:{type:"boolean"},mode:{enum:["one","two"]}}};
  const check=new Ajv2020().compile(schema);
  p.controls=[{...entry(id),parameters:{port:22,strict:false,mode:"one"}}];
  assert.deepEqual(validateProfile(p,controls,{[id]:check}).errors,[]);
  p.controls[0].parameters.port="22";
  assert.ok(validateProfile(p,controls,{[id]:check}).errors.length);
  assert.equal(parameterValue({type:"integer"},"22"),22);
  assert.equal(parameterValue({type:"boolean"},"false"),false);
  assert.equal(parameterValue({enum:["one","two"]},"1"),"two");
  assert.equal(parameterValue({type:"string"},"on"),"on");
  assert.equal(parameterValue({type:"integer",default:22},""),undefined);
  assert.deepEqual(Object.keys(normalize({...base(),controls:[{...entry(),parameters:{z:1,a:2}}]}).controls[0].parameters),["a","z"]);
});
test("CSP hashes exactly match embedded content and network is forbidden",()=>{
  const html=readFileSync("dist/index.html","utf8");
  for (const tag of ["script","style"]) {
    const source=html.match(new RegExp("<"+tag+">([\\s\\S]*?)</"+tag+">"))[1];
    const hash=createHash("sha256").update(source).digest("base64");
    assert.ok(html.includes("'sha256-"+hash+"'"));
  }
  assert.ok(html.includes("connect-src 'none'"));
  assert.doesNotMatch(html,/<(?:script|link)[^>]+(?:src|href)=/);
  assert.ok(html.includes("Copyright"));
});

test("YAML strings preserve their types and values in the Python parser",()=>{
  const p=base();p.name="on";
  p.controls=[{...entry(undefined,false),reason:"2026-11-03: null, yes, 012, café"}];
  const raw=exportProfile(p);
  const result=spawnSync("../.venv/bin/python",["-c",
    "import json,sys; from hardener.validation import parse_yaml; print(json.dumps(parse_yaml(sys.stdin.read())))"],
    {input:raw,encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
  assert.deepEqual(JSON.parse(result.stdout),p);
  assert.throws(()=>importProfile(exportProfile(base()).replace("revision: 1","revision: 9007199254740993")));
});
