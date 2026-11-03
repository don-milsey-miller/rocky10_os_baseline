import { parseDocument, stringify, visit, isScalar, isAlias, isPair } from "yaml";
import data from "../.generated/catalog.json" with { type: "json" };
import { profileValidator, parameterValidators } from "../.generated/validators.mjs";

export { data };

export function available(control, target) {
  return control.implemented && control.applies_to.os === target.os &&
    control.applies_to.major_version === target.major_version &&
    control.applies_to.role === target.role;
}

export function validateProfile(profile, controls = data.controls,
  params = parameterValidators, schemaValidator = profileValidator) {
  const errors = [], warnings = [];
  if (!schemaValidator(profile)) {
    for (const issue of schemaValidator.errors || []) {
      errors.push((issue.instancePath || "Profile") + ": " + issue.message);
    }
    return { errors, warnings };
  }
  const numericIssue = (value) => {
    if (typeof value === "number") return !Number.isFinite(value) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value));
    if (value && typeof value === "object") return Object.values(value).some(numericIssue);
    return false;
  };
  if (numericIssue(profile)) errors.push("Numbers must be finite and integers must fit the safe browser range.");
  const catalog = new Map(controls.map(control => [control.id, control]));
  const seen = new Set();
  const selected = new Set(profile.controls.filter(item => item.enabled).map(item => item.id));
  for (const item of profile.controls) {
    if (seen.has(item.id)) errors.push("Duplicate control: " + item.id);
    seen.add(item.id);
    const control = catalog.get(item.id);
    if (!control) { errors.push("Unknown control: " + item.id); continue; }
    const check = params[item.id];
    if (!check || !check(item.parameters || {})) {
      errors.push(item.id + ": invalid parameters" +
        (check?.errors?.[0]?.message ? " (" + check.errors[0].message + ")" : ""));
    }
    if (!item.enabled) continue;
    if (!available(control, profile.target)) errors.push(item.id + ": unavailable for this target");
    for (const required of control.requires) {
      if (!selected.has(required)) errors.push(item.id + ": requires " + required);
    }
    for (const conflict of control.conflicts_with) {
      if (selected.has(conflict)) errors.push(item.id + ": conflicts with " + conflict);
    }
    if (control.impact === "high") warnings.push(control.title + ": " + control.impact_note);
    if (control.reboot_required) warnings.push(control.title + ": may require a reboot");
  }
  if (!selected.size) warnings.push("No controls are included. This profile will make no changes.");
  return { errors, warnings };
}

function sortedValue(value) {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortedValue(value[key])]));
  }
  return value;
}

export function normalize(profile) {
  const result = { schema_version: profile.schema_version, id: profile.id };
  if ("name" in profile) result.name = profile.name;
  result.revision = profile.revision;
  result.target = { os: profile.target.os, major_version: profile.target.major_version,
    role: profile.target.role };
  result.controls = [...profile.controls].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
    .map(item => {
      const row = { id: item.id, enabled: item.enabled };
      if ("parameters" in item) row.parameters = sortedValue(item.parameters);
      if ("reason" in item) row.reason = item.reason;
      return row;
    });
  return result;
}

export function exportProfile(profile) {
  const result = validateProfile(profile);
  if (result.errors.length) throw new Error(result.errors.join("\n"));
  return stringify(normalize(profile), { version: "1.1", directives: false,
    lineWidth: 0, aliasDuplicateObjects: false });
}

export function importProfile(raw) {
  if (new TextEncoder().encode(raw).length > 65536) throw new Error("Profile exceeds 64 KiB.");
  const doc = parseDocument(raw, { version: "1.1", merge: false, uniqueKeys: true });
  if (doc.errors.length || doc.warnings.length) throw new Error("Invalid or unsupported YAML.");
  if (doc.directives.yaml.explicit) throw new Error("YAML directives are not supported.");
  visit(doc, (key, node, path) => {
    if (path.length > 64) throw new Error("YAML is nested too deeply.");
    if (isAlias(node)) throw new Error("YAML aliases are not supported.");
    if (node?.tag && !["str", "int", "float", "bool", "null", "map", "seq"]
      .some(tag => node.tag === "tag:yaml.org,2002:" + tag)) {
      throw new Error("Unsupported YAML tag.");
    }
    if (isPair(node) &&
      (!isScalar(node.key) || typeof node.key.value !== "string")) {
      throw new Error("YAML keys must be strings.");
    }
  });
  const profile = doc.toJS({ maxAliasCount: 0 });
  const result = validateProfile(profile);
  if (result.errors.length) throw new Error(result.errors.join("\n"));
  return normalize(profile);
}

export function parameterValue(schema, text) {
  if (text === "") return undefined;
  if (schema.enum) return schema.enum[Number(text)];
  if (schema.type === "boolean") return text === "true";
  if (schema.type === "integer" || schema.type === "number") {
    return Number(text);
  }
  return text;
}
