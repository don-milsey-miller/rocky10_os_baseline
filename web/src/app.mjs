import { data, available, validateProfile, exportProfile, importProfile, parameterValue } from "./core.mjs";

const $ = (id) => document.getElementById(id);
const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const catalog = data.controls;
let profile = {
  schema_version: data.profileSchema.properties.schema_version.const,
  id: "rocky10-custom", name: "My server profile", revision: 1,
  target: Object.fromEntries(Object.entries(data.profileSchema.properties.target.properties)
    .map(([key, value]) => [key, value.const])),
  controls: []
};
const selectedItem = (id) => profile.controls.find(item => item.id === id);
const category = (control) => control.id.split(".")[0];
const sameTarget = (control) => ["os", "major_version", "role"]
  .every(key => control.applies_to[key] === profile.target[key]);
const categories = [...new Set(catalog.map(category))].sort();
for (const name of categories) {
  $("category").append(new Option(name[0].toUpperCase() + name.slice(1), name));
}
$("catalog-count").textContent = catalog.filter(c => available(c, profile.target)).length + " controls available";
$("catalog-version").textContent = "Catalog v" + data.engineVersion;
$("footer-version").textContent = "Rocky 10 OS baseline · " + data.engineVersion;

function updateSummary() {
  const included = profile.controls.filter(item => item.enabled).length;
  $("included-count").textContent = included;
  $("excluded-count").textContent = profile.controls.length - included;
  $("omitted-count").textContent = catalog.length - profile.controls.length;
  const result = validateProfile(profile);
  const panel = $("validation");
  panel.classList.toggle("invalid", result.errors.length > 0);
  panel.replaceChildren(element("strong", "", result.errors.length ? "Review profile issues" : "Profile is valid"));
  for (const [messages, className] of [[result.errors, "error-list"], [result.warnings, "warning-list"]]) {
    if (!messages.length) continue;
    const list = element("ul", className);
    for (const message of messages) list.append(element("li", "", message));
    panel.append(list);
  }
  $("export").disabled = result.errors.length > 0;
  $("yaml-preview").value = result.errors.length ? "Resolve the profile issues to preview and export YAML." : exportProfile(profile);
}

function parameterFields(control, item) {
  const wrap = element("div", "parameter-fields");
  const properties = control.parameters.properties || {};
  for (const [key, schema] of Object.entries(properties)) {
    const label = element("label", "", schema.title || key);
    let input;
    const current = item.parameters?.[key];
    if (schema.type === "array" && schema.items?.type === "string") {
      input = element("textarea");
      input.rows = 3;
      input.value = (current || []).join("\n");
      input.placeholder = "One value per line";
    } else if (schema.enum || schema.type === "boolean") {
      input = element("select");
      input.append(new Option("Not specified", ""));
      if (schema.enum) {
        schema.enum.forEach((value, index) => input.append(new Option(String(value), String(index))));
        input.value = current === undefined ? "" : String(schema.enum.indexOf(current));
      } else {
        input.append(new Option("True", "true"), new Option("False", "false"));
        input.value = current === undefined ? "" : String(current);
      }
    } else if (["string", "integer", "number"].includes(schema.type)) {
      input = element("input");
      input.type = schema.type === "string" ? "text" : "number";
      if (input.type === "number") input.step = schema.type === "integer" ? "1" : "any";
      if (schema.minimum !== undefined) input.min = schema.minimum;
      if (schema.maximum !== undefined) input.max = schema.maximum;
      if (schema.maxLength !== undefined) input.maxLength = schema.maxLength;
      input.value = current === undefined ? "" : String(current);
      if (schema.default !== undefined) input.placeholder = "Default: " + String(schema.default);
    } else {
      wrap.append(element("p", "hint", key + ": edit this parameter in YAML and import it."));
      continue;
    }
    input.setAttribute("aria-label", control.title + ": " + key);
    input.addEventListener("input", () => {
      const value = parameterValue(schema, input.value);
      item.parameters ||= {};
      if (value === undefined) delete item.parameters[key];
      else item.parameters[key] = value;
      if (!Object.keys(item.parameters).length) delete item.parameters;
      updateSummary();
    });
    label.append(input);
    if (schema.description) label.append(element("span", "hint", schema.description));
    wrap.append(label);
  }
  return wrap;
}

function renderControls() {
  const query = $("search").value.trim().toLowerCase();
  const rows = catalog.filter(control => {
    const search = [control.id, control.title, control.summary].join(" ").toLowerCase();
    if (query && !search.includes(query)) return false;
    if ($("category").value && category(control) !== $("category").value) return false;
    if ($("impact").value && control.impact !== $("impact").value) return false;
    if ($("availability").value === "available" && !available(control, profile.target)) return false;
    if ($("availability").value === "unavailable" && available(control, profile.target)) return false;
    if ($("applicability").value === "applicable" && !sameTarget(control)) return false;
    if ($("applicability").value === "inapplicable" && sameTarget(control)) return false;
    return true;
  });
  $("visible-count").textContent = rows.length + " of " + catalog.length;
  $("empty-state").hidden = rows.length > 0;
  const cards = rows.map(control => {
    const item = selectedItem(control.id);
    const state = !item ? "omit" : item.enabled ? "enabled" : "excluded";
    const usable = available(control, profile.target);
    const card = element("article", "control-card");
    card.classList.toggle("included", state === "enabled");
    card.classList.toggle("excluded", state === "excluded");
    card.classList.toggle("unavailable", !usable);
    const top = element("div", "card-top");
    const title = element("div");
    title.append(element("h3", "", control.title), element("span", "control-id", control.id));
    const selectLabel = element("label", "selection-label", "Selection");
    const select = element("select");
    select.dataset.control = control.id;
    select.setAttribute("aria-label", "Selection for " + control.title);
    select.append(new Option("Not selected", "omit"), new Option("Include", "enabled"), new Option("Exclude", "excluded"));
    select.options[1].disabled = !usable;
    select.value = state;
    select.addEventListener("change", () => {
      profile.controls = profile.controls.filter(row => row.id !== control.id);
      if (select.value !== "omit") {
        const next = item ? { ...item, enabled: select.value === "enabled" } : { id: control.id, enabled: select.value === "enabled" };
        if (next.enabled && item?.enabled === false) delete next.reason;
        profile.controls.push(next);
      }
      renderControls();
      updateSummary();
      document.querySelector('[data-control="' + CSS.escape(control.id) + '"]')?.focus();
    });
    selectLabel.append(select);
    top.append(title, selectLabel);
    card.append(top, element("p", "control-summary", control.summary));
    const meta = element("div", "card-meta");
    meta.append(element("span", "tag", category(control)),
      element("span", "tag impact-" + control.impact, control.impact + " impact"));
    if (!Object.keys(control.parameters.properties || {}).length) meta.append(element("span", "tag", "Fixed setting"));
    if (!usable) card.append(element("p", "unavailable-reason", control.implemented ? "Unavailable for this target." : "Implementation unavailable."));
    card.append(meta);
    const details = element("details", "control-details");
    details.append(element("summary", "", "Benefits, trade-offs & requirements"));
    const grid = element("div", "detail-grid");
    for (const [heading, lines] of [["Benefit", control.benefits], ["Trade-off", control.tradeoffs]]) {
      const block = element("div");
      const list = element("ul");
      for (const line of lines) list.append(element("li", "", line));
      block.append(element("span", "detail-label", heading), list);
      grid.append(block);
    }
    details.append(grid, element("p", "impact-note", control.impact_note));
    if (control.requires.length) details.append(element("p", "dependencies", "Requires: " + control.requires.join(", ")));
    if (control.conflicts_with.length) details.append(element("p", "dependencies", "Conflicts with: " + control.conflicts_with.join(", ")));
    if (control.supported_modes && !control.supported_modes.includes("apply"))
      details.append(element("p", "dependencies", "Assessment only. Use audit or verify. Apply will refuse this selection."));
    if (control.reboot_required) details.append(element("p", "dependencies", "A reboot may be required."));
    card.append(details);
    if (state === "excluded") {
      const label = element("label", "exclusion-label", "Exclusion reason (optional)");
      const reason = element("input");
      reason.value = item.reason || "";
      reason.maxLength = 500;
      reason.setAttribute("aria-label", "Exclusion reason for " + control.title);
      reason.placeholder = "Record why this control is excluded";
      reason.addEventListener("input", () => {
        if (reason.value) item.reason = reason.value;
        else delete item.reason;
        updateSummary();
      });
      label.append(reason);
      card.append(label);
    } else if (state === "enabled") {
      card.append(parameterFields(control, item));
    }
    return card;
  });
  $("controls").replaceChildren(...cards);
}

for (const id of ["search", "category", "impact", "availability", "applicability"]) {
  $(id).addEventListener("input", renderControls);
}
for (const [id, field] of [["profile-name", "name"], ["profile-id", "id"], ["revision", "revision"]]) {
  $(id).addEventListener("input", () => {
    if (field === "name" && !$(id).value) delete profile.name;
    else profile[field] = field === "revision" ? $(id).valueAsNumber : $(id).value;
    updateSummary();
  });
}

$("open-import").addEventListener("click", () => {
  $("import-error").textContent = "";
  $("import-dialog").showModal();
  $("import-text").focus();
});
$("close-import").addEventListener("click", () => $("import-dialog").close());
$("import-file").addEventListener("change", async () => {
  const file = $("import-file").files[0];
  if (!file) return;
  if (file.size > 65536) { $("import-error").textContent = "Profile exceeds 64 KiB."; return; }
  try { $("import-text").value = await file.text(); $("import-error").textContent = ""; }
  catch { $("import-error").textContent = "The selected file could not be read."; }
});
$("confirm-import").addEventListener("click", () => {
  try {
    const incoming = importProfile($("import-text").value);
    profile = incoming;
    $("profile-name").value = profile.name || "";
    $("profile-id").value = profile.id;
    $("revision").value = profile.revision;
    renderControls();
    updateSummary();
    $("import-dialog").close();
  } catch (error) {
    $("import-error").textContent = "Import rejected: " + error.message;
  }
});
$("export").addEventListener("click", () => {
  const text = exportProfile(profile);
  const url = URL.createObjectURL(new Blob([text], { type: "application/yaml;charset=utf-8" }));
  const link = element("a");
  link.href = url;
  link.download = profile.id + ".yaml";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
renderControls();
updateSummary();
