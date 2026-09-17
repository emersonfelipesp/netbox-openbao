"use strict";

const TTL_MS = 300_000;
const UNKNOWN = "OpenBao may have accepted the request. Do not retry; verify current state first.";

function isObject(value) { return Boolean(value) && !Array.isArray(value) && typeof value === "object"; }

export function parseField(value, kind) {
  if (["string-list", "header-values", "json-map", "bounded-json-map"].includes(kind)) {
    let parsed;
    try { parsed = JSON.parse(value); } catch { throw new Error("Structured fields must contain valid JSON."); }
    if (["string-list", "header-values"].includes(kind) && !Array.isArray(parsed)) throw new Error("This field must be a JSON list.");
    if (["json-map", "bounded-json-map"].includes(kind) && !isObject(parsed)) throw new Error("This field must be a JSON object.");
    return parsed;
  }
  return value;
}

export function fieldValue(control, contract) {
  if (contract.kind === "boolean") return control.value === "" ? undefined : control.value === "true";
  if (["integer", "positive-integer", "strict-positive-integer"].includes(contract.kind)) return control.value === "" ? undefined : Number(control.value);
  if (control.value === "" && !contract.required) return undefined;
  return parseField(control.value, contract.kind);
}

export function createMutationGate(onChange = () => {}) {
  let active = false;
  return async (task) => {
    if (active) return undefined;
    active = true; onChange(true);
    try { return await task(); } finally { active = false; onChange(false); }
  };
}

export function createRequestGeneration() {
  let value = 0;
  return { begin: () => ++value, invalidate: () => ++value, current: (candidate) => candidate === value };
}

function createControl(name, contract) {
  let control;
  if (contract.kind === "boolean" || contract.choices?.length) {
    control = document.createElement("select"); control.className = "form-select";
    if (!contract.required) control.append(new Option("— unchanged —", ""));
    const choices = contract.kind === "boolean" ? ["true", "false"] : contract.choices;
    for (const choice of choices) control.append(new Option(choice, choice));
  } else if (["string-list", "header-values", "json-map", "bounded-json-map"].includes(contract.kind) || name === "data") {
    control = document.createElement("textarea"); control.className = "form-control font-monospace"; control.rows = 4;
  } else {
    control = document.createElement("input"); control.className = "form-control";
    control.type = contract.material ? "password" : (["integer", "positive-integer", "strict-positive-integer"].includes(contract.kind) ? "number" : "text");
    control.autocomplete = "off"; control.spellcheck = false;
  }
  control.name = name; control.required = Boolean(contract.required); control.dataset.material = String(Boolean(contract.material));
  return control;
}

export function renderFields(container, fields) {
  container.replaceChildren();
  for (const [name, contract] of Object.entries(fields)) {
    const group = document.createElement("div"); const label = document.createElement("label");
    label.className = "form-label"; label.textContent = name.replaceAll("_", " ");
    const control = createControl(name, contract); label.htmlFor = `openbao-final-${name}`; control.id = label.htmlFor;
    group.append(label, control); container.append(group);
  }
}

export async function request(url, options = {}) {
  const { unknownOnLoss = false, ...fetchOptions } = options;
  let response;
  try { response = await fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json", ...(fetchOptions.headers || {}) }, ...fetchOptions }); }
  catch { if (unknownOnLoss) return { outcome: "unknown", message: UNKNOWN }; throw new Error("OpenBao administration is unavailable."); }
  let data;
  try { data = await response.json(); } catch { if (unknownOnLoss) return { outcome: "unknown", message: UNKNOWN }; throw new Error("The server returned an invalid response."); }
  if (!isObject(data)) {
    if (unknownOnLoss) return { outcome: "unknown", message: UNKNOWN };
    throw new Error("The server returned an invalid response.");
  }
  if (!response.ok && data.outcome !== "unknown") throw new Error(JSON.stringify(data));
  return data;
}

export function outcomePresentation(outcome) {
  const persistent = ["unknown", "accepted-audit-incomplete"].includes(outcome);
  return { kind: persistent ? "danger" : "success", persistent };
}

export function clearMaterialControls(root) {
  for (const control of root.querySelectorAll('[data-material="true"]')) control.value = "";
}

export function initializeFinalWorkspace(root, { apiRequest = request, ttlMs = TTL_MS } = {}) {
  const apiBase = root.dataset.apiBase; const csrf = root.querySelector("[name=csrfmiddlewaretoken]")?.value || "";
  const resource = root.querySelector("#openbao-final-resource"); const operation = root.querySelector("#openbao-final-operation");
  const identifier = root.querySelector("#openbao-final-identifier"); const identifierGroup = root.querySelector("#openbao-final-identifier-group");
  const fields = root.querySelector("#openbao-final-fields"); const form = root.querySelector("#openbao-final-form");
  const result = root.querySelector("#openbao-final-result"); const status = root.querySelector("#openbao-final-status");
  const preview = root.querySelector("#openbao-final-preview"); const impactPanel = root.querySelector("#openbao-final-impact");
  const impactOutput = root.querySelector("#openbao-final-impact-output"); const confirmation = root.querySelector("#openbao-final-confirmation");
  const confirmationHint = root.querySelector("#openbao-final-confirmation-hint"); const submit = root.querySelector("#openbao-final-submit");
  let catalog = []; let capabilityDigest = ""; let impactDigest = ""; let timer;
  const requests = createRequestGeneration();
  const selectedResource = () => catalog.find((entry) => entry.key === resource.value);
  const selectedOperation = () => selectedResource()?.operations?.[operation.value];
  const runMutation = createMutationGate((active) => { submit.disabled = active; });
  function clear() { requests.invalidate(); if (timer) window.clearTimeout(timer); result.textContent = "No result."; status.className = "alert d-none"; impactDigest = ""; impactPanel.classList.add("d-none"); clearMaterialControls(root); }
  function show(value, kind = "success", persistent = false) { result.textContent = JSON.stringify(value, null, 2); status.className = `alert alert-${kind}`; status.textContent = value.outcome === "unknown" ? UNKNOWN : value.outcome === "accepted-audit-incomplete" ? "OpenBao accepted the operation, but its audit is incomplete. Do not retry." : "Operation completed."; const current = requests.begin(); if (!persistent) timer = window.setTimeout(() => { if (requests.current(current)) clear(); }, ttlMs); }
  function payload() { const values = {}; for (const [name, contract] of Object.entries(selectedOperation()?.fields || {})) { const value = fieldValue(fields.querySelector(`[name="${CSS.escape(name)}"]`), contract); if (value !== undefined) values[name] = value; } return { resource: resource.value, operation: operation.value, ...(selectedOperation().identifier_required ? { identifier: identifier.value } : {}), payload: values, reason: root.querySelector("#openbao-final-reason").value, capability_digest: capabilityDigest }; }
  function updateOperation() { clear(); const selected = selectedOperation(); if (!selected) return; renderFields(fields, selected.fields); identifierGroup.classList.toggle("d-none", !selected.identifier_required); identifier.required = selected.identifier_required && !selected.identifier_allow_blank; preview.classList.toggle("d-none", !selected.destructive); }
  function updateResource() { operation.replaceChildren(); for (const name of Object.keys(selectedResource()?.operations || {})) operation.append(new Option(name, name)); updateOperation(); }
  async function guarded(fetchData, apply) { const current = requests.begin(); try { const data = await fetchData(); if (requests.current(current)) apply(data); } catch (error) { if (requests.current(current)) show({ error: error.message }, "danger"); } }
  async function load() { clear(); return guarded(() => apiRequest(`${apiBase}final-resources/`), (data) => { catalog = data.resources || []; capabilityDigest = data.capability_digest; resource.replaceChildren(); for (const item of catalog) resource.append(new Option(item.label, item.key)); updateResource(); }); }
  async function previewImpact() { const body = { ...payload(), preview: true }; clear(); return guarded(() => apiRequest(`${apiBase}final-resources/operate/`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrf }, body: JSON.stringify(body) }), (data) => { impactDigest = data.impact_digest; impactOutput.textContent = JSON.stringify(data.impact, null, 2); confirmationHint.textContent = data.confirmation; impactPanel.classList.remove("d-none"); }); }
  async function execute(event) { event.preventDefault(); return runMutation(async () => { const selected = selectedOperation(); const body = { ...payload(), ...(selected.destructive ? { impact_digest: impactDigest, confirmation: confirmation.value } : {}) }; clear(); await guarded(() => apiRequest(`${apiBase}final-resources/operate/`, { method: "POST", unknownOnLoss: true, headers: { "Content-Type": "application/json", "X-CSRFToken": csrf }, body: JSON.stringify(body) }), (data) => { const presentation = outcomePresentation(data.outcome); show(data, presentation.kind, presentation.persistent); }); }); }
  resource.addEventListener("change", updateResource); operation.addEventListener("change", updateOperation); form.addEventListener("submit", execute); preview.addEventListener("click", previewImpact); root.querySelector("#openbao-final-clear").addEventListener("click", clear); root.querySelector("#openbao-final-conformance").addEventListener("click", () => { clear(); guarded(() => apiRequest(`${apiBase}final-conformance/`), show); }); window.addEventListener("pagehide", clear); load();
  return { clear, load, previewImpact };
}

if (typeof document !== "undefined") { const root = document.querySelector("#openbao-final"); if (root) initializeFinalWorkspace(root); }
