"use strict";

const ACCESS_RESULT_TTL_MS = 300_000;
const UNKNOWN_MUTATION_MESSAGE = "OpenBao may have accepted the request. Do not retry; verify current state first.";

class InvalidResponseError extends Error {}

function isObject(value) {
  return Boolean(value) && !Array.isArray(value) && typeof value === "object";
}

export function parseStructuredField(value, kind) {
  let parsed;
  try {
    parsed = JSON.parse(value || (kind.endsWith("-list") ? "[]" : "{}"));
  } catch {
    throw new Error("Structured fields must contain valid JSON.");
  }
  if (kind.endsWith("-list") && !Array.isArray(parsed)) throw new Error("This field must be a JSON list.");
  if (!kind.endsWith("-list") && !isObject(parsed)) throw new Error("This field must be a JSON object.");
  return parsed;
}

export function fieldValue(control, contract) {
  if (contract.kind === "boolean") {
    if (control.value === "" && !contract.required) return undefined;
    return control.value === "true";
  }
  if (["integer", "positive-integer", "strict-positive-integer"].includes(contract.kind)) {
    return control.value === "" ? undefined : Number(control.value);
  }
  if (["string-list", "uuid-list", "url-list", "string-map", "json-map"].includes(contract.kind)) {
    if (!control.value && !contract.required) return undefined;
    return parseStructuredField(control.value, contract.kind);
  }
  return control.value === "" && !contract.required ? undefined : control.value;
}

function createControl(name, contract) {
  let control;
  if (contract.kind === "boolean") {
    control = document.createElement("select");
    control.className = "form-select";
    if (!contract.required) control.append(new Option("— unchanged —", ""));
    control.append(new Option("true", "true"), new Option("false", "false"));
  } else if (contract.choices?.length) {
    control = document.createElement("select");
    control.className = "form-select";
    if (!contract.required) control.append(new Option("—", ""));
    for (const choice of contract.choices) control.append(new Option(choice, choice));
  } else if (
    ["string-list", "uuid-list", "url-list", "string-map", "json-map"].includes(contract.kind) ||
    ["policy", "template"].some((part) => name.includes(part))
  ) {
    control = document.createElement("textarea");
    control.className = "form-control font-monospace";
    control.rows = name.includes("policy") || name.includes("template") ? 10 : 3;
  } else {
    control = document.createElement("input");
    control.className = "form-control";
    if (["integer", "positive-integer", "strict-positive-integer"].includes(contract.kind)) {
      control.type = "number";
      if (contract.kind !== "integer") control.min = contract.kind === "strict-positive-integer" ? "1" : "0";
    } else {
      control.type = contract.material ? "password" : "text";
      control.autocomplete = "off";
      control.spellcheck = false;
    }
  }
  control.name = name;
  control.id = `openbao-access-field-${name}`;
  control.required = Boolean(contract.required);
  control.dataset.kind = contract.kind;
  control.dataset.required = String(Boolean(contract.required));
  control.dataset.material = String(Boolean(contract.material));
  return control;
}

export function renderFields(container, fields) {
  container.replaceChildren();
  for (const [name, contract] of Object.entries(fields)) {
    const group = document.createElement("div");
    if (["policy", "template"].some((part) => name.includes(part))) group.className = "openbao-access-field-wide";
    const label = document.createElement("label");
    label.className = "form-label";
    label.htmlFor = `openbao-access-field-${name}`;
    label.textContent = name.replaceAll("_", " ");
    const control = createControl(name, contract);
    group.append(label, control);
    container.append(group);
  }
}

function collectPayload(container, fields) {
  const payload = {};
  for (const [name, contract] of Object.entries(fields)) {
    const control = container.querySelector(`[name="${CSS.escape(name)}"]`);
    const value = fieldValue(control, contract);
    if (value !== undefined) payload[name] = value;
  }
  return payload;
}

async function parseResponse(response) {
  let data;
  try {
    data = await response.json();
  } catch {
    throw new InvalidResponseError("The server returned an invalid response.");
  }
  if (!isObject(data)) throw new InvalidResponseError("The server returned an invalid response.");
  if (!response.ok && data.outcome !== "unknown") throw new Error(JSON.stringify(data));
  return data;
}

export async function apiRequest(url, { method = "GET", payload, csrf = "" } = {}) {
  const options = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json", "X-CSRFToken": csrf },
  };
  if (payload !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  try {
    return await parseResponse(await fetch(url, options));
  } catch (error) {
    if (method !== "GET" && (error instanceof TypeError || error instanceof InvalidResponseError)) {
      return { outcome: "unknown", message: UNKNOWN_MUTATION_MESSAGE };
    }
    throw error;
  }
}

export function createMutationGate(onChange = () => {}) {
  let inFlight = false;
  return async function runMutation(task) {
    if (inFlight) return undefined;
    inFlight = true;
    onChange(true);
    try {
      return await task();
    } finally {
      inFlight = false;
      onChange(false);
    }
  };
}

export function initializeAccessWorkspace(root, { request = apiRequest, ttlMs = ACCESS_RESULT_TTL_MS } = {}) {
  const apiBase = root.dataset.apiBase;
  const csrf = root.querySelector("[name=csrfmiddlewaretoken]")?.value || "";
  const resourceSelect = root.querySelector("#openbao-access-resource");
  const operationSelect = root.querySelector("#openbao-access-operation");
  const identifier = root.querySelector("#openbao-access-identifier");
  const identifierGroup = root.querySelector("#openbao-access-identifier-group");
  const identifierHelp = root.querySelector("#openbao-access-identifier-help");
  const fieldsContainer = root.querySelector("#openbao-access-fields");
  const form = root.querySelector("#openbao-access-form");
  const result = root.querySelector("#openbao-access-result");
  const statusBox = root.querySelector("#openbao-access-status");
  const previewButton = root.querySelector("#openbao-access-preview");
  const submitButton = root.querySelector("#openbao-access-submit");
  const impactPanel = root.querySelector("#openbao-access-impact");
  const impactOutput = root.querySelector("#openbao-access-impact-output");
  const confirmation = root.querySelector("#openbao-access-confirmation");
  const confirmationHint = root.querySelector("#openbao-access-confirmation-hint");
  const downloadButton = root.querySelector("#openbao-access-download");
  let catalog = [];
  let capabilityDigest = "";
  let impactDigest = "";
  let currentResult = null;
  let clearTimer = null;
  let generation = 0;
  const runMutation = createMutationGate((inFlight) => { submitButton.disabled = inFlight; });

  const selectedResource = () => catalog.find((item) => item.key === resourceSelect.value);
  const selectedOperation = () => selectedResource()?.operations?.[operationSelect.value];

  function clearResult({ message = "No result." } = {}) {
    generation += 1;
    if (clearTimer) window.clearTimeout(clearTimer);
    clearTimer = null;
    currentResult = null;
    result.textContent = message;
    statusBox.className = "alert d-none";
    statusBox.textContent = "";
    downloadButton.classList.add("d-none");
    for (const control of root.querySelectorAll('#openbao-access-fields [data-material="true"]')) {
      control.value = "";
    }
  }

  function clearImpact() {
    impactDigest = "";
    impactOutput.textContent = "";
    confirmation.value = "";
    confirmationHint.textContent = "";
    impactPanel.classList.add("d-none");
  }

  function showStatus(message, kind = "success") {
    statusBox.className = `alert alert-${kind}`;
    statusBox.textContent = message;
  }

  function showResult(value, operation) {
    currentResult = value;
    result.textContent = JSON.stringify(value, null, 2);
    downloadButton.classList.toggle("d-none", operation.response_kind !== "material");
    if (clearTimer) window.clearTimeout(clearTimer);
    const expectedGeneration = generation;
    clearTimer = window.setTimeout(() => {
      if (generation === expectedGeneration) clearResult({ message: "Result expired and was cleared." });
    }, ttlMs);
  }

  function updateOperation() {
    clearResult();
    clearImpact();
    const resource = selectedResource();
    const operation = selectedOperation();
    if (!resource || !operation) return;
    renderFields(fieldsContainer, operation.fields || {});
    identifierGroup.classList.toggle("d-none", !operation.identifier_required);
    identifier.required = Boolean(operation.identifier_required);
    identifierHelp.textContent = `${resource.identifier_kind} identifier; encoded as one reviewed path value.`;
    previewButton.classList.toggle("d-none", !operation.destructive);
  }

  function updateResource() {
    clearResult();
    clearImpact();
    operationSelect.replaceChildren();
    const resource = selectedResource();
    for (const name of Object.keys(resource?.operations || {})) operationSelect.append(new Option(name, name));
    updateOperation();
  }

  async function loadCatalog() {
    clearResult({ message: "Loading reviewed resources…" });
    clearImpact();
    const expectedGeneration = generation;
    const data = await request(`${apiBase}access-resources/`, { csrf });
    if (expectedGeneration !== generation) return;
    catalog = Array.isArray(data.resources) ? data.resources : [];
    capabilityDigest = data.capability_digest || "";
    resourceSelect.replaceChildren();
    for (const resource of catalog) resourceSelect.append(new Option(resource.label, resource.key));
    updateResource();
    showStatus(`Loaded ${catalog.length} permission-filtered resource families.`);
  }

  function requestPayload() {
    const resource = selectedResource();
    const operation = selectedOperation();
    return {
      resource: resource.key,
      operation: operationSelect.value,
      ...(operation.identifier_required ? { identifier: identifier.value } : {}),
      payload: collectPayload(fieldsContainer, operation.fields || {}),
      capability_digest: capabilityDigest,
    };
  }

  async function previewImpact() {
    const payload = requestPayload();
    clearResult({ message: "Loading current impact…" });
    clearImpact();
    const expectedGeneration = generation;
    const data = await request(`${apiBase}access-resources/preview/`, {
      method: "POST",
      csrf,
      payload,
    });
    if (expectedGeneration !== generation) return;
    if (data.outcome === "unknown") throw new Error("Impact preview could not be confirmed. Reload before continuing.");
    impactDigest = data.impact_digest;
    impactOutput.textContent = JSON.stringify(data.impact, null, 2);
    confirmationHint.textContent = data.confirmation;
    impactPanel.classList.remove("d-none");
    showStatus("Current impact loaded. Review it before entering the exact confirmation.", "warning");
  }

  async function execute(event) {
    event.preventDefault();
    return runMutation(async () => {
      const operation = selectedOperation();
      const payload = {
        ...requestPayload(),
        reason: root.querySelector("#openbao-access-reason").value,
        ...(operation.destructive
          ? { impact_digest: impactDigest, confirmation: confirmation.value }
          : {}),
      };
      clearResult({ message: "Running reviewed operation…" });
      const expectedGeneration = generation;
      const data = await request(`${apiBase}access-resources/execute/`, { method: "POST", csrf, payload });
      if (expectedGeneration !== generation) return;
      showResult(data, operation);
      showStatus(data.outcome === "unknown" ? UNKNOWN_MUTATION_MESSAGE : "Operation completed.", data.outcome === "unknown" ? "danger" : "success");
      clearImpact();
    });
  }

  resourceSelect.addEventListener("change", updateResource);
  operationSelect.addEventListener("change", updateOperation);
  identifier.addEventListener("input", clearImpact);
  fieldsContainer.addEventListener("input", clearImpact);
  form.addEventListener("submit", (event) => execute(event).catch((error) => {
    clearResult({ message: "Request failed." });
    showStatus(error.message || "The request failed.", "danger");
  }));
  previewButton.addEventListener("click", () => previewImpact().catch((error) => {
    clearImpact();
    showStatus(error.message || "Impact preview failed.", "danger");
  }));
  root.querySelector("#openbao-access-refresh").addEventListener("click", () => loadCatalog().catch((error) => showStatus(error.message, "danger")));
  root.querySelector("#openbao-access-clear").addEventListener("click", () => clearResult());
  downloadButton.addEventListener("click", () => {
    if (currentResult === null) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(currentResult, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `openbao-${selectedResource()?.key || "result"}.json`;
    link.click();
    URL.revokeObjectURL(url);
  });
  window.addEventListener("pagehide", () => clearResult());
  loadCatalog().catch((error) => showStatus(error.message || "The access contract could not be loaded.", "danger"));
  return { clearResult, loadCatalog, previewImpact };
}

if (typeof document !== "undefined") {
  const root = document.querySelector("#openbao-access");
  if (root) initializeAccessWorkspace(root);
}
