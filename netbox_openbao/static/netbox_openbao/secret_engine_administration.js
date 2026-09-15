export function parseJsonObject(value, fieldName) {
  const parsed = JSON.parse(value || "{}");
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error(`${fieldName} must be a JSON object.`);
  }
  return parsed;
}

export function destructiveConfirmation(operation, mount, resource, clusterSlug) {
  if (!operation || operation.risk_level !== "destructive") return "";
  const path = operation.path_template
    .replace("{secret_mount_path}", mount)
    .replace("{path}", resource);
  return `${operation.method} ${path} ON ${clusterSlug}`;
}

export function journeyConfirmation(journey, resource, pathParameters, clusterSlug) {
  if (!journey?.confirmation_prefix) return "";
  let path = journey.path_template.replace("{secret_mount_path}", encodeURIComponent(journey.mount_path));
  if (path.includes("{path}")) {
    const encodedResource = resource.split("/").map(encodePathValue).join("/");
    path = path.replace("{path}", encodedResource);
  }
  Object.entries(pathParameters).forEach(([name, value]) => {
    path = path.replace(`{${name}}`, encodePathValue(String(value)));
  });
  return `${journey.confirmation_prefix} ${path} ON ${clusterSlug}`;
}

function encodePathValue(value) {
  return encodeURIComponent(value).replace(/%3A/gi, ":").replace(/%40/gi, "@").replace(/%2B/gi, "+");
}

export function clearJourneyInputs(scope = document) {
  ["resource", "reason", "confirmation"].forEach((name) => {
    const field = scope.getElementById(`openbao-journey-${name}`);
    if (field) field.value = "";
  });
  ["path", "query", "body"].forEach((name) => {
    const field = scope.getElementById(`openbao-journey-${name}`);
    if (field) field.value = "{}";
  });
}

export function createMaterialExpiry({ setTimer = setTimeout, clearTimer = clearTimeout, ttlMs = 300000 } = {}) {
  let timer = null;
  return {
    schedule(clear) {
      if (timer !== null) clearTimer(timer);
      timer = setTimer(() => {
        timer = null;
        clear();
      }, ttlMs);
    },
    cancel() {
      if (timer !== null) clearTimer(timer);
      timer = null;
    },
  };
}

export function replaceSelectOptions(select, options) {
  if (select.tomselect) {
    select.tomselect.clear(true);
    select.tomselect.clearOptions();
    select.tomselect.addOption(options);
    select.tomselect.refreshOptions(false);
    if (options.length) {
      select.tomselect.setValue(options[0].value, true);
      select.tomselect.enable();
      select.disabled = false;
    } else {
      select.tomselect.disable();
      select.disabled = true;
    }
    return;
  }
  select.replaceChildren();
  options.forEach(({ value, text }) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = text;
    select.appendChild(option);
  });
  select.disabled = options.length === 0;
}

function listen(element, eventName, handler) {
  if (element) element.addEventListener(eventName, handler);
}

function bootstrap() {
  "use strict";
  const root = document.getElementById("openbao-secret-engines");
  if (!root) return;
  const apiBase = root.dataset.apiBase.replace(/\/$/, "");
  const csrf = root.querySelector("input[name=csrfmiddlewaretoken]")?.value || "";
  const status = document.getElementById("openbao-engine-status");
  const result = document.getElementById("openbao-operation-result");
  const journeyResult = document.getElementById("openbao-journey-result");
  let capabilityDigest = "";
  let operations = new Map();
  let journeyDigest = "";
  let journeys = new Map();
  const materialExpiry = createMaterialExpiry();

  function message(text, failed = false) {
    status.textContent = text;
    status.className = `alert mt-3 ${failed ? "alert-danger" : "alert-success"}`;
  }

  async function request(path, options = {}) {
    const response = await fetch(`${apiBase}/${path}`, {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      ...options,
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, ...(options.headers || {}) },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "OpenBao refused the reviewed operation.");
    return payload;
  }

  async function refreshMounts() {
    try {
      const payload = await request("secret-engines/");
      const body = document.getElementById("openbao-engine-mounts");
      body.replaceChildren();
      const mountSelects = document.querySelectorAll(".openbao-mount-select, #openbao-operation-mount");
      const mountOptions = [];
      payload.mounts.forEach((mount) => {
        const row = document.createElement("tr");
        [mount.path, mount.engine_type, mount.description, `${mount.default_lease_ttl} / ${mount.max_lease_ttl}`]
          .forEach((value) => { const cell = document.createElement("td"); cell.textContent = String(value); row.appendChild(cell); });
        body.appendChild(row);
        if (!["cubbyhole", "identity", "sys"].includes(mount.path)) {
          mountOptions.push({ value: mount.path, text: `${mount.path} (${mount.engine_type})` });
        }
      });
      mountSelects.forEach((select) => replaceSelectOptions(select, mountOptions));
      message(`Loaded ${payload.mounts.length} mounted engines.`);
    } catch (error) { message(error.message, true); }
  }

  listen(document.getElementById("openbao-engine-refresh"), "click", refreshMounts);
  listen(document.querySelector(".openbao-engine-read-form"), "submit", async (event) => {
    event.preventDefault();
    const submitter = event.submitter;
    if (!submitter?.dataset.action) return;
    const fields = Object.fromEntries(new FormData(event.currentTarget));
    try {
      const payload = await request(submitter.dataset.action, { method: "POST", body: JSON.stringify(fields) });
      document.getElementById("openbao-engine-details").textContent = JSON.stringify(payload, null, 2);
      message("Loaded bounded mount metadata.");
    } catch (error) { message(error.message, true); }
  });
  document.querySelectorAll(".openbao-engine-form").forEach((form) => form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fields = Object.fromEntries(new FormData(form));
    try {
      if (fields.configuration) fields.configuration = parseJsonObject(fields.configuration, "Configuration");
      await request(form.dataset.action, { method: "POST", body: JSON.stringify(fields) });
      message("The reviewed lifecycle operation completed.");
      await refreshMounts();
    }
    catch (error) { message(error.message, true); }
  }));

  listen(document.getElementById("openbao-journey-refresh"), "click", async () => {
    try {
      const payload = await request("secret-engine-journeys/");
      journeyDigest = payload.capability_digest;
      journeys = new Map(payload.journeys.map((journey, index) => [String(index), journey]));
      const select = document.getElementById("openbao-journey-key");
      replaceSelectOptions(select, payload.journeys.map((journey, index) => ({
        value: String(index),
        text: `${journey.mount_path} · ${journey.group} · ${journey.label}`,
      })));
      document.getElementById("openbao-journey-catalog").textContent =
        `${payload.journeys.length} permission-filtered, runtime-advertised journeys are available.`;
      select.dispatchEvent(new Event("change"));
      message("Loaded the first-class engine journey catalog.");
    } catch (error) { message(error.message, true); }
  });

  listen(document.getElementById("openbao-journey-key"), "change", (event) => {
    const journey = journeys.get(event.currentTarget.value);
    if (!journey) return;
    document.getElementById("openbao-journey-summary").textContent =
      `${journey.method} ${journey.path_template} · ${journey.risk_level} · ${journey.response_class}`;
    document.getElementById("openbao-journey-resource-field").hidden = !journey.path_template.includes("{path}");
    const named = journey.path_parameters.filter((name) => !["secret_mount_path", "path"].includes(name));
    document.getElementById("openbao-journey-path-field").hidden = named.length === 0;
    document.getElementById("openbao-journey-path-help").textContent = named.length
      ? `Required keys: ${named.join(", ")}.` : "";
    const diff = journey.journey_id === "kv2.diff";
    const fixedQuery = new Map(journey.fixed_query || []);
    const availableQuery = journey.query_parameter_types.filter(([name]) => !fixedQuery.has(name));
    document.getElementById("openbao-journey-query-field").hidden = !diff && availableQuery.length === 0;
    document.getElementById("openbao-journey-query-help").textContent = diff
      ? "Required integer keys: from_version and to_version."
      : [
          fixedQuery.size ? `Fixed: ${[...fixedQuery].map(([name, value]) => `${name}=${value}`).join(", ")}.` : "",
          availableQuery.length ? `Allowed: ${availableQuery.map(([name, type]) => `${name} (${type})`).join(", ")}.` : "",
        ].filter(Boolean).join(" ");
    document.getElementById("openbao-journey-body-field").hidden = journey.body_fields.length === 0;
    document.getElementById("openbao-journey-body-help").textContent = journey.body_fields.length
      ? `Allowed: ${journey.body_field_types.map(([name, type]) => `${name} (${type})`).join(", ")}. ` +
        `Required: ${journey.required_body_fields.join(", ") || "none"}.`
      : "";
    document.getElementById("openbao-journey-confirmation-field").hidden = !journey.confirmation_prefix;
    document.getElementById("openbao-journey-confirmation").required = Boolean(journey.confirmation_prefix);
    updateJourneyConfirmation();
  });

  function updateJourneyConfirmation() {
    const journey = journeys.get(document.getElementById("openbao-journey-key")?.value);
    if (!journey?.confirmation_prefix) return;
    try {
      const resource = document.getElementById("openbao-journey-resource").value;
      const pathParameters = parseJsonObject(document.getElementById("openbao-journey-path").value, "Path parameters");
      const confirmation = journeyConfirmation(journey, resource, pathParameters, root.dataset.clusterSlug);
      document.getElementById("openbao-journey-confirmation-help").textContent = `Enter exactly: ${confirmation}`;
    } catch (_error) {
      document.getElementById("openbao-journey-confirmation-help").textContent =
        "Enter valid path-parameter JSON to calculate the exact confirmation.";
    }
  }

  listen(document.getElementById("openbao-journey-resource"), "input", updateJourneyConfirmation);
  listen(document.getElementById("openbao-journey-path"), "input", updateJourneyConfirmation);

  listen(document.getElementById("openbao-journey-form"), "submit", async (event) => {
    event.preventDefault();
    const journey = journeys.get(document.getElementById("openbao-journey-key").value);
    try {
      if (!journey || !journeyDigest) throw new Error("Reload the engine journey catalog before execution.");
      const fields = Object.fromEntries(new FormData(event.currentTarget));
      fields.journey_id = journey.journey_id;
      fields.mount_path = journey.mount_path;
      fields.capability_digest = journeyDigest;
      fields.query = parseJsonObject(fields.query, "Query");
      fields.body = parseJsonObject(fields.body, "Body");
      fields.path_parameters = parseJsonObject(fields.path_parameters, "Path parameters");
      const payload = await request("secret-engine-journeys/execute/", {
        method: "POST", body: JSON.stringify(fields),
      });
      journeyResult.textContent = JSON.stringify(payload, null, 2);
      scheduleMaterialClear();
      message("The first-class engine task completed. Clear the result after use.");
    } catch (error) { journeyResult.textContent = "No result."; message(error.message, true); }
    finally { clearJourneyInputs(); }
  });

  listen(document.getElementById("openbao-operation-refresh"), "click", async () => {
    try {
      const payload = await request("secret-operations/");
      capabilityDigest = payload.capability_digest;
      const executable = payload.operations.filter((operation) => operation.executable);
      operations = new Map(executable.map((operation) => [operation.operation_key, operation]));
      const select = document.getElementById("openbao-operation-key");
      replaceSelectOptions(select, executable.map((operation) => ({
        value: operation.operation_key,
        text: `${operation.method} · ${operation.summary || operation.path_template}`,
      })));
      document.getElementById("openbao-operation-catalog").textContent =
        `${executable.length} reviewed operations are executable; ` +
        `${payload.operations.length - executable.length} discovered operations remain display-only.`;
      select.dispatchEvent(new Event("change"));
      message("Loaded the classified operation catalog.");
    } catch (error) { message(error.message, true); }
  });

  listen(document.getElementById("openbao-operation-key"), "change", (event) => {
    const operation = operations.get(event.currentTarget.value);
    if (!operation) return;
    document.getElementById("openbao-operation-summary").textContent =
      `${operation.method} ${operation.path_template} · ${operation.risk_level} · ${operation.response_class}`;
    document.getElementById("openbao-resource-path-field").hidden = !operation.path_template.includes("{path}");
    const otherParameters = [...operation.path_template.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)]
      .map((match) => match[1]).filter((name) => !["secret_mount_path", "path"].includes(name));
    document.getElementById("openbao-path-parameters-field").hidden = otherParameters.length === 0;
    document.getElementById("openbao-query-field").hidden = operation.query_parameters.length === 0;
    document.getElementById("openbao-query-help").textContent = operation.query_parameters.length
      ? `Allowed: ${operation.query_parameter_types.map(([name, type]) => `${name} (${type})`).join(", ")}` : "";
    document.getElementById("openbao-body-field").hidden = operation.body_fields.length === 0;
    document.getElementById("openbao-body-help").textContent = operation.body_fields.length
      ? `Allowed: ${operation.body_field_types.map(([name, type]) => `${name} (${type})`).join(", ")}. ` +
        `Required: ${operation.required_body_fields.join(", ") || "none"}.`
      : "";
    const destructive = operation.risk_level === "destructive";
    document.getElementById("openbao-confirmation-field").hidden = !destructive;
    document.getElementById("openbao-operation-confirmation").required = destructive;
    updateConfirmationHelp();
  });

  function updateConfirmationHelp() {
    const operation = operations.get(document.getElementById("openbao-operation-key")?.value);
    if (!operation || operation.risk_level !== "destructive") return;
    const mount = document.getElementById("openbao-operation-mount").value;
    const resource = document.getElementById("openbao-operation-resource").value;
    const confirmation = destructiveConfirmation(operation, mount, resource, root.dataset.clusterSlug);
    document.getElementById("openbao-confirmation-help").textContent = `Enter exactly: ${confirmation}`;
  }

  listen(document.getElementById("openbao-operation-mount"), "change", updateConfirmationHelp);
  listen(document.getElementById("openbao-operation-resource"), "input", updateConfirmationHelp);

  listen(document.getElementById("openbao-operation-form"), "submit", async (event) => {
    event.preventDefault();
    const fields = Object.fromEntries(new FormData(event.currentTarget));
    try {
      fields.query = parseJsonObject(fields.query, "Query");
      fields.body = parseJsonObject(fields.body, "Body");
      fields.path_parameters = parseJsonObject(fields.path_parameters, "Path parameters");
      fields.capability_digest = capabilityDigest;
      if (!capabilityDigest) throw new Error("Reload the classified operation catalog before execution.");
      const payload = await request("secret-operations/execute/", { method: "POST", body: JSON.stringify(fields) });
      result.textContent = JSON.stringify(payload, null, 2);
      scheduleMaterialClear();
      message("The reviewed mounted operation completed. Clear the result after use.");
    } catch (error) { result.textContent = "No result."; message(error.message, true); }
  });

  function scheduleMaterialClear() {
    materialExpiry.schedule(clearResult);
  }

  function clearResult() {
    materialExpiry.cancel();
    if (result) result.textContent = "No result.";
    if (journeyResult) journeyResult.textContent = "No result.";
    clearJourneyInputs();
    const details = document.getElementById("openbao-engine-details");
    if (details) details.textContent = "No mount metadata loaded.";
  }
  document.querySelectorAll(".openbao-result-clear").forEach((button) => listen(button, "click", clearResult));
  window.addEventListener("pagehide", clearResult);
  refreshMounts();
}

if (typeof document !== "undefined") bootstrap();
