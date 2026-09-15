"use strict";

const LOGIN_FIELDS = {
  token: ["token"],
  userpass: ["username", "password"],
  ldap: ["username", "password"],
  radius: ["username", "password"],
  jwt: ["role", "jwt"],
  approle: ["role_id", "secret_id"],
  kubernetes: ["role", "jwt"],
};
const OIDC_FLOW_TTL_MS = 300_000;
const UNKNOWN_MUTATION_MESSAGE = "OpenBao may have accepted the request. Do not retry; verify current state first.";

function cleanPathPart(value) {
  return encodeURIComponent(String(value || "").trim());
}

function formValues(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function jsonPayload(value) {
  const parsed = JSON.parse(value || "{}");
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("The reviewed field payload must be one JSON object.");
  }
  return parsed;
}

function buildLoginPayload(values) {
  const fields = LOGIN_FIELDS[values.method_type];
  if (!fields) throw new Error("The selected login method is unsupported.");
  const payload = { method_type: values.method_type, reason: values.reason };
  for (const name of fields) payload[name] = values[name] || "";
  return payload;
}

function unknownMutationResult() {
  return { outcome: "unknown", audit_status: "unconfirmed", message: UNKNOWN_MUTATION_MESSAGE };
}

function handleTransportFailure(method) {
  if (method !== "GET") return unknownMutationResult();
  throw new Error("The OpenBao request could not be completed.");
}

function isResponseObject(data) {
  return Boolean(data) && !Array.isArray(data) && typeof data === "object";
}

async function parseAPIResponse(response, method) {
  let data;
  try {
    data = await response.json();
  } catch {
    if (method !== "GET" && response.ok) return unknownMutationResult();
    throw new Error("The server returned an invalid response.");
  }
  if (!isResponseObject(data)) {
    if (method !== "GET" && response.ok) return unknownMutationResult();
    throw new Error("The server returned an invalid response.");
  }
  if (!response.ok && data.outcome !== "unknown") throw new Error(JSON.stringify(data));
  return data;
}

async function apiRequest(url, { method = "GET", payload, csrf = "" } = {}) {
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
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    return handleTransportFailure(method);
  }
  return parseAPIResponse(response, method);
}

function createOIDCController({ now = () => Date.now(), ttlMs = OIDC_FLOW_TTL_MS } = {}) {
  let flow = null;
  return {
    begin(data, mountPath, reason) {
      flow = {
        mountPath,
        reason,
        state: data.state,
        clientNonce: data.client_nonce,
        envelope: data.envelope,
        expiresAt: now() + ttlMs,
      };
    },
    pollPayload(mountPath) {
      if (this.expire()) throw new Error("The OIDC flow expired. Start OIDC again.");
      if (!flow || flow.mountPath !== mountPath) throw new Error("Start OIDC in this tab before polling.");
      return {
        state: flow.state,
        client_nonce: flow.clientNonce,
        envelope: flow.envelope,
        reason: flow.reason,
      };
    },
    clear() {
      flow = null;
    },
    expire() {
      if (!flow || now() < flow.expiresAt) return false;
      flow = null;
      return true;
    },
    remainingMs() {
      return flow ? Math.max(0, flow.expiresAt - now()) : 0;
    },
    active() {
      this.expire();
      return flow !== null;
    },
  };
}

function isUncertainOutcome(data) {
  return data?.outcome === "unknown" || data?.outcome === "accepted-audit-incomplete";
}

function isOIDCExpiryError(error) {
  return String(error?.message || "").includes("OIDC polling envelope is invalid or expired");
}

async function reconcileAfterMutation(loader, data) {
  try {
    await loader();
  } catch (error) {
    if (!isUncertainOutcome(data)) throw error;
  }
}

function methodCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value ?? "");
  row.append(cell);
}

function renderMethods(body, methods) {
  body.replaceChildren();
  if (!methods.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No reviewed auth methods were returned.";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const method of methods) {
    const row = document.createElement("tr");
    methodCell(row, method.path);
    methodCell(row, method.method_type);
    methodCell(row, method.description);
    methodCell(row, method.default_lease_ttl);
    methodCell(row, method.max_lease_ttl);
    body.append(row);
  }
}

function clearMaterialFields(root) {
  const selector = [
    "input[type=password]",
    "textarea[name=jwt]",
    "textarea[name=payload]",
    "textarea[name=advanced_payload]",
    "textarea[name=mfa_payload]",
    "input[name=role_id]",
    "input[name=secret_id]",
    "input[name=token]",
    "input[name=accessor]",
  ].join(",");
  for (const field of root.querySelectorAll(selector)) field.value = "";
}

function bindConfirmationHint(form, output, formatter) {
  if (!form || !output) return;
  const update = () => {
    output.textContent = formatter(formValues(form));
  };
  form.addEventListener("input", update);
  form.addEventListener("change", update);
  update();
}

function associateFormLabels(root) {
  let sequence = 0;
  for (const label of root.querySelectorAll("label.form-label")) {
    const control = label.parentElement?.querySelector("input, select, textarea");
    if (!control) continue;
    if (!control.id) control.id = `openbao-auth-field-${sequence++}`;
    label.htmlFor = control.id;
  }
}

function compactValues(values) {
  return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== ""));
}

function clearQRCode(qr) {
  if (!qr) return;
  qr.removeAttribute("src");
  qr.classList.add("d-none");
}

function displayResultValue(value, error, qr) {
  clearQRCode(qr);
  if (error || !value || typeof value !== "object" || typeof value.barcode !== "string") return value;
  if (qr) {
    qr.src = `data:image/png;base64,${value.barcode}`;
    qr.classList.remove("d-none");
  }
  const visibleValue = { ...value };
  delete visibleValue.barcode;
  return visibleValue;
}

function mergeAdvancedPayload(payload, rawValue) {
  const advanced = jsonPayload(rawValue);
  if (Object.keys(advanced).some((key) => Object.hasOwn(payload, key))) {
    throw new Error("Advanced fields cannot replace a named form field.");
  }
  return { ...payload, ...advanced };
}

function lifecycleRequest(operation, values, apiBase) {
  if (operation === "enable-method") {
    const payload = compactValues(values);
    delete payload.advanced_payload;
    return {
      url: `${apiBase}auth-methods/`,
      method: "POST",
      payload: mergeAdvancedPayload(payload, values.advanced_payload),
    };
  }
  if (operation === "tune-method") {
    const payload = { ...values };
    delete payload.mount_path;
    delete payload.advanced_payload;
    for (const name of ["default_lease_ttl", "max_lease_ttl"])
      if (payload[name] !== "") payload[name] = Number(payload[name]);
      else delete payload[name];
    return {
      url: `${apiBase}auth-methods/${cleanPathPart(values.mount_path)}/`,
      method: "POST",
      payload: mergeAdvancedPayload(compactValues(payload), values.advanced_payload),
    };
  }
  if (operation === "remount-method") {
    return {
      url: `${apiBase}auth-remount/`,
      method: "POST",
      payload: { source: values.source, destination: values.destination, reason: values.reason },
    };
  }
  return {
    url: `${apiBase}auth-methods/${cleanPathPart(values.mount_path)}/`,
    method: "DELETE",
    payload: { reason: values.reason, confirmation: values.confirmation },
  };
}

function configurationRequest(operation, values, apiBase) {
  if (operation === "auth-config") {
    const url = `${apiBase}auth-config/${cleanPathPart(values.mount_path)}/`;
    return values.config_operation === "read"
      ? { url, method: "GET" }
      : { url, method: "POST", payload: { payload: jsonPayload(values.payload), reason: values.reason } };
  }
  const name = values.resource_operation === "list" ? "" : `/${cleanPathPart(values.name)}`;
  const url = `${apiBase}auth-resources/${cleanPathPart(values.mount_path)}/${cleanPathPart(values.resource_key)}${name}/`;
  if (["list", "read"].includes(values.resource_operation)) return { url, method: "GET" };
  if (values.resource_operation === "delete") {
    return {
      url,
      method: "DELETE",
      payload: { reason: values.reason, confirmation: values.confirmation },
    };
  }
  return { url, method: "POST", payload: { payload: jsonPayload(values.payload), reason: values.reason } };
}

function approleRequest(values, apiBase) {
  const roleBase = `${apiBase}auth-approle/${cleanPathPart(values.mount_path)}/${cleanPathPart(values.role_name)}`;
  if (values.secret_id_operation === "read-role-id") return { url: `${roleBase}/role-id/`, method: "GET" };
  if (values.secret_id_operation === "write-role-id") {
    return {
      url: `${roleBase}/role-id/`,
      method: "POST",
      payload: { role_id: values.role_id, reason: values.reason },
    };
  }
  if (values.secret_id_operation === "issue") {
    return {
      url: `${roleBase}/secret-id/`,
      method: "POST",
      payload: { ...jsonPayload(values.payload), reason: values.reason },
    };
  }
  const destructive = values.secret_id_operation === "destroy";
  const payload = { accessor: values.accessor, reason: values.reason };
  if (destructive) payload.confirmation = values.confirmation;
  return { url: `${roleBase}/secret-id-accessor/`, method: destructive ? "DELETE" : "POST", payload };
}

function authenticationRequest(operation, values, apiBase) {
  if (operation === "login") {
    return {
      url: `${apiBase}auth-login/${cleanPathPart(values.mount_path)}/`,
      method: "POST",
      payload: buildLoginPayload(values),
    };
  }
  return {
    url: `${apiBase}auth-oidc/${cleanPathPart(values.mount_path)}/start/`,
    method: "POST",
    payload: { role: values.role, reason: values.reason },
  };
}

function mfaMethodRequest(values, apiBase) {
  if (values.mfa_operation === "list") return { url: `${apiBase}auth-mfa/methods/`, method: "GET" };
  const item = `${apiBase}auth-mfa/methods/${cleanPathPart(values.method_type)}/${cleanPathPart(values.method_id)}/`;
  if (values.mfa_operation === "read") return { url: item, method: "GET" };
  const url = values.mfa_operation === "update" ? item : `${apiBase}auth-mfa/methods/${cleanPathPart(values.method_type)}/`;
  return { url, method: "POST", payload: { payload: jsonPayload(values.payload), reason: values.reason } };
}

function mfaEnforcementRequest(values, apiBase) {
  if (values.enforcement_operation === "list") {
    return { url: `${apiBase}auth-mfa/enforcements/`, method: "GET" };
  }
  const url = `${apiBase}auth-mfa/enforcements/${cleanPathPart(values.name)}/`;
  return values.enforcement_operation === "read"
    ? { url, method: "GET" }
    : { url, method: "POST", payload: { payload: jsonPayload(values.payload), reason: values.reason } };
}

function mfaRequest(operation, values, apiBase) {
  if (operation === "mfa-method") return mfaMethodRequest(values, apiBase);
  if (operation === "mfa-enforcement") return mfaEnforcementRequest(values, apiBase);
  if (operation === "mfa-totp-self") {
    return {
      url: `${apiBase}auth-mfa/totp/${cleanPathPart(values.method_id)}/self/`,
      method: "POST",
      payload: { token: values.token, reason: values.reason },
    };
  }
  if (operation === "mfa-totp-self-reset") {
    return {
      url: `${apiBase}auth-mfa/totp/${cleanPathPart(values.method_id)}/self/reset/`,
      method: "POST",
      payload: { token: values.token, reason: values.reason, confirmation: values.confirmation },
    };
  }
  if (operation === "mfa-totp") {
    const method = values.totp_operation === "destroy" ? "DELETE" : "POST";
    const payload = { reason: values.reason };
    if (method === "DELETE") payload.confirmation = values.confirmation;
    return {
      url: `${apiBase}auth-mfa/totp/${cleanPathPart(values.method_id)}/entities/${cleanPathPart(values.entity_id)}/`,
      method,
      payload,
    };
  }
  if (operation === "mfa-delete") {
    const url =
      values.delete_kind === "method"
        ? `${apiBase}auth-mfa/methods/${cleanPathPart(values.method_type)}/${cleanPathPart(values.identifier)}/`
        : `${apiBase}auth-mfa/enforcements/${cleanPathPart(values.identifier)}/`;
    return {
      url,
      method: "DELETE",
      payload: { reason: values.reason, confirmation: values.confirmation },
    };
  }
  return {
    url: `${apiBase}auth-mfa/validate/`,
    method: "POST",
    payload: {
      mfa_request_id: values.mfa_request_id,
      mfa_payload: jsonPayload(values.mfa_payload),
      reason: values.reason,
    },
  };
}

function tokenRequest(values, apiBase) {
  const selfOperation = values.token_operation.endsWith("self");
  const payload = {
    [selfOperation ? "token" : "accessor"]: values[selfOperation ? "token" : "accessor"],
    reason: values.reason,
  };
  if (values.token_operation.startsWith("renew") && values.increment !== "") {
    payload.increment = Number(values.increment);
  }
  if (values.token_operation.startsWith("revoke")) payload.confirmation = values.confirmation;
  return {
    url: `${apiBase}auth-tokens/${cleanPathPart(values.token_operation)}/`,
    method: "POST",
    payload,
  };
}

function buildOperationRequest(operation, values, apiBase) {
  if (["enable-method", "tune-method", "remount-method", "disable-method"].includes(operation)) {
    return lifecycleRequest(operation, values, apiBase);
  }
  if (["auth-config", "auth-resource"].includes(operation)) {
    return configurationRequest(operation, values, apiBase);
  }
  if (operation === "approle-secret-id") return approleRequest(values, apiBase);
  if (["login", "oidc-start"].includes(operation)) return authenticationRequest(operation, values, apiBase);
  if (operation.startsWith("mfa-")) return mfaRequest(operation, values, apiBase);
  if (operation === "token") return tokenRequest(values, apiBase);
  throw new Error("The selected operation is unsupported.");
}

export {
  apiRequest,
  buildLoginPayload,
  buildOperationRequest,
  createOIDCController,
  isOIDCExpiryError,
  jsonPayload,
  reconcileAfterMutation,
  renderMethods,
};

if (typeof document !== "undefined")
  document.addEventListener("DOMContentLoaded", () => {
    const root = document.getElementById("openbao-authentication");
    if (!root) return;

    const apiBase = root.dataset.apiBase;
    const clusterSlug = root.dataset.clusterSlug;
    const csrf = root.querySelector("input[name=csrfmiddlewaretoken]")?.value || "";
    const methodsBody = document.getElementById("openbao-auth-methods");
    const result = document.getElementById("openbao-auth-result");
    const qr = document.getElementById("openbao-auth-qr");
    const emptyResult = document.getElementById("openbao-auth-empty");
    const oidcPoll = document.getElementById("openbao-oidc-poll");
    const oidc = createOIDCController();
    let clearTimer = null;
    let oidcExpiryTimer = null;

    function clearOIDCFlow() {
      if (oidcExpiryTimer) window.clearTimeout(oidcExpiryTimer);
      oidcExpiryTimer = null;
      oidc.clear();
      if (oidcPoll) oidcPoll.disabled = true;
    }

    function showOIDCExpiry() {
      if (!oidc.expire()) return false;
      if (oidcExpiryTimer) window.clearTimeout(oidcExpiryTimer);
      oidcExpiryTimer = null;
      if (oidcPoll) oidcPoll.disabled = true;
      showResult("The OIDC flow expired. Start OIDC again.", true);
      return true;
    }

    function scheduleOIDCExpiry() {
      if (oidcExpiryTimer) window.clearTimeout(oidcExpiryTimer);
      oidcExpiryTimer = window.setTimeout(() => {
        oidcExpiryTimer = null;
        if (!showOIDCExpiry() && oidc.active()) scheduleOIDCExpiry();
      }, oidc.remainingMs());
    }

    function clearResult() {
      if (clearTimer) window.clearTimeout(clearTimer);
      clearTimer = null;
      if (result) {
        result.textContent = "";
        result.classList.add("d-none");
      }
      clearQRCode(qr);
      emptyResult?.classList.remove("d-none");
      clearMaterialFields(root);
    }

    function showResult(value, error = false) {
      if (!result) return;
      emptyResult?.classList.add("d-none");
      result.classList.remove("d-none", "text-danger", "text-success");
      result.classList.add(error ? "text-danger" : "text-success");
      const visibleValue = displayResultValue(value, error, qr);
      result.textContent = typeof visibleValue === "string" ? visibleValue : JSON.stringify(visibleValue, null, 2);
      result.scrollIntoView({ block: "nearest" });
      if (clearTimer) window.clearTimeout(clearTimer);
      clearTimer = window.setTimeout(clearResult, 300_000);
    }

    async function loadMethods() {
      const data = await apiRequest(`${apiBase}auth-methods/`, { csrf });
      renderMethods(methodsBody, data.auth_methods || []);
    }

    document.getElementById("openbao-refresh-methods")?.addEventListener("click", () => {
      loadMethods().catch((error) => showResult(error.message, true));
    });
    document.getElementById("openbao-clear-result")?.addEventListener("click", clearResult);
    associateFormLabels(root);
    bindConfirmationHint(
      root.querySelector('form[data-operation="auth-resource"]'),
      document.getElementById("openbao-resource-confirmation"),
      (values) =>
        values.resource_operation === "delete" && values.name
          ? `Type exactly: DELETE AUTH RESOURCE ${values.resource_key}/${values.name} ON ${clusterSlug}`
          : "Select delete and enter a name to show the exact phrase.",
    );
    bindConfirmationHint(
      root.querySelector('form[data-operation="mfa-delete"]'),
      document.getElementById("openbao-mfa-confirmation"),
      (values) => {
        if (!values.identifier) return "Enter an identifier to show the exact phrase.";
        return values.delete_kind === "method"
          ? `Type exactly: DELETE MFA METHOD ${values.identifier} ON ${clusterSlug}`
          : `Type exactly: DELETE MFA ENFORCEMENT ${values.identifier} ON ${clusterSlug}`;
      },
    );

    for (const form of root.querySelectorAll("form.openbao-auth-form")) {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const values = formValues(form);
        const operation = form.dataset.operation;
        try {
          const { url, method, payload } = buildOperationRequest(operation, values, apiBase);
          const data = await apiRequest(url, { method, payload, csrf });
          if (isUncertainOutcome(data)) {
            showResult(
              `${data.message || "The OpenBao outcome requires reconciliation."}\n${JSON.stringify(data, null, 2)}`,
              true,
            );
          } else if (operation === "oidc-start") {
            oidc.begin(data, values.mount_path, values.reason);
            if (oidcPoll) {
              oidcPoll.dataset.mountPath = values.mount_path;
              oidcPoll.disabled = false;
            }
            scheduleOIDCExpiry();
            const opened = window.open(data.auth_url, "_blank", "noopener,noreferrer");
            if (opened) opened.opener = null;
            showResult({
              message: "The identity provider opened in a separate tab. Return here and poll after login.",
              poll_interval: data.poll_interval,
            });
          } else {
            showResult(data);
          }
          if (["enable-method", "tune-method", "remount-method", "disable-method"].includes(operation)) {
            await reconcileAfterMutation(loadMethods, data);
          }
        } catch (error) {
          showResult(error.message, true);
        } finally {
          clearMaterialFields(form);
        }
      });
    }

    oidcPoll?.addEventListener("click", async () => {
      if (showOIDCExpiry()) return;
      const mountPath = oidcPoll.dataset.mountPath || "";
      try {
        const payload = oidc.pollPayload(mountPath);
        const data = await apiRequest(`${apiBase}auth-oidc/${cleanPathPart(mountPath)}/poll/`, {
          method: "POST",
          payload,
          csrf,
        });
        clearOIDCFlow();
        showResult(data);
      } catch (error) {
        if (oidc.expire() || isOIDCExpiryError(error)) {
          clearOIDCFlow();
          showResult("The OIDC flow expired. Start OIDC again.", true);
          return;
        }
        showResult(error.message, true);
      }
    });

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) showOIDCExpiry();
    });

    window.addEventListener("pagehide", () => {
      clearOIDCFlow();
      clearResult();
    });
  });
