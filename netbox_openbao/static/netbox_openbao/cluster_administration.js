"use strict";

function isObject(value) { return Boolean(value) && !Array.isArray(value) && typeof value === "object"; }

async function completeAction(send, reloadRequested, showResult, reloadPage) {
  let response;
  try { response = await send(); }
  catch {
    const data = { outcome: "unknown", audit_status: "unavailable" };
    showResult(`OpenBao may have accepted the operation. Do not retry. Verify current state first.\n${JSON.stringify(data, null, 2)}`, true);
    return data;
  }
  let data;
  try { data = await response.json(); }
  catch {
    const unknown = { outcome: "unknown", audit_status: "unavailable" };
    showResult(`OpenBao may have accepted the operation. Do not retry. Verify current state first.\n${JSON.stringify(unknown, null, 2)}`, true);
    return unknown;
  }
  if (!isObject(data)) {
    const unknown = { outcome: "unknown", audit_status: "unavailable" };
    showResult(`OpenBao may have accepted the operation. Do not retry. Verify current state first.\n${JSON.stringify(unknown, null, 2)}`, true);
    return unknown;
  }
  if (data.outcome === "unknown") {
    showResult(
      `OpenBao may have accepted the operation. Do not retry. Verify current state first.\n${JSON.stringify(data, null, 2)}`,
      true,
    );
    return data;
  }
  if (data.outcome === "accepted-audit-incomplete") {
    showResult(
      `OpenBao accepted the operation, but the completion audit is incomplete. Do not retry. Verify current OpenBao state and repair NetBox auditing before another mutation.\n${JSON.stringify(data, null, 2)}`,
      true,
    );
    return data;
  }
  if (!response.ok) throw new Error(JSON.stringify(data));
  showResult(data);
  if (reloadRequested) reloadPage();
  return data;
}

function initializePayload(payload) {
  const recovery = payload.seal_mode === "recovery";
  delete payload.seal_mode;
  for (const name of recovery ? ["secret_shares", "secret_threshold", "pgp_keys"] : ["recovery_shares", "recovery_threshold", "recovery_pgp_keys"]) delete payload[name];
  for (const name of ["pgp_keys", "recovery_pgp_keys"]) {
    if (payload[name]) payload[name] = payload[name].split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    else delete payload[name];
  }
  if (!payload.root_token_pgp_key) delete payload.root_token_pgp_key;
}

function coerceClusterNumbers(payload) {
  for (const name of ["secret_shares", "secret_threshold", "recovery_shares", "recovery_threshold", "configuration_index", "auto_join_port"]) {
    if (name in payload && payload[name] !== "") payload[name] = Number(payload[name]);
  }
}

function joinPayload(payload, fields) {
  for (const name of ["retry", "non_voter"]) payload[name] = fields.has(name);
  for (const name of ["leader_api_addr", "leader_ca_cert", "leader_client_cert", "leader_client_key", "leader_tls_servername", "auto_join", "auto_join_scheme", "auto_join_port"]) {
    if (payload[name] === "" || payload[name] === undefined) delete payload[name];
  }
  if (payload.leader_api_addr) for (const name of ["auto_join_scheme", "auto_join_port"]) delete payload[name];
}

function clusterActionPayload(action, fields) {
  const payload = Object.fromEntries(fields.entries());
  if (action === "initialize") initializePayload(payload);
  coerceClusterNumbers(payload);
  if (action === "join") joinPayload(payload, fields);
  return payload;
}

function clearClusterActionMaterial(form) {
  for (const input of form.querySelectorAll(
    '[name="key"], [name="leader_ca_cert"], [name="leader_client_cert"], [name="leader_client_key"]',
  )) input.value = "";
}

export { clearClusterActionMaterial, clusterActionPayload, completeAction };

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("openbao-administration");
  if (!root) return;

  const result = document.getElementById("openbao-action-result");
  const csrf = root.querySelector("input[name=csrfmiddlewaretoken]")?.value || "";
  const urls = {
    initialize: root.dataset.initializeUrl,
    join: root.dataset.joinUrl,
    unseal: root.dataset.unsealUrl,
    seal: root.dataset.sealUrl,
    "remove-peer": root.dataset.removePeerUrl,
  };

  const sealMode = root.querySelector("select[name=seal_mode]");
  function updateSealMode() {
    const recovery = sealMode?.value === "recovery";
    for (const field of root.querySelectorAll(".openbao-shamir-field")) field.classList.toggle("d-none", recovery);
    for (const field of root.querySelectorAll(".openbao-recovery-field")) field.classList.toggle("d-none", !recovery);
  }
  sealMode?.addEventListener("change", updateSealMode);
  updateSealMode();

  function show(value, error = false) {
    if (!result) return;
    result.classList.remove("d-none", "alert-secondary", "alert-danger", "alert-success");
    result.classList.add(error ? "alert-danger" : "alert-success");
    result.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  for (const form of root.querySelectorAll("form.openbao-json-action")) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const action = form.dataset.action;
      const fields = new FormData(form);
      const payload = clusterActionPayload(action, fields);
      try {
        await completeAction(
          () => fetch(urls[action], {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
            body: JSON.stringify(payload),
            cache: "no-store",
          }),
          form.dataset.reload === "true",
          show,
          () => window.location.reload(),
        );
      } catch (error) {
        show(error.message, true);
      } finally {
        clearClusterActionMaterial(form);
      }
    });
  }

  for (const form of root.querySelectorAll("form.openbao-snapshot-restore")) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const fileInput = form.querySelector("input[name=snapshot]");
      const file = fileInput?.files?.[0];
      const limit = Number(root.dataset.snapshotLimit);
      if (!file || file.size < 1 || file.size > limit) {
        show("The snapshot file is empty or exceeds the configured upload limit.", true);
        return;
      }
      const force = form.dataset.force === "true";
      const url = force ? root.dataset.forceRestoreUrl : root.dataset.restoreUrl;
      try {
        await completeAction(
          () => fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type": "application/octet-stream",
              "X-CSRFToken": csrf,
              "X-OpenBao-Reason": form.elements.reason.value,
              "X-OpenBao-Confirmation": form.elements.confirmation.value,
              "X-OpenBao-Cluster-ID": form.elements.cluster_id.value,
              "X-OpenBao-Raft-Index": form.elements.configuration_index.value,
            },
            body: file,
            cache: "no-store",
          }),
          true,
          show,
          () => window.location.reload(),
        );
      } catch (error) {
        show(error.message, true);
      } finally {
        fileInput.value = "";
      }
    });
  }

  window.addEventListener("pagehide", () => {
    if (result) result.textContent = "";
    for (const input of root.querySelectorAll("input[type=password], input[type=file], textarea")) input.value = "";
  });
});
