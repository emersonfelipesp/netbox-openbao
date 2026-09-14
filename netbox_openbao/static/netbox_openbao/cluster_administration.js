"use strict";

async function completeAction(send, reloadRequested, showResult, reloadPage) {
  const response = await send();
  const data = await response.json().catch(() => ({ detail: "The server returned an invalid response." }));
  if (!response.ok) throw new Error(JSON.stringify(data));
  if (data.outcome === "accepted-audit-incomplete") {
    showResult(
      `OpenBao accepted the operation, but the completion audit is incomplete. Do not retry. Verify current OpenBao state and repair NetBox auditing before another mutation.\n${JSON.stringify(data, null, 2)}`,
      true,
    );
    return data;
  }
  showResult(data);
  if (reloadRequested) reloadPage();
  return data;
}

export { completeAction };

if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("openbao-administration");
  if (!root) return;

  const result = document.getElementById("openbao-action-result");
  const csrf = root.querySelector("input[name=csrfmiddlewaretoken]")?.value || "";
  const urls = {
    initialize: root.dataset.initializeUrl,
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
      const payload = Object.fromEntries(fields.entries());
      if (action === "initialize") {
        const recovery = payload.seal_mode === "recovery";
        delete payload.seal_mode;
        for (const name of recovery ? ["secret_shares", "secret_threshold", "pgp_keys"] : ["recovery_shares", "recovery_threshold", "recovery_pgp_keys"]) delete payload[name];
        for (const name of ["pgp_keys", "recovery_pgp_keys"]) {
          if (payload[name]) payload[name] = payload[name].split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
          else delete payload[name];
        }
        if (!payload.root_token_pgp_key) delete payload.root_token_pgp_key;
      }
      for (const name of ["secret_shares", "secret_threshold", "recovery_shares", "recovery_threshold", "configuration_index"]) {
        if (name in payload) payload[name] = Number(payload[name]);
      }
      const keyInput = form.querySelector("input[name=key]");
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
        if (keyInput) keyInput.value = "";
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
