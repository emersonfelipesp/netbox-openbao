"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  clearJourneyInputs,
  clearSensitiveMaterial,
  createMaterialExpiry,
  destructiveConfirmation,
  downloadJourneyResult,
  journeyConfirmation,
  parseJsonObject,
  replaceSelectOptions,
} from "../../static/netbox_openbao/secret_engine_administration.js";

test("request-scoped downloads revoke their object URL immediately", () => {
  const calls = [];
  const scope = {
    Blob: class Blob { constructor(parts, options) { calls.push(["blob", parts, options]); } },
    URL: {
      createObjectURL: () => { calls.push(["create"]); return "blob:result"; },
      revokeObjectURL: (url) => calls.push(["revoke", url]),
    },
    document: { createElement: () => ({
      click() { calls.push(["click", this.href, this.download, this.rel]); },
    }) },
  };

  downloadJourneyResult('{"data":{"certificate":"sensitive"}}', "certificate.json", scope);

  assert.deepEqual(calls.at(-2), ["click", "blob:result", "certificate.json", "noopener"]);
  assert.deepEqual(calls.at(-1), ["revoke", "blob:result"]);
  assert.throws(() => downloadJourneyResult("No result.", "certificate.json", scope), /No downloadable/);
});

test("journey input clearing removes material and restores empty JSON envelopes", () => {
  const fields = new Map([
    ["openbao-journey-resource", { value: "sensitive/path" }],
    ["openbao-journey-reason", { value: "operator reason" }],
    ["openbao-journey-confirmation", { value: "exact confirmation" }],
    ["openbao-journey-path", { value: '{"name":"sensitive"}' }],
    ["openbao-journey-query", { value: '{"token":"sensitive"}' }],
    ["openbao-journey-body", { value: '{"plaintext":"sensitive"}' }],
  ]);

  clearJourneyInputs({ getElementById: (id) => fields.get(id) });

  assert.equal(fields.get("openbao-journey-resource").value, "");
  assert.equal(fields.get("openbao-journey-reason").value, "");
  assert.equal(fields.get("openbao-journey-confirmation").value, "");
  assert.equal(fields.get("openbao-journey-path").value, "{}");
  assert.equal(fields.get("openbao-journey-query").value, "{}");
  assert.equal(fields.get("openbao-journey-body").value, "{}");
});

test("material expiry resets from each successful response and can be cancelled", () => {
  let nextId = 0;
  const timers = new Map();
  const cleared = [];
  const expiry = createMaterialExpiry({
    setTimer: (callback, duration) => {
      const id = ++nextId;
      timers.set(id, { callback, duration });
      return id;
    },
    clearTimer: (id) => { cleared.push(id); timers.delete(id); },
    ttlMs: 300000,
  });
  let clearCalls = 0;

  expiry.schedule(() => { clearCalls += 1; });
  expiry.schedule(() => { clearCalls += 1; });
  assert.deepEqual(cleared, [1]);
  assert.equal(timers.get(2).duration, 300000);
  timers.get(2).callback();
  assert.equal(clearCalls, 1);
  expiry.schedule(() => { clearCalls += 1; });
  expiry.cancel();
  assert.deepEqual(cleared, [1, 3]);
});

test("sensitive clearing cancels expiry and removes both result surfaces and downloads", () => {
  let cancelled = 0;
  const fields = new Map([
    ["openbao-journey-resource", { value: "secret" }],
    ["openbao-journey-reason", { value: "reason" }],
    ["openbao-journey-confirmation", { value: "confirmation" }],
    ["openbao-journey-path", { value: '{"name":"secret"}' }],
    ["openbao-journey-query", { value: '{"token":"secret"}' }],
    ["openbao-journey-body", { value: '{"private_key":"secret"}' }],
  ]);
  const elements = {
    result: { textContent: "generic secret" },
    journeyResult: { textContent: "journey secret" },
    journeyDownload: { hidden: false, dataset: { filename: "secret.json" } },
  };

  clearSensitiveMaterial(
    { cancel: () => { cancelled += 1; } },
    elements,
    { getElementById: (id) => fields.get(id) },
  );

  assert.equal(cancelled, 1);
  assert.equal(elements.result.textContent, "No result.");
  assert.equal(elements.journeyResult.textContent, "No result.");
  assert.equal(elements.journeyDownload.hidden, true);
  assert.equal(elements.journeyDownload.dataset.filename, "");
  assert.equal(fields.get("openbao-journey-body").value, "{}");
});

test("advanced engine fields accept only JSON objects", () => {
  assert.deepEqual(parseJsonObject('{"type":"kv"}', "Configuration"), { type: "kv" });
  assert.throws(() => parseJsonObject('["kv"]', "Configuration"), /must be a JSON object/);
  assert.throws(() => parseJsonObject('"kv"', "Configuration"), /must be a JSON object/);
});

test("destructive confirmations bind the advertised method and compiled mount path", () => {
  const operation = {
    method: "POST",
    path_template: "/{secret_mount_path}/destroy/{path}",
    risk_level: "destructive",
  };
  assert.equal(
    destructiveConfirmation(operation, "secret", "team/database", "primary"),
    "POST /secret/destroy/team/database ON primary",
  );
  assert.equal(destructiveConfirmation({ ...operation, risk_level: "write" }, "secret", "x", "primary"), "");
});

test("first-class journey confirmation matches the server path compiler", () => {
  const journey = {
    confirmation_prefix: "DELETE DATABASE ROLE",
    mount_path: "database",
    path_template: "/{secret_mount_path}/roles/{name}",
  };
  assert.equal(
    journeyConfirmation(journey, "", { name: "team@app+blue" }, "primary"),
    "DELETE DATABASE ROLE /database/roles/team@app+blue ON primary",
  );
  assert.equal(journeyConfirmation({ ...journey, confirmation_prefix: "" }, "", {}, "primary"), "");
});

test("dynamic options synchronize an enhanced select", () => {
  const calls = [];
  const select = { disabled: true, tomselect: {
    clear: (silent) => calls.push(["clear", silent]),
    clearOptions: () => calls.push(["clearOptions"]),
    addOption: (options) => calls.push(["addOption", options]),
    refreshOptions: (open) => calls.push(["refreshOptions", open]),
    setValue: (value, silent) => calls.push(["setValue", value, silent]),
    enable: () => calls.push(["enable"]),
    disable: () => calls.push(["disable"]),
  } };
  const options = [{ value: "secret", text: "secret (kv)" }];

  replaceSelectOptions(select, options);

  assert.deepEqual(calls, [
    ["clear", true],
    ["clearOptions"],
    ["addOption", options],
    ["refreshOptions", false],
    ["setValue", "secret", true],
    ["enable"],
  ]);
  assert.equal(select.disabled, false);
});
