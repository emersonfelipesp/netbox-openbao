"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  createMaterialExpiry,
  destructiveConfirmation,
  parseJsonObject,
  replaceSelectOptions,
} from "../../static/netbox_openbao/secret_engine_administration.js";

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
