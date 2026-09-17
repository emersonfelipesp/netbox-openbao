"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  clearMaterialControls,
  createMutationGate,
  createRequestGeneration,
  fieldValue,
  parseField,
  outcomePresentation,
  request,
  renderFields,
} from "../../static/netbox_openbao/finalization_administration.js";

test("mutation gate suppresses overlapping finalization operations", async () => {
  let release;
  let calls = 0;
  const transitions = [];
  const runMutation = createMutationGate((value) => transitions.push(value));
  const first = runMutation(async () => {
    calls += 1;
    await new Promise((resolve) => { release = resolve; });
  });
  assert.equal(await runMutation(async () => { calls += 1; }), undefined);
  assert.equal(calls, 1);
  release();
  await first;
  assert.deepEqual(transitions, [true, false]);
});

test("wrapping JSON canaries clear through the shared explicit, expiry, operation, and pagehide path", () => {
  const controls = [{ value: "wrapping-canary" }, { value: "token-canary" }];
  clearMaterialControls({ querySelectorAll: () => controls });
  assert.deepEqual(controls.map((control) => control.value), ["", ""]);
});

test("preview transport and malformed responses are ordinary errors while execution is unknown", async () => {
  const previousFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error("timeout"); };
    await assert.rejects(request("/preview", { method: "POST" }), /unavailable/);
    assert.equal((await request("/execute", { method: "POST", unknownOnLoss: true })).outcome, "unknown");
    globalThis.fetch = async () => ({ ok: true, json: async () => { throw new Error("malformed"); } });
    await assert.rejects(request("/preview", { method: "POST" }), /invalid response/);
    assert.equal((await request("/execute", { method: "POST", unknownOnLoss: true })).outcome, "unknown");
    for (const payload of [[], null, "accepted", 1]) {
      globalThis.fetch = async () => ({ ok: true, json: async () => payload });
      await assert.rejects(request("/preview", { method: "POST" }), /invalid response/);
      assert.equal((await request("/execute", { method: "POST", unknownOnLoss: true })).outcome, "unknown");
    }
  } finally { globalThis.fetch = previousFetch; }
});

test("uncertain and audit-incomplete results persist as danger states", () => {
  assert.deepEqual(outcomePresentation("unknown"), { kind: "danger", persistent: true });
  assert.deepEqual(outcomePresentation("accepted-audit-incomplete"), { kind: "danger", persistent: true });
  assert.deepEqual(outcomePresentation(undefined), { kind: "success", persistent: false });
});

test("request generation makes reversed responses monotonic", () => {
  const requests = createRequestGeneration();
  const older = requests.begin(); const newer = requests.begin();
  assert.equal(requests.current(newer), true);
  assert.equal(requests.current(older), false);
  requests.invalidate();
  assert.equal(requests.current(newer), false);
});

test("typed finalization fields preserve omission, false, numeric values, and JSON", () => {
  assert.equal(fieldValue({ value: "" }, { kind: "boolean", required: false }), undefined);
  assert.equal(fieldValue({ value: "false" }, { kind: "boolean", required: false }), false);
  assert.equal(fieldValue({ value: "32" }, { kind: "strict-positive-integer", required: true }), 32);
  assert.deepEqual(parseField('["DENY"]', "string-list"), ["DENY"]);
  assert.deepEqual(parseField('{"owner":"platform"}', "json-map"), { owner: "platform" });
  assert.throws(() => parseField("{}", "string-list"), /must be a JSON list/);
  assert.throws(() => parseField("[]", "json-map"), /must be a JSON object/);
});

test("rendered material controls use password inputs and text-only labels", () => {
  class Element {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.className = "";
      this.dataset = {};
    }
    append(...children) { this.children.push(...children); }
  }
  const previousDocument = globalThis.document;
  const previousOption = globalThis.Option;
  globalThis.document = { createElement: (tag) => new Element(tag) };
  globalThis.Option = class Option { constructor(text, value) { this.text = text; this.value = value; } };
  const container = new Element("div");
  container.replaceChildren = () => { container.children = []; };
  try {
    renderFields(container, {
      token: { kind: "text", required: true, choices: [], material: true },
      data: { kind: "bounded-json-map", required: true, choices: [], material: true },
      bytes: { kind: "strict-positive-integer", required: true, choices: [], material: false },
    });
  } finally {
    globalThis.document = previousDocument;
    globalThis.Option = previousOption;
  }
  const [tokenLabel, tokenControl] = container.children[0].children;
  assert.equal(tokenLabel.textContent, "token");
  assert.equal(tokenControl.type, "password");
  assert.equal(tokenControl.dataset.material, "true");
  assert.equal(container.children[1].children[1].dataset.material, "true");
  assert.equal(container.children[2].children[1].type, "number");
});
