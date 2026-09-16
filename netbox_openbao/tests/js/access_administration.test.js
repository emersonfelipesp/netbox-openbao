"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  apiRequest,
  createMutationGate,
  fieldValue,
  parseStructuredField,
  renderFields,
} from "../../static/netbox_openbao/access_administration.js";

test("mutation gate suppresses overlapping submissions and restores controls", async () => {
  let release;
  let calls = 0;
  const transitions = [];
  const runMutation = createMutationGate((value) => transitions.push(value));
  const first = runMutation(async () => {
    calls += 1;
    await new Promise((resolve) => { release = resolve; });
    return "accepted";
  });
  const second = await runMutation(async () => { calls += 1; });
  assert.equal(second, undefined);
  assert.equal(calls, 1);
  release();
  assert.equal(await first, "accepted");
  assert.deepEqual(transitions, [true, false]);
});

test("accepted mutation with malformed response is reported as unknown", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => { throw new SyntaxError("truncated JSON"); },
  });
  try {
    assert.deepEqual(await apiRequest("/execute", { method: "POST", payload: {} }), {
      outcome: "unknown",
      message: "OpenBao may have accepted the request. Do not retry; verify current state first.",
    });
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("structured access fields accept only their reviewed JSON shape", () => {
  assert.deepEqual(parseStructuredField('["entity-id"]', "uuid-list"), ["entity-id"]);
  assert.deepEqual(parseStructuredField('{"owner":"platform"}', "string-map"), { owner: "platform" });
  assert.throws(() => parseStructuredField('{"entity":"id"}', "uuid-list"), /must be a JSON list/);
  assert.throws(() => parseStructuredField('["owner"]', "string-map"), /must be a JSON object/);
});

test("typed field extraction preserves booleans, integers, and inert documents", () => {
  assert.equal(fieldValue({ value: "false" }, { kind: "boolean", required: true }), false);
  assert.equal(fieldValue({ value: "true" }, { kind: "boolean", required: false }), true);
  assert.equal(fieldValue({ value: "" }, { kind: "boolean", required: false }), undefined);
  assert.equal(fieldValue({ value: "" }, { kind: "uuid-list", required: false }), undefined);
  assert.deepEqual(fieldValue({ value: "[]" }, { kind: "uuid-list", required: false }), []);
  assert.equal(fieldValue({ value: "3600" }, { kind: "positive-integer" }), 3600);
  assert.equal(
    fieldValue({ value: 'path "secret/*" { capabilities = ["read"] }' }, { kind: "text", required: true }),
    'path "secret/*" { capabilities = ["read"] }',
  );
  assert.equal(fieldValue({ value: "" }, { kind: "text", required: false }), undefined);
});

test("schema rendering uses text APIs and labels every generated control", () => {
  class Element {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.className = "";
      this.value = "";
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
      policy: { kind: "text", required: true, choices: [], material: false },
      client_type: { kind: "choice", required: false, choices: ["public", "confidential"], material: false },
      disabled: { kind: "boolean", required: false, choices: [], material: false },
    });
  } finally {
    globalThis.document = previousDocument;
    globalThis.Option = previousOption;
  }
  assert.equal(container.children.length, 3);
  const [policyLabel, policyControl] = container.children[0].children;
  assert.equal(policyLabel.htmlFor, "openbao-access-field-policy");
  assert.equal(policyControl.id, "openbao-access-field-policy");
  assert.equal(policyLabel.textContent, "policy");
  const disabledControl = container.children[2].children[1];
  assert.equal(disabledControl.tag, "select");
  assert.deepEqual(disabledControl.children.map((option) => option.value), ["", "true", "false"]);
});
