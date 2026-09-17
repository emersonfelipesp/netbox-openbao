"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import { clearClusterActionMaterial, clusterActionPayload, completeAction } from "../../static/netbox_openbao/cluster_administration.js";

function response(payload) {
  return {
    ok: true,
    json: async () => payload,
  };
}

test("accepted-audit-incomplete stays visible without reload or retry", async () => {
  let requests = 0;
  let reloads = 0;
  let shown;
  const send = async () => {
    requests += 1;
    return response({ outcome: "accepted-audit-incomplete", audit_status: "preflight-only" });
  };

  await completeAction(send, true, (value, error) => { shown = { value, error }; }, () => { reloads += 1; });

  assert.equal(requests, 1);
  assert.equal(reloads, 0);
  assert.equal(shown.error, true);
  assert.match(shown.value, /Do not retry/);
  assert.match(shown.value, /preflight-only/);
});

test("ordinary accepted mutations reload once after one request", async () => {
  let requests = 0;
  let reloads = 0;
  const send = async () => {
    requests += 1;
    return response({ sealed: true });
  };

  await completeAction(send, true, () => {}, () => { reloads += 1; });

  assert.equal(requests, 1);
  assert.equal(reloads, 1);
});

test("schema-invalid decoded mutation responses are unknown and never reload", async () => {
  for (const payload of [[], null, "accepted", 1]) {
    let reloads = 0; let shown;
    const data = await completeAction(
      async () => response(payload),
      true,
      (value, error) => { shown = { value, error }; },
      () => { reloads += 1; },
    );
    assert.equal(data.outcome, "unknown");
    assert.equal(reloads, 0);
    assert.equal(shown.error, true);
    assert.match(shown.value, /Do not retry/);
  }
});

test("mutation JSON decoding failure is unknown and never reloads", async () => {
  let reloads = 0; let shown;
  const data = await completeAction(
    async () => ({ ok: true, json: async () => { throw new Error("truncated"); } }),
    true,
    (value, error) => { shown = { value, error }; },
    () => { reloads += 1; },
  );
  assert.equal(data.outcome, "unknown");
  assert.equal(reloads, 0);
  assert.equal(shown.error, true);
  assert.match(shown.value, /Do not retry/);
});

test("unknown mutation is displayed once and is never retried or reloaded", async () => {
  let requests = 0; let reloads = 0; let shown;
  await completeAction(async () => {
    requests += 1;
    return { ok: false, json: async () => ({ outcome: "unknown", audit_status: "best-effort" }) };
  }, true, (value, error) => { shown = { value, error }; }, () => { reloads += 1; });
  assert.equal(requests, 1); assert.equal(reloads, 0); assert.equal(shown.error, true);
  assert.match(shown.value, /Do not retry/);
});

test("explicit terminal outcomes never reload regardless of HTTP status", async () => {
  for (const [ok, outcome] of [
    [true, "unknown"], [false, "unknown"],
    [true, "accepted-audit-incomplete"], [false, "accepted-audit-incomplete"],
  ]) {
    let reloads = 0; let shown;
    const data = await completeAction(
      async () => ({ ok, json: async () => ({ outcome, audit_status: "best-effort" }) }),
      true,
      (value, error) => { shown = { value, error }; },
      () => { reloads += 1; },
    );
    assert.equal(data.outcome, outcome);
    assert.equal(reloads, 0);
    assert.equal(shown.error, true);
    assert.match(shown.value, /Do not retry/);
  }
});

test("ordinary non-OK cluster responses remain errors", async () => {
  await assert.rejects(
    completeAction(
      async () => ({ ok: false, json: async () => ({ detail: "denied" }) }),
      true,
      () => {},
      () => assert.fail("must not reload"),
    ),
    /denied/,
  );
});

test("join transport loss is unknown and never retried", async () => {
  let requests = 0; let shown;
  const data = await completeAction(async () => { requests += 1; throw new Error("timeout"); }, true,
    (value, error) => { shown = { value, error }; }, () => assert.fail("must not reload"));
  assert.equal(requests, 1); assert.equal(data.outcome, "unknown"); assert.equal(shown.error, true);
  assert.match(shown.value, /Do not retry/);
});

test("join payload keeps exactly one discovery mode", () => {
  const direct = new Map([["leader_api_addr", "https://leader.example:8200"], ["auto_join", ""], ["auto_join_scheme", "https"], ["auto_join_port", "8200"]]);
  assert.deepEqual(clusterActionPayload("join", direct), { leader_api_addr: "https://leader.example:8200", retry: false, non_voter: false });
  const automatic = new Map([["leader_api_addr", ""], ["auto_join", "provider=aws"], ["auto_join_scheme", "http"], ["auto_join_port", "8201"]]);
  assert.deepEqual(clusterActionPayload("join", automatic), { auto_join: "provider=aws", auto_join_scheme: "http", auto_join_port: 8201, retry: false, non_voter: false });
});

test("every join certificate and private key is cleared together", () => {
  const controls = ["key", "leader_ca_cert", "leader_client_cert", "leader_client_key"].map((name) => ({ name, value: `${name}-canary` }));
  clearClusterActionMaterial({ querySelectorAll: () => controls });
  assert.deepEqual(controls.map((control) => control.value), ["", "", "", ""]);
});
