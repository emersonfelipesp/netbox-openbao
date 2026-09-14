"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import { completeAction } from "../../static/netbox_openbao/cluster_administration.js";

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
