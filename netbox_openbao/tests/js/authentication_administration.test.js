"use strict";

import assert from "node:assert/strict";
import test from "node:test";

import {
  apiRequest,
  buildLoginPayload,
  buildOperationRequest,
  createOIDCController,
  isOIDCExpiryError,
  jsonPayload,
  reconcileAfterMutation,
} from "../../static/netbox_openbao/authentication_administration.js";

test("login payload contains only the selected method's material", () => {
  const payload = buildLoginPayload({
    method_type: "userpass",
    username: "alice",
    password: "password-canary",
    jwt: "jwt-canary",
    token: "token-canary",
    reason: "Interactive login.",
  });

  assert.deepEqual(payload, {
    method_type: "userpass",
    username: "alice",
    password: "password-canary",
    reason: "Interactive login.",
  });
});

test("RADIUS login uses only username and password", () => {
  assert.deepEqual(
    buildLoginPayload({
      method_type: "radius",
      username: "alice",
      password: "password-canary",
      jwt: "jwt-canary",
      reason: "Interactive login.",
    }),
    {
      method_type: "radius",
      username: "alice",
      password: "password-canary",
      reason: "Interactive login.",
    },
  );
});

test("OIDC state stays in one controller and clears without browser storage", () => {
  const controller = createOIDCController();
  controller.begin(
    { state: "state-canary", client_nonce: "nonce-canary", envelope: "envelope-canary" },
    "oidc",
    "Interactive login.",
  );

  assert.deepEqual(controller.pollPayload("oidc"), {
    state: "state-canary",
    client_nonce: "nonce-canary",
    envelope: "envelope-canary",
    reason: "Interactive login.",
  });
  assert.throws(() => controller.pollPayload("different"), /Start OIDC/);
  controller.clear();
  assert.equal(controller.active(), false);
  assert.throws(() => controller.pollPayload("oidc"), /Start OIDC/);
  assert.equal(
    isOIDCExpiryError(new Error('{"detail":"The OIDC polling envelope is invalid or expired."}')),
    true,
  );
});

test("OIDC state expires locally without clearing during an ordinary visibility interval", () => {
  let clock = 10_000;
  const controller = createOIDCController({ now: () => clock, ttlMs: 300_000 });
  controller.begin(
    { state: "state-canary", client_nonce: "nonce-canary", envelope: "envelope-canary" },
    "oidc",
    "Interactive login.",
  );

  clock += 299_999;
  assert.equal(controller.active(), true);
  assert.equal(controller.remainingMs(), 1);
  clock += 1;
  assert.equal(controller.active(), false);
  assert.throws(() => controller.pollPayload("oidc"), /Start OIDC/);
});

test("API requests are no-store and are never retried", async () => {
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, options) => {
    calls += 1;
    assert.equal(options.cache, "no-store");
    assert.equal(options.credentials, "same-origin");
    return { ok: true, json: async () => ({ accepted: true }) };
  };
  try {
    const result = await apiRequest("/api/test/", {
      method: "POST",
      payload: { value: true },
      csrf: "csrf-token",
    });
    assert.deepEqual(result, { accepted: true });
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("mutation transport and malformed-success loss return an unknown do-not-retry result", async () => {
  const originalFetch = globalThis.fetch;
  const cases = [
    async () => {
      throw new TypeError("connection reset after dispatch");
    },
    async () => ({ ok: true, json: async () => { throw new SyntaxError("truncated JSON"); } }),
    async () => ({ ok: true, json: async () => ["unexpected"] }),
  ];
  try {
    for (const fetchCase of cases) {
      let calls = 0;
      globalThis.fetch = async (...args) => {
        calls += 1;
        return fetchCase(...args);
      };
      const result = await apiRequest("/api/test/", { method: "POST", payload: { value: true } });
      assert.equal(result.outcome, "unknown");
      assert.equal(result.audit_status, "unconfirmed");
      assert.match(result.message, /Do not retry/);
      assert.equal(calls, 1);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("failed reconciliation cannot replace an uncertain mutation warning", async () => {
  let calls = 0;
  const failedRefresh = async () => {
    calls += 1;
    throw new Error("refresh failed");
  };

  await reconcileAfterMutation(failedRefresh, { outcome: "unknown" });
  await reconcileAfterMutation(failedRefresh, { outcome: "accepted-audit-incomplete" });
  await assert.rejects(reconcileAfterMutation(failedRefresh, { outcome: "succeeded" }), /refresh failed/);
  assert.equal(calls, 3);
});

test("advanced payload input requires one JSON object", () => {
  assert.deepEqual(jsonPayload('{"policies":["default"]}'), { policies: ["default"] });
  assert.throws(() => jsonPayload('["not-an-object"]'), /JSON object/);
});

test("read-only workspace operations issue GET requests without bodies", () => {
  const cases = [
    ["auth-config", { mount_path: "ldap", config_operation: "read" }, "/api/auth-config/ldap/"],
    [
      "auth-resource",
      { mount_path: "userpass", resource_key: "userpass-users", resource_operation: "list" },
      "/api/auth-resources/userpass/userpass-users/",
    ],
    ["mfa-method", { mfa_operation: "list" }, "/api/auth-mfa/methods/"],
    ["mfa-enforcement", { enforcement_operation: "list" }, "/api/auth-mfa/enforcements/"],
  ];

  for (const [operation, values, url] of cases) {
    assert.deepEqual(buildOperationRequest(operation, values, "/api/"), { url, method: "GET" });
  }
});

test("destructive workspace operations preserve exact confirmation payloads", () => {
  const resource = buildOperationRequest(
    "auth-resource",
    {
      mount_path: "userpass",
      resource_key: "userpass-users",
      resource_operation: "delete",
      name: "alice",
      reason: "Retire the user.",
      confirmation: "DELETE AUTH RESOURCE userpass-users/alice ON primary",
    },
    "/api/",
  );
  const mfa = buildOperationRequest(
    "mfa-delete",
    {
      delete_kind: "method",
      method_type: "totp",
      identifier: "12345678-1234-1234-1234-123456789abc",
      reason: "Retire the method.",
      confirmation: "DELETE MFA METHOD 12345678-1234-1234-1234-123456789abc ON primary",
    },
    "/api/",
  );

  assert.equal(resource.method, "DELETE");
  assert.equal(resource.payload.confirmation, "DELETE AUTH RESOURCE userpass-users/alice ON primary");
  assert.equal(mfa.method, "DELETE");
  assert.equal(mfa.payload.confirmation, "DELETE MFA METHOD 12345678-1234-1234-1234-123456789abc ON primary");
});

test("TOTP self-enrollment sends the submitted token only to the self route", () => {
  const request = buildOperationRequest(
    "mfa-totp-self",
    {
      method_id: "11111111-1111-4111-8111-111111111111",
      token: "submitted-token-canary",
      reason: "Enroll the current entity.",
    },
    "/api/plugins/openbao/clusters/1/",
  );

  assert.deepEqual(request, {
    url: "/api/plugins/openbao/clusters/1/auth-mfa/totp/11111111-1111-4111-8111-111111111111/self/",
    method: "POST",
    payload: { token: "submitted-token-canary", reason: "Enroll the current entity." },
  });
});

test("TOTP self-reset preserves the exact confirmation and never accepts an entity ID", () => {
  const request = buildOperationRequest(
    "mfa-totp-self-reset",
    {
      method_id: "11111111-1111-4111-8111-111111111111",
      token: "submitted-token-canary",
      entity_id: "attacker-controlled-entity",
      reason: "Restart enrollment.",
      confirmation: "RESET MY TOTP ON primary",
    },
    "/api/",
  );
  assert.deepEqual(request, {
    url: "/api/auth-mfa/totp/11111111-1111-4111-8111-111111111111/self/reset/",
    method: "POST",
    payload: {
      token: "submitted-token-canary",
      reason: "Restart enrollment.",
      confirmation: "RESET MY TOTP ON primary",
    },
  });
});

test("mount lifecycle forms merge only non-conflicting advanced fields", () => {
  const request = buildOperationRequest(
    "enable-method",
    {
      mount_path: "userpass",
      method_type: "userpass",
      description: "People",
      advanced_payload: '{"local":true,"user_lockout_config":{"lockout_threshold":"5"}}',
      reason: "Enable the people mount.",
    },
    "/api/",
  );

  assert.equal(request.payload.local, true);
  assert.deepEqual(request.payload.user_lockout_config, { lockout_threshold: "5" });
  assert.throws(
    () =>
      buildOperationRequest(
        "enable-method",
        {
          mount_path: "userpass",
          method_type: "userpass",
          advanced_payload: '{"mount_path":"other"}',
          reason: "Enable the people mount.",
        },
        "/api/",
      ),
    /cannot replace/,
  );
});
