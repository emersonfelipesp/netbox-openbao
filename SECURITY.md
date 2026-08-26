# Security policy

## Reporting a vulnerability

**Please do not open a public issue.**

Email **emerson@netdevopsbr.com** with:

- what an attacker can do, stated as an outcome rather than as a code smell
- the steps to reproduce it, and the plugin, NetBox, and OpenBao versions
- whether you believe it is already being exploited

You will get an acknowledgement within **72 hours** and an assessment within
**7 days**. If a fix is warranted, the advisory and the release will credit you
unless you ask otherwise.

This is a volunteer-maintained project, not a vendor with a paid response team.
The timelines above are what is realistically honoured, not an SLA.

## Scope

In scope — anything that breaks one of the properties in
[`docs/security.md`](docs/security.md), particularly:

- secret material reaching a model field, a changelog entry, a log line, an
  export, an exception, or any response that is not the reveal endpoint
- reading material without `netbox_openbao.reveal_credential`, or past an
  ObjectPermission constraint, or past a `CredentialPolicy` group gate
- an authorization check present on one surface and absent on another — the
  REST actions, the two UI reveal paths, the UI promote/discard, and the edit
  form all reach the same material
- an OpenBao server response body (which can enumerate policy rules) escaping
  through an exception, a log, or an API error payload
- `CredentialTypeSchema` being made to execute code or to mirror secret fields
  into NetBox columns
- auth material (RoleID, SecretID, tokens, broker client keys) reaching the
  database, a model field, or a tracked file

Out of scope:

- an operator setting `tls_verify = False` and being intercepted. The field
  says so, and the plugin refuses it outright in broker mode.
- broker mode not making "NetBox compromise ≠ secret compromise" true. It does
  not, and the documentation says so in as many words. See
  [`docs/security.md`](docs/security.md#broker-mode).
- vulnerabilities in NetBox, OpenBao, Vault, or `hvac` themselves — report
  those upstream. If the *plugin's* use of them is what makes an upstream issue
  exploitable, that is in scope here.
- an operator granting `reveal_credential` too widely.

## Supported versions

Pre-1.0. Only the latest release receives fixes.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |
