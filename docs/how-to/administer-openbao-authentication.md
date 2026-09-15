# Administer OpenBao authentication and MFA

This runbook covers the NetBox-native authentication workspace for the reviewed
OpenBao 2.6.2 through 2.6.x contract. It includes auth mount lifecycle,
method-specific configuration and resources, request-scoped login, AppRole
RoleIDs and SecretIDs, direct OIDC, token lookup/renewal/revocation, and MFA
methods and login enforcements.

## Security boundary

NetBox authentication authorizes the person to open this workspace. OpenBao
authentication authorizes the configured cluster service identity to perform a
specific upstream operation. Both checks must pass. A NetBox permission never
becomes an OpenBao token, and an OpenBao service token never becomes the
operator's browser session.

The workspace does not persist OpenBao passwords, tokens, JWTs, RoleIDs,
SecretIDs, MFA request IDs, passcodes, OIDC state, OIDC nonce, provider codes,
or TOTP setup material in a model, Django session, cache, task, message, URL,
audit record, exception, or browser storage. Material-bearing responses use
`Cache-Control: no-store`, appear in the one-shot result panel, clear after five
minutes, and clear when the page is closed. Ordinary tab hiding does not clear
TOTP material because an operator must be able to switch to an authenticator
and return. Copy required output directly into an approved custody system and
select **Clear now**.

Do not use the browser's Save Password feature on this workspace. Do not paste
material into tickets, chat, screenshots, documentation, or shell history.
Closing the NetBox page is a local logout only; it does not revoke an issued
OpenBao token. Revoke that token explicitly when the workflow is finished.

## Permissions

Every permission is object-constrainable. Grant `view_openbaocluster` together
with only the actions an operator needs.

| Permission | Purpose |
|---|---|
| `view_authentication_openbaocluster` | View reviewed auth mounts, resources, MFA metadata, and the workspace |
| `manage_auth_methods_openbaocluster` | Enable, configure, tune, and remount auth methods |
| `disable_auth_methods_openbaocluster` | Disable an auth mount after exact confirmation |
| `manage_auth_resources_openbaocluster` | Write token roles, userpass users, AppRoles, Kubernetes/JWT roles, LDAP mappings, and certificate resources |
| `delete_auth_resources_openbaocluster` | Delete typed resources and destroy AppRole SecretIDs |
| `issue_auth_material_openbaocluster` | Issue an AppRole SecretID once |
| `authenticate_openbaocluster` | Run request-scoped login, direct OIDC polling, and MFA validation |
| `manage_tokens_openbaocluster` | Look up and renew self tokens or accessors |
| `revoke_tokens_openbaocluster` | Revoke self tokens or accessors after exact confirmation |
| `manage_mfa_openbaocluster` | Create or update MFA methods, TOTP setup, and login enforcements |
| `delete_mfa_openbaocluster` | Delete MFA methods/enforcements or destroy an entity's TOTP setup |

The reserved broad `operate_*` risk permissions do not grant these actions.
The dedicated permission is always checked through NetBox's restricted
queryset, so an object constraint can hide an out-of-scope cluster.

## Compatibility and capability preflight

Every operation re-reads seal state and the bounded runtime OpenAPI document.
The cluster must be initialized, unsealed, and report OpenBao 2.6.2 through the
2.6.x line. The exact reviewed operation identifier must be advertised.
Discovery proves only that a reviewed operation exists; it cannot create a URL,
field, permission, or response parser. Paths and fields come from the static
2.6.2 registry. Unknown method types, resource families, fields, response
shapes, later minor versions, redirects, and broker transports without the
administration contract fail closed.

## Manage auth mounts

Open the cluster and select **Authentication**. Load the method table before a
change and verify the mount path, type, description, and TTLs.

The workspace can enable `userpass`, `approle`, `kubernetes`, `jwt`, `oidc`,
`ldap`, `radius`, and `cert` mounts. The built-in `token` mount is listed but cannot be
enabled as another mount through this contract. Mount paths are one safe path
segment; arbitrary OpenBao paths are never accepted.

Use **Tune a mount** for description, default/maximum TTL, token type, listing
visibility, reviewed request/response headers, audit non-HMAC keys, plugin
version, options, and bounded user-lockout configuration. The enable and tune
forms expose common fields directly and accept the remaining reviewed fields as
one advanced JSON object. Use **Remount** to begin OpenBao's asynchronous
remount operation, then query the returned migration ID through the REST status
action. Refresh the method table after completion.

Disabling a mount removes its login path and can make users or applications
unable to authenticate. Freeze dependent changes, verify an alternate
administrative identity, enter a reason, and type:

```text
DISABLE AUTH <mount> ON <cluster-slug>
```

Do not retry a disable or remount after a lost response. Read current mount or
migration state first.

## Configure method-specific resources

The static registry supports these families:

| Mount type | Typed resources |
|---|---|
| `token` | Token roles |
| `userpass` | Users, policies, TTLs, CIDR restrictions, and token settings |
| `approle` | Roles, custom RoleIDs, issued SecretIDs, and accessor lookup/destruction |
| `kubernetes` | Backend configuration and roles |
| `jwt` / `oidc` | Backend configuration and JWT/OIDC roles, including direct callback mode |
| `ldap` | Backend configuration, groups, and users |
| `radius` | Backend host/shared-secret configuration and users |
| `cert` | Backend configuration, trusted certificates, and CRLs |

Advanced forms accept a JSON object, but the server accepts only fields and
types listed in the static registry. A runtime schema cannot expand the
contract. Secret configuration fields are write-only: a later read will show
only public metadata supplied by OpenBao.

Resource deletion requires a reason and:

```text
DELETE AUTH RESOURCE <family>/<name> ON <cluster-slug>
```

## AppRole custody

Read or assign a RoleID through the dedicated RoleID operation. Issuing a
SecretID returns the SecretID and its accessor once. Store the SecretID under
the consuming workload's approved custody policy; the accessor is safe to use
for subsequent metadata lookup and revocation workflows but should still be
handled as sensitive operational metadata.

Destroying by accessor requires:

```text
DESTROY APPROLE SECRET ID ON <cluster-slug>
```

The SecretID itself is never placed in a URL or audit record. Rotate an exposed
SecretID by issuing a replacement, moving the workload, proving the replacement
works, and then destroying the old accessor.

## Request-scoped login

The login form supports token lookup, userpass, LDAP, RADIUS, JWT, AppRole, and
Kubernetes credentials. It sends exactly the fields for the selected method.
Successful credential-based login returns the OpenBao token, accessor,
policies, entity, lease duration, renewal state, and safe identity metadata
once. If an OIDC role explicitly requests `access_token`, `id_token`, or
`refresh_token` through `oauth2_metadata`, those values are also returned once
inside the response metadata and receive the same material-handling controls.
An MFA-enforced login returns a challenge instead of a token; complete it
through **Complete MFA challenge**.

This feature does not create a long-lived OpenBao session in NetBox. The token
is not attached to later requests. Use the token through the approved client or
workload, renew it only while it remains needed, and explicitly revoke it at
the end. Revocation requires:

```text
REVOKE TOKEN ON <cluster-slug>
```

Accessor operations use the configured OpenBao service identity. Self
operations use the submitted token for that request only and never replace or
mutate the service identity's cached client.

## Direct OIDC

Only OpenBao's direct callback mode is supported. Configure the OIDC role with
the exact callback URL:

```text
https://<openbao-api>/v1/auth/<mount>/oidc/callback
```

For a namespaced cluster, NetBox normalizes optional leading and trailing
slashes and inserts the URL-encoded namespace path between
`/v1/` and `/auth/`, including every nested namespace segment. The callback is
therefore `https://<openbao-api>/v1/<namespace>/auth/<mount>/oidc/callback`.
The identity provider cannot supply `X-Vault-Namespace`, so a root-namespace
callback must not be reused for a namespaced role.

NetBox refuses to write or start a direct OIDC role when
`oidc_disable_confirmation` or `verbose_oidc_logging` is enabled. The former
weakens OpenBao's direct-mode confirmation defense, while the latter can place
received OIDC tokens and claims in OpenBao logs. Neither setting belongs in the
reviewed administration contract.

Starting OIDC asks OpenBao for an authorization URL using a fresh client nonce.
The browser opens the validated HTTPS provider URL in a separate tab. The
provider callback goes directly to OpenBao; a provider authorization code is
never sent to a NetBox URL. NetBox returns a signed, five-minute envelope that
binds the cluster, NetBox user, mount, state digest, and nonce digest. State,
nonce, and envelope live only in the JavaScript closure for the current tab.
The browser clears that controller after five minutes, on an invalid or expired
poll response, after successful polling, or on `pagehide`. An ordinary tab
visibility change does not clear it during the provider handoff.

Return to the workspace and select **Poll completion** after the provider flow
finishes. A changed cluster, user, mount, state, nonce, signature, or expiry is
rejected before OpenBao is contacted. OpenBao consumes successful direct-mode
state, so replayed polling cannot issue the token again. Client callback mode
and device mode are refused until they receive separate custody and replay
reviews.

## MFA methods and enforcements

The registry supports TOTP, Duo, Okta, and PingID method configuration plus
login enforcements scoped by auth method accessor/type or identity entity/group.
Provider API tokens, Duo secret keys, and PingID settings are write-only.

TOTP generation returns the provisioning URI and a scannable QR code once for one explicit
entity. An operator with `authenticate_openbaocluster` can also submit that
entity's current OpenBao token to the self-enrollment form. NetBox uses the
token only as the header of the single `/identity/mfa/method/totp/generate`
request; it never replaces the cluster service token or stores the submitted
token. Transfer the resulting material directly to that identity's approved
authenticator. Destroying an entity's setup requires:

```text
DESTROY TOTP FOR <entity-id> ON <cluster-slug>
```

If an operator loses the one-shot enrollment material, OpenBao refuses another
generation until the existing entity secret is destroyed. Use **Restart my
TOTP enrollment** and type `RESET MY TOTP ON <cluster-slug>`. NetBox first calls
`/auth/token/lookup-self` with the submitted token, derives that token's entity
ID, and then uses the cluster service identity for
`/identity/mfa/method/totp/admin-destroy`. The request accepts no entity ID, so
it cannot reset a different identity.

The submitted user token must be allowed to `read` its
`auth/token/lookup-self` endpoint and `update`
`identity/mfa/method/totp/generate`. The cluster service identity must be
allowed to `update` `identity/mfa/method/totp/admin-destroy`. NetBox permissions
do not replace these OpenBao ACLs.

Delete methods only after removing or replacing every enforcement that refers
to them. Method and enforcement deletions require the exact confirmation shown
by the workspace. Test an alternate login path before changing a production
enforcement; an invalid enforcement can lock out every matching identity.

## Audit and unknown outcomes

Every read and write creates a metadata-only NetBox administration log. A
mutation's authorization record must commit before OpenBao is contacted. The
OpenBao audit device remains authoritative for the service identity and
upstream request; correlate it with the NetBox actor, request ID, operation ID,
and capability digest.

If OpenBao accepts a mutation but the completion audit fails, the response
contains `outcome: accepted-audit-incomplete` and `audit_status:
preflight-only`. Do not retry. Preserve the preflight record, inspect current
OpenBao state and its audit log, repair NetBox auditing, and only then decide
whether another operation is required.

A transport timeout after dispatch, or an accepted mutation response that
cannot pass bounded parsing, returns `outcome: unknown` and `audit_status:
preflight-only`. The metadata-only audit records the unknown outcome. Do not
retry. Reconcile the fixed upstream resource path and OpenBao audit log first;
an automatic retry could issue a second credential or repeat a destructive
operation.

If the browser loses a mutation response before it can validate the server
payload, it shows the same fixed do-not-retry instruction with `outcome:
unknown` and `audit_status: unconfirmed`. That status does not claim a NetBox
preflight record exists. A failed follow-up refresh cannot replace the warning;
reconcile NetBox and OpenBao audit state before another mutation.

## References

- [OpenBao authentication concepts](https://openbao.org/docs/concepts/auth/)
- [OpenBao system auth API](https://openbao.org/docs/api/system/auth/)
- [OpenBao identity MFA API](https://openbao.org/docs/api/secret/identity/mfa/)
- [OpenBao JWT/OIDC auth](https://openbao.org/docs/auth/jwt/)
- [OpenBao 2.6.2 release](https://github.com/openbao/openbao/releases/tag/v2.6.2)
