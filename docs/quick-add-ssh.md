# Quick-add SSH

Giving a device SSH access by hand means three forms: create an `ipam.Service`,
create a `Credential`, create a `CredentialAssignment`. It is also the single
most common thing anyone does with this plugin.

**Add SSH access** on any Device or VM page does all three in one transaction.
The same workflow is available to authenticated automation at
`POST /api/plugins/openbao/credentials/quick-add-ssh/`; see the REST API guide
for its write-only request fields and bounded response.

## What it creates

The chain is mandatory and always the same:

`OpenBao Credential > SSH Application Service > Virtual Machine or Device`

1. An `ipam.Service` (an Application Service) on the object, built from the
   **service template** chosen in the form — the pre-seeded `SSH` template
   (`tcp/22`) by default. The port is taken from the template and may be
   overridden for a non-standard SSH port. An existing service of the same name
   on the object is reused, with the port added if it is not already there.
2. A `Credential` written to OpenBao — either `ssh-password` (login password)
   or `ssh-keypair` (private key + optional passphrase), with public metadata
   extracted into NetBox for keypairs.
3. A `CredentialAssignment` binding the credential to the service. SSH
   credentials are **never** assigned directly to the Device or VM:
   `CredentialAssignment.clean()` rejects it, for the UI, REST and ORM alike.

The `SSH` service template is created by migration `0023` if no template of that
name exists, and is never overwritten. If an operator deletes it, pick or create
another template in the form.

When audited host automation is needed, `netbox-rpc` resolves the credential
through the same reveal contract and dispatches an approved procedure through
`netbox-rpc-backend`; no second credential mirror is required.

All of it inside one `transaction.atomic()`, and the material goes through the
same `store_credential()` every other write uses — so the rollback compensator
covers it. A backend failure leaves no service, no credential, and no
assignment.

## Authentication methods

| | |
|---|---|
| **Username and password** | Stores an `ssh-password` credential in OpenBao. This is the SSH **login** password, not a key passphrase. Audited RPC consumers resolve it through the POST-only reveal contract. |
| **SSH keypair** | See the three key-supply options below. |

## Three ways to supply a keypair

| | |
|---|---|
| **Generate** | An Ed25519 keypair (or whatever `default_ssh_key_type` says) is generated server-side. The **public** half is shown once, so it can go straight into `authorized_keys`. The private half is written to OpenBao and never rendered. |
| **Paste** | Supply an existing private key, with a passphrase if it has one. |
| **Reuse** | Point at a credential that already exists — the fleet key deployed everywhere. No new credential is created; only a new assignment. |

Generation happens in the NetBox process, never in browser JavaScript and never
through OpenBao's SSH secrets engine. Both alternatives would put the private
key somewhere this plugin does not control at the moment it exists.

## NetBox 4.7 only

Service ports are a single `port_mappings` array of `"tcp/22"` strings, and a
service binds to its parent through a generic foreign key. NetBox 4.6 and
earlier are not supported; there is no `protocol` + `ports` fallback.

`ipam.service` is in the default `assignable_models`. Denying it through
`assignable_models_deny` makes SSH assignments made through the UI or REST API
fail validation, because SSH access is addressed through the service.

## Permissions

The button appears for users with `netbox_openbao.add_credential`, which is what
the action needs — the service and the assignment are consequences of creating
the credential. The target must also be a type listed in `assignable_models`;
anything else is a 404 rather than a silently ignored request.

The REST action applies the same `add_credential` gate, resolves the Device or
VirtualMachine through the caller's constrained `view` permission, and also
requires constrained view access to the selected policy and any reused
credential. Its response includes only assignments for the requested target
and SSH service; reusing a credential never exposes its unrelated bindings.
The selected policy must match a reused credential's policy. The action checks
the current assignment allowlist and the created credential against constrained
`add_credential` permissions through a late conformance callback after all
assignments and synchronization have run but before the service's database and
material transactions commit. Refusal therefore leaves no service, credential,
assignment, or owned OpenBao version.
