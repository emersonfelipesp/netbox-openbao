# Quick-add SSH

Giving a device SSH access by hand means three forms: create an `ipam.Service`,
create a `Credential`, create a `CredentialAssignment`. It is also the single
most common thing anyone does with this plugin.

**Add SSH access** on any Device or VM page does all three in one transaction.
The same workflow is available to authenticated automation at
`POST /api/plugins/openbao/credentials/quick-add-ssh/`; see the REST API guide
for its write-only request fields and bounded response.

## What it creates

1. An `ipam.Service` named `ssh` on the object, with a `tcp/22` port mapping —
   or the existing one, with the port added if it is not already there.
2. A `Credential` written to OpenBao — either `ssh-password` (login password)
   or `ssh-keypair` (private key + optional passphrase), with public metadata
   extracted into NetBox for keypairs.
3. A `CredentialAssignment` binding the credential to the service, and a second
   binding it to the object itself.

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

## Services on 4.6 and 4.7

The service this creates is shaped for whichever release is running:

- Protocol and port are a single `port_mappings` array of `"tcp/22"` strings,
  not separate `protocol` and `ports` fields.
- A service binds to its parent through a **generic foreign key**, not a device
  or VM foreign key.

Code written against 4.6 fails on both, which is why the tests assert the
created service's shape directly rather than just its existence.

## If you do not model services

If `ipam.service` is not in `assignable_models`, the service step is skipped and
the credential is assigned to the device or VM directly. An estate that does not
model services still wants the credential attached, so this is configured-out
rather than an error.

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
