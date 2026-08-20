# Quick-add SSH

Giving a device SSH access by hand means three forms: create an `ipam.Service`,
create a `Credential`, create a `CredentialAssignment`. It is also the single
most common thing anyone does with this plugin.

**Add SSH access** on any Device or VM page does all three in one transaction.

## What it creates

1. An `ipam.Service` named `ssh` on the object, with a `tcp/22` port mapping —
   or the existing one, with the port added if it is not already there.
2. A `Credential` of type `ssh-keypair`, with the private half written to
   OpenBao and the public key, fingerprint, and key type extracted into NetBox.
3. A `CredentialAssignment` binding the credential to the service, and a second
   binding it to the object itself.

All of it inside one `transaction.atomic()`, and the material goes through the
same `store_credential()` every other write uses — so the rollback compensator
covers it. A backend failure leaves no service, no credential, and no
assignment.

## Three ways to supply the key

| | |
|---|---|
| **Generate** | An Ed25519 keypair (or whatever `default_ssh_key_type` says) is generated server-side. The **public** half is shown once, so it can go straight into `authorized_keys`. The private half is written to OpenBao and never rendered. |
| **Paste** | Supply an existing private key, with a passphrase if it has one. |
| **Reuse** | Point at a credential that already exists — the fleet key deployed everywhere. No new credential is created; only a new assignment. |

Generation happens in the NetBox process, never in browser JavaScript and never
through OpenBao's SSH secrets engine. Both alternatives would put the private
key somewhere this plugin does not control at the moment it exists.

## NetBox 4.7 specifics

The service this creates is shaped for 4.7, which changed both halves of it:

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
