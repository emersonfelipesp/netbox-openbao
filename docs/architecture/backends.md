# Secret backends

An abstract base class sits between the plugin and OpenBao from day one, so the
plugin never imports a vendor client directly.

That cost roughly two hundred lines and bought three things: HashiCorp Vault
support that reduces to a near-empty subclass, a broker mode that was an
addition rather than a rewrite, and a boundary where every vendor exception is
caught and scrubbed exactly once.

## The contract

```python
class SecretBackend(ABC):
    def read(self, path, version=None): ...
    def write(self, path, data, cas=None): ...        # returns the new version
    def delete(self, path, versions=None): ...
    def list_versions(self, path): ...                # metadata, never values
    def set_metadata(self, path, metadata): ...
    def health(self): ...                             # must not raise
```

Full signatures and semantics: [`backends.base`](../reference/backends/base.md).

Two rules the rest of the plugin depends on:

1. **Never raise a vendor exception.** Catch it and raise a
   [`backends.exceptions`](../reference/backends/exceptions.md) type, which
   carries no server text.
2. **Never log, format, or attach secret material** to an exception, a span, or
   a metric. `read()` returns it; nothing else may retain it.

And one for `health()` specifically: it must **not** raise for a
reachable-but-unhealthy instance. Report it in the return value instead, so the
health job can tell *sealed* from *unreachable* — the two demand different
operator responses.

## Why exceptions are scrubbed

Upstream client libraries embed the server's response body in their exception
text. An OpenBao `403` body can contain a **full policy dump**.

Letting that propagate puts the contents of your authorization model into
Sentry, into `logging`, and into any DRF error response. So every exception is
constructed here from a fixed message plus, at most, an HTTP status code — and
the original is never chained with `from`, for the same reason.

| Exception | Raised when |
|---|---|
| `BackendConfigurationError` | The engine or its environment is wrong; the request never ran |
| `OpenBaoAuthError` | Authentication or authorization rejected |
| `OpenBaoNotFound` | No secret at that path or version |
| `OpenBaoConflict` | A check-and-set write lost a race |
| `OpenBaoUnavailable` | Unreachable, sealed, or TLS verification failed |

The incoming message *is* inspected internally — that is how a check-and-set
conflict is distinguished from any other `400` — and then discarded.

## `OpenBaoBackend` — the reference implementation

Built on `hvac`. Three behaviours are load-bearing:

**No auth material touches the database or disk.** RoleIDs and SecretIDs are
read from the process environment, or from a file the environment points at,
at the moment of login. The `_FILE` indirection is what lets a deployment mount
a Docker or Kubernetes secret rather than exporting the value into
`/proc/<pid>/environ`.

**Tokens are cached in Django's cache only**, and expire at 80% of the lease so
a token is never presented at the moment it expires. Never in a model field.

**Sessions are pooled per endpoint.** Building a fresh TLS connection for every
reveal would dominate the latency budget of an operation that is otherwise a
single round-trip.

!!! danger "Do not move authentication onto the pooled session"

    Sharing a `requests.Session` between clients is safe **because** `hvac`
    builds the `X-Vault-Token` header per request from the adapter instance and
    never assigns to `session.headers` — verified against `hvac`'s
    `adapters.py`.

    If that ever changed, two policy tiers pointed at the same engine URL would
    share a session and one tier's token could be sent with the other tier's
    request. That is a cross-tier credential disclosure, from an optimisation
    that looks harmless.

### Authentication methods

| Method | Environment |
|---|---|
| `approle` | `<PREFIX>_ROLE_ID`, `<PREFIX>_SECRET_ID` |
| `token` | `<PREFIX>_TOKEN` — **development only** |
| `kubernetes` | `<PREFIX>_K8S_ROLE`, optionally `<PREFIX>_K8S_JWT_PATH` |
| `cert` | none — the client certificate is presented by the TLS session |

Every variable also accepts a `_FILE` suffix naming a file to read instead.

An absent RoleID is a `BackendConfigurationError` — an operator error — which is
deliberately distinct from OpenBao rejecting valid-looking material, which is
an `OpenBaoAuthError`. Sending someone to check the wrong one costs an
afternoon.

## `VaultBackend` — honestly almost empty

OpenBao is a fork of Vault, and their KV v2 and AppRole surfaces remain
compatible, which is why `hvac` drives both unmodified and why this class
overrides one method.

That is the honest outcome, not an unfinished one. Inventing overrides to look
substantial would mean maintaining divergence that does not exist.

Differences **confirmed against a live Vault**, not assumed:

- Vault's `sys/health` returns a strict **superset** of OpenBao's payload,
  adding `performance_standby`, `enterprise`, `clock_skew_ms`,
  `echo_duration_ms`, and `replication_primary_canary_age_ms`. Every field the
  base implementation reads is present on both, so health parsing needs no
  override — only a better message.
- A Vault **performance standby** serves reads while reporting `standby: true`.
  Treating it as a standby is correct; saying so in the status message saves an
  operator guessing why a "standby" node is answering.
- **Version strings are not comparable between the two projects.** Never infer
  capability from them.

The plugin's whole wire-protocol contract runs as **one shared suite against
both servers**, so this is verified rather than claimed. See [Use HashiCorp
Vault](../how-to/use-vault.md).

## `BrokerBackend` — a transport swap, not a different store

Points at `netbox-openbao-broker`, which holds the AppRole so this NetBox does
not. NetBox presents a **client certificate** that lets it *ask*; the broker
holds the thing that can actually *read*.

It must stay indistinguishable from direct mode above `SecretBackend` — same
exception types for the same conditions — and three constraints keep it honest:

- **Never send `kv_mount` or `namespace`.** They are the broker's own
  configuration. Sending them would let a compromised NetBox address mounts the
  operator never granted, which inverts the point of the mode.
- **The client certificate is keyed on `env_prefix`**, exactly as the AppRole
  is. The broker identifies callers by certificate CN, so flattening this to one
  certificate would silently give every policy tier the same access.
- **Never relay the broker's error text.** It is written not to leak policy, but
  this side cannot verify that, and forwarding a remote string gives up the
  guarantee `exceptions.py` exists to provide.

TLS verification **cannot be disabled** in broker mode. Direct mode tolerates it
and the cost is a short-lived token presented to whoever answers; here the
client certificate is the credential and it is long-lived, so an unverified peer
is a credential handed to a man in the middle. A self-signed broker certificate
is served by pointing `ca_cert_path` at it, so this refuses nothing legitimate.

Responses are read through a `_field()` helper rather than indexed directly: a
broker that answered `200` with an unexpected shape — a version skew, a proxy
that rewrote the body — would otherwise raise a `KeyError` out of the backend,
which is precisely the vendor-shaped exception the ABC forbids and which the
reveal path is not written to catch.

→ [Run broker mode](../how-to/broker-mode.md), including what it is honestly
worth.

## Adding one

1. Subclass `SecretBackend` and implement all six methods.
2. Register it in `backends.BACKENDS` and in `choices.BackendChoices`.
3. Add an integration subclass of `_KVIntegrationTests` in
   `tests/test_backends.py`.

A backend tested only against a *different* server proves nothing about it. The
shared suite exists so that "OpenBao and Vault agree" is a test result rather
than an assumption — and three defects in this repository have already hidden
behind a passing fake.

An unknown `backend` value falls back to `OpenBaoBackend` rather than raising:
an engine row written by a newer version of the plugin should degrade to the
compatible default, not take every credential on it offline.
