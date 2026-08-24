# Report on expiry

*"What expires in the next 30 days?"* costs **one indexed PostgreSQL query and
zero OpenBao reads.**

That is the payoff of [splitting metadata from
material](../architecture/data-model.md): `valid_from` and `valid_until` are
extracted from the certificate once, at write time, and stored in NetBox where
they are indexed and filterable. A plugin that stored certificates opaquely
would have to read every one of them to answer the same question — and would go
blind exactly when the vault is sealed.

## The queries

```bash
BASE=https://netbox.example.net/api/plugins/openbao/credentials
AUTH="Authorization: Bearer $TOKEN"

# Renewal dashboard
curl -H "$AUTH" "$BASE/?expires_within_days=30"

# Already expired
curl -H "$AUTH" "$BASE/?status=expired"

# A hard boundary
curl -H "$AUTH" "$BASE/?expires_before=2026-12-31T00:00:00Z"

# Only things that have an expiry at all
curl -H "$AUTH" "$BASE/?has_expiry=true"

# Narrow to a type and a tier
curl -H "$AUTH" "$BASE/?credential_type=x509-keypair&policy=prod-core&expires_within_days=14"
```

None of these needs `reveal_credential`. `view_credential` is enough, which is
the point: whoever runs your renewal process does not need to be able to read
private keys.

## In the UI

**OpenBao → Credentials**, then the filter form's **Expires within (days)**
field. Add the **Expires** column and sort by it. Save it as a NetBox saved
filter or a table config and it becomes a standing view.

## Automatically

[`ExpiryScanJob`](../architecture/background-jobs.md#expiryscanjob) runs daily
by default. It marks anything past `valid_until` as `expired` and logs a
warning at each horizon in `expiry_warning_days`:

```python
PLUGINS_CONFIG = {
    'netbox_openbao': {
        'expiry_warning_days': [60, 30, 14, 7, 1],
        'expiry_scan_interval': 1440,   # minutes
    },
}
```

Intervals are read at import time, so a change needs a NetBox restart.

The job's output appears in **Operations → Jobs**, and the warnings go to
NetBox's logging — route `netbox.plugins.netbox_openbao` wherever your alerting
reads from.

## Finding where a key is deployed

The same split makes the reverse question free too. A fingerprint is public by
definition, so it is stored and indexed:

```bash
# Which credential is this?
curl -H "$AUTH" "$BASE/?fingerprint=SHA256:2f9c…"

# What is it assigned to?
curl -H "$AUTH" \
  "https://netbox.example.net/api/plugins/openbao/assignments/?credential_id=142"
```

And in reverse:

```bash
# What does device 88 hold?
curl -H "$AUTH" "$BASE/?assigned_object_type=dcim.device&assigned_object_id=88"

# Only its login credential
curl -H "$AUTH" "$BASE/?assigned_object_type=dcim.device&assigned_object_id=88&purpose=login"
```

The global search box covers name, username, fingerprint, certificate subject,
and serial.

## Rendering a public key into a config template

`public_key` is a plain NetBox field, so an export template or a config context
can use it directly — no OpenBao read, no reveal permission, no secret in the
rendering path:

```jinja
{% for a in device.custom_field_data %}{% endfor %}
{# via the API, or an export template over Credential: #}
{{ credential.public_key }}
```

That is the everyday case the design is built around: the thing you actually
need in a template is the *public* half, and it was never secret.

## What has no expiry

`valid_from` and `valid_until` are populated only by the `x509` extractor, so
they are set for `x509-keypair` and `x509-CA` credentials and empty for
passwords, tokens, SSH keys, and SNMP credentials.

For those, use `rotation_interval` and
[`RotationDueJob`](../architecture/background-jobs.md#rotationduejob) instead —
"should have been changed by now" rather than "stops working on this date".

You can also set `valid_until` by hand on any credential; nothing restricts it
to certificates.
