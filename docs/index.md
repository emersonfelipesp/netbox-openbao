# netbox-openbao

Secret material in OpenBao. Credential inventory and relationships in NetBox.

- [Installation](installation.md) — requirements, the OpenBao side, delivering
  the AppRole
- [Configuration](configuration.md) — `PLUGINS_CONFIG`, environment, policy
  tiers
- [Quick-add SSH](quick-add-ssh.md) — the one-form path, and what it creates
- [Security model](security.md) — what is guaranteed, and by what mechanism
- [REST API](api.md) — endpoints, the reveal contract, filtering
- [Migrating from netbox-secrets](migration-from-netbox-secrets.md) — the
  importer, and how it types what it finds
- [Development](development.md) — running the suite against real NetBox and
  OpenBao

## The one-paragraph version

`netbox-secrets` stores secrets *in* NetBox. `netbox-vault-secrets` reads them
in the *browser*. This plugin keeps them in OpenBao and resolves them
*server-side over the API*, so automation can use them and not just operators.
Non-secret attributes — public keys, fingerprints, certificate subjects and
expiry — stay in NetBox where they are indexed and queryable, which is what
makes "every certificate expiring in 30 days" one SQL query and zero OpenBao
reads.
