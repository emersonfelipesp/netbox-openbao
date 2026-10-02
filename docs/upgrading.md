# Upgrading to database-backed configuration

This procedure preserves legacy security controls and OpenBao service
identities while moving them into NetBox models. Runtime code does not read
`PLUGINS_CONFIG['netbox_openbao']` or `NETBOX_BAO_*`; only the two explicit
one-time import commands read those sources.

## Procedure

1. Enter a maintenance window. Back up PostgreSQL and the exact Django
   `SECRET_KEY` used by the old installation. Keep the legacy configuration and
   environment variables in place.
2. Install the package and run `python manage.py migrate`.
3. Inspect the settings conversion without writing:

   ```bash
   python manage.py openbao_configure import-legacy-settings --dry-run
   ```

   Review every effective value, especially `allow_generation`,
   `assignable_models`, `assignable_models_deny`, `reveal_rate_limit`,
   `reveal_ttl`, `token_cache_ttl`, `audit_retention_days`, `path_prefix`,
   `default_ssh_key_type`, `expiry_warning_days`, and all five job intervals.
4. Persist the validated settings and review the effective-value printout:

   ```bash
   python manage.py openbao_configure import-legacy-settings
   python manage.py openbao_configure show
   ```

   The model's existing path-prefix guard applies. If credentials already
   exist, the import refuses a prefix that does not match their stamped paths;
   changing the prefix would strand existing credentials.
5. Import each legacy identity:

   ```bash
   python manage.py openbao_configure import-env --engine <engine-slug>
   python manage.py openbao_configure import-env --policy <policy-slug>
   python manage.py openbao_configure import-env --cluster <cluster-slug>
   ```

   Migration `0024_engine_auth_material` renames each policy's former
   `approle_env_prefix` column to `legacy_approle_env_prefix`. The retained
   field is non-editable and absent from forms, serializers, tables, and APIs;
   `import-env --policy` uses it only to locate the old variables. Do not remove
   that metadata until all tier-specific imports are verified. After every
   policy authentication test and reveal succeeds, clear it explicitly:

   ```bash
   python manage.py openbao_configure cleanup-legacy-prefixes \
     --confirm-imports-verified
   ```

   The command refuses any policy that has no imported authentication row.
   Cleanup is never an automatic migration step, and the reversible metadata
   column remains available for schema rollback.
6. Authenticate every engine and cluster, then perform one real
   permission-scoped reveal:

   ```bash
   python manage.py openbao_configure test --engine <engine-slug>
   python manage.py openbao_configure test --cluster <cluster-slug>
   ```

7. Only after the effective settings, authentication tests, and reveal all
   succeed, remove the old `PLUGINS_CONFIG['netbox_openbao']` keys and
   `NETBOX_BAO_*` variables. Restart every NetBox web and RQ process.

## Rollback

Before removing legacy sources, rollback means restoring the database backup,
the matching `SECRET_KEY`, and the previous package. After removing them,
restore those sources from the maintenance-window backup as well. Never change
`SECRET_KEY` without first following the re-encryption procedure in
[Configuration](configuration.md#secret_key-root-of-trust).
