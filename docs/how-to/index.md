# How-to guides

Task-shaped. Each one assumes the plugin is [installed](../installation.md) and
gets you to a working result.

<div class="grid cards" markdown>

-   :material-server-security: **[Administer an OpenBao cluster](administer-openbao-cluster.md)**

    ---

    Bootstrap, unseal, HA, Raft peers, authenticated snapshots, and guarded
    disaster recovery without retaining custody material.

-   :material-account-key: **[Administer OpenBao authentication and MFA](administer-openbao-authentication.md)**

    ---

    Manage auth mounts, typed resources, direct OIDC, one-shot tokens, and MFA
    without creating an OpenBao browser session in NetBox.

-   :material-account-group: **[Administer OpenBao policies, identity, OIDC, and namespaces](administer-openbao-access.md)**

    ---

    Manage access-control resources through typed, permissioned operations with
    impact previews and request-scoped generated material.

-   :material-key-plus: **[Grant a device SSH access](../quick-add-ssh.md)**

    ---

    One form: the service, the keypair, and both assignments — in a single
    transaction.

-   :material-autorenew: **[Rotate without breaking consumers](rotate-a-credential.md)**

    ---

    Stage, verify against the real device, promote. Or discard and nothing
    changed.

-   :material-shield-account: **[Set up a policy tier](policy-tiers.md)**

    ---

    A tier with its own OpenBao policy and its own AppRole, so a leaked
    SecretID reaches only that tier — and an honest account of what that does
    not buy.

-   :material-lock-outline: **[Scope an OpenBao policy](scope-openbao-policies.md)**

    ---

    The capabilities the plugin actually needs, and what happens when you get
    them wrong.

-   :material-code-json: **[Define your own credential type](../custom-credential-types.md)**

    ---

    Model a vendor API key or a RADIUS secret as data, without forking.

-   :material-calendar-alert: **[Report on expiry](expiry-reporting.md)**

    ---

    "Everything expiring in 30 days", answered with zero OpenBao reads.

-   :material-server-network: **[Run broker mode](broker-mode.md)**

    ---

    Move the AppRole off the NetBox host — and an honest account of what that
    buys.

-   :material-vault: **[Use HashiCorp Vault](use-vault.md)**

    ---

    Change one field. The differences that exist are cosmetic, and verified.

-   :material-import: **[Migrate from netbox-secrets](../migration-from-netbox-secrets.md)**

    ---

    A resumable copy that never deletes, and infers each type by proving it.

-   :material-help-circle: **[Troubleshoot](troubleshooting.md)**

    ---

    The failures that do not say what they mean.

</div>
