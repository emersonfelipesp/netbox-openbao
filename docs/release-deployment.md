# Release, deploy, and rollback

netbox-openbao 0.1.0 uses a package-first release path. The immutable wheel,
source distribution, and canonical release manifest are published before any
production deployment. Production never installs from PyPI or from a mutable
working checkout.

## Release channels and targets

| Purpose | Contract |
|---|---|
| Gitea package publication | NMS package publish target **9** dispatches `publish-gitea.yml` on `main` |
| Staging | A reviewed push to `develop` dispatches deployment target **20** |
| Production | NMS deployment target **21** dispatches `deploy-production.yml` on `main`; the default is `latest_package`, with `main_branch` as an explicit override |
| Public release candidate | A direct `v*rc*` tag push runs the GitHub workflow and publishes to TestPyPI |
| Public final | Publishing a GitHub Release runs the GitHub workflow and publishes to PyPI |

The Gitea package is the production artifact of record. TestPyPI and PyPI are
public distribution and validation channels, not production inputs.

## Immutable package contract

Each version publishes exactly one wheel and one source distribution under the
`netbox-openbao` package. A separately linked generic package named
`netbox-openbao-release-manifest` contains one file,
`release-manifest.json`. The canonical schema is:

```json
{"artifacts":[{"name":"netbox_openbao-0.1.0-py3-none-any.whl","sha256":"<64 lowercase hex>","size":123},{"name":"netbox_openbao-0.1.0.tar.gz","sha256":"<64 lowercase hex>","size":456}],"package":"netbox-openbao","schema":1,"source_sha":"<40 lowercase hex>","version":"0.1.0"}
```

NMS binds target 21 to the package version, source commit, manifest digest,
and complete two-artifact inventory. The workflow independently downloads and
hashes those bytes before passing the claimed proof to the deploy-host helper.

## Release sequence

1. Merge the reviewed release change to `develop` with a squash commit.
2. Wait for target 20 and validate `https://staging.netbox.nmulti.cloud`.
3. Squash-promote `develop` to `main`, then recreate `develop` from the new
   `main` tip.
4. Create an annotated `v0.1.0rcN` tag on the reviewed main commit.
5. Before dispatching target 9, record the candidate in the release journal's
   append-only version ledger. Dispatch target 9 with that exact tag.
6. Verify the package, manifest link, files, source SHA, and digests through
   `nms git packages`.
7. Push only the RC tag to GitHub. The `v*rc*` trigger publishes to TestPyPI;
   do not create a GitHub Release for an RC.
8. Install the RC in a clean environment and run the documented smoke suite.
   Fixes consume the next `rcN`; published versions are never overwritten.
9. Publish and verify the final `0.1.0` Gitea package through target 9.
10. Dispatch production target 21 through NMS with `latest_package` and the
    exact final version. `main_branch` is available only as an explicit
    operator override and must leave `package_version` empty. Hand dispatches
    without a claimed NMS request fail.
11. Validate `https://netbox.nmulti.cloud`, then publish the final GitHub
    Release. The `release: published` event publishes the final package to
    PyPI. Do not push the final tag directly as the public publishing action.
12. Reconcile the Gitea package, tags, GitHub Release, TestPyPI, and PyPI, then
    remove temporary branches and worktrees.

## Proof-v3 production boundary

The target-21 workflow accepts only a claimed NMS proof for attempt 1 of the
exact repository, `deploy-production.yml`, main workflow commit, package
version, and target. Its outer key set is exact. The nested schema-2 request
must select target 21 and exactly one reviewed source. Package mode selects
`latest_package`, `netbox-openbao`, and `netbox-openbao-release-manifest`;
main mode selects the canonical workflow commit and carries no package fields
or artifacts. A bounded claim retry is allowed only for
`DEPLOYMENT_PROOF_NOT_BOUND`; every other response fails immediately. The
deploy host verifies the Ed25519
`NMS-DEPLOYMENT-PROOF` v3 signature and independently recomputes the separately
supplied request digest. Runner-owned JSON is never authority.

Secret material is not part of any package, manifest, deployment proof, log,
receipt, rollback record, or release note. Runtime AppRole and broker custody
remain outside the artifact boundary.

## Validation

After staging or production deployment:

- confirm NetBox health and that `netbox-rq` is running;
- confirm `netbox_openbao.__version__` and distribution metadata equal the
  requested version and originate from the immutable release directory;
- run Django system checks and migrations checks;
- exercise login, inventory-only credential reads, and one authorized OpenBao
  administration read without recording response material;
- verify denied reveal/admin requests remain denied and responses retain
  `Cache-Control: no-store` where material may exist.

## Rollback and recovery

Do not delete a bad package, tag, deployment generation, or prior release.
Before migrations begin, a failed candidate leaves the previous immutable
generation active. After migrations begin, the helper retains the exact
candidate and durable transaction state for reconciliation; database and
static changes are not described as atomically reversible.

For an application regression, dispatch target 21 through NMS with the last
known-good immutable package version and a new proof. For a forward repair,
publish `0.1.0.postN` through the complete staging, package, production, and
public-release sequence. Never reuse or replace a published version. Preserve
the failed run, proof request identity, manifest digest, health evidence, and
selected rollback version in the incident record, without secret material.
