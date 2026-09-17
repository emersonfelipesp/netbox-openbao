# Administer an OpenBao cluster

This runbook covers guarded bootstrap, seal state, HA, Raft peers, snapshots,
disaster recovery, rollback, and incident response through netbox-openbao. It
targets the reviewed OpenBao 2.6.2 contract. The plugin admits later patch
releases within the 2.6 line but fails closed below 2.6.2 or at 2.7.0 and later
until compatibility is reviewed.

The cluster-bootstrap parity family includes guarded Raft join. Leader CA,
client certificate, and client private-key values are accepted only in the
current no-store request and are cleared from the page after submission. Do not
infer any additional executable operation from capability discovery alone.

## Prerequisites

1. Place both NetBox and the OpenBao API listener on the management network or
   behind the management VPN. Do not expose either administration surface to
   the public Internet.
2. Configure an `OpenBaoCluster` with TLS verification enabled. Install the
   internal CA and set `ca_cert_path` when public trust is unavailable.
3. Point the cluster URL at the active node or a trusted, OpenBao-aware load
   balancer. netbox-openbao disables HTTP redirects and never follows a leader
   URL reported by an upstream response.
4. Configure the cluster-derived service identity outside the database. For a
   slug of `prod-core`, use the `NETBOX_BAO_PROD_CORE_*` environment or file
   variables described in [configuration](../configuration.md).
5. Grant `view_openbaocluster` and `discover_openbaocluster` only for clusters
   within the operator's scope. Grant each lifecycle permission separately.
6. Confirm that OpenBao's own audit device is healthy. The NetBox audit records
   the requesting person; the OpenBao audit records what the service identity
   performed. Correlate them with the request ID.

## Permission separation

| Permission | Operational role |
|---|---|
| `initialize_openbaocluster` | Bootstrap custodian |
| `unseal_openbaocluster` | Unseal custodian |
| `seal_openbaocluster` | Incident commander or vault operator |
| `join_raft_openbaocluster` | Raft bootstrap custodian |
| `remove_raft_peer_openbaocluster` | Raft administrator |
| `download_raft_snapshot_openbaocluster` | Backup operator |
| `restore_raft_snapshot_openbaocluster` | Recovery operator |
| `force_restore_raft_snapshot_openbaocluster` | Break-glass recovery owner |

Apply NetBox ObjectPermission constraints to each grant. A broad model
permission is inappropriate for a multi-cluster deployment. Force restore must
not be bundled into a normal backup or normal restore role.

## Bootstrap and custody

Open the cluster and select **Administration**. Verify the endpoint, reported
version, and uninitialized state before continuing.

For manual Shamir unseal, choose the number of shares and threshold. A common
starting policy is five shares with a threshold of three, but the values must
come from the organization's custody policy. Optional PGP encryption requires
one public key for every share. Each value must be the standard-base64 encoding
of the key's binary OpenPGP representation, without ASCII armor. For example,
export a key with `gpg --export <fingerprint> | base64 -w0`. Supplying malformed
encoding, invalid self-signatures or subkey bindings, or a key without an
explicit encryption capability is rejected before OpenBao is contacted. The
validator parses the complete bounded export, requires an exact binary
round-trip, verifies its bindings, and performs an in-memory encryption canary;
the key and canary ciphertext are never persisted.

For auto-unseal, select recovery shares and a recovery threshold. OpenBao 2.4
and later permits zero recovery shares in some auto-unseal configurations. Zero
shares removes human recovery material; use it only when the seal service,
backup, and break-glass design explicitly accepts that dependency. Recovery
shares do not manually unseal an auto-unseal cluster.

Type the exact cluster-specific confirmation and submit once. The response is
shown once and is not cached. Immediately transfer every returned share,
recovery key, and the initial root token into the approved offline custody
system. Do not copy them into a ticket, chat, terminal history, repository,
NetBox field, browser storage, screenshot, or password manager that is outside
the custody policy. Revoke or tightly constrain the initial root token after
creating durable administrative identities.

If the browser disconnects or the request reports an unavailable backend,
check current initialization status before doing anything else. Never retry an
initialization request blindly. If OpenBao is initialized and the response was
lost, the original custody material cannot be retrieved; invoke the bootstrap
incident procedure for the chosen seal design.

## Unseal and seal

The unseal form accepts exactly one share per request. Each custodian should
submit only their own share and then clear their clipboard. The response shows
only progress and seal state. A duplicate or invalid share is returned as a
fixed refusal without echoing the material.

Use **Reset accumulated progress** when a ceremony is abandoned or when the
seal-migration choice was wrong. During a seal migration, every submitted share
must use the same migration setting. Restart the ceremony after any reset.

Sealing is a destructive availability operation. Confirm that dependent
applications can tolerate the outage and that enough custodians or a healthy
auto-unseal service are available. The plugin re-reads status and refuses to
seal a standby. Type the exact confirmation and record the incident or change
reason.

## HA and Raft peers

The administration page displays the active node, observed HA nodes, the Raft
configuration index, leader, voter state, address, and protocol version. Treat
the index as a short-lived stale-UI detector, not an atomic Raft compare-and-swap.
OpenBao's peer-removal and snapshot-restore endpoints do not accept the observed
index or cluster ID as a server-enforced precondition. Freeze direct membership
changes during the ceremony and re-read cluster state after every operation;
an external Raft change can still race after NetBox's final preflight read.

Before removing a peer, verify that the target process is permanently gone or
will rejoin with the intended identity. The plugin re-reads the configuration
immediately before removal. It refuses a stale index, leader removal, and voter
removal when only three voters remain. It also refuses the operation when the
configured endpoint reports itself as a standby. Select a reviewed active
endpoint rather than following or copying an untrusted leader URL.

Peer removal does not repair the failed host and does not add a replacement.
After removal, validate Raft health from every surviving node and complete the
replacement procedure before considering redundancy restored.

## Download and protect a snapshot

Use **Download authenticated snapshot** from an initialized, unsealed Raft
cluster whose configured endpoint reports itself as active. Browser sessions
must provide a reason, type the cluster-specific confirmation, and submit a
CSRF-protected POST. API tokens may use the authenticated GET endpoint. The
service requests identity encoding and streams the upstream response without
retaining it. The download is bounded to 512 MiB and marked as an attachment,
`nosniff`, and `no-store`.

Move the file immediately to the approved encrypted backup system. Calculate
and store an integrity digest in that system, not in the NetBox administrative
audit. Record the OpenBao cluster ID, Raft index, OpenBao version, seal type,
backup time, encryption owner, and retention class alongside the backup. Test
restore procedures against a disposable cluster on the organization's defined
schedule.

An incomplete browser download creates an unsuccessful transfer audit record.
Discard the partial local file and start a new download. Do not concatenate or
repair partial snapshot files.

## Restore a snapshot

A normal restore requires a snapshot produced under a compatible seal design.
Verify the backup digest outside NetBox before selecting it. Open the current
administration page immediately before restore so its hidden cluster ID and
Raft index represent fresh state. Enter the reason, type the exact confirmation,
and submit.

The browser sends the selected file as raw `application/octet-stream`. The
plugin rejects multipart, content encoding, an absent or invalid length, an
empty file, a body over 512 MiB, a changed cluster ID or Raft index, a sealed or
non-Raft cluster, and a standby endpoint before it reads snapshot bytes.

Normal restore preserves OpenBao's seal-consistency validation. If it refuses
the snapshot, investigate the source cluster, seal keys, and backup integrity.
Do not escalate automatically to force restore.

## Force restore and disaster recovery

Force restore bypasses the normal seal-consistency check and has a separate
permission, URL, confirmation, and audit action. Use it only under an approved
disaster-recovery procedure when the original seal mechanism or keys are
unavailable and the recovery owner has verified the snapshot source and
consequences.

Before force restore:

1. Freeze normal changes and record the incident commander and risk owner.
2. Preserve the current cluster state and OpenBao audit evidence without
   copying secret or snapshot contents into the incident record.
3. Verify the backup digest, provenance, version, and encryption custody.
4. Confirm the target endpoint is the active node and the expected cluster ID
   and Raft index still match.
5. Confirm how applications will be stopped, restarted, and re-authenticated.

After either restore, treat a lost HTTP response as an unknown outcome. Do not
retry automatically. Re-read seal, leader, and Raft state, inspect the OpenBao
audit, and validate known non-secret metadata. Then test authentication and
secret-engine behavior through approved application identities.

If the response reports `outcome: accepted-audit-incomplete` or the
`X-OpenBao-Operation-Outcome: accepted-audit-incomplete` header, OpenBao
accepted the mutation but NetBox could not append the completion record. Do not
retry it. Preserve the durable preflight record, inspect current OpenBao state
and its audit device, and resolve the NetBox audit failure before another
administrative mutation.

## Rollback and retirement

There is no transactional rollback across NetBox, the network stream, and
OpenBao's Raft restore. Rollback means restoring a separately verified recovery
point under the same guarded procedure, not replaying the prior request. Keep
at least one pre-change snapshot until post-restore validation and the retention
policy both permit retirement.

When retiring a cluster, preserve metadata-only NetBox and OpenBao audit records
according to policy. Never archive initialization material or snapshot bytes in
the source repository, CI artifacts, test fixtures, documentation, screenshots,
or issue attachments.

## Incident checklist

- Lost initialization response: stop, read status, and invoke bootstrap
  recovery; never retry blindly.
- Lost restore response: treat the outcome as unknown, read current state, and
  inspect both audit systems before another mutation.
- Suspected share exposure: reset an incomplete ceremony and start the approved
  rekey or recovery process; do not paste the share into an incident record.
- Unexpected leader or redirect: stop and validate DNS, TLS, load-balancer, and
  cluster membership. The plugin will not follow it.
- Oversized or corrupt snapshot: quarantine the file in the backup system,
  verify provenance and digest, and select another recovery point.
- Audit failure: stop further changes. Initialization is the sole exception
  where already-issued custody material is still returned after a committed
  preflight audit; the response marks this as `preflight-only`.
