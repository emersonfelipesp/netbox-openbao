# Security invariants

[The security model](../security.md) states what this plugin guarantees. This
page states, for each guarantee, **what enforces it** and **which test fails
when you break it** — so a reviewer can check the claims rather than take them.

If you change one of these and the named test still passes, the test is wrong.
Fix the test.

## Nothing secret can be stored, serialized, or logged

| Claim | Enforced by | Test |
|---|---|---|
| No `Credential` column can hold material | The absence of a field. `test_credential_has_no_secret_bearing_field` walks `_meta.get_fields()` and fails on any name containing `password`, `private`, `secret`, `passphrase`, or `token` | `test_security.test_credential_has_no_secret_bearing_field` |
| No `SecretEngine` column holds auth material | Same absence: no `role_id`, `secret_id`, or `token` field | `test_models.test_no_auth_material_fields_exist` |
| `secret_data` is never serialized | `write_only=True` — **DRF itself** refuses, so it cannot appear in a `GET`, a `brief=true` response, the browsable API, an export, or an OpenAPI example | `test_security.test_secret_data_is_write_only`, `test_secret_data_absent_from_brief_fields`, `test_no_secret_field_in_read_representation` |
| No endpoint echoes material | — | `test_api.test_no_endpoint_echoes_material`, `test_detail_never_returns_material`, `test_list_never_returns_material`, `test_brief_never_returns_material` |
| A rejected form does not echo the key back | `render_value=False` on every sensitive widget | `test_views.test_material_is_not_echoed_back_on_a_validation_error` |
| The audit log never records a value | `log_access` takes no payload argument | `test_services.test_log_never_contains_the_value`, `test_rotation.test_audit_never_records_the_material` |
| An import failure never reports the material | Only `type(exc).__name__` is logged, never the message | `test_import.test_failures_never_report_the_material` |
| A schema error reports a path, not a value | `jsonschema`'s message quotes the failing instance; only `absolute_path` is surfaced | `test_type_schemas.test_validation_errors_never_quote_the_material` |
| Extraction cannot mirror a secret into a column | The `EXTRACTABLE_FIELDS` allowlist filters whatever an extractor returns | `test_registry.test_extraction_never_returns_secret_fields`, `test_type_schemas.test_extraction_output_is_still_confined_to_the_allowlist`, `test_a_schema_cannot_name_a_field_outside_the_allowlist` |

## Reading material is separately permissioned and separately routed

| Claim | Enforced by | Test |
|---|---|---|
| `reveal` is a distinct model action | `Credential.Meta.permissions`, auto-registered by NetBox 4.7 | `test_security.test_reveal_is_a_distinct_permission` |
| `view` alone cannot reveal | `restrict(user, 'reveal')` | `test_api.test_view_permission_alone_cannot_reveal`, `test_views.test_view_permission_alone_cannot_reveal` (×2 surfaces) |
| ObjectPermission constraints hide other tiers | The same `restrict()` — a 404, not a 403 | `test_api.test_constrained_permission_hides_other_tiers` |
| The policy group gate applies on **every** surface | `services.enforce_policy_access`, called from the service chokepoint and from the REST authorization helper | `test_policy_gate` — 12 tests across the REST reveal, `PATCH` of `secret_data`, the full-page UI reveal, the HTMX reveal, and UI promote/discard |
| A reveal is never reachable by `GET` in the UI | POST-only views | `test_views.test_get_is_not_allowed`, `test_rejects_get`, `test_promote_and_discard_reject_get` |
| The response is unstorable | `renderer_classes=[JSONRenderer]` + `no-store` | `test_security.test_reveal_uses_json_renderer_only`, `test_rotate_uses_json_renderer_only`; `test_api.test_reveal_response_is_not_storable`; `test_views.test_reveal_response_is_not_storable`, `test_fragment_is_not_storable` |
| A leaked token cannot drain the store silently | `RevealRateThrottle`, default `30/hour` | `test_security.test_reveal_is_throttled`, `test_api.test_reveal_is_rate_limited` |
| `POST reveal` does not demand `add_credential` | `SecretActionPermissions` remaps `POST` → `view_<model>` | `test_api.test_reveal_does_not_require_add_permission`, `test_stage_does_not_require_add_permission` |
| The TTL cannot exceed the tier's ceiling | `min(reveal_ttl, policy.max_reveal_ttl)` | `test_services.test_ttl_is_capped_by_policy`, `test_views.test_fragment_carries_the_policy_capped_ttl` |
| A required reason is enforced, and a refusal is a 400 not a 500 | `services.reveal_material` + `_as_drf_validation_error` | `test_services.test_required_reason_is_enforced`, `test_api.test_missing_required_reason_is_a_400_not_a_500`, `test_views.test_policy_required_reason_is_enforced_and_leaks_nothing` |
| Revealed material is not templated into the DOM as markup | `textContent` + `remove()` | `test_views.test_fragment_uses_no_innerhtml` |

## The audit trail is evidence

| Claim | Enforced by | Test |
|---|---|---|
| Every access is recorded, including failures | `log_access` on both branches of every operation | `test_services.test_write_is_logged`, `test_reveal_is_logged`; `test_rotation.test_every_transition_is_audited`; `test_policy_gate.test_refusal_is_audited_as_a_failed_reveal` |
| The source IP is stored as a string | `str(get_client_ip(...))` — an unconverted `netaddr.IPAddress` fails the insert **silently** | `test_api.test_reveal_is_audited`, `test_views.test_reveal_is_audited` |
| A record survives deletion of its credential | name and UUID snapshots, `on_delete=SET_NULL` | `test_services.test_log_survives_credential_deletion` |
| The log cannot be edited or erased through the API | `NetBoxReadOnlyModelViewSet` — retrieve and list only | `test_api.test_access_log_is_read_only`, `test_policy_gate.test_the_viewset_declares_no_write_handler`, `test_write_methods_are_not_allowed_even_with_the_permission` |
| ObjectPermission constraints apply to the log's API | The same `NetBoxReadOnlyModelViewSet` — `BaseViewSet.initial()` is what calls `restrict()` | `test_policy_gate.test_constraint_is_applied_to_the_list_endpoint`, `test_constraint_is_applied_to_the_detail_endpoint` |

## The two stores cannot silently disagree

| Claim | Enforced by | Test |
|---|---|---|
| A failed write leaves no orphaned secret | The explicit compensator in `store_credential` | `test_services.test_backend_failure_rolls_back_the_row`, `test_metadata_failure_compensates_the_orphaned_write`, `test_failed_create_still_removes_the_whole_path` |
| **A failed rotation must not destroy the live secret** | The compensator branches on `cas`: version-scoped delete when `cas != 0` | `test_services.test_failed_rotation_must_not_destroy_the_existing_secret` |
| A create cannot overwrite material at a colliding path | `cas=0` | `test_backends.test_cas_zero_refuses_to_overwrite`, `test_services.test_duplicate_path_is_refused_by_the_database` |
| A rotation cannot clobber a concurrent write | `cas=kv_version` | `test_backends.test_cas_stale_version_refuses`, `test_services.test_cas_refuses_a_write_against_a_stale_version` |
| A malformed payload is rejected before anything is written | `prepare_material` is pure and runs first | `test_services.test_invalid_payload_is_rejected_before_any_write` |
| Deleting a credential destroys its material | `pre_delete` signal | `test_services.test_deleting_a_credential_destroys_its_material` |
| A failed quick-add leaves nothing behind | One transaction wrapping service, credential, and assignment | `test_quickadd.test_a_backend_failure_leaves_nothing_behind` |
| `custom_metadata` never carries an empty value | `build_custom_metadata` drops empties; the fake rejects them as the server does | `test_services.test_custom_metadata_never_contains_an_empty_value` |

## A rotation cannot break a consumer

| Claim | Enforced by | Test |
|---|---|---|
| Staging does not change what consumers get | `live_kv_version` resolution | `test_rotation.test_staging_does_not_change_what_consumers_get`, `test_api.test_staged_material_is_not_served_to_readers` |
| A credential predating staging is pinned first | `stage_material` pins `live_kv_version` before writing | `test_rotation.test_credential_predating_staging_is_pinned_before_staging` |
| Promotion refuses a version that vanished | `list_versions` check before flipping the pointer | `test_rotation.test_promotion_refuses_a_version_that_vanished` |
| Discard destroys only the staged version | version-scoped `delete` | `test_rotation.test_discard_leaves_the_live_version_serving`, `test_backends.test_version_scoped_delete_leaves_the_others` |
| Staging twice is refused | `has_staged_version` guard | `test_rotation.test_cannot_stage_twice` |

## The backend boundary leaks nothing

| Claim | Enforced by | Test |
|---|---|---|
| No server response text escapes | Every exception built from a fixed string, `from None` | `test_security.test_backend_exceptions_carry_no_server_text`; `test_backends.test_forbidden_becomes_scrubbed_auth_error`, `test_unknown_exception_is_still_scrubbed`, `test_bad_token_is_scrubbed_auth_error` |
| The broker's error text is never relayed | `_translate_status` ignores the body | `test_broker_backend.test_the_brokers_own_error_text_is_never_relayed` |
| A malformed broker response is an error, not a crash | `_field()` rather than direct indexing | `test_broker_backend.test_a_missing_field_is_a_scrubbed_error`, `test_a_non_dict_body_is_a_scrubbed_error`, `test_an_undecodable_body_is_an_error_not_a_crash` |
| Broker mode never sends the mount | `read`/`write`/`delete` payloads omit it | `test_broker_backend.test_the_mount_is_never_sent` |
| Broker mode refuses unverified TLS | `_get_session` raises when `verify` is falsy | `test_broker_backend.test_verification_cannot_be_turned_off`, `test_a_ca_path_satisfies_it` |
| Each tier presents its own broker certificate | keyed on `env_prefix` | `test_broker_backend.test_a_policy_tier_uses_its_own_certificate` |
| Broker and direct mode raise the same exceptions | one shared mapping | `test_broker_backend.test_status_codes_map_to_the_same_exceptions_as_direct_mode` |

## An operator-defined type cannot execute code

| Claim | Enforced by | Test |
|---|---|---|
| `extractor` is a registry name, never a path | `clean()` validates against `EXTRACTORS`; the form renders a `<select>` | `test_type_schemas.test_extractor_must_come_from_the_registry`, `test_api_rejects_an_extractor_outside_the_registry` |
| A stored type cannot shadow a built-in | `clean()` refuses the slug | `test_type_schemas.test_a_stored_type_may_not_shadow_a_builtin` |
| `secret_fields` must exist in the schema | `clean()` | `test_type_schemas.test_secret_fields_must_exist_in_the_schema` |
| A malformed JSON Schema is rejected at save | `Draft202012Validator.check_schema` | `test_type_schemas.test_malformed_json_schema_is_rejected` |

## Assignment is bounded

| Claim | Enforced by | Test |
|---|---|---|
| Only permitted object types accept credentials | `CredentialAssignment.clean()` — on the **model**, so the API and direct ORM callers are held to it too | `test_assignments.test_assignment_to_forbidden_type_is_rejected`, `test_quickadd.test_unassignable_target_is_a_404` |
| Exactly one primary per object and purpose | a partial unique constraint | `test_assignments.test_only_one_primary_per_object_and_purpose` |
| At most one default engine | a partial unique constraint | `test_models.test_only_one_engine_may_be_default` |
| A credential's engine matches its policy's | `Credential.clean()` | `test_models.test_engine_must_match_policy_engine` |
| The path never changes | stamped once in `save()` | `test_models.test_path_is_stable_across_renames`, `test_path_is_derived_from_uuid` |

## A note on what a green suite proves

Most of the tests above run against a `FakeBackend`. That is enough for the
NetBox-side invariants, and not enough for the wire protocol.

Three defects in this repository have hidden behind a passing fake: a whole-path
delete where a version-scoped one was needed, tombstoned versions reported as
alive, and an empty `custom_metadata` value that **both** OpenBao and Vault
reject — the last of which broke credential creation against every real server
while 200+ tests stayed green.

A fake only fails in ways its author already thought of. The
`_KVIntegrationTests` suite runs the same cases against a live OpenBao, a live
Vault, and a live broker, and skips cleanly when their addresses are unset. Run
it before believing a green suite: [Development](../development.md).
