"""Commit-boundary coverage for OpenBao custom metadata projections."""

from copy import deepcopy
from threading import Event, Thread, current_thread
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import close_old_connections, connections, transaction
from netbox.context import current_request

from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.material_transactions import current_material_transaction, material_transaction
from netbox_openbao.models import Credential, CredentialAssignment
from netbox_openbao.services import write_material

from .base import OpenBaoTransactionTestCase
from .fakes import FakeBackend

ALIAS = "metadata_projection"
settings.DATABASES[ALIAS] = deepcopy(settings.DATABASES["default"])
settings.DATABASES[ALIAS]["TEST"] = {"MIRROR": "default"}


class MetadataProjectionTest(OpenBaoTransactionTestCase):
    """Exercise callbacks against PostgreSQL commits rather than test wrappers."""

    databases = {"default", ALIAS}

    def setUp(self):
        super().setUp()
        site = Site.objects.create(name="Projection site", slug="projection-site")
        manufacturer = Manufacturer.objects.create(name="Projection vendor", slug="projection-vendor")
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer,
            model="Projection type",
            slug="projection-type",
        )
        role = DeviceRole.objects.create(name="Projection role", slug="projection-role")
        self.device = Device.objects.create(
            name="projection-device",
            site=site,
            device_type=device_type,
            role=role,
        )
        self.content_type = ContentType.objects.get_for_model(Device)

    def _write_credential(self, name):
        credential = self.make_credential(name=name)
        write_material(credential, {"password": "not-logged"})
        credential.refresh_from_db()
        return credential

    def _assignment(self, credential):
        return CredentialAssignment.objects.create(
            credential=credential,
            assigned_object_type=self.content_type,
            assigned_object_id=self.device.pk,
        )

    def _assignment_value(self, credential):
        return FakeBackend.metadata[credential.path].get("netbox_assignments")

    def test_assignment_create_rollback_does_not_publish(self):
        credential = self._write_credential("create-rollback")

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self._assignment(credential)
                raise RuntimeError("rollback")

        self.assertIsNone(self._assignment_value(credential))

    def test_queryset_delete_rollback_does_not_publish(self):
        credential = self._write_credential("delete-rollback")
        assignment = self._assignment(credential)
        expected = self._assignment_value(credential)

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                CredentialAssignment.objects.filter(pk=assignment.pk).delete()
                raise RuntimeError("rollback")

        self.assertEqual(self._assignment_value(credential), expected)

    def test_committed_instance_delete_clears_assignment_metadata(self):
        credential = self._write_credential("instance-delete")
        assignment = self._assignment(credential)

        assignment.delete()

        self.assertIsNone(self._assignment_value(credential))

    def test_committed_queryset_delete_clears_assignment_metadata(self):
        credential = self._write_credential("queryset-delete")
        assignment = self._assignment(credential)

        CredentialAssignment.objects.filter(pk=assignment.pk).delete()

        self.assertIsNone(self._assignment_value(credential))

    def test_committed_reassignment_publishes_old_and_new_owners(self):
        old = self._write_credential("old-owner")
        new = self._write_credential("new-owner")
        assignment = self._assignment(old)

        assignment.credential = new
        assignment.save(update_fields=("credential",))

        self.assertIsNone(self._assignment_value(old))
        self.assertIn(f"dcim.device:{self.device.pk}", self._assignment_value(new))

    def test_service_rollback_does_not_publish(self):
        credential = self.make_credential(name="service-rollback")

        with self.assertRaises(RuntimeError):
            with material_transaction():
                write_material(credential, {"password": "not-logged"})
                raise RuntimeError("rollback")

        self.assertNotIn(credential.path, FakeBackend.metadata)

    def test_service_commit_publishes(self):
        credential = self._write_credential("service-commit")

        self.assertEqual(FakeBackend.metadata[credential.path]["managed_by"], "netbox-openbao")

    def test_untranslated_callback_error_does_not_log_exception_text(self):
        credential = self.make_credential(name="safe-diagnostic")

        with patch.object(FakeBackend, "set_metadata", side_effect=RuntimeError("leaked-secret")):
            with self.assertLogs("netbox.plugins.netbox_openbao", level="ERROR") as captured:
                write_material(credential, {"password": "not-logged"})

        self.assertIn("untranslated error", captured.output[0])
        self.assertNotIn("leaked-secret", captured.output[0])
        self.assertNotIn("not-logged", captured.output[0])

    def test_publish_delete_race_is_a_noop_before_material_destruction(self):
        credential = self._write_credential("deleted-source")
        path = credential.path

        with transaction.atomic():
            self._assignment(credential)
            credential.delete()

        self.assertNotIn(path, FakeBackend.store)
        self.assertNotIn(path, FakeBackend.metadata)

    def test_delete_commits_after_reload_before_publication(self):
        import netbox_openbao.services as services

        credential = self._write_credential("interleaved-delete")
        path = credential.path
        reloaded = Event()
        release = Event()
        errors = []
        publisher_pid = []
        thread = None

        def pause_after_reload(credential_id, using):
            if current_thread() is not thread:
                return
            with connections[using].cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                publisher_pid.append(cursor.fetchone()[0])
            reloaded.set()
            if not release.wait(timeout=10):
                raise AssertionError("publisher release timed out")

        def publish_assignment():
            close_old_connections()
            try:
                with patch.object(services, "_metadata_source_reloaded", side_effect=pause_after_reload):
                    self._assignment(credential)
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_old_connections()

        thread = Thread(target=publish_assignment)
        thread.start()
        self.assertTrue(reloaded.wait(timeout=10), "publisher did not reach its committed reload")
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            deleting_pid = cursor.fetchone()[0]
        Credential.objects.get(pk=credential.pk).delete()
        release.set()
        thread.join(timeout=10)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(publisher_pid), 1)
        self.assertNotEqual(publisher_pid[0], deleting_pid)
        self.assertNotIn(path, FakeBackend.store)
        self.assertNotIn(path, FakeBackend.metadata)

    def test_publisher_lock_blocks_delete_until_publication_finishes(self):
        import netbox_openbao.services as services

        credential = self._write_credential("publisher-wins")
        path = credential.path
        publishing = Event()
        release = Event()
        delete_attempting_lock = Event()
        delete_finished = Event()
        errors = []
        publisher_pid = []
        deleter_pid = []
        original_set_metadata = FakeBackend.set_metadata
        publisher = None
        deleter = None

        def observe_lock_attempt(credential_id, using):
            with connections[using].cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pid = cursor.fetchone()[0]
            if current_thread() is publisher:
                publisher_pid.append(pid)
            if current_thread() is deleter:
                deleter_pid.append(pid)
                delete_attempting_lock.set()

        def blocking_set_metadata(backend, metadata_path, metadata):
            if current_thread() is publisher:
                publishing.set()
                if not release.wait(timeout=10):
                    raise AssertionError("publication release timed out")
            return original_set_metadata(backend, metadata_path, metadata)

        def publish_assignment():
            close_old_connections()
            try:
                self._assignment(credential)
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_old_connections()

        def delete_credential():
            close_old_connections()
            try:
                Credential.objects.get(pk=credential.pk).delete()
                delete_finished.set()
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_old_connections()

        with patch.object(services, "_before_metadata_projection_lock", side_effect=observe_lock_attempt):
            with patch.object(FakeBackend, "set_metadata", new=blocking_set_metadata):
                publisher = Thread(target=publish_assignment)
                publisher.start()
                self.assertTrue(publishing.wait(timeout=10), "publisher never held the advisory lock")
                deleter = Thread(target=delete_credential)
                deleter.start()
                self.assertTrue(delete_attempting_lock.wait(timeout=10), "deleter never attempted the real lock")
                self.assertEqual(len(publisher_pid), 1)
                self.assertEqual(len(deleter_pid), 1)
                self.assertNotEqual(publisher_pid[0], deleter_pid[0])
                delete_completed_while_locked = delete_finished.wait(timeout=0.2)
                self.assertFalse(delete_completed_while_locked, "deletion committed while publication held the lock")
                release.set()
                publisher.join(timeout=10)
                deleter.join(timeout=10)

        self.assertFalse(publisher.is_alive())
        self.assertFalse(deleter.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(delete_finished.is_set())
        self.assertNotIn(path, FakeBackend.store)
        self.assertNotIn(path, FakeBackend.metadata)

    def test_callback_boundary_contains_reload_transaction_and_lock_failures(self):
        import netbox_openbao.services as services

        credential = self._write_credential("callback-boundary")
        failures = (
            patch.object(Credential.objects, "using", side_effect=RuntimeError("reload-secret")),
            patch.object(services.transaction, "atomic", side_effect=RuntimeError("transaction-secret")),
            patch.object(services, "lock_custom_metadata_projection", side_effect=RuntimeError("lock-secret")),
        )

        for failure in failures:
            later = []
            owner = transaction.atomic()
            owner.__enter__()
            services.defer_custom_metadata((credential.pk,), using="default")
            transaction.on_commit(lambda callbacks=later: callbacks.append(True), using="default")
            failure.start()
            try:
                with self.assertLogs("netbox.plugins.netbox_openbao", level="ERROR") as captured:
                    owner.__exit__(None, None, None)
            finally:
                failure.stop()

            self.assertEqual(later, [True])
            self.assertIn("callback failed", captured.output[0])
            self.assertNotIn("secret", captured.output[0])

    def test_callback_uses_database_alias_and_clean_context(self):
        import netbox_openbao.services as services

        aliases = []
        contexts = []
        original_on_commit = services.transaction.on_commit
        original_publish = services._publish_custom_metadata

        def recording_on_commit(callback, using=None, robust=False):
            if getattr(callback, "func", None) is services._run_metadata_projection:
                aliases.append(using)
            return original_on_commit(callback, using=using, robust=robust)

        def recording_publish(credential_id, using):
            try:
                current_material_transaction()
            except OpenBaoError:
                owner_is_clear = True
            else:
                owner_is_clear = False
            contexts.append((current_request.get(), owner_is_clear))
            return original_publish(credential_id, using)

        request = SimpleNamespace(user=get_user_model().objects.create_user(username="context-user"), id=uuid4())
        request_token = current_request.set(request)
        try:
            with patch.object(services.transaction, "on_commit", side_effect=recording_on_commit):
                with patch.object(services, "_publish_custom_metadata", side_effect=recording_publish):
                    self._write_credential("context-boundary")
        finally:
            current_request.reset(request_token)

        self.assertEqual(aliases, ["default"])
        self.assertEqual(contexts, [(None, True)])

    def test_nondefault_alias_drives_registration_and_both_reloads(self):
        import netbox_openbao.services as services

        alias = ALIAS
        credential = self._write_credential("alias-proof")
        aliases = []
        reloads = []
        original_on_commit = services.transaction.on_commit
        original_using = Credential.objects.using

        def recording_on_commit(callback, using=None, robust=False):
            if getattr(callback, "func", None) is services._run_metadata_projection:
                aliases.append(using)
            return original_on_commit(callback, using=using, robust=robust)

        def recording_using(using):
            reloads.append(using)
            return original_using(using)

        with patch.object(services.transaction, "on_commit", side_effect=recording_on_commit):
            with patch.object(Credential.objects, "using", side_effect=recording_using):
                with transaction.atomic(using=alias):
                    assignment = CredentialAssignment(
                        credential=credential,
                        assigned_object_type=self.content_type,
                        assigned_object_id=self.device.pk,
                    )
                    assignment.save(using=alias)

        self.assertEqual(aliases, [alias])
        self.assertGreaterEqual(reloads.count(alias), 2)
