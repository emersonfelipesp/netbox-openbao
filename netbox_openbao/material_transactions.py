"""Explicit outer ownership for database changes and version-scoped compensation."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from typing import Any
from uuid import uuid4

from django.db import IntegrityError, connection, transaction
from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends.exceptions import OpenBaoError

MATERIAL_TRANSACTION_CONTRACT_VERSION = 1
_owner: ContextVar[Any] = ContextVar('openbao_material_transaction', default=None)
logger = logging.getLogger('netbox.plugins.netbox_openbao.material_transactions')


@dataclass
class MaterialAttempt:
    credential: Any
    backend: Any
    path: str
    user: Any
    action: str
    version: int | None = None
    audit_id: int | None = None


@dataclass
class MaterialTransaction:
    operation_id: str = field(default_factory=lambda: str(uuid4()))
    attempts: list[MaterialAttempt] = field(default_factory=list)
    deletions: list[MaterialAttempt] = field(default_factory=list)
    failed: bool = False
    committed: bool = False
    known_rollback: bool = False
    graph_ids: dict[str, set[int]] = field(default_factory=dict)
    graph_frozen: bool = False

    def declare_graph(self, **identities: set[int]) -> None:
        for kind, requested in identities.items():
            known = self.graph_ids.setdefault(kind, set())
            if self.graph_frozen and not requested <= known:
                raise OpenBaoError('All material participants must be locked before the first write.')
            known.update(requested)

    def witness(self) -> None:
        """Detect a framework-caught inner rollback before committing its owner."""
        from netbox_openbao.models import CredentialAccessLog

        for attempt in self.attempts + self.deletions:
            if not attempt.audit_id or not CredentialAccessLog.objects.filter(pk=attempt.audit_id).exists():
                raise OpenBaoError('The material transaction did not retain its commit witness.')

    def mark_committed(self) -> None:
        self.committed = True

    def recover(self, *, unknown: bool) -> None:
        """Never infer an owned version or delete after an unknown commit."""
        self.known_rollback = not unknown and not self.committed
        for attempt in reversed(self.attempts):
            outcome = 'Material transaction outcome unknown; reconciliation required.'
            if self.committed:
                outcome = 'Material transaction committed; post-commit processing requires reconciliation.'
            elif not unknown and attempt.version is not None:
                try:
                    backend = attempt.backend
                    backend.delete(attempt.path, versions=[attempt.version])
                    outcome = 'Material transaction rolled back; its exact version was removed.'
                except Exception:
                    outcome = 'Material transaction rolled back; version cleanup requires reconciliation.'
            self.record_recovery(attempt, outcome)
        for deletion in self.deletions:
            self.record_recovery(deletion, self.discard_recovery_message(unknown))

    def discard_recovery_message(self, unknown: bool) -> str:
        if self.committed:
            return 'Discard committed; cleanup was not performed and requires reconciliation.'
        if unknown:
            return 'Discard outcome unknown; cleanup was not performed and requires reconciliation.'
        return 'Discard rolled back; no discard deletion was performed.'

    def finish_deletions(self) -> None:
        """Run irreversible staged cleanup only after the owner exits successfully."""
        from netbox_openbao.models import CredentialAccessLog

        if self.deletions and not self.committed:
            raise OpenBaoError('Staged cleanup requires a confirmed material transaction commit.')
        incomplete = False
        for deletion in self.deletions:
            try:
                backend = deletion.backend
                backend.delete(deletion.path, versions=[deletion.version])
                updated = CredentialAccessLog.objects.filter(pk=deletion.audit_id).update(
                    success=True, message='Discard committed; its exact staged version was removed.',
                )
                if updated != 1:
                    raise OpenBaoError('The committed discard audit is unavailable.')
            except Exception:
                incomplete = True
                self.record_recovery(deletion, 'Discard committed; cleanup or its audit requires reconciliation.')
        if incomplete:
            raise OpenBaoError('Discard committed; cleanup is incomplete and requires reconciliation.') from None

    def record_recovery(self, attempt: MaterialAttempt, message: str) -> None:
        from netbox_openbao.models import CredentialAccessLog

        # No object FK: a create may have rolled back, and uncertainty is not
        # permission to infer whether its inventory row exists.
        try:
            CredentialAccessLog.objects.create(
                credential_uuid_snapshot=attempt.credential.uuid,
                username_snapshot=getattr(attempt.user, 'username', '')[:150],
                action=attempt.action, success=False, request_id=self.operation_id,
                resolved_version=attempt.version, message=message,
            )
        except Exception:
            logger.error('Material reconciliation audit unavailable; operation %s.', self.operation_id)
        logger.warning('%s Operation %s.', message, self.operation_id)


def current_material_transaction() -> MaterialTransaction:
    owner = _owner.get()
    if owner is None:
        raise OpenBaoError('An outer material transaction is required.')
    return owner


def _unknown_rollback(exc: BaseException, body_error: BaseException | None) -> bool:
    if exc is body_error:
        return connection.connection is None or connection.closed_in_transaction
    cause = exc.__cause__
    state = getattr(cause, 'sqlstate', getattr(cause, 'pgcode', '')) or ''
    rejected = (isinstance(exc, IntegrityError) and isinstance(cause, connection.Database.IntegrityError)
                and state.startswith('23'))
    return not rejected


@contextmanager
@sensitive_variables()
def material_transaction():
    """Own the final commit; nested calls join only this explicit owner.

    Enter before framework atomic blocks and owner/assignment persistence.
    A new owner requires actual autocommit. Neither a manually managed
    transaction nor a test wrapper can substitute a savepoint for final commit.
    """
    existing = _owner.get()
    if existing is not None:
        try:
            yield existing
        except BaseException:
            existing.failed = True
            raise
        return
    if not connection.get_autocommit():
        raise OpenBaoError('An outer material transaction requires autocommit before application transactions.')
    owner = MaterialTransaction()
    token = _owner.set(owner)
    body_error = None
    try:
        try:
            with transaction.atomic(durable=True):
                # Register first: errors in later callbacks happen after a
                # confirmed commit, even when their type is IntegrityError.
                transaction.on_commit(owner.mark_committed)
                try:
                    yield owner
                    if owner.failed:
                        raise OpenBaoError('The material transaction was refused.')
                    owner.witness()
                except BaseException as exc:
                    body_error = exc
                    raise
        except BaseException as exc:
            _owner.reset(token)
            token = None
            owner.recover(unknown=_unknown_rollback(exc, body_error))
            raise
    finally:
        if token is not None:
            _owner.reset(token)
    owner.finish_deletions()


def material_operation(function: Any) -> Any:
    """Make a standalone service own its commit or join a declared caller."""
    @wraps(function)
    @sensitive_variables()
    def owned(*args: Any, **kwargs: Any) -> Any:
        with material_transaction():
            return function(*args, **kwargs)
    return owned
