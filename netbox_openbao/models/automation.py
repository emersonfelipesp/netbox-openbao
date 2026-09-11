"""Non-secret, durable reservations preventing a second automation reveal."""

from django.db import models


class AutomationResolutionReceipt(models.Model):
    """A dispatch may reveal a named bundle once; an unknown outcome stays spent.

    This is internal state with no CRUD API. The signed dispatch nonce is hashed
    before storage. Material is never cached here, including after successful
    delivery; a lost response requires a newly authorized dispatch.
    """

    execution_id = models.PositiveBigIntegerField()
    dispatch_nonce_digest = models.CharField(max_length=64)
    step_id = models.CharField(max_length=100, blank=True)
    reference_name = models.CharField(max_length=100)
    credential_uuid = models.UUIDField()
    assignment_id = models.PositiveBigIntegerField()
    resolved_version = models.PositiveIntegerField()
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = (
            models.UniqueConstraint(
                fields=('execution_id', 'dispatch_nonce_digest', 'step_id', 'reference_name'),
                name='openbao_automation_once',
            ),
        )
