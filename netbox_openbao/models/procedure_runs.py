from django.contrib.auth.models import User
from django.db import models
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel

__all__ = ('OpenBaoProcedureRun',)


class OpenBaoProcedureRun(NetBoxModel):
    """Links a SecretEngine to an audited netbox-rpc OpenBao procedure execution."""

    engine = models.ForeignKey(
        to='netbox_openbao.SecretEngine',
        on_delete=models.PROTECT,
        related_name='procedure_runs',
    )
    rpc_execution = models.ForeignKey(
        to='netbox_rpc.RPCExecution',
        on_delete=models.PROTECT,
        related_name='+',
    )
    procedure_name = models.CharField(
        verbose_name=_('procedure'),
        max_length=100,
    )
    initiated_by = models.ForeignKey(
        to=User,
        on_delete=models.PROTECT,
        related_name='+',
    )

    class Meta:
        ordering = ('-created',)
        verbose_name = _('OpenBao procedure run')
        verbose_name_plural = _('OpenBao procedure runs')

    def __str__(self):
        return f'{self.procedure_name} ({self.engine})'

    def get_status_color(self):
        status = getattr(self.rpc_execution, 'status', None)
        return {
            'completed': 'green',
            'failed': 'red',
            'running': 'cyan',
            'queued': 'blue',
            'pending': 'gray',
        }.get(status, 'gray')
