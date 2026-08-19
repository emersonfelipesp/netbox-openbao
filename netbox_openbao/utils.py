"""Shared helpers with no dependency on the API or form layers."""

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

from .config import assignable_model_labels

__all__ = ('assignable_content_types',)


def assignable_content_types():
    """
    ContentTypes the deployment permits credential assignment to.

    Lives here rather than in `api.serializers` so the forms layer can use it
    without importing the API layer — which would drag DRF into module import
    order during `AppConfig.ready()`.
    """
    query = Q(pk__in=[])
    for label in assignable_model_labels():
        app_label, _, model = label.partition('.')
        query |= Q(app_label=app_label, model=model)
    return ContentType.objects.filter(query)
