from django.urls import include, path
from utilities.urls import get_model_urls

from . import views

app_name = 'netbox_openbao'

urlpatterns = (
    # Quick-add is keyed by the target object rather than by a credential, so
    # it is a plain path rather than a registered model view.
    path(
        'quick-add/ssh/<str:app_label>/<str:model_name>/<int:pk>/',
        views.QuickAddSSHView.as_view(),
        name='quickadd_ssh',
    ),

    path('engines/', include(get_model_urls('netbox_openbao', 'secretengine', detail=False))),
    path('engines/<int:pk>/', include(get_model_urls('netbox_openbao', 'secretengine'))),

    path('policies/', include(get_model_urls('netbox_openbao', 'credentialpolicy', detail=False))),
    path('policies/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialpolicy'))),

    path('credentials/', include(get_model_urls('netbox_openbao', 'credential', detail=False))),
    path('credentials/<int:pk>/', include(get_model_urls('netbox_openbao', 'credential'))),

    path('assignments/', include(get_model_urls('netbox_openbao', 'credentialassignment', detail=False))),
    path('assignments/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialassignment'))),

    path('type-schemas/', include(get_model_urls('netbox_openbao', 'credentialtypeschema', detail=False))),
    path('type-schemas/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialtypeschema'))),

    path('access-logs/', include(get_model_urls('netbox_openbao', 'credentialaccesslog', detail=False))),
    path('access-logs/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialaccesslog'))),

    path('procedure-runs/', include(get_model_urls('netbox_openbao', 'openbaoprocedurerun', detail=False))),
    path('procedure-runs/<int:pk>/', include(get_model_urls('netbox_openbao', 'openbaoprocedurerun'))),

    path('settings/', include(get_model_urls('netbox_openbao', 'openbaosettings', detail=False))),
    path('settings/<int:pk>/', include(get_model_urls('netbox_openbao', 'openbaosettings'))),
)
