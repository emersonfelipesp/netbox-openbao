from django.urls import include, path
from utilities.urls import get_model_urls

app_name = 'netbox_openbao'

urlpatterns = (
    path('engines/', include(get_model_urls('netbox_openbao', 'secretengine', detail=False))),
    path('engines/<int:pk>/', include(get_model_urls('netbox_openbao', 'secretengine'))),

    path('policies/', include(get_model_urls('netbox_openbao', 'credentialpolicy', detail=False))),
    path('policies/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialpolicy'))),

    path('credentials/', include(get_model_urls('netbox_openbao', 'credential', detail=False))),
    path('credentials/<int:pk>/', include(get_model_urls('netbox_openbao', 'credential'))),

    path('assignments/', include(get_model_urls('netbox_openbao', 'credentialassignment', detail=False))),
    path('assignments/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialassignment'))),

    path('access-logs/', include(get_model_urls('netbox_openbao', 'credentialaccesslog', detail=False))),
    path('access-logs/<int:pk>/', include(get_model_urls('netbox_openbao', 'credentialaccesslog'))),
)
