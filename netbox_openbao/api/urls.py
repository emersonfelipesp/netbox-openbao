from netbox.api.routers import NetBoxRouter

from . import views

app_name = 'netbox_openbao-api'

router = NetBoxRouter()
router.register('engines', views.SecretEngineViewSet)
router.register('policies', views.CredentialPolicyViewSet)
router.register('credentials', views.CredentialViewSet)
router.register('assignments', views.CredentialAssignmentViewSet)
router.register('type-schemas', views.CredentialTypeSchemaViewSet)
router.register('access-logs', views.CredentialAccessLogViewSet)
router.register('procedure-runs', views.OpenBaoProcedureRunViewSet)
router.register('settings', views.OpenBaoSettingsViewSet)

urlpatterns = router.urls
