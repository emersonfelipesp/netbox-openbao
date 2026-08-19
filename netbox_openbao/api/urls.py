from netbox.api.routers import NetBoxRouter

from . import views

app_name = 'netbox_openbao-api'

router = NetBoxRouter()
router.register('engines', views.SecretEngineViewSet)
router.register('policies', views.CredentialPolicyViewSet)
router.register('credentials', views.CredentialViewSet)
router.register('assignments', views.CredentialAssignmentViewSet)
router.register('access-logs', views.CredentialAccessLogViewSet)

urlpatterns = router.urls
