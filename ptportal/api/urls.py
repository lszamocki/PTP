# portal/api/urls.py
from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from .views import *

urlpatterns = [
    path('auth/', obtain_auth_token, name='api-auth'),
    path('affected-systems/', AffectedSystemListView.as_view(), name='affected-systems-list'),
    path('mitigations/', MitigationListView.as_view(), name='mitigations-list'),
    path('specific-findings/', SpecificFindingListView.as_view(), name='specific-findings-list'),
    path('uploaded-findings/', UploadedFindingListView.as_view(), name='uploaded-findings-list'),
    path('uploaded-findings/<int:pk>/', UploadedFindingUpdateView.as_view(), name='uploaded-findings-update')
]
