from django.urls import path

from authentication.views import VerifyAPIView, AccessTokenAPIView, RefreshTokenAPIView

urlpatterns = [
    path('verify', VerifyAPIView.as_view(), name='verify'),
    path('access', AccessTokenAPIView.as_view(), name='access'),
    path('refresh', RefreshTokenAPIView.as_view(), name='refresh'),
]
