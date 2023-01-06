from django.urls import path

from jwt_auth.views import LoginAPIView, VerifyAPIView, RegisterAPIView, LogoutAPIView, AccessTokenAPIView, \
    RefreshTokenAPIView

urlpatterns = [
    path('login', LoginAPIView.as_view(), name='login'),
    path('register', RegisterAPIView.as_view(), name='register'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('access', AccessTokenAPIView.as_view(), name='access'),
    path('refresh', RefreshTokenAPIView.as_view(), name='refresh'),
]
