from django.urls import path

from user.views import LoginAPIView, RegisterAPIView, LogoutAPIView, ResetPasswordView, ResetPasswordTokenView

urlpatterns = [
    path('login', LoginAPIView.as_view(), name='login'),
    path('register', RegisterAPIView.as_view(), name='register'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('password_reset_request', ResetPasswordTokenView.as_view(), name='password_reset_request'),
    path('password_reset', ResetPasswordView.as_view(), name='password_reset'),
]
