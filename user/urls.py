from django.urls import path

from user.views import LoginView, RegisterView, LogoutView, ResetPasswordView, ResetPasswordTokenView, ActivateView

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('register', RegisterView.as_view(), name='register'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('activate', ActivateView.as_view(), name='activate'),
    path('password_reset_request', ResetPasswordTokenView.as_view(), name='password_reset_request'),
    path('password_reset', ResetPasswordView.as_view(), name='password_reset'),
]
