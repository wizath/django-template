from django.urls import path

from jwt_auth.views import LoginAPIView, VerifyAPIView, RegisterAPIView

urlpatterns = [
    path('login', LoginAPIView.as_view(), name='login'),
    path('register', RegisterAPIView.as_view(), name='register'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
]
