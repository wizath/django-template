from django.urls import path

from jwt_auth.views import LoginAPIView, VerifyAPIView

urlpatterns = [
    path('login', LoginAPIView.as_view(), name='login'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
]
