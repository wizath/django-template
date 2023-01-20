from django.urls import path

from user.views import LoginAPIView, RegisterAPIView, LogoutAPIView

urlpatterns = [
    path('login', LoginAPIView.as_view(), name='login'),
    path('register', RegisterAPIView.as_view(), name='register'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
]
