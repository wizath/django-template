import os
from http import cookies

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.models import UserRefreshToken
from authentication.tokens import AccessToken, RefreshToken

User = get_user_model()


class TestLogoutAPI(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_logout_clear_cookies(self):
        token_cookie = cookies.SimpleCookie({
            'access_token': AccessToken.encode({'uid': 1}),
            'refresh_token': RefreshToken.encode({'uid': 1})
        })
        self.client.cookies = token_cookie
        response = self.client.post(reverse('logout'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        raw_access = response.client.cookies.get('access_token', "")
        raw_refresh = response.client.cookies.get('refresh_token', "")

        self.assertEqual(raw_access.value, "")
        self.assertEqual(raw_refresh.value, "")

    def test_logout_cookie_blacklist(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_token = response.data["refresh_token"]
        self.client.cookies = response.client.cookies

        logout_response = self.client.post(reverse('logout'))
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

        # check blacklisted token
        payload = RefreshToken.decode(refresh_token)
        old_token = UserRefreshToken.objects.filter(jti=payload.get('jti')).first()

        self.assertIsNotNone(old_token)
        self.assertEqual(old_token.user_id, 1)
        self.assertTrue(old_token.blacklisted)

    def test_logout_api_blacklist(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_token = response.data["refresh_token"]

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_token}')
        logout_response = self.client.post(reverse('logout'))
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

        # check blacklisted token
        payload = RefreshToken.decode(refresh_token)
        old_token = UserRefreshToken.objects.filter(jti=payload.get('jti')).first()

        self.assertIsNotNone(old_token)
        self.assertEqual(old_token.user_id, 1)
        self.assertTrue(old_token.blacklisted)

    def test_logout_api_blacklististed_token_used(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        refresh_token = response.data["refresh_token"]

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_token}')
        logout_response = self.client.post(reverse('logout'))
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

        # check blacklisted token
        payload = RefreshToken.decode(refresh_token)
        old_token = UserRefreshToken.objects.filter(jti=payload.get('jti')).first()

        self.assertIsNotNone(old_token)
        self.assertEqual(old_token.user_id, 1)
        self.assertTrue(old_token.blacklisted)

        # should fail
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_token}')
        logout_response = self.client.post(reverse('refresh'))
        self.assertEqual(logout_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_logout_not_authorized(self):
        token_cookie = cookies.SimpleCookie({'refresh_token': os.urandom(32).hex()})
        self.client.cookies = token_cookie
        response = self.client.post(reverse('logout'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
