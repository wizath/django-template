import os
from http import cookies

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.tokens import AccessToken, RefreshToken
from authentication.models import UserRefreshToken

User = get_user_model()


class TestLoginAPI(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

        user2 = User(username='testuser2', email='test2@test.com')
        user2.set_password('testpassword2')
        user2.is_active = False
        user2.save()

    def test_no_credentials(self):
        response = self.client.post(reverse('login'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data.keys())
        self.assertTrue('password' in response.data.keys())

    def test_wrong_credentials(self):
        response = self.client.post(reverse('login'), {'username': 'wrong', 'password': 'wrong'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('non_field_errors' in response.data.keys())

    def test_login_ok(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data['uid'], 1)
        self.assertTrue('access_token' in response.data.keys())
        self.assertTrue('refresh_token' in response.data.keys())

        access_token = response.data['access_token']
        self.assertNotEqual(AccessToken.decode(access_token), None)
        refresh_token = response.data['refresh_token']
        self.assertNotEqual(RefreshToken.decode(refresh_token), None)


class TestRegistrationAPI(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_register_no_params(self):
        response = self.client.post(reverse('register'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('username' in response.data.keys())
        self.assertTrue('email' in response.data.keys())
        self.assertTrue('password' in response.data.keys())

    def test_register_used_email(self):
        response = self.client.post(reverse('register'), {
            'username': 'test',
            'password': 'test1234',
            'email': 'test@test.com'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['email'][0], 'This field must be unique.')

    def test_register_used_username(self):
        response = self.client.post(reverse('register'), {
            'username': 'testuser',
            'password': 'test1234',
            'email': 'test111@test.com'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['username'][0], 'This field must be unique.')

    def test_register_proper(self):
        username = 'test'
        password = 'test1234'
        email = 'test11@test.com'
        response = self.client.post(reverse('register'), {
            'username': username,
            'password': password,
            'email': email
        })

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], username)
        self.assertEqual(response.data['email'], email)


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

    def test_logout_not_authorized(self):
        token_cookie = cookies.SimpleCookie({'refresh_token': os.urandom(32).hex()})
        self.client.cookies = token_cookie
        response = self.client.post(reverse('logout'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
