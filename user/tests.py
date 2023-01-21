import datetime
import os
from http import cookies
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.urls import reverse
from django.utils.timezone import make_aware
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.models import UserRefreshToken
from authentication.tokens import AccessToken, RefreshToken
from user.models import ResetPasswordToken

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

    def test_login_verify(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data['uid'], 1)
        self.assertTrue('access_token' in response.data.keys())
        self.assertTrue('refresh_token' in response.data.keys())

        access_token = response.data['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        logout_response = self.client.get(reverse('verify'))
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)


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


class TestPasswordResetAPI(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

    def test_reset_wrong_email(self):
        response = self.client.post(reverse('password_reset_request'), {'email': 'noexist@test.com'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('Invalid email address' in response.data['non_field_errors'])

    @mock.patch('user.models.reset_password_token_created.send')
    def test_proper_reset_token_request(self, mock_reset_password_token_created):
        response = self.client.post(reverse('password_reset_request'), {'email': 'test@test.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(mock_reset_password_token_created.called)

        last_reset_password_token = mock_reset_password_token_created.call_args[1]['reset_password_token']
        token = ResetPasswordToken.objects.first()
        self.assertEqual(token.id, last_reset_password_token.id)
        self.assertEqual(token.token, last_reset_password_token.token)

    def test_proper_double_reset_token_request(self):
        response = self.client.post(reverse('password_reset_request'), {'email': 'test@test.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.post(reverse('password_reset_request'), {'email': 'test@test.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        tokens = ResetPasswordToken.objects.all()
        self.assertEqual(len(tokens), 1)

    def test_password_reset_wrong_token(self):
        response = self.client.post(reverse('password_reset'), {'password': 'newpassword', 'token': 'wrongtokenonly'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('Invalid token' in response.data['non_field_errors'])

    def test_password_reset_wrong_password(self):
        user = User.objects.first()
        now = make_aware(datetime.datetime.utcnow())
        token = ResetPasswordToken.objects.create(
            user=user,
            ip_address="",
            user_agent="",
            token=ResetPasswordToken.generate_token(),
            created_at=now,
            expires_at=now + datetime.timedelta(hours=24)
        )
        response = self.client.post(reverse('password_reset'), {'password': 'a', 'token': token.token})
        self.assertTrue(
            'This password is too short. It must contain at least 8 characters.' in response.data['non_field_errors'])
        self.assertTrue('This password is too common.' in response.data['non_field_errors'])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_expired_token(self):
        user = User.objects.first()
        now = make_aware(datetime.datetime.utcnow())
        token = ResetPasswordToken.objects.create(
            user=user,
            ip_address="",
            user_agent="",
            token=ResetPasswordToken.generate_token(),
            created_at=now,
            expires_at=now - datetime.timedelta(hours=24)
        )
        response = self.client.post(reverse('password_reset'), {'password': 'a', 'token': token.token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('Invalid token' in response.data['non_field_errors'])

    def test_password_reset_ok(self):
        user = User.objects.first()
        now = make_aware(datetime.datetime.utcnow())
        token = ResetPasswordToken.objects.create(
            user=user,
            ip_address="",
            user_agent="",
            token=ResetPasswordToken.generate_token(),
            created_at=now,
            expires_at=now + datetime.timedelta(hours=24)
        )
        new_password = 'newpasswored122334'
        response = self.client.post(reverse('password_reset'), {'password': new_password, 'token': token.token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # check if the new password works
        user = User.objects.first()
        self.assertTrue(check_password(new_password, user.password))

        # check if token is deleted afterwards
        reset_tokens = ResetPasswordToken.objects.all()
        self.assertEqual(len(reset_tokens), 0)

    def test_password_reset_double_token_use(self):
        user = User.objects.first()
        now = make_aware(datetime.datetime.utcnow())
        token = ResetPasswordToken.objects.create(
            user=user,
            ip_address="",
            user_agent="",
            token=ResetPasswordToken.generate_token(),
            created_at=now,
            expires_at=now + datetime.timedelta(hours=24)
        )
        new_password = 'newpasswored122334'
        response = self.client.post(reverse('password_reset'), {'password': new_password, 'token': token.token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # check if token is deleted afterwards
        reset_tokens = ResetPasswordToken.objects.all()
        self.assertEqual(len(reset_tokens), 0)

        new_password = 'newpasswored122334'
        response = self.client.post(reverse('password_reset'), {'password': new_password, 'token': token.token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('Invalid token' in response.data['non_field_errors'])
