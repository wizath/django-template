import datetime
import os
import uuid
from unittest import mock
from http import cookies

import jwt
from django.conf import settings
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

from authentication.tokens import AccessToken, Token, RefreshToken

User = get_user_model()


class TokenSecurityTests(TestCase):
    def test_jwt_token_no_algorithm_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'issuer': 'test'
        }, None, algorithm='none')

        with self.assertRaises(jwt.exceptions.InvalidAlgorithmError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_no_claims_exception(self):
        token = jwt.encode({
            'uid': 1
        }, settings.SECRET_KEY, algorithm='HS256')

        with self.assertRaises(jwt.exceptions.MissingRequiredClaimError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_wrong_algorithm_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS512')

        with self.assertRaises(jwt.exceptions.InvalidAlgorithmError):
            Token.decode_token(token, issuer='test')

    def test_jwt_token_expired_exception(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=2)
        dt = now - datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS256')

        with self.assertRaises(jwt.exceptions.ExpiredSignatureError):
            Token.decode_token(token, issuer='test')

    def test_jwt_wrong_token_exception(self):
        with self.assertRaises(jwt.exceptions.DecodeError):
            Token.decode_token('wrong token', issuer='test')

    def test_jwt_proper_token(self):
        now = datetime.datetime.now()
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=2)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS256')

        self.assertNotEquals(Token.decode_token(token, issuer='test'), None)

    def test_jwt_proper_user_id(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=1)
        user_id = 1
        token = jwt.encode({
            'uid': user_id,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': 'test'
        }, settings.SECRET_KEY, algorithm='HS256')

        decoded = Token.decode_token(token, issuer='test')
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['uid'], user_id)

    @mock.patch('authentication.tokens.datetime')
    def test_jwt_access_proper_datetime(self, mocked_dt):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        mocked_dt.datetime.now.return_value = now

        token = AccessToken.encode({'uid': 1})
        decoded = AccessToken.decode(token)

        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['iat'], int(now.timestamp()))
        self.assertEqual(decoded['exp'], int((now + AccessToken.expire_time).timestamp()))

    @mock.patch('authentication.tokens.datetime')
    def test_jwt_refresh_proper_datetime(self, mocked_dt):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        mocked_dt.datetime.now.return_value = now

        token = RefreshToken.encode({'uid': 1})
        decoded = RefreshToken.decode(token)

        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['iat'], int(now.timestamp()))
        self.assertEqual(decoded['exp'], int((now + RefreshToken.expire_time).timestamp()))

    def test_jwt_refresh_proper_issuer(self):
        token = RefreshToken.encode({'uid': 1})
        decoded = RefreshToken.decode(token)

        self.assertIsNotNone(decoded)
        self.assertEqual(decoded['iss'], RefreshToken.issuer)

    def test_jwt_invalid_issuer(self):
        token = AccessToken.encode({'uid': 1})
        with self.assertRaises(jwt.exceptions.InvalidIssuerError):
            RefreshToken.decode(token)


class TestTokenAuth(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

        user2 = User(username='testuser2', email='test2@test.com')
        user2.set_password('testpassword2')
        user2.is_active = False
        user2.save()

    def test_authorization_no_header(self):
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_wrong_header(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Bearer ')
        response = client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_wrong_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Token wrong-token')
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_proper(self):
        token = AccessToken.encode({'uid': 1})
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_id'], 1)

    def test_authorization_expired_token(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now - datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_wrong_user(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 99,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Wrong user credentials')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_disabled_user(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 2,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'User is not active')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class TestCookieAuth(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

        user2 = User(username='testuser2', email='test2@test.com')
        user2.set_password('testpassword2')
        user2.is_active = False
        user2.save()

    def test_cookie_authorization_wrong_header(self):
        client = APIClient()
        token_cookie = cookies.SimpleCookie({'access_token': str(os.urandom(32))})
        self.client.cookies = token_cookie
        response = client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_proper(self):
        token = AccessToken.encode({'uid': 1})
        token_cookie = cookies.SimpleCookie({'access_token': token})
        self.client.cookies = token_cookie
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user_id'], 1)

    def test_authorization_expired_token(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        dt = now - datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 1,
            'exp': dt.timestamp(),
            'iat': now.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        token_cookie = cookies.SimpleCookie({'access_token': token})
        self.client.cookies = token_cookie
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Invalid token')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_wrong_user(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 99,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        token_cookie = cookies.SimpleCookie({'access_token': token})
        self.client.cookies = token_cookie
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'Wrong user credentials')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authorization_disabled_user(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        issued = now - datetime.timedelta(minutes=1)
        dt = now + datetime.timedelta(minutes=1)
        token = jwt.encode({
            'uid': 2,
            'exp': dt.timestamp(),
            'iat': issued.timestamp(),
            'jti': uuid.uuid4().hex,
            'iss': AccessToken.issuer
        }, settings.SECRET_KEY, algorithm='HS256')

        token_cookie = cookies.SimpleCookie({'access_token': token})
        self.client.cookies = token_cookie
        response = self.client.get(reverse('verify'))

        self.assertEqual(response.data['detail'], 'User is not active')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class TestCookieSecurity(APITestCase):
    def test_cookie_samesite_flag(self):
        # todo
        self.assertTrue(True)

    def test_cookie_secure_flag(self):
        # todo
        self.assertTrue(True)

    def test_refresh_cookie_specified_paths(self):
        # todo
        self.assertTrue(True)
