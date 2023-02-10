import datetime
from unittest import mock

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core import mail
from django.urls import reverse
from django.utils.timezone import make_aware
from rest_framework import status
from rest_framework.test import APITestCase

from user.models import ResetPasswordToken

User = get_user_model()


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


class TestPasswordResetEmail(APITestCase):

    def setUp(self) -> None:
        settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.save()

        mail.outbox = []

    @mock.patch('user.models.send_password_reset_email')
    def test_password_reset_email_send_func_called(self, mock_send_email_func):
        response = self.client.post(reverse('password_reset_request'), {'email': 'test@test.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # check proper api return
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(mock_send_email_func.called)

    def test_password_reset_email_send_memory(self):
        response = self.client.post(reverse('password_reset_request'), {'email': 'test@test.com'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # check proper api return
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

        # check sent email
        u = User.objects.all().first()
        t = u.password_reset_tokens.first()

        email = mail.outbox[0]
        self.assertTrue(t.token in email.body)
        self.assertEqual(email.to, [u.email])
