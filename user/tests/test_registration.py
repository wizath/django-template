from unittest import mock
from django.core import mail

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


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

        # check proper api return
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], username)
        self.assertEqual(response.data['email'], email)

        # check db object
        u = User.objects.filter(username=username).first()
        self.assertEqual(u.username, username)
        self.assertEqual(u.email, email)
        self.assertTrue(check_password(password, u.password))


class TestRegistrationEmail(APITestCase):

    def setUp(self) -> None:
        settings.EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

    @mock.patch('user.models.send_activation_email')
    def test_registration_email_send_func_called(self, mock_send_email_func):
        username = 'test'
        password = 'test1234'
        email = 'test11@test.com'
        response = self.client.post(reverse('register'), {
            'username': username,
            'password': password,
            'email': email
        })

        # check proper api return
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(mock_send_email_func.called)

    def test_registration_email_send_memory(self):
        username = 'test'
        password = 'test1234'
        email = 'test11@test.com'
        response = self.client.post(reverse('register'), {
            'username': username,
            'password': password,
            'email': email
        })

        # check proper api return
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(len(mail.outbox), 1)

        # check sent email
        u = User.objects.all().first()
        email = mail.outbox[0]
        self.assertTrue(u.activation_code in email.body)
        self.assertEqual(email.to, [u.email])
