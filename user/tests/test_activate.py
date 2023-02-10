from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from authentication.tokens import AccessToken, RefreshToken

User = get_user_model()


class TestActivateAPI(APITestCase):
    def setUp(self):
        user = User(username='testuser', email='test@test.com')
        user.set_password('testpassword')
        user.is_active = False
        user.activation_code = User.generate_activation_code()
        user.save()

    def test_no_credentials(self):
        response = self.client.post(reverse('activate'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('token' in response.data.keys())

    def test_wrong_credentials(self):
        response = self.client.post(reverse('activate'), {'token': '000000'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('non_field_errors' in response.data.keys())

    def test_too_short_credentials(self):
        response = self.client.post(reverse('activate'), {'token': '000'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('non_field_errors' in response.data.keys())

    def test_activate_ok(self):
        u = User.objects.all().first()
        response = self.client.post(reverse('activate'), {'token': u.activation_code})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        u = User.objects.all().first()
        self.assertEqual(response.data['uid'], 1)
        self.assertTrue(u.is_active)

    def test_already_activated(self):
        u = User.objects.all().first()
        u.is_active = True
        u.save()

        response = self.client.post(reverse('activate'), {'token': u.activation_code})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('non_field_errors' in response.data.keys())
