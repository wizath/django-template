from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase

from authentication.tokens import AccessToken, RefreshToken

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
        self.assertEqual(response.status_code, 400)
        self.assertTrue('username' in response.data.keys())
        self.assertTrue('password' in response.data.keys())

    def test_wrong_credentials(self):
        response = self.client.post(reverse('login'), {'username': 'wrong', 'password': 'wrong'})

        self.assertEqual(response.status_code, 400)
        self.assertTrue('non_field_errors' in response.data.keys())

    def test_login_ok(self):
        response = self.client.post(reverse('login'), {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, 200)

        self.assertEqual(response.data['uid'], 1)
        self.assertTrue('access_token' in response.data.keys())
        self.assertTrue('refresh_token' in response.data.keys())

        access_token = response.data['access_token']
        self.assertNotEqual(AccessToken.decode(access_token), None)
        refresh_token = response.data['refresh_token']
        self.assertNotEqual(RefreshToken.decode(refresh_token), None)
