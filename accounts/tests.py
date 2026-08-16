from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


class UserModelTest(TestCase):
    def test_create_user_with_hashed_password(self):
        user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.assertEqual(user.username, "testuser")
        self.assertTrue(user.check_password("testpass123"))
        self.assertNotEqual(user.password, "testpass123")
        self.assertTrue(user.password.startswith("pbkdf2_sha256$"))

    def test_user_role_defaults_to_user(self):
        user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.assertEqual(user.role, "USER")

    def test_user_str_representation(self):
        user = User.objects.create_user(
            username="testuser",
            password="testpass123",
        )
        self.assertEqual(str(user), "testuser")


class RegisterEndpointTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = "/api/auth/register/"

    def test_register_user_success(self):
        data = {
            "username": "newuser",
            "password": "securepass123",
            "first_name": "John",
            "last_name": "Doe",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["username"], "newuser")
        self.assertEqual(response.data["first_name"], "John")
        self.assertEqual(response.data["last_name"], "Doe")
        self.assertEqual(response.data["role"], "USER")
        self.assertNotIn("password", response.data)

        user = User.objects.get(username="newuser")
        self.assertTrue(user.check_password("securepass123"))
        self.assertFalse(User.objects.filter(password="securepass123").exists())

    def test_register_user_duplicate_username(self):
        User.objects.create_user(username="existing", password="pass12345")
        data = {
            "username": "existing",
            "password": "anotherpass",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_user_short_password(self):
        data = {
            "username": "shortpass",
            "password": "1234567",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_user_missing_fields(self):
        data = {"username": "nousername"}
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_user_password_never_stored_plaintext(self):
        data = {
            "username": "hashtest",
            "password": "mypassword",
        }
        self.client.post(self.register_url, data, format="json")
        user = User.objects.get(username="hashtest")
        self.assertNotEqual(user.password, "mypassword")
        self.assertIn("$", user.password)
