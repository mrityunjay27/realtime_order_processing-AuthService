from datetime import datetime, timezone

import jwt

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from accounts.services.tokens import decode_access_token, generate_access_token

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


class LoginEndpointTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from accounts.services.tokens import ensure_keypair

        ensure_keypair()

    def setUp(self):
        self.client = APIClient()
        self.login_url = "/api/auth/login/"
        self.user = User.objects.create_user(
            username="loginuser",
            password="loginpass123",
        )

    def test_login_success_returns_rs256_token(self):
        response = self.client.post(
            self.login_url,
            {"username": "loginuser", "password": "loginpass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["token_type"], "Bearer")
        self.assertIn("access_token", response.data)
        self.assertEqual(response.data["expires_in"], 900)

        header = jwt.get_unverified_header(response.data["access_token"])
        self.assertEqual(header["alg"], "RS256")

    def test_login_token_contains_required_claims(self):
        response = self.client.post(
            self.login_url,
            {"username": "loginuser", "password": "loginpass123"},
            format="json",
        )
        token = response.data["access_token"]
        claims = decode_access_token(token)

        self.assertEqual(claims["sub"], str(self.user.id))
        self.assertEqual(claims["username"], "loginuser")
        self.assertEqual(claims["role"], "USER")
        self.assertEqual(claims["token_type"], "access")
        self.assertEqual(claims["iss"], "auth-service-test")
        self.assertIn("jti", claims)
        self.assertIn("iat", claims)
        self.assertIn("exp", claims)

        exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        self.assertEqual(int((exp - iat).total_seconds()), 900)

    def test_login_wrong_password(self):
        response = self.client.post(
            self.login_url,
            {"username": "loginuser", "password": "wrongpass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["detail"], "Invalid username or password.")

    def test_login_unknown_username(self):
        response = self.client.post(
            self.login_url,
            {"username": "ghost", "password": "whatever123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_inactive_user_rejected(self):
        User.objects.filter(username="loginuser").update(is_active=False)
        response = self.client.post(
            self.login_url,
            {"username": "loginuser", "password": "loginpass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_missing_fields(self):
        response = self.client.post(self.login_url, {"username": "loginuser"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class AccessTokenTest(TestCase):
    def setUp(self):
        from accounts.services.tokens import ensure_keypair

        ensure_keypair()
        self.user = User.objects.create_user(
            username="tokenuser",
            password="tokenpass123",
            role=User.Role.ADMIN,
        )

    def test_generated_token_is_signed_with_rs256_and_verifies_with_public_key(self):
        token = generate_access_token(self.user)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")

        claims = decode_access_token(token)
        self.assertEqual(claims["username"], "tokenuser")
        self.assertEqual(claims["role"], "ADMIN")

    def test_decode_rejects_tampered_token(self):
        token = generate_access_token(self.user)
        header_b64, payload_b64, signature_b64 = token.split(".")
        tampered = f"{header_b64}.{payload_b64[:-4]}AAAA.{signature_b64}"
        with self.assertRaises(jwt.InvalidSignatureError):
            decode_access_token(tampered)

    def test_alg_confusion_attacks_rejected(self):
        from accounts.services.tokens import public_key

        with self.assertRaises(jwt.InvalidKeyError):
            jwt.encode(
                {"sub": str(self.user.id), "username": "tokenuser"},
                public_key(),
                algorithm="HS256",
            )

        attacker_signed = jwt.encode(
            {"sub": str(self.user.id), "username": "tokenuser"},
            "attacker-controlled-secret",
            algorithm="HS256",
        )
        with self.assertRaises(jwt.InvalidAlgorithmError):
            decode_access_token(attacker_signed)

    def test_expired_token_rejected(self):
        from datetime import timedelta

        from accounts.services.tokens import _private_key

        payload = {
            "sub": str(self.user.id),
            "username": "tokenuser",
            "role": "ADMIN",
            "token_type": "access",
            "iss": "auth-service-test",
            "exp": datetime.now(tz=timezone.utc) - timedelta(seconds=60),
        }
        expired = jwt.encode(payload, _private_key(), algorithm="RS256")
        with self.assertRaises(jwt.ExpiredSignatureError):
            decode_access_token(expired)
