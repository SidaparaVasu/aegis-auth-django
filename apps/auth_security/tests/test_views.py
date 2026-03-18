from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthViewsTest(APITestCase):

    def setUp(self):
        self.email = "viewtest@example.com"
        self.username = "viewuser"
        self.password = "SecurePassword123!"
        self.user = User.objects.create_user(
            email=self.email,
            username=self.username,
            password=self.password
        )
        self.login_url = reverse("auth_security:login")

    def test_login_api_with_email_success(self):
        """API accepts 'identifier' as email."""
        data = {"identifier": self.email, "password": self.password}
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data["data"])
        self.assertEqual(response.data["data"]["user"]["email"], self.email)

    def test_login_api_with_username_success(self):
        """API accepts 'identifier' as username."""
        data = {"identifier": self.username, "password": self.password}
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data["data"])
        self.assertEqual(response.data["data"]["user"]["username"], self.username)

    def test_login_api_identifier_required(self):
        """API returns 400 if 'identifier' is missing from payload."""
        data = {"password": self.password}
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("identifier", response.data["errors"])

    def test_login_api_invalid_credentials(self):
        """API returns 401 for wrong password."""
        data = {"identifier": self.email, "password": "wrong"}
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["message"], "Invalid credentials.")

    def test_login_api_verification_required(self):
        """API returns 403 with code='VERIFICATION_REQUIRED' if email not verified."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="email_verification_required", is_enabled=True)

        data = {"identifier": self.email, "password": self.password}
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "VERIFICATION_REQUIRED")

