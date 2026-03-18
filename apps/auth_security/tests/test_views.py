from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthViewsTest(APITestCase):

    def setUp(self):
        from django.core.cache import cache
        cache.clear()

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

    # ------------------------------------------------------------------
    # OTP-Only Login Tests (Chunk E)
    # ------------------------------------------------------------------

    def test_otp_login_flow_success(self):
        """Standard path: Request OTP -> Confirm OTP -> Get Tokens."""
        from apps.core_system.models import FeatureFlag
        from apps.auth_security.models import AuthOTPVerification
        from apps.auth_security.constants import OTPPurpose
        
        FeatureFlag.objects.create(feature_key="otp_login", is_enabled=True)

        # 1. Request OTP
        req_url = reverse("auth_security:otp_login_request")
        res_req = self.client.post(req_url, {"identifier": self.email})
        self.assertEqual(res_req.status_code, status.HTTP_200_OK)

        # 2. Extract OTP from DB
        otp_record = AuthOTPVerification.objects.get(user=self.user, purpose=OTPPurpose.LOGIN)

        # 3. Confirm OTP
        conf_url = reverse("auth_security:otp_login_confirm")
        res_conf = self.client.post(conf_url, {
            "identifier": self.email,
            "otp_code": otp_record.otp_code
        })

        self.assertEqual(res_conf.status_code, status.HTTP_200_OK)
        self.assertIn("access", res_conf.data["data"])
        self.assertIn("refresh", res_conf.data["data"])
        self.assertEqual(res_conf.data["data"]["user"]["email"], self.email)

    def test_otp_login_confirm_wrong_otp_returns_401(self):
        """Invalid OTP in confirmed step returns generic 401."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="otp_login", is_enabled=True)

        conf_url = reverse("auth_security:otp_login_confirm")
        response = self.client.post(conf_url, {
            "identifier": self.email,
            "otp_code": "000000"
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data["message"], "Invalid credentials.")

    def test_otp_login_request_is_vague_for_unknown_user(self):
        """Security: Don't reveal if user exists in Step 1."""
        req_url = reverse("auth_security:otp_login_request")
        response = self.client.post(req_url, {"identifier": "ghost@shadow.com"})

        # Should return 200 with generic success message
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("If a matching account exists", response.data["message"])

    def test_otp_login_confirm_locked_account_blocked(self):
        """Locked users are blocked even if they have a valid OTP."""
        from apps.auth_security.models import AuthAccountLock
        from django.utils import timezone
        from datetime import timedelta
        
        # Lock the user
        AuthAccountLock.objects.create(
            user=self.user,
            locked_until=timezone.now() + timedelta(hours=1)
        )

        conf_url = reverse("auth_security:otp_login_confirm")
        response = self.client.post(conf_url, {
            "identifier": self.email,
            "otp_code": "any"
        })

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("temporarily locked", response.data["message"])


