"""
Tests for OTPService — generation, delivery, and verification.
"""

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from datetime import timedelta
from apps.auth_security.services.otp_service import OTPService
from apps.auth_security.models import AuthOTPVerification
from apps.auth_security.constants import OTPPurpose
from common.exceptions import OTPInvalidException, FeatureDisabledException

User = get_user_model()


class OTPTest(TestCase):

    def setUp(self):
        self.service = OTPService()
        self.user = User.objects.create_user(
            email="otp@example.com",
            username="otpuser",
            password="Password123!"
        )

    def test_send_otp_success(self):
        """Sending OTP creates a record and sends an email."""
        # Note: 'otp_login' feature flag must be enabled or mock it.
        # For tests, we'll assume flags are handled or use override_settings if needed.
        # But our FeatureFlagService reads from DB.
        
        # Ensure feature flag 'otp_login' is ON for testing LOGIN purpose
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="otp_login", is_enabled=True)

        self.service.send_otp(self.user, OTPPurpose.LOGIN)

        # Verify DB record
        otp = AuthOTPVerification.objects.get(user=self.user)
        self.assertEqual(otp.purpose, OTPPurpose.LOGIN)
        self.assertFalse(otp.is_verified)
        self.assertEqual(len(otp.otp_code), 6)

        # Verify email sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(otp.otp_code, mail.outbox[0].body)

    def test_verify_otp_success(self):
        """Correct OTP code results in success and consumes the OTP."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="otp_login", is_enabled=True)
        
        self.service.send_otp(self.user, OTPPurpose.LOGIN)
        otp_record = AuthOTPVerification.objects.get(user=self.user)

        is_valid = self.service.verify_otp(self.user, otp_record.otp_code, OTPPurpose.LOGIN)
        self.assertTrue(is_valid)

        # Verify consumed
        otp_record.refresh_from_db()
        self.assertTrue(otp_record.is_verified)

    def test_verify_otp_invalid_raises_error(self):
        """Wrong OTP code raises OTPInvalidException."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="otp_login", is_enabled=True)
        
        self.service.send_otp(self.user, OTPPurpose.LOGIN)
        
        with self.assertRaises(OTPInvalidException):
            self.service.verify_otp(self.user, "000000", OTPPurpose.LOGIN)

    def test_verify_otp_expired_raises_error(self):
        """Expired OTP code raises OTPInvalidException."""
        otp = AuthOTPVerification.objects.create(
            user=self.user,
            email=self.user.email,
            otp_code="123456",
            purpose=OTPPurpose.LOGIN,
            expires_at=timezone.now() - timedelta(minutes=1)
        )

        with self.assertRaises(OTPInvalidException):
            self.service.verify_otp(self.user, "123456", OTPPurpose.LOGIN)

    def test_otp_single_use(self):
        """OTP cannot be used twice."""
        otp = AuthOTPVerification.objects.create(
            user=self.user,
            email=self.user.email,
            otp_code="123456",
            purpose=OTPPurpose.LOGIN,
            expires_at=timezone.now() + timedelta(minutes=5)
        )

        # Use once
        self.service.verify_otp(self.user, "123456", OTPPurpose.LOGIN)

        # Use again
        with self.assertRaises(OTPInvalidException):
            self.service.verify_otp(self.user, "123456", OTPPurpose.LOGIN)

    def test_otp_purpose_mismatch(self):
        """Password Reset OTP cannot be used for Login."""
        otp = AuthOTPVerification.objects.create(
            user=self.user,
            email=self.user.email,
            otp_code="123456",
            purpose=OTPPurpose.PASSWORD_RESET,
            expires_at=timezone.now() + timedelta(minutes=5)
        )

        with self.assertRaises(OTPInvalidException):
            self.service.verify_otp(self.user, "123456", OTPPurpose.LOGIN)
