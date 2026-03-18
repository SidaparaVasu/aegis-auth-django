"""
Tests for AuthService.login and related securities.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.auth_security.services.auth_service import AuthService
from apps.auth_security.models import AuthLoginAttempt, AuthSessionLog, AuthAccountLock
from apps.auth_security.constants import AttemptStatus
from common.exceptions import InvalidCredentialsException, AccountLockedException
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


class LoginTest(TestCase):

    def setUp(self):
        self.service = AuthService()
        self.email = "test@example.com"
        self.password = "SecurePassword123!"
        self.user = User.objects.create_user(
            email=self.email,
            username="testuser",
            password=self.password
        )

    def test_login_success(self):
        """Successful login issues tokens and records attempt/session."""
        result = self.service.login(identifier=self.email, password=self.password, ip_address="127.0.0.1")

        self.assertIn("access", result)
        self.assertIn("refresh", result)
        self.assertEqual(result["user"], self.user)

        # Verify attempt recorded
        attempt = AuthLoginAttempt.objects.get(email=self.email)
        self.assertEqual(attempt.attempt_status, AttemptStatus.SUCCESS)

        # Verify session record
        session = AuthSessionLog.objects.get(user=self.user)
        self.assertTrue(session.is_active)
        self.assertEqual(session.ip_address, "127.0.0.1")

    def test_login_wrong_password_records_failure(self):
        """Wrong password raises correct error and records failure."""
        with self.assertRaises(InvalidCredentialsException):
            self.service.login(identifier=self.email, password="wrongpassword", ip_address="1.2.3.4")

        attempt = AuthLoginAttempt.objects.get(email=self.email)
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)
        self.assertEqual(attempt.ip_address, "1.2.3.4")

    def test_login_nonexistent_user_generic_error(self):
        """Login with unknown email raises generic error (no enumeration)."""
        with self.assertRaises(InvalidCredentialsException) as cm:
            self.service.login(identifier="unknown@example.com", password="any", ip_address="1.1.1.1")

        self.assertEqual(str(cm.exception), "Invalid credentials.")
        
        # Still record attempt for unknown email
        attempt = AuthLoginAttempt.objects.get(email="unknown@example.com")
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)

    def test_login_inactive_user_blocked(self):
        """Inactive users cannot log in."""
        self.user.is_active = False
        self.user.save()

        with self.assertRaises(InvalidCredentialsException):
            self.service.login(identifier=self.email, password=self.password)

        attempt = AuthLoginAttempt.objects.filter(email=self.email).last()
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)

    def test_logout_invalidates_session(self):
        """Logout marks session as inactive."""
        login_res = self.service.login(identifier=self.email, password=self.password)
        session_key = login_res["access"] # This is just a string in mock, but AuthService issues real tokens

        # Actually, in create_session (session_service), the session_key is access['jti']
        # Let's find the record
        session = AuthSessionLog.objects.get(user=self.user, is_active=True)
        
        self.service.logout(self.user, session.session_key)
        
        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertIsNotNone(session.logout_at)

    def test_login_with_username_success(self):
        """Service resolves user correctly when identifier is the username."""
        result = self.service.login(identifier="testuser", password=self.password)
        self.assertEqual(result["user"], self.user)

    def test_login_email_case_insensitive(self):
        """Service resolves user correctly even if email has mixed casing."""
        result = self.service.login(identifier="TEST@EXAMPLE.com", password=self.password)
        self.assertEqual(result["user"], self.user)

    def test_login_identifier_strip_whitespace(self):
        """Service handles identifiers with leading/trailing whitespace."""
        result = self.service.login(identifier="  testuser  ", password=self.password)
        self.assertEqual(result["user"], self.user)

    # ------------------------------------------------------------------
    # Email Verification Interceptor Tests
    # ------------------------------------------------------------------

    def test_verified_user_bypasses_interceptor(self):
        """Users with is_email_verified=True log in without interruption."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="email_verification_required", is_enabled=True)
        
        self.user.is_email_verified = True
        self.user.save()

        result = self.service.login(identifier=self.email, password=self.password)
        self.assertIn("access", result)

    def test_unverified_user_triggers_interceptor(self):
        """Unverified users are blocked and sent an OTP when feature is ON."""
        from apps.core_system.models import FeatureFlag
        from common.exceptions import EmailVerificationRequiredException
        from django.core import mail
        
        FeatureFlag.objects.create(feature_key="email_verification_required", is_enabled=True)
        
        # self.user.is_email_verified is False by default
        with self.assertRaises(EmailVerificationRequiredException):
            self.service.login(identifier=self.email, password=self.password)

        # Verify OTP was sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Email Verification OTP", mail.outbox[0].subject)

    def test_unverified_user_with_flag_off_succeeds(self):
        """Unverified users can log in if the feature flag is OFF."""
        from apps.core_system.models import FeatureFlag
        FeatureFlag.objects.create(feature_key="email_verification_required", is_enabled=False)

        result = self.service.login(identifier=self.email, password=self.password)
        self.assertIn("access", result)


