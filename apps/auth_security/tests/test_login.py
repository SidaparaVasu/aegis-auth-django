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
        result = self.service.login(self.email, self.password, ip_address="127.0.0.1")

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
            self.service.login(self.email, "wrongpassword", ip_address="1.2.3.4")

        attempt = AuthLoginAttempt.objects.get(email=self.email)
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)
        self.assertEqual(attempt.ip_address, "1.2.3.4")

    def test_login_nonexistent_user_generic_error(self):
        """Login with unknown email raises generic error (no enumeration)."""
        with self.assertRaises(InvalidCredentialsException) as cm:
            self.service.login("unknown@example.com", "any", ip_address="1.1.1.1")

        self.assertEqual(str(cm.exception), "Invalid email or password.")
        
        # Still record attempt for unknown email
        attempt = AuthLoginAttempt.objects.get(email="unknown@example.com")
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)

    def test_login_inactive_user_blocked(self):
        """Inactive users cannot log in."""
        self.user.is_active = False
        self.user.save()

        with self.assertRaises(InvalidCredentialsException):
            self.service.login(self.email, self.password)

        attempt = AuthLoginAttempt.objects.filter(email=self.email).last()
        self.assertEqual(attempt.attempt_status, AttemptStatus.FAILED)

    def test_logout_invalidates_session(self):
        """Logout marks session as inactive."""
        login_res = self.service.login(self.email, self.password)
        session_key = login_res["access"] # This is just a string in mock, but AuthService issues real tokens

        # Actually, in create_session (session_service), the session_key is access['jti']
        # Let's find the record
        session = AuthSessionLog.objects.get(user=self.user, is_active=True)
        
        self.service.logout(self.user, session.session_key)
        
        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertIsNotNone(session.logout_at)
