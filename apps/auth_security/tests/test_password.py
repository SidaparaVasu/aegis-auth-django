"""
Tests for PasswordService — policies, history, and change/reset.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.auth_security.services.password_service import PasswordService
from apps.auth_security.models import AuthPasswordPolicy, AuthPasswordHistory
from apps.auth_security.constants import PasswordPolicyKey
from common.exceptions import (
    PasswordPolicyViolationException,
    PasswordReuseException,
    InvalidCredentialsException
)

User = get_user_model()


class PasswordTest(TestCase):

    def setUp(self):
        self.service = PasswordService()
        self.user = User.objects.create_user(
            email="pw@example.com",
            username="pwuser",
            password="OldPassword123!"
        )
        # Seed basic policies
        AuthPasswordPolicy.objects.create(
            policy_key=PasswordPolicyKey.MIN_LENGTH, policy_value="8"
        )
        AuthPasswordPolicy.objects.create(
            policy_key=PasswordPolicyKey.REQUIRE_UPPERCASE, policy_value="true"
        )
        AuthPasswordPolicy.objects.create(
            policy_key=PasswordPolicyKey.REQUIRE_DIGITS, policy_value="true"
        )

    def test_policy_validation_failure(self):
        """Short or weak password raises PasswordPolicyViolationException."""
        # Too short
        with self.assertRaises(PasswordPolicyViolationException) as cm:
            self.service.validate_policy("short1")
        self.assertIn("at least 8 characters", str(cm.exception))

        # No digits
        with self.assertRaises(PasswordPolicyViolationException) as cm:
            self.service.validate_policy("NoDigitsHere")
        self.assertIn("at least one digit", str(cm.exception))

        # No uppercase
        with self.assertRaises(PasswordPolicyViolationException) as cm:
            self.service.validate_policy("nouppercase1")
        self.assertIn("at least one uppercase letter", str(cm.exception))

    def test_password_change_success(self):
        """Changing password updates user hash and saves to history."""
        new_pw = "NewPassword456!"
        self.service.change_password(self.user, "OldPassword123!", new_pw)

        # Verify password changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_pw))

        # Verify history entry created
        history = AuthPasswordHistory.objects.get(user=self.user)
        self.assertTrue(self.user.check_password(new_pw)) # Current hash is NOT in history yet
        # Actually, history stores the OLD hash
        from django.contrib.auth.hashers import check_password
        self.assertTrue(check_password("OldPassword123!", history.password_hash))

    def test_password_reuse_blocked(self):
        """Reusing a recent password raises PasswordReuseException."""
        # Mock history record
        AuthPasswordHistory.objects.create(
            user=self.user,
            password_hash=self.user.password # old hash
        )

        with self.assertRaises(PasswordReuseException):
            # Change password to the SAME thing that's in history
            self.service.change_password(self.user, "OldPassword123!", "OldPassword123!")

    def test_change_password_wrong_old_password(self):
        """Wrong current password raises InvalidCredentialsException."""
        with self.assertRaises(InvalidCredentialsException):
            self.service.change_password(self.user, "wrongcurrent", "NewPassword123!")

    def test_reset_password_revokes_sessions(self):
        """Resetting password (unauthenticated) revokes all sessions."""
        # Create a session
        from apps.auth_security.models import AuthSessionLog
        AuthSessionLog.objects.create(user=self.user, session_key="s1", ip_address="1.1.1.1", is_active=True)
        
        self.service.reset_password(self.user, "ResetPassword789!")
        
        self.assertEqual(AuthSessionLog.objects.filter(user=self.user, is_active=True).count(), 0)
