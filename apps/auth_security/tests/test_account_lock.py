"""
Tests for LockService — brute-force detection and account locking.
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from apps.auth_security.services.lock_service import LockService
from apps.auth_security.services.auth_service import AuthService
from apps.auth_security.models import AuthLoginAttempt, AuthAccountLock
from apps.auth_security.constants import AttemptStatus
from apps.core_system.models import SystemConfig
from apps.core_system.constants import ConfigKey
from common.exceptions import AccountLockedException, InvalidCredentialsException

User = get_user_model()


class AccountLockTest(TestCase):

    def setUp(self):
        self.lock_service = LockService()
        self.auth_service = AuthService()
        self.email = "lock@example.com"
        self.password = "Password123!"
        self.user = User.objects.create_user(
            email=self.email,
            username="lockuser",
            password=self.password
        )
        # Set threshold to 3 for faster testing
        SystemConfig.objects.create(
            config_key=ConfigKey.MAX_LOGIN_ATTEMPTS,
            config_value="3",
            value_type="integer"
        )
        SystemConfig.objects.create(
            config_key=ConfigKey.ACCOUNT_LOCK_DURATION_MINUTES,
            config_value="30",
            value_type="integer"
        )

    def test_account_locks_after_threshold(self):
        """Failed attempts trigger a lock record when threshold is reached."""
        # 1st fail
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong1")
        
        # 2nd fail
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong2")

        # 3rd fail — this should trigger the LOCK
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong3")

        # Verify lock exists
        self.assertTrue(AuthAccountLock.objects.filter(user=self.user).exists())
        
        # 4th attempt — should raise AccountLockedException even with CORRECT password
        with self.assertRaises(AccountLockedException) as cm:
            self.auth_service.login(self.email, self.password)
        self.assertIn("temporarily locked", str(cm.exception))

    def test_lock_expires(self):
        """Account is accessible again once the lock expires."""
        # Manually create an expired lock
        AuthAccountLock.objects.create(
            user=self.user,
            locked_until=timezone.now() - timedelta(minutes=1),
            reason="Brute force"
        )

        # Login should now work (LockService.check_lock deletes expired locks)
        result = self.auth_service.login(self.email, self.password)
        self.assertIn("access", result)
        self.assertFalse(AuthAccountLock.objects.filter(user=self.user).exists())

    def test_successful_login_resets_failures(self):
        """A successful login prevents a lock from previous failures."""
        # 2 failed attempts
        self.auth_service.record_attempt = True # internal, auth_service.login calls lock_service.record_attempt
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong1")
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong2")
        
        # 1 successful login
        self.auth_service.login(self.email, self.password)

        # 1 more failure — total fails is 3 but non-consecutive
        # Wait, the rule is usually 'recent' failures within a window OR since last success.
        # Our LockService logic: count(status=FAILED) where attempt_time > last_success_time.
        
        with self.assertRaises(InvalidCredentialsException):
            self.auth_service.login(self.email, "wrong3")

        # Threshold is 3, but only 1 failure happened after the last success. So no lock.
        self.assertFalse(AuthAccountLock.objects.filter(user=self.user).exists())
