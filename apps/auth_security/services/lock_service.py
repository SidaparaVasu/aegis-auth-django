"""
LockService — brute-force detection and account locking.

Rules:
    - Record every login attempt (success AND failure) BEFORE credential check.
    - After MAX_LOGIN_ATTEMPTS failures within the lock window, lock the account.
    - Threshold values are read from SystemConfig — never hardcoded.
    - All lock/unlock events are audited.
"""

import logging
from datetime import timedelta
from django.utils import timezone

from apps.core_system.constants import AuditAction, ConfigKey
from apps.auth_security.constants import AttemptStatus

logger = logging.getLogger(__name__)


class LockService:

    def __init__(
        self,
        attempt_repo=None,
        lock_repo=None,
        config_service=None,
        audit_service=None,
        event_service=None,
    ):
        self._attempt_repo = attempt_repo
        self._lock_repo = lock_repo
        self._config_service = config_service
        self._audit_service = audit_service
        self._event_service = event_service

    # ------------------------------------------------------------------
    # Lazy dependency resolution
    # ------------------------------------------------------------------

    @property
    def attempt_repo(self):
        if self._attempt_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthLoginAttemptRepository
            self._attempt_repo = AuthLoginAttemptRepository()
        return self._attempt_repo

    @property
    def lock_repo(self):
        if self._lock_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthAccountLockRepository
            self._lock_repo = AuthAccountLockRepository()
        return self._lock_repo

    @property
    def config_service(self):
        if self._config_service is None:
            from apps.core_system.services.config_service import ConfigService
            self._config_service = ConfigService()
        return self._config_service

    @property
    def audit_service(self):
        if self._audit_service is None:
            from apps.core_system.services.audit_service import AuditService
            self._audit_service = AuditService()
        return self._audit_service

    @property
    def event_service(self):
        if self._event_service is None:
            from apps.core_system.services.event_service import EventService
            self._event_service = EventService()
        return self._event_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_attempt(self, email: str, ip_address: str, status: str) -> None:
        """Append a login attempt record. Call this before any credential check."""
        self.attempt_repo.record(email, ip_address, status)

    def check_lock(self, user) -> object | None:
        """Return the active AccountLock if the account is locked, else None."""
        return self.lock_repo.get_active_lock(user)

    def check_and_lock(self, user, email: str, ip_address: str) -> bool:
        """
        After a FAILED login attempt, count recent failures and lock if threshold exceeded.

        Reads thresholds from SystemConfig:
            MAX_LOGIN_ATTEMPTS            — failure count before lock
            ACCOUNT_LOCK_DURATION_MINUTES — lock duration and attempt window

        Returns True if the account was just locked.
        """
        try:
            max_attempts = self.config_service.get_config_int(ConfigKey.MAX_LOGIN_ATTEMPTS)
            lock_duration = self.config_service.get_config_int(ConfigKey.ACCOUNT_LOCK_DURATION_MINUTES)
        except Exception:
            # Fall back to safe defaults if config is unavailable
            max_attempts, lock_duration = 5, 30

        failed_count = self.attempt_repo.count_recent_failed(email, window_minutes=lock_duration)

        if failed_count >= max_attempts:
            locked_until = timezone.now() + timedelta(minutes=lock_duration)
            self.lock_repo.create_lock(
                user=user,
                locked_until=locked_until,
                reason=f"Locked after {failed_count} consecutive failed login attempts.",
            )

            self.audit_service.log(
                action=AuditAction.ACCOUNT_LOCK,
                module="auth_security",
                user_id=user.id,
                entity_type="AuthUser",
                entity_id=str(user.id),
                new_value={"reason": "Too many failed attempts", "count": failed_count},
                ip_address=ip_address,
            )
            self.event_service.warning(
                event_type="ACCOUNT_LOCKED",
                module="auth_security",
                message=f"Account {email} locked after {failed_count} failed attempts.",
                payload={"user_id": user.id, "locked_until": str(locked_until)},
            )
            logger.warning("Account locked: user_id=%s email=%s", user.id, email)
            return True

        return False

    def unlock_account(
        self,
        user,
        admin_user_id: int | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Manually unlock an account (admin action)."""
        self.lock_repo.delete_lock(user)
        self.audit_service.log(
            action=AuditAction.ACCOUNT_UNLOCK,
            module="auth_security",
            user_id=admin_user_id,
            entity_type="AuthUser",
            entity_id=str(user.id),
            ip_address=ip_address,
        )
        logger.info("Account unlocked: user_id=%s by admin=%s", user.id, admin_user_id)
