"""
PasswordService — password validation, change, and reset.

Rules:
    - All complexity rules are read from AuthPasswordPolicy — never hardcoded.
    - Password history is checked before every change/reset.
    - Old password hash is saved to AuthPasswordHistory on every change.
    - After a reset, ALL active sessions are revoked.
    - Audit log created on every change/reset.
    - Sensitive values (hashes) must never appear in logs.
"""

import re
import logging

from django.contrib.auth.hashers import check_password

from apps.auth_security.constants import PasswordPolicyKey
from apps.core_system.constants import AuditAction, ConfigKey
from common.exceptions import (
    InvalidCredentialsException,
    PasswordPolicyViolationException,
    PasswordReuseException,
)

logger = logging.getLogger(__name__)


class PasswordService:

    def __init__(
        self,
        user_repo=None,
        history_repo=None,
        policy_repo=None,
        session_service=None,
        config_service=None,
        audit_service=None,
        event_service=None,
    ):
        self._user_repo = user_repo
        self._history_repo = history_repo
        self._policy_repo = policy_repo
        self._session_service = session_service
        self._config_service = config_service
        self._audit_service = audit_service
        self._event_service = event_service

    # ------------------------------------------------------------------
    # Lazy dependency resolution
    # ------------------------------------------------------------------

    @property
    def user_repo(self):
        if self._user_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthUserRepository
            self._user_repo = AuthUserRepository()
        return self._user_repo

    @property
    def history_repo(self):
        if self._history_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthPasswordHistoryRepository
            self._history_repo = AuthPasswordHistoryRepository()
        return self._history_repo

    @property
    def policy_repo(self):
        if self._policy_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthPasswordPolicyRepository
            self._policy_repo = AuthPasswordPolicyRepository()
        return self._policy_repo

    @property
    def session_service(self):
        if self._session_service is None:
            from apps.auth_security.services.session_service import SessionService
            self._session_service = SessionService()
        return self._session_service

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

    def change_password(
        self,
        user,
        old_password: str,
        new_password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Authenticated password change (user knows current password).

        Steps:
            1. Verify old password.
            2. Validate new password against AuthPasswordPolicy.
            3. Check password history (no reuse of last N passwords).
            4. Save old hash to AuthPasswordHistory.
            5. Set new password.
            6. Audit log.
        """
        if not user.check_password(old_password):
            raise InvalidCredentialsException("Current password is incorrect.")

        self.validate_policy(new_password)
        self._check_history(user, new_password)

        # Save current hash to history BEFORE overwriting
        self.history_repo.add(user=user, password_hash=user.password)

        self.user_repo.update_password(user, new_password)

        self.audit_service.log_password_change(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        logger.info("Password changed: user_id=%s", user.id)

    def reset_password(
        self,
        user,
        new_password: str,
        revoke_all_sessions: bool = True,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Unauthenticated password reset (OTP already verified by caller).

        Steps:
            1. Validate new password against AuthPasswordPolicy.
            2. Check password history.
            3. Save old hash to history.
            4. Set new password.
            5. Revoke all active sessions (security: device-loss scenario).
            6. Audit log.
        """
        self.validate_policy(new_password)
        self._check_history(user, new_password)

        self.history_repo.add(user=user, password_hash=user.password)
        self.user_repo.update_password(user, new_password)

        if revoke_all_sessions:
            revoked = self.session_service.revoke_all_sessions(user)
            logger.info(
                "Password reset: %d sessions revoked for user_id=%s", revoked, user.id
            )

        self.audit_service.log_password_change(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        logger.info("Password reset: user_id=%s", user.id)

    def validate_policy(self, password: str) -> None:
        """
        Validate a plain-text password against all active AuthPasswordPolicy rules.

        Raises:
            PasswordPolicyViolationException: with a list of all violated rules.
        """
        policies = self.policy_repo.get_all_active()
        errors = []

        for policy in policies:
            key = policy.policy_key
            value = policy.policy_value.strip()

            if key == PasswordPolicyKey.MIN_LENGTH:
                try:
                    min_len = int(value)
                    if len(password) < min_len:
                        errors.append(f"Password must be at least {min_len} characters.")
                except ValueError:
                    pass

            elif key == PasswordPolicyKey.REQUIRE_UPPERCASE and value.lower() == "true":
                if not re.search(r"[A-Z]", password):
                    errors.append("Password must contain at least one uppercase letter (A-Z).")

            elif key == PasswordPolicyKey.REQUIRE_LOWERCASE and value.lower() == "true":
                if not re.search(r"[a-z]", password):
                    errors.append("Password must contain at least one lowercase letter (a-z).")

            elif key == PasswordPolicyKey.REQUIRE_DIGITS and value.lower() == "true":
                if not re.search(r"\d", password):
                    errors.append("Password must contain at least one digit (0-9).")

            elif key == PasswordPolicyKey.REQUIRE_SPECIAL and value.lower() == "true":
                if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
                    errors.append("Password must contain at least one special character.")

        if errors:
            raise PasswordPolicyViolationException(" | ".join(errors))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_history(self, user, new_password: str) -> None:
        """
        Reject new_password if it matches any of the last N historical hashes.

        Raises:
            PasswordReuseException: if the new password was recently used.
        """
        try:
            history_count = self.config_service.get_config_int(ConfigKey.PASSWORD_HISTORY_COUNT)
        except Exception:
            history_count = 5

        recent_hashes = self.history_repo.get_recent(user, history_count)
        for entry in recent_hashes:
            if check_password(new_password, entry.password_hash):
                raise PasswordReuseException(
                    f"You cannot reuse any of your last {history_count} passwords."
                )
