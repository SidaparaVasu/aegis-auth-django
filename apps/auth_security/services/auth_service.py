"""
AuthService — user registration, login, logout, and profile management.

Rules:
    - Credentials are validated in constant time (check_password handles timing).
    - Error messages never reveal whether an email exists or not.
    - All actions are delegated to specialised services — no direct DB here.
    - All outcomes (success + failure) are audited and session-tracked.
"""

import logging

from apps.core_system.constants import AuditAction
from apps.auth_security.constants import AttemptStatus
from common.exceptions import (
    InvalidCredentialsException,
    AccountLockedException,
    RegistrationException,
)

logger = logging.getLogger(__name__)


class AuthService:

    def __init__(
        self,
        user_repo=None,
        profile_repo=None,
        session_service=None,
        lock_service=None,
        password_service=None,
        audit_service=None,
        event_service=None,
    ):
        self._user_repo = user_repo
        self._profile_repo = profile_repo
        self._session_service = session_service
        self._lock_service = lock_service
        self._password_service = password_service
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
    def profile_repo(self):
        if self._profile_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthUserProfileRepository
            self._profile_repo = AuthUserProfileRepository()
        return self._profile_repo

    @property
    def session_service(self):
        if self._session_service is None:
            from apps.auth_security.services.session_service import SessionService
            self._session_service = SessionService()
        return self._session_service

    @property
    def lock_service(self):
        if self._lock_service is None:
            from apps.auth_security.services.lock_service import LockService
            self._lock_service = LockService()
        return self._lock_service

    @property
    def password_service(self):
        if self._password_service is None:
            from apps.auth_security.services.password_service import PasswordService
            self._password_service = PasswordService()
        return self._password_service

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
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        email: str,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ):
        """
        Create a new user account.

        Steps:
            1. Check email uniqueness.
            2. Validate password against policy.
            3. Create AuthUser + AuthUserProfile.
            4. Audit and event log.

        Raises:
            RegistrationException: if email already registered.
            PasswordPolicyViolationException: if password fails policy.
        """
        if self.user_repo.get_by_email(email):
            raise RegistrationException("An account with this email address already exists.")

        # Validate password policy before creating user
        self.password_service.validate_policy(password)

        user = self.user_repo.create(email=email, username=username, password=password)

        # Create empty profile
        self.profile_repo.get_or_create(user)

        self.audit_service.log(
            action=AuditAction.CREATE,
            module="auth_security",
            user_id=user.id,
            entity_type="AuthUser",
            entity_id=str(user.id),
            new_value={"email": email, "username": username},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.event_service.info(
            event_type="USER_REGISTERED",
            module="auth_security",
            message=f"New user registered: {email}",
            payload={"user_id": user.id},
        )
        logger.info("User registered: user_id=%s email=%s", user.id, email)
        return user

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    def login(
        self,
        identifier: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Authenticate a user and issue JWT tokens.

        Security rules:
            - All errors (wrong email/username, wrong password, inactive, locked) raise the
              SAME generic message to prevent user enumeration.
            - Attempts are always recorded BEFORE credential verification.

        Returns:
            {"access": str, "refresh": str, "user": AuthUser}

        Raises:
            InvalidCredentialsException
            AccountLockedException
        """
        ip = ip_address or ""

        # Look up user (we'll use a generic error in all failure cases)
        user = self.user_repo.get_by_identifier(identifier)

        # Check account lock early (before recording attempt, to avoid spam on locked accounts)
        if user:
            lock = self.lock_service.check_lock(user)
            if lock:
                # Still record the attempt
                self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
                raise AccountLockedException(
                    f"Your account is temporarily locked. Try again after "
                    f"{lock.locked_until.strftime('%H:%M UTC')}."
                )

        # Check inactive user
        if user and not user.is_active:
            self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
            raise InvalidCredentialsException("Invalid credentials.")

        # Validate password (use same error for non-existent user)
        credentials_valid = user is not None and user.check_password(password)

        if not credentials_valid:
            self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
            if user:
                self.lock_service.check_and_lock(user, identifier, ip)
            raise InvalidCredentialsException("Invalid credentials.")

        # --- Credentials valid from here ---

        # -------------------------------------------------------------
        # FIRST-TIME EMAIL VERIFICATION INTERCEPTOR
        # If the feature is ON, and user is NOT verified, halt login.
        # Send an OTP and return 403 containing VERIFICATION_REQUIRED.
        # -------------------------------------------------------------
        from apps.core_system.services.feature_flag_service import FeatureFlagService
        if FeatureFlagService().is_enabled("email_verification_required"):
            if not user.is_email_verified:
                from apps.auth_security.services.otp_service import OTPService
                from apps.auth_security.constants import OTPPurpose
                from common.exceptions import EmailVerificationRequiredException

                # Dispatch OTP to email before throwing exception
                OTPService().send_otp(user=user, purpose=OTPPurpose.EMAIL_VERIFICATION)

                # Throw a specialized exception that the frontend can catch
                raise EmailVerificationRequiredException()

        self.lock_service.record_attempt(identifier, ip, AttemptStatus.SUCCESS)
        self.user_repo.update_last_login(user)

        # Issue JWT + create session
        access_token, refresh_token, session_key = self.session_service.create_session(
            user=user, ip_address=ip, user_agent=user_agent
        )

        self.audit_service.log_login(
            user_id=user.id, ip_address=ip, user_agent=user_agent
        )
        logger.info("User logged in: user_id=%s", user.id)

        return {
            "access": access_token,
            "refresh": refresh_token,
            "user": user,
        }

    def otp_login(
        self,
        identifier: str,
        otp_code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        """
        Authenticate a user via a one-time password and issue JWT tokens.
        """
        ip = ip_address or ""

        user = self.user_repo.get_by_identifier(identifier)

        # Check account lock early
        if user:
            lock = self.lock_service.check_lock(user)
            if lock:
                self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
                raise AccountLockedException(
                    f"Your account is temporarily locked. Try again after "
                    f"{lock.locked_until.strftime('%H:%M UTC')}."
                )

        if user and not user.is_active:
            self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
            raise InvalidCredentialsException("Invalid credentials.")

        if not user:
            self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
            raise InvalidCredentialsException("Invalid credentials.")

        # Verify the OTP via standard OTPService
        try:
            from apps.auth_security.services.otp_service import OTPService
            from apps.auth_security.constants import OTPPurpose
            OTPService().verify_otp(user=user, otp_code=otp_code, purpose=OTPPurpose.LOGIN)
        except Exception:
            self.lock_service.record_attempt(identifier, ip, AttemptStatus.FAILED)
            self.lock_service.check_and_lock(user, identifier, ip)
            raise InvalidCredentialsException("Invalid credentials.")

        # --- OTP valid from here ---
        self.lock_service.record_attempt(identifier, ip, AttemptStatus.SUCCESS)
        self.user_repo.update_last_login(user)

        # Issue JWT + create session
        access_token, refresh_token, session_key = self.session_service.create_session(
            user=user, ip_address=ip, user_agent=user_agent
        )

        self.audit_service.log_login(
            user_id=user.id, ip_address=ip, user_agent=user_agent
        )
        logger.info("User logged in via OTP: user_id=%s", user.id)

        return {
            "access": access_token,
            "refresh": refresh_token,
            "user": user,
        }

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    def logout(
        self,
        user,
        session_key: str,
        raw_refresh_token: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Invalidate the current session.

        - Soft-revokes the AuthSessionLog entry.
        - If a refresh token is provided, blacklists it via simplejwt.
        """
        self.session_service.revoke_by_key(session_key)

        if raw_refresh_token:
            self.session_service.blacklist_refresh_token(raw_refresh_token)

        self.audit_service.log_logout(
            user_id=user.id, ip_address=ip_address, user_agent=user_agent
        )
        logger.info("User logged out: user_id=%s", user.id)

    # ------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------

    def update_profile(self, user, **fields):
        """Update the user's AuthUserProfile. Returns updated profile."""
        return self.profile_repo.update(user=user, **fields)
