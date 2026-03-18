"""
auth_security repository layer.

The ONLY place in auth_security allowed to query models directly.
All services must call these repositories — no direct ORM in services or views.
"""

from datetime import timedelta
from django.db import transaction
from django.utils import timezone

from apps.auth_security.models import (
    AuthUser,
    AuthUserProfile,
    AuthPasswordHistory,
    AuthOTPVerification,
    AuthSessionLog,
    AuthLoginAttempt,
    AuthAccountLock,
    AuthPasswordPolicy,
)
from apps.auth_security.constants import AttemptStatus


# ---------------------------------------------------------------------------
# AuthUser
# ---------------------------------------------------------------------------

class AuthUserRepository:

    def get_by_email(self, email: str) -> AuthUser | None:
        try:
            return AuthUser.objects.get(email=email.lower().strip())
        except AuthUser.DoesNotExist:
            return None

    def get_by_id(self, user_id: int) -> AuthUser | None:
        try:
            return AuthUser.objects.get(pk=user_id)
        except AuthUser.DoesNotExist:
            return None

    @transaction.atomic
    def create(self, email: str, username: str, password: str, **extra_fields) -> AuthUser:
        return AuthUser.objects.create_user(
            email=email, username=username, password=password, **extra_fields
        )

    def update_last_login(self, user: AuthUser) -> None:
        AuthUser.objects.filter(pk=user.pk).update(last_login=timezone.now())

    def update_password(self, user: AuthUser, raw_password: str) -> None:
        """Hash and save a new password using Django's hashing (argon2)."""
        user.set_password(raw_password)
        user.save(update_fields=["password", "updated_at"])


# ---------------------------------------------------------------------------
# AuthUserProfile
# ---------------------------------------------------------------------------

class AuthUserProfileRepository:

    def get_or_create(self, user: AuthUser) -> tuple[AuthUserProfile, bool]:
        return AuthUserProfile.objects.get_or_create(user=user)

    def update(self, user: AuthUser, **fields) -> AuthUserProfile:
        allowed = {
            "first_name", "last_name", "phone_number",
            "profile_image_url", "date_of_birth", "gender",
        }
        safe = {k: v for k, v in fields.items() if k in allowed}
        AuthUserProfile.objects.filter(user=user).update(**safe)
        return AuthUserProfile.objects.get(user=user)


# ---------------------------------------------------------------------------
# AuthSessionLog
# ---------------------------------------------------------------------------

class AuthSessionRepository:

    def create(
        self,
        user: AuthUser,
        session_key: str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> AuthSessionLog:
        return AuthSessionLog.objects.create(
            user=user,
            session_key=session_key,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def get_active_for_user(self, user: AuthUser) -> list:
        return list(
            AuthSessionLog.objects.filter(user=user, is_active=True).order_by("-login_at")
        )

    def get_by_id_and_user(self, session_id: int, user: AuthUser) -> AuthSessionLog | None:
        try:
            return AuthSessionLog.objects.get(pk=session_id, user=user)
        except AuthSessionLog.DoesNotExist:
            return None

    def get_by_session_key(self, session_key: str) -> AuthSessionLog | None:
        try:
            return AuthSessionLog.objects.get(session_key=session_key)
        except AuthSessionLog.DoesNotExist:
            return None

    def revoke_by_key(self, session_key: str) -> bool:
        """Mark a session inactive. Returns True if a record was updated."""
        count = AuthSessionLog.objects.filter(
            session_key=session_key, is_active=True
        ).update(is_active=False, logout_at=timezone.now())
        return count > 0

    def revoke_by_id(self, session_id: int, user: AuthUser) -> bool:
        count = AuthSessionLog.objects.filter(
            pk=session_id, user=user, is_active=True
        ).update(is_active=False, logout_at=timezone.now())
        return count > 0

    def revoke_all_for_user(self, user: AuthUser) -> int:
        return AuthSessionLog.objects.filter(user=user, is_active=True).update(
            is_active=False, logout_at=timezone.now()
        )


# ---------------------------------------------------------------------------
# AuthOTPVerification
# ---------------------------------------------------------------------------

class AuthOTPRepository:

    def invalidate_all_for_purpose(self, user: AuthUser, purpose: str) -> None:
        """Consume all unused OTPs for this user+purpose before issuing a new one."""
        AuthOTPVerification.objects.filter(
            user=user, purpose=purpose, is_verified=False
        ).update(is_verified=True)

    def create(
        self,
        user: AuthUser,
        otp_code: str,
        purpose: str,
        expires_at,
    ) -> AuthOTPVerification:
        return AuthOTPVerification.objects.create(
            user=user,
            email=user.email,
            otp_code=otp_code,
            purpose=purpose,
            expires_at=expires_at,
        )

    def get_valid(
        self,
        user: AuthUser,
        otp_code: str,
        purpose: str,
    ) -> AuthOTPVerification | None:
        """
        Return the matching OTP only if it is: not expired, not verified, correct purpose.
        Returns None on any mismatch (never leaks which condition failed).
        """
        try:
            return AuthOTPVerification.objects.get(
                user=user,
                otp_code=otp_code,
                purpose=purpose,
                is_verified=False,
                expires_at__gt=timezone.now(),
            )
        except AuthOTPVerification.DoesNotExist:
            return None

    def mark_verified(self, otp: AuthOTPVerification) -> AuthOTPVerification:
        otp.is_verified = True
        otp.save(update_fields=["is_verified"])
        return otp


# ---------------------------------------------------------------------------
# AuthLoginAttempt
# ---------------------------------------------------------------------------

class AuthLoginAttemptRepository:

    def record(self, email: str, ip_address: str, status: str) -> AuthLoginAttempt:
        return AuthLoginAttempt.objects.create(
            email=email.lower().strip(),
            ip_address=ip_address,
            attempt_status=status,
        )

    def count_recent_failed(self, email: str, window_minutes: int) -> int:
        """
        Count FAILED attempts for this email within the window, but ONLY
        consecutive failures since the last SUCCESSFUL login.
        """
        email_clean = email.lower().strip()
        cutoff = timezone.now() - timedelta(minutes=window_minutes)

        # 1. Find the time of the latest SUCCESSFUL login in this window
        last_success = AuthLoginAttempt.objects.filter(
            email=email_clean,
            attempt_status=AttemptStatus.SUCCESS,
            attempt_time__gte=cutoff,
        ).order_by("-attempt_time").first()

        # 2. Start counting failures from after that success (or from cutoff)
        failure_search_start = last_success.attempt_time if last_success else cutoff

        return AuthLoginAttempt.objects.filter(
            email=email_clean,
            attempt_status=AttemptStatus.FAILED,
            attempt_time__gt=failure_search_start,
        ).count()


# ---------------------------------------------------------------------------
# AuthAccountLock
# ---------------------------------------------------------------------------

class AuthAccountLockRepository:

    def get_active_lock(self, user: AuthUser) -> AuthAccountLock | None:
        """
        Return the active lock or None if account is not locked.
        Automatically prunes expired locks for this user.
        """
        now = timezone.now()
        # Delete expired locks for this user
        AuthAccountLock.objects.filter(user=user, locked_until__lte=now).delete()

        try:
            return AuthAccountLock.objects.get(user=user, locked_until__gt=now)
        except AuthAccountLock.DoesNotExist:
            return None

    @transaction.atomic
    def create_lock(
        self, user: AuthUser, locked_until, reason: str = ""
    ) -> AuthAccountLock:
        # Remove any expired locks before creating new one
        AuthAccountLock.objects.filter(user=user).delete()
        return AuthAccountLock.objects.create(
            user=user,
            locked_until=locked_until,
            reason=reason or "Too many failed login attempts.",
        )

    def delete_lock(self, user: AuthUser) -> None:
        AuthAccountLock.objects.filter(user=user).delete()


# ---------------------------------------------------------------------------
# AuthPasswordHistory
# ---------------------------------------------------------------------------

class AuthPasswordHistoryRepository:

    def add(self, user: AuthUser, password_hash: str) -> AuthPasswordHistory:
        return AuthPasswordHistory.objects.create(
            user=user, password_hash=password_hash
        )

    def get_recent(self, user: AuthUser, count: int) -> list:
        return list(
            AuthPasswordHistory.objects.filter(user=user)
            .order_by("-created_at")[:count]
        )


# ---------------------------------------------------------------------------
# AuthPasswordPolicy
# ---------------------------------------------------------------------------

class AuthPasswordPolicyRepository:

    def get_all_active(self) -> list:
        return list(AuthPasswordPolicy.objects.filter(is_active=True).order_by("policy_key"))

    def get_by_key(self, key: str) -> AuthPasswordPolicy | None:
        try:
            return AuthPasswordPolicy.objects.get(policy_key=key, is_active=True)
        except AuthPasswordPolicy.DoesNotExist:
            return None
