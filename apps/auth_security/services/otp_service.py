"""
OTPService — generation, delivery, and verification of one-time passwords.

Rules:
    - OTPs are single-use: once verified, is_verified=True and can never be reused.
    - OTPs expire: always check expires_at (enforced by repository query).
    - Before issuing a new OTP, all previous unused OTPs for the same user+purpose are invalidated.
    - otp_code must NEVER appear in logs or API responses.
    - Expiry is read from SystemConfig(OTP_EXPIRY_SECONDS) — not hardcoded.
    - Purpose flags are checked: otp_login feature must be enabled for LOGIN purpose.
"""

import random
import logging
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail

from apps.auth_security.constants import OTPPurpose
from apps.core_system.constants import ConfigKey, FeatureKey
from common.exceptions import OTPExpiredException, OTPInvalidException, FeatureDisabledException

logger = logging.getLogger(__name__)


class OTPService:

    def __init__(
        self,
        otp_repo=None,
        config_service=None,
        feature_flag_service=None,
        event_service=None,
    ):
        self._otp_repo = otp_repo
        self._config_service = config_service
        self._feature_flag_service = feature_flag_service
        self._event_service = event_service

    @property
    def otp_repo(self):
        if self._otp_repo is None:
            from apps.auth_security.repositories.auth_repository import AuthOTPRepository
            self._otp_repo = AuthOTPRepository()
        return self._otp_repo

    @property
    def config_service(self):
        if self._config_service is None:
            from apps.core_system.services.config_service import ConfigService
            self._config_service = ConfigService()
        return self._config_service

    @property
    def feature_flag_service(self):
        if self._feature_flag_service is None:
            from apps.core_system.services.feature_flag_service import FeatureFlagService
            self._feature_flag_service = FeatureFlagService()
        return self._feature_flag_service

    @property
    def event_service(self):
        if self._event_service is None:
            from apps.core_system.services.event_service import EventService
            self._event_service = EventService()
        return self._event_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_otp(self, user, purpose: str) -> None:
        """
        Generate a new OTP for the given purpose and send it to the user's email.

        Steps:
            1. Validate feature flag (if purpose requires it).
            2. Invalidate all previous OTPs for user+purpose.
            3. Generate a 6-digit OTP.
            4. Calculate expiry from SystemConfig.
            5. Persist to AuthOTPVerification.
            6. Send email.
            7. Log event (NOT logging the OTP code itself).

        Raises:
            FeatureDisabledException: if the required feature flag is disabled.
        """
        self._check_feature_flag(purpose)

        # Invalidate all old OTPs for this user+purpose
        self.otp_repo.invalidate_all_for_purpose(user, purpose)

        # Generate
        otp_code = self._generate_otp()

        # Expiry from config (default 300s = 5 minutes)
        try:
            expiry_seconds = self.config_service.get_config_int(ConfigKey.OTP_EXPIRY_SECONDS)
        except Exception:
            expiry_seconds = 300

        expires_at = timezone.now() + timedelta(seconds=expiry_seconds)

        # Persist
        self.otp_repo.create(user=user, otp_code=otp_code, purpose=purpose, expires_at=expires_at)

        # Send email
        try:
            self._send_email(user.email, otp_code, purpose, expiry_seconds)
        except Exception as exc:
            self.event_service.error(
                event_type="OTP_EMAIL_FAILURE",
                module="auth_security",
                message=f"Failed to send OTP email to {user.email}.",
                payload={"user_id": user.id, "purpose": purpose, "error": str(exc)},
            )
            raise

        # Log event (no otp_code in payload)
        self.event_service.info(
            event_type="OTP_SENT",
            module="auth_security",
            message=f"OTP sent to {user.email} for {purpose}.",
            payload={"user_id": user.id, "purpose": purpose, "expires_in_seconds": expiry_seconds},
        )
        logger.info("OTP sent: user_id=%s purpose=%s", user.id, purpose)

    def verify_otp(self, user, otp_code: str, purpose: str) -> bool:
        """
        Verify an OTP.

        Rules:
            - OTP must match, not expired, not already verified, correct purpose.
            - On success: mark is_verified=True (single-use).
            - On failure: always raise OTPInvalidException (never reveal WHY).

        Raises:
            OTPInvalidException: on any failure condition.
        """
        otp = self.otp_repo.get_valid(user=user, otp_code=otp_code, purpose=purpose)
        if otp is None:
            logger.warning("OTP verification failed: user_id=%s purpose=%s", user.id, purpose)
            raise OTPInvalidException("Invalid or expired OTP code.")

        self.otp_repo.mark_verified(otp)

        if purpose == OTPPurpose.EMAIL_VERIFICATION:
            from apps.auth_security.repositories.auth_repository import AuthUserRepository
            AuthUserRepository().mark_email_verified(user)
            logger.info("Email verified: user_id=%s", user.id)

        logger.info("OTP verified: user_id=%s purpose=%s", user.id, purpose)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_otp(self) -> str:
        """Generate a 6-digit numeric OTP using SystemRandom for cryptographic quality."""
        rng = random.SystemRandom()
        return str(rng.randint(100_000, 999_999))

    def _check_feature_flag(self, purpose: str) -> None:
        """Raise FeatureDisabledException if the purpose's feature flag is off."""
        flag_map = {
            OTPPurpose.LOGIN: "otp_login",
            OTPPurpose.PASSWORD_RESET: "password_reset_via_otp",
            OTPPurpose.EMAIL_VERIFICATION: "email_verification_required",
        }
        flag_key = flag_map.get(purpose)
        if flag_key:
            self.feature_flag_service.require_enabled(flag_key)

    def _send_email(self, email: str, otp_code: str, purpose: str, expiry_seconds: int) -> None:
        labels = {
            OTPPurpose.LOGIN: "Login",
            OTPPurpose.PASSWORD_RESET: "Password Reset",
            OTPPurpose.EMAIL_VERIFICATION: "Email Verification",
        }
        label = labels.get(purpose, purpose)
        expiry_mins = expiry_seconds // 60

        send_mail(
            subject=f"Your {label} OTP",
            message=(
                f"Your {label} OTP is: {otp_code}\n\n"
                f"This code expires in {expiry_mins} minute(s). "
                f"Do not share it with anyone."
            ),
            from_email=None,   # uses DEFAULT_FROM_EMAIL from settings
            recipient_list=[email],
            fail_silently=False,
        )
