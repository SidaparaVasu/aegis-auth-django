"""
auth_security throttles.

Enforces rate limits for sensitive authentication endpoints:
- Login: 5 attempts per minute per IP.
- OTP Send: 3 requests per minute per user.
- Password Reset Request: 3 per hour per email (simplified to IP for DRF built-ins).
"""

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """Throttle for login attempts — 5/min per IP."""
    scope = "auth_login"


class OTPSendRateThrottle(UserRateThrottle):
    """Throttle for OTP generation — 3/min per user."""
    scope = "auth_otp_send"


class PasswordResetRateThrottle(AnonRateThrottle):
    """Throttle for password reset requests — 3/hour per IP."""
    scope = "auth_password_reset"
