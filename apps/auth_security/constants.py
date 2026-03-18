"""
auth_security constants.

All ENUM values are defined here as typed Python classes.
Never use raw strings for enum values in code — always import from here.
"""


class OTPPurpose:
    """Supported purposes for AuthOTPVerification.purpose."""
    LOGIN = "LOGIN"
    PASSWORD_RESET = "PASSWORD_RESET"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"

    CHOICES = [
        (LOGIN, "Login"),
        (PASSWORD_RESET, "Password Reset"),
        (EMAIL_VERIFICATION, "Email Verification"),
    ]


class AttemptStatus:
    """Result status for AuthLoginAttempt.attempt_status."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

    CHOICES = [
        (SUCCESS, "Success"),
        (FAILED, "Failed"),
    ]


class GenderChoice:
    """Gender values for AuthUserProfile.gender."""
    MALE = "M"
    FEMALE = "F"
    OTHER = "O"

    CHOICES = [
        (MALE, "Male"),
        (FEMALE, "Female"),
        (OTHER, "Other / Prefer not to say"),
    ]


# ---------------------------------------------------------------------------
# Well-known AuthPasswordPolicy keys
# ---------------------------------------------------------------------------

class PasswordPolicyKey:
    """
    Standard keys used in AuthPasswordPolicy.

    Values are stored as strings in policy_value.
    Services must cast to correct types when reading.
    """
    MIN_LENGTH = "PASSWORD_MIN_LENGTH"
    REQUIRE_UPPERCASE = "PASSWORD_REQUIRE_UPPERCASE"
    REQUIRE_LOWERCASE = "PASSWORD_REQUIRE_LOWERCASE"
    REQUIRE_DIGITS = "PASSWORD_REQUIRE_DIGITS"
    REQUIRE_SPECIAL = "PASSWORD_REQUIRE_SPECIAL"
    MAX_AGE_DAYS = "PASSWORD_MAX_AGE_DAYS"
    HISTORY_COUNT = "PASSWORD_HISTORY_COUNT"


# ---------------------------------------------------------------------------
# Token / Session constants
# ---------------------------------------------------------------------------

class SessionStatus:
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
