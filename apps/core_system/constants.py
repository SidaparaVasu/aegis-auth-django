"""
core_system constants.

All ENUM values used in models and services are defined here as Python
classes with string constants.

Rules:
- Never use raw strings for enum values in code.
- Always import from this file.
"""


class ConfigValueType:
    """Valid types for SystemConfig.value_type."""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    JSON = "json"

    CHOICES = [
        (STRING, "String"),
        (INTEGER, "Integer"),
        (BOOLEAN, "Boolean"),
        (JSON, "JSON"),
    ]


class FeatureFlagScope:
    """Target scope for FeatureFlag.target_scope."""
    GLOBAL = "GLOBAL"
    ROLE = "ROLE"
    DEPARTMENT = "DEPARTMENT"

    CHOICES = [
        (GLOBAL, "Global"),
        (ROLE, "Role"),
        (DEPARTMENT, "Department"),
    ]


class AuditAction:
    """Allowed action values for AuditLog.action."""
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    ACCOUNT_LOCK = "ACCOUNT_LOCK"
    ACCOUNT_UNLOCK = "ACCOUNT_UNLOCK"

    CHOICES = [
        (CREATE, "Create"),
        (UPDATE, "Update"),
        (DELETE, "Delete"),
        (LOGIN, "Login"),
        (LOGOUT, "Logout"),
        (PERMISSION_CHANGE, "Permission Change"),
        (CONFIG_CHANGE, "Config Change"),
        (PASSWORD_CHANGE, "Password Change"),
        (ACCOUNT_LOCK, "Account Lock"),
        (ACCOUNT_UNLOCK, "Account Unlock"),
    ]


class EventSeverity:
    """Severity levels for SystemEventLog.severity."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    CHOICES = [
        (INFO, "Info"),
        (WARNING, "Warning"),
        (ERROR, "Error"),
        (CRITICAL, "Critical"),
    ]


# ---------------------------------------------------------------------------
# Well-known SystemConfig keys — import these instead of using raw strings
# ---------------------------------------------------------------------------
class ConfigKey:
    AUTH_LOGIN_METHOD = "AUTH_LOGIN_METHOD"
    OTP_EXPIRY_SECONDS = "OTP_EXPIRY_SECONDS"
    PASSWORD_MIN_LENGTH = "PASSWORD_MIN_LENGTH"
    MAX_LOGIN_ATTEMPTS = "MAX_LOGIN_ATTEMPTS"
    ACCOUNT_LOCK_DURATION_MINUTES = "ACCOUNT_LOCK_DURATION_MINUTES"
    PASSWORD_HISTORY_COUNT = "PASSWORD_HISTORY_COUNT"


# ---------------------------------------------------------------------------
# Well-known FeatureFlag keys
# ---------------------------------------------------------------------------
class FeatureKey:
    OTP_LOGIN = "otp_login"
    EMAIL_VERIFICATION_REQUIRED = "email_verification_required"
    PASSWORD_RESET_VIA_OTP = "password_reset_via_otp"
