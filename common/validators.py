"""
Shared input validators used across serializers.

Rules:
- Never trust client input.
- Validate email format, password strength, and enum values.
- Use Django ORM / serializer validation — never raw SQL.
"""

import re
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def validate_email_format(email: str) -> str:
    """Validate that the value is a properly formatted email address."""
    try:
        validate_email(email)
    except ValidationError:
        raise ValidationError(f"'{email}' is not a valid email address.")
    return email.lower().strip()


# ---------------------------------------------------------------------------
# Password strength (baseline check — full policy enforced by PasswordPolicyService)
# ---------------------------------------------------------------------------

def validate_password_strength(password: str) -> str:
    """
    Baseline structural validation before the DB policy check.
    Enforces absolute minimums so we catch obvious garbage early.
    """
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Za-z]", password):
        raise ValidationError("Password must contain at least one letter.")
    if not re.search(r"\d", password):
        raise ValidationError("Password must contain at least one digit.")
    return password


# ---------------------------------------------------------------------------
# Enum helpers
# ---------------------------------------------------------------------------

def validate_enum(value: str, allowed: list, field_name: str = "value") -> str:
    """Ensure a string value is within an allowed set."""
    if value not in allowed:
        raise ValidationError(
            f"Invalid {field_name} '{value}'. Allowed values: {', '.join(allowed)}."
        )
    return value


# ---------------------------------------------------------------------------
# Phone number (basic)
# ---------------------------------------------------------------------------

def validate_phone_number(phone: str) -> str:
    """Accept E.164 style phone numbers: optional +, 7-15 digits."""
    cleaned = re.sub(r"[\s\-\(\)]", "", phone)
    if not re.match(r"^\+?\d{7,15}$", cleaned):
        raise ValidationError(f"'{phone}' is not a valid phone number.")
    return cleaned


# ---------------------------------------------------------------------------
# Username
# ---------------------------------------------------------------------------

def validate_username(username: str) -> str:
    """Alphanumeric + underscores, 3-150 chars."""
    if not re.match(r"^[a-zA-Z0-9_]{3,150}$", username):
        raise ValidationError(
            "Username must be 3-150 characters and contain only letters, digits, or underscores."
        )
    return username.strip()
