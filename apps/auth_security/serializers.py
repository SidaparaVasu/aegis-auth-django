"""
auth_security serializers.

Rules:
- Passwords must be validated via common.validators.
- Registration uses RegisterSerializer.
- Profiles are managed via AuthUserProfileSerializer.
- Sensitive fields (hashed passwords, OTP codes) are NEVER returned in responses.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from apps.auth_security.models import AuthUserProfile, AuthSessionLog
from common.validators import validate_username, validate_phone_number
from apps.auth_security.constants import OTPPurpose, GenderChoice

User = get_user_model()


# ---------------------------------------------------------------------------
# User & Profile
# ---------------------------------------------------------------------------

class AuthUserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthUserProfile
        fields = [
            "first_name", "last_name", "phone_number",
            "profile_image_url", "date_of_birth", "gender", "updated_at"
        ]
        read_only_fields = ["updated_at"]

    def validate_phone_number(self, value):
        if value:
            return validate_phone_number(value)
        return value


class AuthUserSerializer(serializers.ModelSerializer):
    """Read-only user data including profile."""
    profile = AuthUserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ["id", "email", "username", "is_active", "last_login", "created_at", "profile"]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# Registration & Login
# ---------------------------------------------------------------------------

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(validators=[validate_username])
    password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if User.objects.filter(email=value.lower().strip()).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower().strip()

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


# ---------------------------------------------------------------------------
# OTP Verification
# ---------------------------------------------------------------------------

class OTPSendSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=OTPPurpose.CHOICES)


class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=10)
    purpose = serializers.ChoiceField(choices=OTPPurpose.CHOICES)


# ---------------------------------------------------------------------------
# Password Management
# ---------------------------------------------------------------------------

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    """Step 1: Request OTP for reset."""
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Step 2: Confirm reset with OTP + New password."""
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=10)
    new_password = serializers.CharField()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class AuthSessionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthSessionLog
        fields = [
            "id", "ip_address", "user_agent", "login_at", "logout_at", "is_active"
        ]
        read_only_fields = fields
