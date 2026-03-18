"""
auth_security models.

Tables:
    AuthUser              — Custom Django user (replaces default User)
    AuthUserProfile       — Extended user profile data
    AuthPasswordHistory   — Previous password hashes (reuse prevention)
    AuthOTPVerification   — One-time passwords (login / reset / verify)
    AuthSessionLog        — Full session tracking per login
    AuthLoginAttempt      — Brute-force detection log
    AuthPasswordPolicy    — Configurable password complexity rules
    AuthAccountLock       — Temporary account lockouts

Rules enforced:
    - All tables include id, created_at
    - ENUM values reference constants.py
    - Required indexes on FK and frequently queried columns
    - Password values are NEVER stored in plain text
    - OTP expiry enforced at model level via expires_at
    - Sessions must be tracked on every login
"""

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

from .constants import OTPPurpose, AttemptStatus, GenderChoice


# ---------------------------------------------------------------------------
# Custom User Manager
# ---------------------------------------------------------------------------

class AuthUserManager(BaseUserManager):
    """
    Manager for AuthUser.

    Rules:
        - email is the USERNAME_FIELD (used for login).
        - username is a required REQUIRED_FIELD (display / handle).
        - Passwords are always set via set_password() — never stored plain.
    """

    def create_user(self, email: str, username: str, password: str = None, **extra_fields):
        if not email:
            raise ValueError("Email address is required.")
        if not username:
            raise ValueError("Username is required.")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)   # hashed via argon2 (PASSWORD_HASHERS in settings)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, username: str, password: str = None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)


# ---------------------------------------------------------------------------
# 1. AuthUser — Custom Django User
# ---------------------------------------------------------------------------

class AuthUser(AbstractBaseUser, PermissionsMixin):
    """
    Central user identity table.

    AbstractBaseUser provides: password (hashed), last_login
    PermissionsMixin provides:  is_superuser, groups, user_permissions

    USERNAME_FIELD = email  → used for authentication lookups.
    REQUIRED_FIELDS = [username] → prompted by createsuperuser.
    """

    username = models.CharField(
        max_length=150,
        unique=True,
        help_text="Display name / handle. 3-150 characters.",
    )
    email = models.EmailField(
        max_length=255,
        unique=True,
        help_text="Primary identifier used for login.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Unset to soft-delete a user without removing the record.",
    )
    is_staff = models.BooleanField(
        default=False,
        help_text="Grants access to Django admin site.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = AuthUserManager()

    class Meta:
        db_table = "auth_user"
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=["email"], name="idx_auth_user_email"),
            models.Index(fields=["username"], name="idx_auth_user_username"),
            models.Index(fields=["is_active"], name="idx_auth_user_active"),
        ]

    def __str__(self):
        return f"{self.email} ({self.username})"

    @property
    def full_name(self) -> str:
        """Convenience property — returns name from profile if available."""
        try:
            p = self.profile
            return f"{p.first_name} {p.last_name}".strip() or self.username
        except AuthUserProfile.DoesNotExist:
            return self.username


# ---------------------------------------------------------------------------
# 2. AuthUserProfile — Extended user details
# ---------------------------------------------------------------------------

class AuthUserProfile(models.Model):
    """
    One-to-one extension of AuthUser for personal profile fields.

    Kept separate so AuthUser stays lean and profile fields can be
    updated independently without touching the auth table.
    """

    user = models.OneToOneField(
        AuthUser,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    first_name = models.CharField(max_length=100, blank=True, default="")
    last_name = models.CharField(max_length=100, blank=True, default="")
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="E.164 format recommended, e.g. +919876543210.",
    )
    profile_image_url = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        help_text="URL to the user's profile image.",
    )
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(
        max_length=1,
        choices=GenderChoice.CHOICES,
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "auth_user_profile"
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"Profile<{self.user.email}>"


# ---------------------------------------------------------------------------
# 3. AuthPasswordHistory — Password reuse prevention
# ---------------------------------------------------------------------------

class AuthPasswordHistory(models.Model):
    """
    Stores hashes of past passwords to prevent reuse.

    Rules:
        - Populated every time a user changes their password.
        - PasswordService checks last N entries (N = PASSWORD_HISTORY_COUNT config).
        - NEVER store plain text — only hashed values.
    """

    user = models.ForeignKey(
        AuthUser,
        on_delete=models.CASCADE,
        related_name="password_history",
    )
    password_hash = models.CharField(
        max_length=255,
        help_text="Argon2/bcrypt hash of a previously used password.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_password_history"
        verbose_name = "Password History"
        verbose_name_plural = "Password History"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user"], name="idx_pw_history_user_id"),
        ]

    def __str__(self):
        return f"PasswordHistory<user={self.user_id} @ {self.created_at}>"


# ---------------------------------------------------------------------------
# 4. AuthOTPVerification — One-time passwords
# ---------------------------------------------------------------------------

class AuthOTPVerification(models.Model):
    """
    Short-lived OTP records for authentication flows.

    Rules:
        - OTP is single-use: is_verified flips to True on first use.
        - OTP must expire: always check expires_at before accepting.
        - Purpose-specific: LOGIN OTP cannot be used for PASSWORD_RESET.
        - Sensitive: otp_code must never appear in logs or API responses.
    """

    user = models.ForeignKey(
        AuthUser,
        on_delete=models.CASCADE,
        related_name="otp_verifications",
    )
    email = models.EmailField(
        max_length=255,
        help_text="Target email the OTP was sent to.",
    )
    otp_code = models.CharField(
        max_length=10,
        help_text="The OTP value (plain or hashed). Never log this field.",
    )
    purpose = models.CharField(
        max_length=25,
        choices=OTPPurpose.CHOICES,
        help_text="What this OTP is authorising.",
    )
    expires_at = models.DateTimeField(
        help_text="Hard expiry timestamp. Must ALWAYS be checked before accepting OTP.",
    )
    is_verified = models.BooleanField(
        default=False,
        help_text="True = consumed. A verified OTP must never be accepted again.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_otp_verification"
        verbose_name = "OTP Verification"
        verbose_name_plural = "OTP Verifications"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "purpose"], name="idx_otp_user_purpose"),
            models.Index(fields=["expires_at"], name="idx_otp_expires_at"),
        ]

    def __str__(self):
        status = "✓ used" if self.is_verified else "pending"
        return f"OTP<{self.purpose} user={self.user_id} {status}>"

    @property
    def is_expired(self) -> bool:
        """Returns True if the OTP is past its expiry time."""
        return timezone.now() > self.expires_at


# ---------------------------------------------------------------------------
# 5. AuthSessionLog — Session tracking
# ---------------------------------------------------------------------------

class AuthSessionLog(models.Model):
    """
    Tracks every login session.

    Rules:
        - Created on EVERY successful login.
        - session_key stores the JWT JTI claim (unique per token).
        - logout_at=NULL means session is still active.
        - Sessions must be invalidated on logout (is_active=False, logout_at set).
    """

    user = models.ForeignKey(
        AuthUser,
        on_delete=models.CASCADE,
        related_name="sessions",
    )
    session_key = models.CharField(
        max_length=255,
        unique=True,
        help_text="JWT JTI claim or session UUID. Unique per session.",
    )
    ip_address = models.CharField(
        max_length=45,
        help_text="IPv4 or IPv6 address at login time.",
    )
    user_agent = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Browser / client user agent string.",
    )
    login_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp of successful login.",
    )
    logout_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of logout. NULL = session still active.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Set to False on logout or token revocation.",
    )

    class Meta:
        db_table = "auth_session_log"
        verbose_name = "Session Log"
        verbose_name_plural = "Session Logs"
        ordering = ["-login_at"]
        indexes = [
            models.Index(fields=["user", "is_active"], name="idx_session_user_active"),
            models.Index(fields=["session_key"], name="idx_session_key"),
            models.Index(fields=["ip_address"], name="idx_session_ip"),
        ]

    def __str__(self):
        state = "active" if self.is_active else "closed"
        return f"Session<user={self.user_id} {state} @ {self.login_at}>"


# ---------------------------------------------------------------------------
# 6. AuthLoginAttempt — Brute-force detection
# ---------------------------------------------------------------------------

class AuthLoginAttempt(models.Model):
    """
    Append-only log of every login attempt (success or failure).

    Rules:
        - Recorded BEFORE credentials are checked so all attempts are captured.
        - LockService counts recent FAILED attempts to trigger AuthAccountLock.
        - ip_address is indexed for IP-level rate monitoring.
    """

    email = models.EmailField(
        max_length=255,
        help_text="Email address used in this login attempt.",
    )
    ip_address = models.CharField(
        max_length=45,
        help_text="Source IP address of the request.",
    )
    attempt_status = models.CharField(
        max_length=10,
        choices=AttemptStatus.CHOICES,
        help_text="Whether the attempt succeeded or failed.",
    )
    attempt_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_login_attempt"
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"
        ordering = ["-attempt_time"]
        indexes = [
            models.Index(fields=["email"], name="idx_auth_login_email"),
            models.Index(fields=["ip_address"], name="idx_auth_login_ip"),
            models.Index(fields=["attempt_time"], name="idx_auth_login_time"),
        ]

    def __str__(self):
        return f"LoginAttempt<{self.email} {self.attempt_status} @ {self.attempt_time}>"


# ---------------------------------------------------------------------------
# 7. AuthPasswordPolicy — Configurable password complexity rules
# ---------------------------------------------------------------------------

class AuthPasswordPolicy(models.Model):
    """
    Stores granular password complexity rules.

    Rules:
        - All password requirements are read from here — no hardcoded thresholds.
        - PasswordPolicyService reads and enforces these at runtime.
        - policy_value is always stored as a string; cast when reading.

    Example entries:
        PASSWORD_MIN_LENGTH        = "8"
        PASSWORD_REQUIRE_UPPERCASE = "true"
        PASSWORD_REQUIRE_DIGITS    = "true"
        PASSWORD_REQUIRE_SPECIAL   = "false"
        PASSWORD_MAX_AGE_DAYS      = "90"
    """

    policy_key = models.CharField(
        max_length=100,
        unique=True,
        help_text="Machine-readable policy key. Must be unique.",
    )
    policy_value = models.CharField(
        max_length=255,
        help_text="String value. Cast to correct type in service layer.",
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Human-readable description of this policy rule.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive policies are ignored by PasswordPolicyService.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_password_policy"
        verbose_name = "Password Policy"
        verbose_name_plural = "Password Policies"
        ordering = ["policy_key"]
        indexes = [
            models.Index(fields=["policy_key"], name="idx_pw_policy_key"),
            models.Index(fields=["is_active"], name="idx_pw_policy_active"),
        ]

    def __str__(self):
        return f"{self.policy_key} = {self.policy_value}"


# ---------------------------------------------------------------------------
# 8. AuthAccountLock — Temporary lockouts after failed attempts
# ---------------------------------------------------------------------------

class AuthAccountLock(models.Model):
    """
    Records a temporary account lock.

    Rules:
        - Created by LockService when failed attempts exceed MAX_LOGIN_ATTEMPTS.
        - Threshold and lock duration read from SystemConfig (never hardcoded).
        - Lock is cleared when locked_until passes or admin manually unlocks.
        - AuthService must check this table before processing any login.
    """

    user = models.ForeignKey(
        AuthUser,
        on_delete=models.CASCADE,
        related_name="account_locks",
    )
    locked_until = models.DateTimeField(
        help_text="Expiry of the lock. Login is rejected until this time passes.",
    )
    reason = models.CharField(
        max_length=255,
        blank=True,
        default="Too many failed login attempts.",
        help_text="Human-readable reason for the lock.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "auth_account_lock"
        verbose_name = "Account Lock"
        verbose_name_plural = "Account Locks"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user"], name="idx_account_lock_user"),
            models.Index(fields=["locked_until"], name="idx_account_lock_until"),
        ]

    def __str__(self):
        return f"AccountLock<user={self.user_id} until={self.locked_until}>"

    @property
    def is_active(self) -> bool:
        """Returns True if the lock is still in effect."""
        return timezone.now() < self.locked_until
