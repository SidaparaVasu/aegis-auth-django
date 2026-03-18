"""
core_system models.

Tables:
    SystemConfig      — Global configuration key-value store
    FeatureFlag       — Dynamic feature toggles
    AuditLog          — Append-only audit trail for all critical operations
    SystemEventLog    — Operational/app-level event logging

Rules enforced:
    - All tables include id, created_at, updated_at
    - ENUM values reference constants.py
    - Indexes on all lookup/FK columns
    - AuditLog is append-only (no updates, no deletes)
"""

from django.db import models
from .constants import ConfigValueType, FeatureFlagScope, AuditAction, EventSeverity


# ---------------------------------------------------------------------------
# 1. SystemConfig
# ---------------------------------------------------------------------------

class SystemConfig(models.Model):
    """
    Global configuration key-value store.

    All configurable values (OTP expiry, password rules, login methods, etc.)
    must be stored here instead of being hardcoded.

    Example keys: AUTH_LOGIN_METHOD, OTP_EXPIRY_SECONDS, PASSWORD_MIN_LENGTH
    """

    config_key = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        help_text="Unique configuration key, e.g. OTP_EXPIRY_SECONDS",
    )
    config_value = models.TextField(
        help_text="Raw string value; cast to correct type via value_type.",
    )
    value_type = models.CharField(
        max_length=20,
        choices=ConfigValueType.CHOICES,
        default=ConfigValueType.STRING,
        help_text="The data type of config_value.",
    )
    config_group = models.CharField(
        max_length=50,
        blank=True,
        default="",
        help_text="Logical grouping, e.g. 'auth', 'email'.",
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Human-readable description of this config key.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive configs are ignored by config_service.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "system_config"
        verbose_name = "System Config"
        verbose_name_plural = "System Configs"
        ordering = ["config_group", "config_key"]
        indexes = [
            models.Index(fields=["config_key"], name="idx_system_config_key"),
            models.Index(fields=["config_group"], name="idx_system_config_group"),
            models.Index(fields=["is_active"], name="idx_system_config_active"),
        ]

    def __str__(self):
        return f"{self.config_key} = {self.config_value}"


# ---------------------------------------------------------------------------
# 2. FeatureFlag
# ---------------------------------------------------------------------------

class FeatureFlag(models.Model):
    """
    Dynamic feature toggles.

    All optional functionality must be gated via this table.

    Example: feature_flag_service.is_enabled('otp_login')
    """

    feature_key = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        help_text="Unique feature key, e.g. 'otp_login'.",
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        default="",
    )
    is_enabled = models.BooleanField(
        default=False,
        help_text="Master on/off toggle for this feature.",
    )
    target_scope = models.CharField(
        max_length=20,
        choices=FeatureFlagScope.CHOICES,
        default=FeatureFlagScope.GLOBAL,
        help_text="Scope at which this flag applies.",
    )
    rollout_percentage = models.PositiveSmallIntegerField(
        default=100,
        help_text="Percentage of target scope that sees this feature (0-100).",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "feature_flag"
        verbose_name = "Feature Flag"
        verbose_name_plural = "Feature Flags"
        ordering = ["feature_key"]
        indexes = [
            models.Index(fields=["feature_key"], name="idx_feature_flag_key"),
            models.Index(fields=["is_enabled"], name="idx_feature_flag_enabled"),
        ]

    def __str__(self):
        status = "✓" if self.is_enabled else "✗"
        return f"[{status}] {self.feature_key}"


# ---------------------------------------------------------------------------
# 3. AuditLog
# ---------------------------------------------------------------------------

class AuditLog(models.Model):
    """
    Append-only audit trail for all critical operations.

    Must be created (never updated or deleted) for:
        CREATE, UPDATE, DELETE, LOGIN, PERMISSION_CHANGE, CONFIG_CHANGE

    user_id is nullable to support system-triggered actions.
    """

    user_id = models.BigIntegerField(
        null=True,
        blank=True,
        help_text="ID of the user who performed the action. NULL = system action.",
    )
    action = models.CharField(
        max_length=100,
        choices=AuditAction.CHOICES,
        help_text="Type of action performed.",
    )
    module = models.CharField(
        max_length=50,
        help_text="App/module that generated this log entry.",
    )
    entity_type = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="The model/resource being acted on, e.g. 'SystemConfig'.",
    )
    entity_id = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="PK or identifier of the entity.",
    )
    old_value = models.TextField(
        blank=True,
        null=True,
        help_text="JSON-serialised before-state.",
    )
    new_value = models.TextField(
        blank=True,
        null=True,
        help_text="JSON-serialised after-state.",
    )
    ip_address = models.CharField(
        max_length=45,
        blank=True,
        null=True,
        help_text="IPv4 or IPv6 address of the requester.",
    )
    user_agent = models.CharField(
        max_length=255,
        blank=True,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_log"
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user_id"], name="idx_audit_user_id"),
            models.Index(fields=["action"], name="idx_audit_action"),
            models.Index(fields=["module"], name="idx_audit_module"),
            models.Index(fields=["created_at"], name="idx_audit_created_at"),
        ]

    def __str__(self):
        return f"[{self.action}] user={self.user_id} module={self.module} @ {self.created_at}"

    def save(self, *args, **kwargs):
        """Enforce append-only: disallow updates after creation."""
        if self.pk:
            raise PermissionError("AuditLog entries are immutable. Updates are not allowed.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Enforce append-only: disallow deletion."""
        raise PermissionError("AuditLog entries are immutable. Deletions are not allowed.")


# ---------------------------------------------------------------------------
# 4. SystemEventLog
# ---------------------------------------------------------------------------

class SystemEventLog(models.Model):
    """
    App-level operational event logging.

    Use this for infrastructure events (startup, config reload, OTP send failures).
    Use AuditLog for user-triggered business events.

    Severity levels: INFO, WARNING, ERROR, CRITICAL
    """

    event_type = models.CharField(
        max_length=100,
        help_text="Short machine-readable event type, e.g. 'OTP_SEND_FAILURE'.",
    )
    severity = models.CharField(
        max_length=10,
        choices=EventSeverity.CHOICES,
        default=EventSeverity.INFO,
    )
    module = models.CharField(
        max_length=100,
        help_text="App/component that generated this event.",
    )
    message = models.TextField(
        help_text="Human-readable description of the event.",
    )
    payload = models.JSONField(
        null=True,
        blank=True,
        help_text="Additional structured data (request context, error details, etc.).",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "system_event_log"
        verbose_name = "System Event Log"
        verbose_name_plural = "System Event Logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["severity"], name="idx_event_severity"),
            models.Index(fields=["module"], name="idx_event_module"),
            models.Index(fields=["event_type"], name="idx_event_type"),
            models.Index(fields=["created_at"], name="idx_event_created_at"),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.event_type} — {self.module} @ {self.created_at}"
