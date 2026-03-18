"""
core_system serializers.

Rules:
    - Serializers handle input validation AND response formatting.
    - Views must NOT contain validation logic.
    - Immutable fields are always read_only.
"""

from rest_framework import serializers
from apps.core_system.models import SystemConfig, FeatureFlag, AuditLog, SystemEventLog
from apps.core_system.constants import ConfigValueType, FeatureFlagScope, AuditAction, EventSeverity


# ---------------------------------------------------------------------------
# SystemConfig serializers
# ---------------------------------------------------------------------------

class SystemConfigSerializer(serializers.ModelSerializer):
    """Read serializer — used in GET responses."""

    class Meta:
        model = SystemConfig
        fields = [
            "id", "config_key", "config_value", "value_type",
            "config_group", "description", "is_active",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class UpdateSystemConfigSerializer(serializers.Serializer):
    """
    Write serializer for PATCH /api/v1/system/configs/{key}/.

    Immutable fields (config_key, value_type, config_group) are intentionally
    excluded — they can never be changed after creation.
    """

    config_value = serializers.CharField(
        required=False,
        allow_blank=False,
        help_text="New configuration value. Must be compatible with the config's value_type.",
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=255,
    )
    is_active = serializers.BooleanField(required=False)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("At least one field must be provided.")
        return attrs


# ---------------------------------------------------------------------------
# FeatureFlag serializers
# ---------------------------------------------------------------------------

class FeatureFlagSerializer(serializers.ModelSerializer):
    """Read serializer — used in GET responses."""

    class Meta:
        model = FeatureFlag
        fields = [
            "id", "feature_key", "description", "is_enabled",
            "target_scope", "rollout_percentage",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "feature_key", "created_at", "updated_at"]


class UpdateFeatureFlagSerializer(serializers.Serializer):
    """
    Write serializer for PATCH /api/v1/system/feature-flags/{key}/.

    feature_key is immutable.
    """

    is_enabled = serializers.BooleanField(required=False)
    description = serializers.CharField(required=False, allow_blank=True, max_length=255)
    rollout_percentage = serializers.IntegerField(required=False, min_value=0, max_value=100)
    target_scope = serializers.ChoiceField(
        required=False,
        choices=FeatureFlagScope.CHOICES,
    )

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("At least one field must be provided.")
        return attrs


class ToggleFeatureFlagSerializer(serializers.Serializer):
    """
    Optional explicit toggle serializer.
    Used when the caller wants to set is_enabled to an explicit value (not just flip).
    """
    is_enabled = serializers.BooleanField()


# ---------------------------------------------------------------------------
# AuditLog serializer
# ---------------------------------------------------------------------------

class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only serializer — AuditLog is append-only."""

    class Meta:
        model = AuditLog
        fields = [
            "id", "user_id", "action", "module",
            "entity_type", "entity_id",
            "old_value", "new_value",
            "ip_address", "user_agent",
            "created_at",
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# SystemEventLog serializer
# ---------------------------------------------------------------------------

class SystemEventLogSerializer(serializers.ModelSerializer):
    """Read-only serializer — SystemEventLog is write-only via EventService."""

    class Meta:
        model = SystemEventLog
        fields = [
            "id", "event_type", "severity", "module",
            "message", "payload", "created_at",
        ]
        read_only_fields = fields
