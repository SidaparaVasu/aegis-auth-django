"""
ConfigRepository — the only layer allowed to touch SystemConfig and
FeatureFlag database records directly.

Rules:
    - Views must never access models directly.
    - Services must call this repository, not the model.
    - No raw SQL queries.
"""

from django.db import transaction
from apps.core_system.models import SystemConfig, FeatureFlag


class ConfigRepository:
    """Data access for SystemConfig."""

    def get_all(self) -> list:
        """Return all SystemConfig records ordered by group and key."""
        return list(SystemConfig.objects.order_by("config_group", "config_key"))

    def get_all_active(self) -> list:
        """Return only active SystemConfig records."""
        return list(
            SystemConfig.objects.filter(is_active=True).order_by("config_group", "config_key")
        )

    def get_by_key(self, key: str) -> SystemConfig | None:
        """Return a single SystemConfig or None if not found."""
        try:
            return SystemConfig.objects.get(config_key=key)
        except SystemConfig.DoesNotExist:
            return None

    def get_active_by_key(self, key: str) -> SystemConfig | None:
        """Return an active SystemConfig or None."""
        try:
            return SystemConfig.objects.get(config_key=key, is_active=True)
        except SystemConfig.DoesNotExist:
            return None

    @transaction.atomic
    def update(self, key: str, **fields) -> SystemConfig:
        """
        Update allowed fields on a SystemConfig record.

        Allowed fields: config_value, description, is_active
        Immutable fields: config_key, value_type, config_group
        """
        allowed = {"config_value", "description", "is_active"}
        safe_fields = {k: v for k, v in fields.items() if k in allowed}
        if not safe_fields:
            raise ValueError("No valid fields provided for update.")
        SystemConfig.objects.filter(config_key=key).update(**safe_fields)
        return self.get_by_key(key)


class FeatureFlagRepository:
    """Data access for FeatureFlag."""

    def get_all(self) -> list:
        return list(FeatureFlag.objects.order_by("feature_key"))

    def get_by_key(self, key: str) -> FeatureFlag | None:
        try:
            return FeatureFlag.objects.get(feature_key=key)
        except FeatureFlag.DoesNotExist:
            return None

    def is_enabled(self, key: str) -> bool:
        """Fast boolean check — returns False if key does not exist."""
        try:
            return FeatureFlag.objects.values_list("is_enabled", flat=True).get(feature_key=key)
        except FeatureFlag.DoesNotExist:
            return False

    @transaction.atomic
    def update(self, key: str, **fields) -> FeatureFlag:
        """
        Update allowed fields on a FeatureFlag record.

        Allowed: is_enabled, description, rollout_percentage, target_scope
        Immutable: feature_key
        """
        allowed = {"is_enabled", "description", "rollout_percentage", "target_scope"}
        safe_fields = {k: v for k, v in fields.items() if k in allowed}
        if not safe_fields:
            raise ValueError("No valid fields provided for update.")
        FeatureFlag.objects.filter(feature_key=key).update(**safe_fields)
        return self.get_by_key(key)
