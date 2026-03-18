"""
FeatureFlagService — controls all feature availability via FeatureFlag table.

Rules:
    - ALL optional features must be gated via: feature_flag_service.is_enabled(key)
    - Toggle operations must be logged to AuditLog.
    - Never check feature availability by hardcoded booleans.
"""

import logging

from common.exceptions import FeatureDisabledException
from apps.core_system.constants import AuditAction, FeatureKey

logger = logging.getLogger(__name__)


class FeatureFlagService:
    """
    Business logic for FeatureFlag operations.

    Dependency injection:
        service = FeatureFlagService(
            repository=FeatureFlagRepository(),
            audit_service=AuditService(),
        )

    For production usage the defaults are used automatically.
    """

    def __init__(self, repository=None, audit_service=None):
        self._repository = repository
        self._audit_service = audit_service

    @property
    def repository(self):
        if self._repository is None:
            from apps.core_system.repositories.config_repository import FeatureFlagRepository
            self._repository = FeatureFlagRepository()
        return self._repository

    @property
    def audit_service(self):
        if self._audit_service is None:
            from apps.core_system.services.audit_service import AuditService
            self._audit_service = AuditService()
        return self._audit_service

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def is_enabled(self, feature_key: str) -> bool:
        """
        Return True if the feature is enabled.

        Returns False (never raises) if the key doesn't exist — unknown
        features are treated as disabled by default.
        """
        return self.repository.is_enabled(feature_key)

    def require_enabled(self, feature_key: str) -> None:
        """
        Assert that a feature is enabled.

        Raises:
            FeatureDisabledException: if the flag is disabled or missing.

        Usage in service layer:
            self.feature_flag_service.require_enabled(FeatureKey.OTP_LOGIN)
        """
        if not self.is_enabled(feature_key):
            raise FeatureDisabledException(
                f"Feature '{feature_key}' is currently disabled."
            )

    def get_all_flags(self) -> list:
        """Return all FeatureFlag records."""
        return self.repository.get_all()

    def get_flag(self, feature_key: str):
        """Return a FeatureFlag instance or None."""
        return self.repository.get_by_key(feature_key)

    # ------------------------------------------------------------------
    # Write operations (all logged to AuditLog)
    # ------------------------------------------------------------------

    def toggle(
        self,
        feature_key: str,
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ):
        """
        Toggle a feature flag between enabled and disabled.

        Business rules:
            1. Flag must already exist.
            2. Toggle is atomic.
            3. Old and new state are logged to AuditLog.

        Raises:
            ValueError: if feature_key does not exist.
        """
        flag = self.repository.get_by_key(feature_key)
        if flag is None:
            raise ValueError(f"Feature flag '{feature_key}' not found.")

        old_state = flag.is_enabled
        new_state = not old_state
        updated = self.repository.update(feature_key, is_enabled=new_state)

        self.audit_service.log(
            action=AuditAction.CONFIG_CHANGE,
            module="core_system",
            user_id=user_id,
            entity_type="FeatureFlag",
            entity_id=feature_key,
            old_value={"is_enabled": old_state},
            new_value={"is_enabled": new_state},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        logger.info(
            "Feature flag '%s' toggled %s → %s by user_id=%s",
            feature_key, old_state, new_state, user_id,
        )
        return updated

    def update_flag(
        self,
        feature_key: str,
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        **fields,
    ):
        """
        Update specific fields on a FeatureFlag (is_enabled, description,
        rollout_percentage, target_scope).

        Raises:
            ValueError: if feature_key doesn't exist or fields are empty.
        """
        flag = self.repository.get_by_key(feature_key)
        if flag is None:
            raise ValueError(f"Feature flag '{feature_key}' not found.")

        old_snapshot = {
            "is_enabled": flag.is_enabled,
            "rollout_percentage": flag.rollout_percentage,
            "target_scope": flag.target_scope,
        }
        updated = self.repository.update(feature_key, **fields)

        self.audit_service.log(
            action=AuditAction.CONFIG_CHANGE,
            module="core_system",
            user_id=user_id,
            entity_type="FeatureFlag",
            entity_id=feature_key,
            old_value=old_snapshot,
            new_value=fields,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return updated
