"""
ConfigService — business logic for reading and writing SystemConfig.

Rules:
    - No values may be hardcoded; everything goes through this service.
    - All write operations must be logged via AuditService.
    - Services receive dependencies via injection (no global imports of models).
"""

import json
import logging

from common.exceptions import ConfigNotFoundException
from apps.core_system.constants import ConfigValueType, AuditAction

logger = logging.getLogger(__name__)


class ConfigService:
    """
    Business logic for SystemConfig operations.

    Dependency injection pattern:
        service = ConfigService(
            repository=ConfigRepository(),
            audit_service=AuditService(),
            event_service=EventService(),
        )

    All three dependencies default to their standard implementations
    when not provided (suitable for production; override in tests).
    """

    def __init__(self, repository=None, audit_service=None, event_service=None):
        self._repository = repository
        self._audit_service = audit_service
        self._event_service = event_service

    # ------------------------------------------------------------------
    # Lazy dependency resolution (avoids circular import on module load)
    # ------------------------------------------------------------------

    @property
    def repository(self):
        if self._repository is None:
            from apps.core_system.repositories.config_repository import ConfigRepository
            self._repository = ConfigRepository()
        return self._repository

    @property
    def audit_service(self):
        if self._audit_service is None:
            from apps.core_system.services.audit_service import AuditService
            self._audit_service = AuditService()
        return self._audit_service

    @property
    def event_service(self):
        if self._event_service is None:
            from apps.core_system.services.event_service import EventService
            self._event_service = EventService()
        return self._event_service

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_config(self, key: str) -> str:
        """
        Return the raw string value for a config key.

        Raises:
            ConfigNotFoundException: if key does not exist or is inactive.
        """
        config = self.repository.get_active_by_key(key)
        if config is None:
            raise ConfigNotFoundException(f"Config key '{key}' not found or is inactive.")
        return config.config_value

    def get_config_typed(self, key: str):
        """
        Return the config value cast to its declared value_type.

        Returns:
            int   for value_type=integer
            bool  for value_type=boolean
            dict  for value_type=json
            str   for value_type=string (default)

        Raises:
            ConfigNotFoundException: if key not found or inactive.
            ValueError: if the stored value cannot be cast to the declared type.
        """
        config = self.repository.get_active_by_key(key)
        if config is None:
            raise ConfigNotFoundException(f"Config key '{key}' not found or is inactive.")
        return self._cast_value(config.config_value, config.value_type, key)

    def get_config_int(self, key: str) -> int:
        """Return config value as integer."""
        return int(self.get_config(key))

    def get_config_bool(self, key: str) -> bool:
        """Return config value as boolean (true/1/yes → True)."""
        return self.get_config(key).lower() in ("true", "1", "yes")

    def get_config_json(self, key: str) -> dict:
        """Return config value parsed from JSON."""
        return json.loads(self.get_config(key))

    def get_all_configs(self, active_only: bool = True) -> list:
        """Return all configs. Services should prefer active_only=True."""
        if active_only:
            return self.repository.get_all_active()
        return self.repository.get_all()

    # ------------------------------------------------------------------
    # Write operations (all logged to AuditLog)
    # ------------------------------------------------------------------

    def set_config(
        self,
        key: str,
        value: str,
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ):
        """
        Update a SystemConfig value.

        Business rules:
            1. Key must already exist (no implicit creation via this method).
            2. Value is validated against the declared value_type.
            3. Old and new values are logged to AuditLog.

        Raises:
            ConfigNotFoundException: if key doesn't exist.
            ValueError: if value doesn't match declared type.
        """
        existing = self.repository.get_by_key(key)
        if existing is None:
            raise ConfigNotFoundException(f"Config key '{key}' not found.")

        # Validate value matches declared type before writing
        self._cast_value(value, existing.value_type, key)

        old_value = existing.config_value
        updated = self.repository.update(key, config_value=value)

        # Audit the config change (mandatory per dev_backend_rules.md §4.1)
        self.audit_service.log_config_change(
            user_id=user_id,
            config_key=key,
            old_value=old_value,
            new_value=value,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self.event_service.info(
            event_type="CONFIG_UPDATED",
            module="core_system",
            message=f"Config '{key}' updated from '{old_value}' to '{value}'.",
            payload={"config_key": key, "user_id": user_id},
        )

        logger.info("Config '%s' updated by user_id=%s", key, user_id)
        return updated

    def set_active(
        self,
        key: str,
        is_active: bool,
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ):
        """Activate or deactivate a config key."""
        existing = self.repository.get_by_key(key)
        if existing is None:
            raise ConfigNotFoundException(f"Config key '{key}' not found.")

        old_state = existing.is_active
        updated = self.repository.update(key, is_active=is_active)

        self.audit_service.log(
            action=AuditAction.CONFIG_CHANGE,
            module="core_system",
            user_id=user_id,
            entity_type="SystemConfig",
            entity_id=key,
            old_value={"is_active": old_state},
            new_value={"is_active": is_active},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return updated

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _cast_value(self, value: str, value_type: str, key: str = ""):
        """Cast a string value to its declared type. Raises ValueError on failure."""
        try:
            if value_type == ConfigValueType.INTEGER:
                return int(value)
            if value_type == ConfigValueType.BOOLEAN:
                if value.lower() not in ("true", "false", "1", "0", "yes", "no"):
                    raise ValueError(f"Invalid boolean value: '{value}'")
                return value.lower() in ("true", "1", "yes")
            if value_type == ConfigValueType.JSON:
                return json.loads(value)
            return value  # STRING — no cast needed
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Config '{key}' has value_type='{value_type}' but value '{value}' "
                f"cannot be cast: {exc}"
            ) from exc
