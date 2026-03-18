"""
AuditService — creates append-only AuditLog entries for all critical operations.

Rules:
    - CREATE, UPDATE, DELETE, LOGIN, PERMISSION_CHANGE, CONFIG_CHANGE must all be logged.
    - Sensitive data (passwords, OTPs, tokens) must NEVER appear in old_value / new_value.
    - This service must be called from other services, never from views.
"""

import json
import logging

from apps.core_system.models import AuditLog
from apps.core_system.constants import AuditAction

logger = logging.getLogger(__name__)


class AuditService:
    """
    Single responsibility: persist AuditLog entries.

    Usage:
        audit_service = AuditService()
        audit_service.log(
            user_id=request.user.id,
            action=AuditAction.CONFIG_CHANGE,
            module="core_system",
            entity_type="SystemConfig",
            entity_id="OTP_EXPIRY_SECONDS",
            old_value={"config_value": "300"},
            new_value={"config_value": "600"},
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT"),
        )
    """

    # Fields that must never appear in audit log values
    SENSITIVE_FIELDS = frozenset({
        "password", "password_hash", "otp_code", "token",
        "access_token", "refresh_token", "session_key", "secret",
    })

    def log(
        self,
        action: str,
        module: str,
        user_id: int | None = None,
        entity_type: str = "",
        entity_id: str = "",
        old_value: dict | None = None,
        new_value: dict | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuditLog:
        """
        Create an immutable AuditLog entry.

        Args:
            action:      Must be one of AuditAction constants.
            module:      App/module name, e.g. 'core_system'.
            user_id:     ID of the acting user. None for system actions.
            entity_type: Model/resource name, e.g. 'SystemConfig'.
            entity_id:   PK or key of the entity, e.g. 'OTP_EXPIRY_SECONDS'.
            old_value:   Dict of before-state (sensitive keys are stripped).
            new_value:   Dict of after-state (sensitive keys are stripped).
            ip_address:  Requester IP (IPv4 or IPv6).
            user_agent:  Browser/client user agent string.

        Returns:
            The created AuditLog instance.
        """
        if action not in dict(AuditAction.CHOICES):
            logger.warning("AuditService.log called with unknown action '%s'. Allowing.", action)

        entry = AuditLog(
            user_id=user_id,
            action=action,
            module=module,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else "",
            old_value=self._serialize(old_value),
            new_value=self._serialize(new_value),
            ip_address=ip_address,
            user_agent=user_agent[:255] if user_agent else None,
        )
        # AuditLog.save() enforces append-only; this will raise on any update attempt.
        entry.save()
        return entry

    # ------------------------------------------------------------------
    # Convenience wrappers for common actions
    # ------------------------------------------------------------------

    def log_login(self, user_id: int, ip_address: str | None, user_agent: str | None):
        return self.log(
            action=AuditAction.LOGIN,
            module="auth_security",
            user_id=user_id,
            entity_type="AuthUser",
            entity_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def log_logout(self, user_id: int, ip_address: str | None, user_agent: str | None):
        return self.log(
            action=AuditAction.LOGOUT,
            module="auth_security",
            user_id=user_id,
            entity_type="AuthUser",
            entity_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def log_config_change(
        self, user_id: int, config_key: str, old_value, new_value,
        ip_address: str | None = None, user_agent: str | None = None,
    ):
        return self.log(
            action=AuditAction.CONFIG_CHANGE,
            module="core_system",
            user_id=user_id,
            entity_type="SystemConfig",
            entity_id=config_key,
            old_value={"config_value": old_value},
            new_value={"config_value": new_value},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def log_password_change(self, user_id: int, ip_address: str | None, user_agent: str | None):
        """Log password change WITHOUT storing any password values."""
        return self.log(
            action=AuditAction.PASSWORD_CHANGE,
            module="auth_security",
            user_id=user_id,
            entity_type="AuthUser",
            entity_id=str(user_id),
            ip_address=ip_address,
            user_agent=user_agent,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _serialize(self, data: dict | None) -> str | None:
        """Convert dict to JSON string, stripping sensitive keys first."""
        if data is None:
            return None
        safe = {k: v for k, v in data.items() if k.lower() not in self.SENSITIVE_FIELDS}
        try:
            return json.dumps(safe, default=str)
        except (TypeError, ValueError) as exc:
            logger.error("AuditService._serialize failed: %s", exc)
            return None
