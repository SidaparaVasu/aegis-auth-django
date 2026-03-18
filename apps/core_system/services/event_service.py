"""
EventService — writes SystemEventLog entries for operational/infrastructure events.

Rules:
    - Use INFO for normal operational events.
    - Use WARNING for recoverable issues.
    - Use ERROR for failures that need attention.
    - Use CRITICAL for failures that impact availability.
    - Never log sensitive data.
"""

import logging

from apps.core_system.models import SystemEventLog
from apps.core_system.constants import EventSeverity

logger = logging.getLogger(__name__)


class EventService:
    """
    Single responsibility: persist SystemEventLog entries.

    Severity should be imported from EventSeverity constants — never pass raw strings.

    Usage:
        event_service = EventService()
        event_service.error(
            event_type="OTP_SEND_FAILURE",
            module="auth_security",
            message="Failed to send OTP to user@example.com",
            payload={"user_id": 42, "reason": "SMTP timeout"},
        )
    """

    def log(
        self,
        severity: str,
        event_type: str,
        module: str,
        message: str,
        payload: dict | None = None,
    ) -> SystemEventLog:
        """
        Create a SystemEventLog entry.

        Args:
            severity:   EventSeverity constant (INFO/WARNING/ERROR/CRITICAL).
            event_type: Short machine-readable type, e.g. 'OTP_SEND_FAILURE'.
            module:     App/component generating this event, e.g. 'auth_security'.
            message:    Human-readable description.
            payload:    Optional structured extra data (avoid sensitive values).
        """
        entry = SystemEventLog(
            severity=severity,
            event_type=event_type,
            module=module,
            message=message,
            payload=payload,
        )
        try:
            entry.save()
        except Exception as exc:
            # Event logging must never break the calling flow.
            logger.error("EventService.log failed to save entry: %s", exc)
        return entry

    # ------------------------------------------------------------------
    # Severity-level convenience methods
    # ------------------------------------------------------------------

    def info(self, event_type: str, module: str, message: str, payload: dict | None = None):
        return self.log(EventSeverity.INFO, event_type, module, message, payload)

    def warning(self, event_type: str, module: str, message: str, payload: dict | None = None):
        return self.log(EventSeverity.WARNING, event_type, module, message, payload)

    def error(self, event_type: str, module: str, message: str, payload: dict | None = None):
        logger.error("[%s] %s — %s", module, event_type, message)
        return self.log(EventSeverity.ERROR, event_type, module, message, payload)

    def critical(self, event_type: str, module: str, message: str, payload: dict | None = None):
        logger.critical("[%s] %s — %s", module, event_type, message)
        return self.log(EventSeverity.CRITICAL, event_type, module, message, payload)
