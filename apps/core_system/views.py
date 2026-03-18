"""
core_system API views.

Rules:
    - Views only handle HTTP: parse request, call service, return response.
    - No business logic or direct model access in views.
    - All responses use common.response helpers.
    - All write endpoints require IsAdminUser.
    - All list endpoints are paginated.
"""

import logging
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser

from common.response import success_response, error_response, not_found_response
from common.pagination import StandardResultsPagination
from common.exceptions import ConfigNotFoundException

from apps.core_system.serializers import (
    SystemConfigSerializer,
    UpdateSystemConfigSerializer,
    FeatureFlagSerializer,
    UpdateFeatureFlagSerializer,
    AuditLogSerializer,
    SystemEventLogSerializer,
)
from apps.core_system.services.config_service import ConfigService
from apps.core_system.services.feature_flag_service import FeatureFlagService
from apps.core_system.models import AuditLog, SystemEventLog

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: extract request metadata for audit logs
# ---------------------------------------------------------------------------

def _get_request_meta(request):
    """Extract IP address and user agent from a DRF request."""
    ip = (
        request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        or request.META.get("REMOTE_ADDR")
    )
    ua = request.META.get("HTTP_USER_AGENT", "")
    return ip, ua


# ---------------------------------------------------------------------------
# SystemConfig views
# ---------------------------------------------------------------------------

class SystemConfigListAPIView(APIView):
    """
    GET /api/v1/system/configs/
    Returns all active SystemConfig records, paginated.
    Requires: IsAdminUser
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = SystemConfigSerializer

    def get(self, request):
        service = ConfigService()
        configs = service.get_all_configs(active_only=False)
        serializer = SystemConfigSerializer(configs, many=True)

        paginator = StandardResultsPagination()
        page = paginator.paginate_queryset(configs, request)
        if page is not None:
            serializer = SystemConfigSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        return success_response(
            message="System configs retrieved.",
            data={"configs": SystemConfigSerializer(configs, many=True).data},
        )


class SystemConfigDetailAPIView(APIView):
    """
    GET   /api/v1/system/configs/{key}/  — Retrieve single config.
    PATCH /api/v1/system/configs/{key}/  — Update config value / meta.
    Requires: IsAdminUser
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = SystemConfigSerializer

    def _get_config_or_404(self, key: str):
        """Fetch from repo directly for read (no active filter for admin view)."""
        from apps.core_system.repositories.config_repository import ConfigRepository
        config = ConfigRepository().get_by_key(key)
        return config

    def get(self, request, key: str):
        config = self._get_config_or_404(key)
        if config is None:
            return not_found_response(f"Config key '{key}' not found.")
        return success_response(
            message="Config retrieved.",
            data=SystemConfigSerializer(config).data,
        )

    def patch(self, request, key: str):
        config = self._get_config_or_404(key)
        if config is None:
            return not_found_response(f"Config key '{key}' not found.")

        serializer = UpdateSystemConfigSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message="Validation failed.", errors=serializer.errors)

        ip, ua = _get_request_meta(request)
        service = ConfigService()
        validated = serializer.validated_data

        try:
            # Update config_value if provided
            if "config_value" in validated:
                service.set_config(
                    key=key,
                    value=validated["config_value"],
                    user_id=request.user.id,
                    ip_address=ip,
                    user_agent=ua,
                )

            # Update is_active if provided
            if "is_active" in validated:
                service.set_active(
                    key=key,
                    is_active=validated["is_active"],
                    user_id=request.user.id,
                    ip_address=ip,
                    user_agent=ua,
                )

            # Update description (no audit needed — metadata only)
            if "description" in validated:
                from apps.core_system.repositories.config_repository import ConfigRepository
                ConfigRepository().update(key, description=validated["description"])

        except ConfigNotFoundException as exc:
            return not_found_response(str(exc))
        except ValueError as exc:
            return error_response(message=str(exc))

        # Fetch updated record for response
        updated = self._get_config_or_404(key)
        return success_response(
            message="Config updated successfully.",
            data=SystemConfigSerializer(updated).data,
        )


# ---------------------------------------------------------------------------
# FeatureFlag views
# ---------------------------------------------------------------------------

class FeatureFlagListAPIView(APIView):
    """
    GET /api/v1/system/feature-flags/
    Returns all FeatureFlag records.
    Requires: IsAdminUser
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = FeatureFlagSerializer

    def get(self, request):
        service = FeatureFlagService()
        flags = service.get_all_flags()

        paginator = StandardResultsPagination()
        page = paginator.paginate_queryset(flags, request)
        if page is not None:
            serializer = FeatureFlagSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        return success_response(
            message="Feature flags retrieved.",
            data={"flags": FeatureFlagSerializer(flags, many=True).data},
        )


class FeatureFlagDetailAPIView(APIView):
    """
    GET   /api/v1/system/feature-flags/{key}/   — Retrieve single flag.
    PATCH /api/v1/system/feature-flags/{key}/   — Update / toggle flag.
    Requires: IsAdminUser
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = FeatureFlagSerializer

    def _get_flag_or_404(self, key: str):
        service = FeatureFlagService()
        return service.get_flag(key)

    def get(self, request, key: str):
        flag = self._get_flag_or_404(key)
        if flag is None:
            return not_found_response(f"Feature flag '{key}' not found.")
        return success_response(
            message="Feature flag retrieved.",
            data=FeatureFlagSerializer(flag).data,
        )

    def patch(self, request, key: str):
        flag = self._get_flag_or_404(key)
        if flag is None:
            return not_found_response(f"Feature flag '{key}' not found.")

        serializer = UpdateFeatureFlagSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message="Validation failed.", errors=serializer.errors)

        ip, ua = _get_request_meta(request)
        service = FeatureFlagService()
        validated = serializer.validated_data

        try:
            updated = service.update_flag(
                feature_key=key,
                user_id=request.user.id,
                ip_address=ip,
                user_agent=ua,
                **validated,
            )
        except ValueError as exc:
            return not_found_response(str(exc))

        return success_response(
            message="Feature flag updated successfully.",
            data=FeatureFlagSerializer(updated).data,
        )


class FeatureFlagToggleAPIView(APIView):
    """
    POST /api/v1/system/feature-flags/{key}/toggle/
    Flips is_enabled to the opposite value.
    Requires: IsAdminUser
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = FeatureFlagSerializer

    def post(self, request, key: str):
        service = FeatureFlagService()
        ip, ua = _get_request_meta(request)

        try:
            updated = service.toggle(
                feature_key=key,
                user_id=request.user.id,
                ip_address=ip,
                user_agent=ua,
            )
        except ValueError as exc:
            return not_found_response(str(exc))

        state = "enabled" if updated.is_enabled else "disabled"
        return success_response(
            message=f"Feature flag '{key}' is now {state}.",
            data=FeatureFlagSerializer(updated).data,
        )


# ---------------------------------------------------------------------------
# AuditLog views
# ---------------------------------------------------------------------------

class AuditLogListAPIView(APIView):
    """
    GET /api/v1/system/audit-logs/
    Returns paginated AuditLog records. Read-only.
    Requires: IsAdminUser

    Query params:
        ?module=core_system
        ?action=CONFIG_CHANGE
        ?user_id=42
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = AuditLogSerializer

    def get(self, request):
        qs = AuditLog.objects.all().order_by("-created_at")

        # Optional filters
        if module := request.query_params.get("module"):
            qs = qs.filter(module=module)
        if action := request.query_params.get("action"):
            qs = qs.filter(action=action)
        if user_id := request.query_params.get("user_id"):
            qs = qs.filter(user_id=user_id)

        paginator = StandardResultsPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = AuditLogSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


# ---------------------------------------------------------------------------
# SystemEventLog views
# ---------------------------------------------------------------------------

class SystemEventLogListAPIView(APIView):
    """
    GET /api/v1/system/event-logs/
    Returns paginated SystemEventLog records. Read-only.
    Requires: IsAdminUser

    Query params:
        ?severity=ERROR
        ?module=auth_security
        ?event_type=OTP_SEND_FAILURE
    """

    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = SystemEventLogSerializer

    def get(self, request):
        qs = SystemEventLog.objects.all().order_by("-created_at")

        if severity := request.query_params.get("severity"):
            qs = qs.filter(severity=severity)
        if module := request.query_params.get("module"):
            qs = qs.filter(module=module)
        if event_type := request.query_params.get("event_type"):
            qs = qs.filter(event_type=event_type)

        paginator = StandardResultsPagination()
        page = paginator.paginate_queryset(qs, request)
        serializer = SystemEventLogSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
