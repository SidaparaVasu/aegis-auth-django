"""
core_system URL patterns.
All routes are served under: /api/v1/system/ (see Core/urls.py).
"""

from django.urls import path
from apps.core_system.views import (
    SystemConfigListAPIView,
    SystemConfigDetailAPIView,
    FeatureFlagListAPIView,
    FeatureFlagDetailAPIView,
    FeatureFlagToggleAPIView,
    AuditLogListAPIView,
    SystemEventLogListAPIView,
)

urlpatterns = [
    # System config
    path("configs/", SystemConfigListAPIView.as_view(), name="system-config-list"),
    path("configs/<str:key>/", SystemConfigDetailAPIView.as_view(), name="system-config-detail"),

    # Feature flags
    path("feature-flags/", FeatureFlagListAPIView.as_view(), name="feature-flag-list"),
    path("feature-flags/<str:key>/", FeatureFlagDetailAPIView.as_view(), name="feature-flag-detail"),
    path("feature-flags/<str:key>/toggle/", FeatureFlagToggleAPIView.as_view(), name="feature-flag-toggle"),

    # Audit & event logs (read-only)
    path("audit-logs/", AuditLogListAPIView.as_view(), name="audit-log-list"),
    path("event-logs/", SystemEventLogListAPIView.as_view(), name="event-log-list"),
]
