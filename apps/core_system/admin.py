"""
core_system Django Admin registrations.

Rules:
    - AuditLog is read-only (no add/change/delete in admin).
    - SystemEventLog is read-only.
    - All list views have search, filter, and ordering.
"""

from django.contrib import admin
from .models import SystemConfig, FeatureFlag, AuditLog, SystemEventLog


# ---------------------------------------------------------------------------
# SystemConfig
# ---------------------------------------------------------------------------

@admin.register(SystemConfig)
class SystemConfigAdmin(admin.ModelAdmin):
    list_display = ("config_key", "config_value", "value_type", "config_group", "is_active", "updated_at")
    list_filter = ("value_type", "config_group", "is_active")
    search_fields = ("config_key", "description", "config_value")
    ordering = ("config_group", "config_key")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        ("Key", {"fields": ("config_key", "value_type", "config_group")}),
        ("Value", {"fields": ("config_value", "description")}),
        ("Status", {"fields": ("is_active",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at"), "classes": ("collapse",)}),
    )


# ---------------------------------------------------------------------------
# FeatureFlag
# ---------------------------------------------------------------------------

@admin.register(FeatureFlag)
class FeatureFlagAdmin(admin.ModelAdmin):
    list_display = ("feature_key", "is_enabled", "target_scope", "rollout_percentage", "updated_at")
    list_filter = ("is_enabled", "target_scope")
    search_fields = ("feature_key", "description")
    ordering = ("feature_key",)
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        ("Flag", {"fields": ("feature_key", "description")}),
        ("Rollout", {"fields": ("is_enabled", "target_scope", "rollout_percentage")}),
        ("Timestamps", {"fields": ("created_at", "updated_at"), "classes": ("collapse",)}),
    )


# ---------------------------------------------------------------------------
# AuditLog — READ ONLY (append-only table)
# ---------------------------------------------------------------------------

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "module", "entity_type", "entity_id", "user_id", "ip_address", "created_at")
    list_filter = ("action", "module")
    search_fields = ("action", "module", "entity_type", "entity_id", "ip_address")
    ordering = ("-created_at",)
    readonly_fields = (
        "user_id", "action", "module", "entity_type", "entity_id",
        "old_value", "new_value", "ip_address", "user_agent", "created_at",
    )
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


# ---------------------------------------------------------------------------
# SystemEventLog — READ ONLY
# ---------------------------------------------------------------------------

@admin.register(SystemEventLog)
class SystemEventLogAdmin(admin.ModelAdmin):
    list_display = ("severity", "event_type", "module", "message", "created_at")
    list_filter = ("severity", "module")
    search_fields = ("event_type", "module", "message")
    ordering = ("-created_at",)
    readonly_fields = ("event_type", "severity", "module", "message", "payload", "created_at")
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
