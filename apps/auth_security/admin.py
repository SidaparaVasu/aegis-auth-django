"""
auth_security Django Admin registrations.

Rules:
    - AuthUser admin uses Django's password hashing — never plain text.
    - AuthOTPVerification is read-only (otp_code is sensitive).
    - AuthLoginAttempt is read-only (append-only brute-force log).
    - AuthAccountLock allows manual unlock (delete).
    - AuthPasswordPolicy allows in-admin editing like SystemConfig.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import (
    AuthUser,
    AuthUserProfile,
    AuthPasswordHistory,
    AuthOTPVerification,
    AuthSessionLog,
    AuthLoginAttempt,
    AuthPasswordPolicy,
    AuthAccountLock,
)


# ---------------------------------------------------------------------------
# AuthUser
# ---------------------------------------------------------------------------

class AuthUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = AuthUser
        fields = ("email", "username")


class AuthUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = AuthUser
        fields = "__all__"


class AuthUserProfileInline(admin.StackedInline):
    model = AuthUserProfile
    can_delete = False
    verbose_name_plural = "Profile"
    extra = 0


@admin.register(AuthUser)
class AuthUserAdmin(BaseUserAdmin):
    form = AuthUserChangeForm
    add_form = AuthUserCreationForm
    inlines = [AuthUserProfileInline]

    list_display = ("email", "username", "is_active", "is_staff", "is_superuser", "created_at")
    list_filter = ("is_active", "is_staff", "is_superuser")
    search_fields = ("email", "username")
    ordering = ("email",)
    readonly_fields = ("created_at", "updated_at", "last_login")

    fieldsets = (
        ("Credentials", {"fields": ("email", "username", "password")}),
        ("Status", {"fields": ("is_active", "is_staff", "is_superuser")}),
        ("Permissions", {"fields": ("groups", "user_permissions"), "classes": ("collapse",)}),
        ("Timestamps", {"fields": ("last_login", "created_at", "updated_at"), "classes": ("collapse",)}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "username", "password1", "password2"),
        }),
    )


# ---------------------------------------------------------------------------
# AuthUserProfile
# ---------------------------------------------------------------------------

@admin.register(AuthUserProfile)
class AuthUserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "first_name", "last_name", "phone_number", "gender", "updated_at")
    search_fields = ("user__email", "user__username", "first_name", "last_name", "phone_number")
    readonly_fields = ("created_at", "updated_at")
    raw_id_fields = ("user",)


# ---------------------------------------------------------------------------
# AuthPasswordHistory — READ ONLY (sensitive historical hashes)
# ---------------------------------------------------------------------------

@admin.register(AuthPasswordHistory)
class AuthPasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ("user", "created_at")
    search_fields = ("user__email",)
    readonly_fields = ("user", "password_hash", "created_at")
    ordering = ("-created_at",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# ---------------------------------------------------------------------------
# AuthOTPVerification — READ ONLY (otp_code is sensitive)
# ---------------------------------------------------------------------------

@admin.register(AuthOTPVerification)
class AuthOTPVerificationAdmin(admin.ModelAdmin):
    list_display = ("user", "purpose", "email", "is_verified", "expires_at", "created_at")
    list_filter = ("purpose", "is_verified")
    search_fields = ("user__email", "email")
    readonly_fields = ("user", "email", "otp_code", "purpose", "expires_at", "is_verified", "created_at")
    ordering = ("-created_at",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# ---------------------------------------------------------------------------
# AuthSessionLog — READ ONLY
# ---------------------------------------------------------------------------

@admin.register(AuthSessionLog)
class AuthSessionLogAdmin(admin.ModelAdmin):
    list_display = ("user", "ip_address", "is_active", "login_at", "logout_at")
    list_filter = ("is_active",)
    search_fields = ("user__email", "ip_address")
    readonly_fields = ("user", "session_key", "ip_address", "user_agent", "login_at", "logout_at", "is_active")
    ordering = ("-login_at",)
    date_hierarchy = "login_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# ---------------------------------------------------------------------------
# AuthLoginAttempt — READ ONLY (append-only brute-force log)
# ---------------------------------------------------------------------------

@admin.register(AuthLoginAttempt)
class AuthLoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("email", "ip_address", "attempt_status", "attempt_time")
    list_filter = ("attempt_status",)
    search_fields = ("email", "ip_address")
    readonly_fields = ("email", "ip_address", "attempt_status", "attempt_time")
    ordering = ("-attempt_time",)
    date_hierarchy = "attempt_time"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


# ---------------------------------------------------------------------------
# AuthPasswordPolicy — editable by admin
# ---------------------------------------------------------------------------

@admin.register(AuthPasswordPolicy)
class AuthPasswordPolicyAdmin(admin.ModelAdmin):
    list_display = ("policy_key", "policy_value", "description", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("policy_key", "description")
    readonly_fields = ("created_at",)
    ordering = ("policy_key",)
    fieldsets = (
        ("Policy", {"fields": ("policy_key", "policy_value", "description")}),
        ("Status", {"fields": ("is_active",)}),
        ("Timestamps", {"fields": ("created_at",), "classes": ("collapse",)}),
    )


# ---------------------------------------------------------------------------
# AuthAccountLock — Admin can manually unlock
# ---------------------------------------------------------------------------

@admin.register(AuthAccountLock)
class AuthAccountLockAdmin(admin.ModelAdmin):
    list_display = ("user", "locked_until", "reason", "is_currently_active", "created_at")
    search_fields = ("user__email", "reason")
    readonly_fields = ("user", "created_at")
    ordering = ("-created_at",)

    @admin.display(boolean=True, description="Currently Locked")
    def is_currently_active(self, obj):
        return obj.is_active

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
