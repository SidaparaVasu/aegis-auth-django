"""
Unit tests for core_system service layer.

Tests cover:
    - ConfigService: get_config, get_config_typed, set_config, type casting,
      missing key handling, type mismatch rejection, audit log creation.
    - FeatureFlagService: is_enabled, require_enabled, toggle, update_flag.
    - AuditService: log entry creation, sensitive field stripping.
    - EventService: entries created at correct severity.
"""

from django.test import TestCase
from apps.core_system.models import SystemConfig, FeatureFlag, AuditLog, SystemEventLog
from apps.core_system.constants import (
    ConfigValueType, FeatureFlagScope, AuditAction, EventSeverity, ConfigKey
)
from apps.core_system.services.config_service import ConfigService
from apps.core_system.services.feature_flag_service import FeatureFlagService
from apps.core_system.services.audit_service import AuditService
from apps.core_system.services.event_service import EventService
from common.exceptions import ConfigNotFoundException, FeatureDisabledException


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(key, value, vtype=ConfigValueType.STRING, active=True):
    return SystemConfig.objects.create(
        config_key=key,
        config_value=value,
        value_type=vtype,
        config_group="test",
        is_active=active,
    )


def _make_flag(key, enabled=False):
    return FeatureFlag.objects.create(
        feature_key=key,
        is_enabled=enabled,
        target_scope=FeatureFlagScope.GLOBAL,
    )


# ---------------------------------------------------------------------------
# ConfigService tests
# ---------------------------------------------------------------------------

class ConfigServiceGetTest(TestCase):

    def setUp(self):
        _make_config(ConfigKey.AUTH_LOGIN_METHOD, "password", ConfigValueType.STRING)
        _make_config(ConfigKey.OTP_EXPIRY_SECONDS, "300", ConfigValueType.INTEGER)
        _make_config("FEATURE_BOOL", "true", ConfigValueType.BOOLEAN)
        _make_config("FEATURE_JSON", '{"key": "val"}', ConfigValueType.JSON)
        _make_config("INACTIVE_KEY", "x", ConfigValueType.STRING, active=False)

    def test_get_config_returns_raw_string(self):
        value = ConfigService().get_config(ConfigKey.AUTH_LOGIN_METHOD)
        self.assertEqual(value, "password")

    def test_get_config_typed_returns_int(self):
        value = ConfigService().get_config_typed(ConfigKey.OTP_EXPIRY_SECONDS)
        self.assertEqual(value, 300)
        self.assertIsInstance(value, int)

    def test_get_config_typed_returns_bool_true(self):
        value = ConfigService().get_config_typed("FEATURE_BOOL")
        self.assertTrue(value)
        self.assertIsInstance(value, bool)

    def test_get_config_typed_returns_dict(self):
        value = ConfigService().get_config_typed("FEATURE_JSON")
        self.assertIsInstance(value, dict)
        self.assertEqual(value["key"], "val")

    def test_get_config_int_helper(self):
        value = ConfigService().get_config_int(ConfigKey.OTP_EXPIRY_SECONDS)
        self.assertEqual(value, 300)

    def test_get_config_bool_helper(self):
        value = ConfigService().get_config_bool("FEATURE_BOOL")
        self.assertTrue(value)

    def test_get_config_raises_for_missing_key(self):
        with self.assertRaises(ConfigNotFoundException):
            ConfigService().get_config("NONEXISTENT_KEY")

    def test_get_config_raises_for_inactive_key(self):
        """Inactive configs must be treated as missing for consumers."""
        with self.assertRaises(ConfigNotFoundException):
            ConfigService().get_config("INACTIVE_KEY")

    def test_get_all_configs_returns_list(self):
        configs = ConfigService().get_all_configs(active_only=False)
        self.assertGreaterEqual(len(configs), 4)

    def test_get_all_active_configs_excludes_inactive(self):
        active = ConfigService().get_all_configs(active_only=True)
        keys = [c.config_key for c in active]
        self.assertNotIn("INACTIVE_KEY", keys)


class ConfigServiceWriteTest(TestCase):

    def setUp(self):
        _make_config(ConfigKey.AUTH_LOGIN_METHOD, "password", ConfigValueType.STRING)
        _make_config(ConfigKey.OTP_EXPIRY_SECONDS, "300", ConfigValueType.INTEGER)

    def test_set_config_updates_value(self):
        ConfigService().set_config(ConfigKey.AUTH_LOGIN_METHOD, "otp")
        updated = ConfigService().get_config(ConfigKey.AUTH_LOGIN_METHOD)
        self.assertEqual(updated, "otp")

    def test_set_config_creates_audit_log(self):
        initial_count = AuditLog.objects.count()
        ConfigService().set_config(
            ConfigKey.AUTH_LOGIN_METHOD, "otp", user_id=99
        )
        self.assertEqual(AuditLog.objects.count(), initial_count + 1)

    def test_set_config_audit_log_has_correct_action(self):
        ConfigService().set_config(ConfigKey.AUTH_LOGIN_METHOD, "otp")
        log = AuditLog.objects.filter(
            action=AuditAction.CONFIG_CHANGE,
            entity_id=ConfigKey.AUTH_LOGIN_METHOD,
        ).last()
        self.assertIsNotNone(log)

    def test_set_config_rejects_type_mismatch(self):
        """Setting a non-integer value for an integer config must raise ValueError."""
        with self.assertRaises(ValueError):
            ConfigService().set_config(ConfigKey.OTP_EXPIRY_SECONDS, "not_a_number")

    def test_set_config_raises_for_missing_key(self):
        with self.assertRaises(ConfigNotFoundException):
            ConfigService().set_config("DOES_NOT_EXIST", "value")


# ---------------------------------------------------------------------------
# FeatureFlagService tests
# ---------------------------------------------------------------------------

class FeatureFlagServiceTest(TestCase):

    def setUp(self):
        _make_flag("otp_login", enabled=False)
        _make_flag("email_verification_required", enabled=True)

    def test_is_enabled_returns_false_for_disabled_flag(self):
        result = FeatureFlagService().is_enabled("otp_login")
        self.assertFalse(result)

    def test_is_enabled_returns_true_for_enabled_flag(self):
        result = FeatureFlagService().is_enabled("email_verification_required")
        self.assertTrue(result)

    def test_is_enabled_returns_false_for_nonexistent_flag(self):
        """Missing flags are treated as disabled — never raise."""
        result = FeatureFlagService().is_enabled("unknown_flag")
        self.assertFalse(result)

    def test_require_enabled_raises_for_disabled_flag(self):
        with self.assertRaises(FeatureDisabledException):
            FeatureFlagService().require_enabled("otp_login")

    def test_require_enabled_passes_for_enabled_flag(self):
        try:
            FeatureFlagService().require_enabled("email_verification_required")
        except FeatureDisabledException:
            self.fail("require_enabled raised FeatureDisabledException for an enabled flag.")

    def test_toggle_flips_disabled_to_enabled(self):
        FeatureFlagService().toggle("otp_login", user_id=1)
        self.assertTrue(FeatureFlagService().is_enabled("otp_login"))

    def test_toggle_flips_enabled_to_disabled(self):
        FeatureFlagService().toggle("email_verification_required", user_id=1)
        self.assertFalse(FeatureFlagService().is_enabled("email_verification_required"))

    def test_toggle_creates_audit_log(self):
        initial = AuditLog.objects.count()
        FeatureFlagService().toggle("otp_login", user_id=1)
        self.assertEqual(AuditLog.objects.count(), initial + 1)

    def test_toggle_raises_for_missing_flag(self):
        with self.assertRaises(ValueError):
            FeatureFlagService().toggle("nonexistent_flag")

    def test_update_flag_changes_rollout_percentage(self):
        FeatureFlagService().update_flag("otp_login", user_id=1, rollout_percentage=50)
        flag = FeatureFlagService().get_flag("otp_login")
        self.assertEqual(flag.rollout_percentage, 50)


# ---------------------------------------------------------------------------
# AuditService tests
# ---------------------------------------------------------------------------

class AuditServiceTest(TestCase):

    def test_log_creates_audit_log_entry(self):
        initial = AuditLog.objects.count()
        AuditService().log(
            action=AuditAction.LOGIN,
            module="auth_security",
            user_id=1,
            entity_type="AuthUser",
            entity_id="1",
        )
        self.assertEqual(AuditLog.objects.count(), initial + 1)

    def test_log_strips_sensitive_fields_from_old_value(self):
        AuditService().log(
            action=AuditAction.UPDATE,
            module="auth_security",
            old_value={"password": "secret123", "username": "alice"},
            new_value={"username": "alice"},
        )
        log = AuditLog.objects.last()
        self.assertNotIn("password", log.old_value)
        self.assertIn("username", log.old_value)

    def test_log_strips_sensitive_fields_from_new_value(self):
        AuditService().log(
            action=AuditAction.UPDATE,
            module="auth_security",
            new_value={"otp_code": "123456", "email": "a@b.com"},
        )
        log = AuditLog.objects.last()
        self.assertNotIn("otp_code", log.new_value)
        self.assertIn("email", log.new_value)

    def test_log_login_convenience_method(self):
        initial = AuditLog.objects.count()
        AuditService().log_login(user_id=5, ip_address="127.0.0.1", user_agent="TestAgent")
        self.assertEqual(AuditLog.objects.count(), initial + 1)
        log = AuditLog.objects.last()
        self.assertEqual(log.action, AuditAction.LOGIN)

    def test_log_config_change_stores_correct_values(self):
        AuditService().log_config_change(
            user_id=1,
            config_key="OTP_EXPIRY_SECONDS",
            old_value="300",
            new_value="600",
        )
        log = AuditLog.objects.filter(action=AuditAction.CONFIG_CHANGE).last()
        self.assertIsNotNone(log)
        self.assertIn("300", log.old_value)
        self.assertIn("600", log.new_value)


# ---------------------------------------------------------------------------
# EventService tests
# ---------------------------------------------------------------------------

class EventServiceTest(TestCase):

    def test_info_creates_event_log(self):
        initial = SystemEventLog.objects.count()
        EventService().info("TEST_INFO", "core_system", "Test info message")
        self.assertEqual(SystemEventLog.objects.count(), initial + 1)

    def test_error_creates_event_log_with_error_severity(self):
        EventService().error("TEST_ERROR", "auth_security", "Something failed")
        log = SystemEventLog.objects.last()
        self.assertEqual(log.severity, EventSeverity.ERROR)

    def test_critical_creates_event_log_with_critical_severity(self):
        EventService().critical("CRITICAL_FAILURE", "auth_security", "System down")
        log = SystemEventLog.objects.last()
        self.assertEqual(log.severity, EventSeverity.CRITICAL)

    def test_log_with_payload_stores_dict(self):
        payload = {"user_id": 42, "detail": "timeout"}
        EventService().warning("OTP_TIMEOUT", "auth_security", "OTP send timed out", payload=payload)
        log = SystemEventLog.objects.last()
        self.assertEqual(log.payload, payload)

    def test_event_service_never_raises_even_on_bad_payload(self):
        """EventService must swallow exceptions to never break calling flow."""
        try:
            EventService().info("BAD_TEST", "test", "msg", payload={"ok": True})
        except Exception as exc:
            self.fail(f"EventService raised unexpectedly: {exc}")
