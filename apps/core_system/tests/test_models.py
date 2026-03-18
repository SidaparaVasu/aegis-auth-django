"""
Unit tests for core_system models.

Tests verify:
    - AuditLog append-only enforcement (save raises on update, delete raises always)
    - Model string representations
    - SystemConfig and FeatureFlag field behaviour
"""

from django.test import TestCase
from apps.core_system.models import SystemConfig, FeatureFlag, AuditLog, SystemEventLog
from apps.core_system.constants import (
    ConfigValueType, FeatureFlagScope, AuditAction, EventSeverity
)


# ---------------------------------------------------------------------------
# AuditLog — append-only enforcement
# ---------------------------------------------------------------------------

class AuditLogAppendOnlyTest(TestCase):

    def _create_log(self, **kwargs):
        defaults = dict(
            action=AuditAction.LOGIN,
            module="auth_security",
            user_id=1,
            entity_type="AuthUser",
            entity_id="1",
        )
        defaults.update(kwargs)
        return AuditLog.objects.create(**defaults)

    def test_create_audit_log_succeeds(self):
        log = self._create_log()
        self.assertIsNotNone(log.pk)

    def test_save_existing_log_raises_permission_error(self):
        """Updating an existing AuditLog must raise PermissionError."""
        log = self._create_log()
        log.action = AuditAction.LOGOUT
        with self.assertRaises(PermissionError):
            log.save()

    def test_delete_audit_log_raises_permission_error(self):
        """Deleting an AuditLog must raise PermissionError."""
        log = self._create_log()
        with self.assertRaises(PermissionError):
            log.delete()

    def test_str_representation(self):
        log = self._create_log()
        self.assertIn("LOGIN", str(log))
        self.assertIn("auth_security", str(log))


# ---------------------------------------------------------------------------
# SystemConfig model
# ---------------------------------------------------------------------------

class SystemConfigModelTest(TestCase):

    def test_str_representation(self):
        config = SystemConfig.objects.create(
            config_key="TEST_KEY",
            config_value="test_value",
            value_type=ConfigValueType.STRING,
        )
        self.assertEqual(str(config), "TEST_KEY = test_value")

    def test_config_key_is_unique(self):
        from django.db import IntegrityError
        SystemConfig.objects.create(
            config_key="UNIQUE_KEY",
            config_value="v1",
            value_type=ConfigValueType.STRING,
        )
        with self.assertRaises(IntegrityError):
            SystemConfig.objects.create(
                config_key="UNIQUE_KEY",
                config_value="v2",
                value_type=ConfigValueType.STRING,
            )

    def test_default_is_active_is_true(self):
        config = SystemConfig.objects.create(
            config_key="ACTIVE_TEST",
            config_value="1",
            value_type=ConfigValueType.INTEGER,
        )
        self.assertTrue(config.is_active)

    def test_created_at_and_updated_at_auto_set(self):
        config = SystemConfig.objects.create(
            config_key="TIMESTAMP_TEST",
            config_value="x",
            value_type=ConfigValueType.STRING,
        )
        self.assertIsNotNone(config.created_at)
        self.assertIsNotNone(config.updated_at)


# ---------------------------------------------------------------------------
# FeatureFlag model
# ---------------------------------------------------------------------------

class FeatureFlagModelTest(TestCase):

    def test_str_representation_enabled(self):
        flag = FeatureFlag.objects.create(
            feature_key="my_feature",
            is_enabled=True,
            target_scope=FeatureFlagScope.GLOBAL,
        )
        self.assertIn("✓", str(flag))
        self.assertIn("my_feature", str(flag))

    def test_str_representation_disabled(self):
        flag = FeatureFlag.objects.create(
            feature_key="off_feature",
            is_enabled=False,
            target_scope=FeatureFlagScope.GLOBAL,
        )
        self.assertIn("✗", str(flag))

    def test_feature_key_is_unique(self):
        from django.db import IntegrityError
        FeatureFlag.objects.create(
            feature_key="dup_feature",
            target_scope=FeatureFlagScope.GLOBAL,
        )
        with self.assertRaises(IntegrityError):
            FeatureFlag.objects.create(
                feature_key="dup_feature",
                target_scope=FeatureFlagScope.GLOBAL,
            )

    def test_default_is_enabled_is_false(self):
        flag = FeatureFlag.objects.create(
            feature_key="new_feature",
            target_scope=FeatureFlagScope.GLOBAL,
        )
        self.assertFalse(flag.is_enabled)


# ---------------------------------------------------------------------------
# SystemEventLog model
# ---------------------------------------------------------------------------

class SystemEventLogModelTest(TestCase):

    def test_create_event_log(self):
        log = SystemEventLog.objects.create(
            event_type="TEST_EVENT",
            severity=EventSeverity.INFO,
            module="core_system",
            message="Test message",
        )
        self.assertIsNotNone(log.pk)
        self.assertIn("TEST_EVENT", str(log))
        self.assertIn("INFO", str(log))

    def test_payload_stored_as_json(self):
        payload = {"key": "value", "count": 42}
        log = SystemEventLog.objects.create(
            event_type="JSON_TEST",
            severity=EventSeverity.WARNING,
            module="core_system",
            message="Test",
            payload=payload,
        )
        reloaded = SystemEventLog.objects.get(pk=log.pk)
        self.assertEqual(reloaded.payload, payload)
