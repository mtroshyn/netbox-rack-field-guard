from types import SimpleNamespace
import pytest

from rack_field_guard.validators import (
    _validate_rules,
    _get_allowed_cf_for_user,
    RackFieldWriteGuard,
)


def test_validate_rules_happy():
    """Test valid rules configuration."""
    rules = [
        {"group_name": "A", "allowed_cf": ["x", "y"]},
        {"group_name": "B", "allowed_cf": ["z"]},
    ]
    assert _validate_rules(rules) is None


def test_validate_rules_empty_list():
    """Test empty rules list (should be valid)."""
    assert _validate_rules([]) is None


@pytest.mark.parametrize(
    "rules,expected",
    [
        (None, None),  # None is treated as disabled
        ("oops", "RULES must be a list of rule objects."),
        (["oops"], "RULES[0] must be an object."),
        ([{}], "RULES[0].group_name must be a non-empty string."),
        (
            [{"group_name": "A"}],
            "RULES[0].allowed_cf must be a list of custom field slugs.",
        ),
        ([{"group_name": ""}], "RULES[0].group_name must be a non-empty string."),
        (
            [{"group_name": "A", "allowed_cf": "not_a_list"}],
            "RULES[0].allowed_cf must be a list of custom field slugs.",
        ),
        ([{"group_name": "A", "allowed_cf": []}], None),  # Empty allowed_cf is valid
    ],
)
def test_validate_rules_errors(rules, expected):
    """Test various invalid rule configurations."""
    assert _validate_rules(rules) == expected


def test_get_allowed_cf_for_user_union():
    """Test that users get union of allowed CFs from all matching groups."""
    user = SimpleNamespace()
    user.groups = SimpleNamespace(values_list=lambda *args, **kwargs: ["A", "C"])

    rules = [
        {"group_name": "A", "allowed_cf": ["x", "y"]},
        {"group_name": "B", "allowed_cf": ["z"]},
        {"group_name": "C", "allowed_cf": ["w"]},
    ]
    allowed = _get_allowed_cf_for_user(rules, user)
    assert allowed == {"x", "y", "w"}


def test_get_allowed_cf_for_user_no_matches():
    """Test user not in any configured groups."""
    user = SimpleNamespace()
    user.groups = SimpleNamespace(values_list=lambda *args, **kwargs: ["OtherGroup"])

    rules = [
        {"group_name": "A", "allowed_cf": ["x", "y"]},
        {"group_name": "B", "allowed_cf": ["z"]},
    ]
    allowed = _get_allowed_cf_for_user(rules, user)
    assert allowed == set()


def test_get_allowed_cf_for_user_empty_rules():
    """Test with empty rules list."""
    user = SimpleNamespace()
    user.groups = SimpleNamespace(values_list=lambda *args, **kwargs: ["A"])

    allowed = _get_allowed_cf_for_user([], user)
    assert allowed == set()


class DummyRack:
    """Mock Rack instance for testing."""

    def __init__(self, pk, custom_field_data=None, **fields):
        self.pk = pk
        self.custom_field_data = custom_field_data or {}
        self._fields = fields

        # Simulate Django model meta
        class F:
            def __init__(self, name):
                self.name = name

        self._meta = SimpleNamespace(concrete_fields=[F(k) for k in fields.keys()])

    def __getattr__(self, item):
        if item in self._fields:
            return self._fields[item]
        raise AttributeError


class TestRackFieldWriteGuard:
    """Test the main validator class."""

    def setup_method(self):
        """Set up common test fixtures."""
        self.original = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r1"
        )

        # Mock Rack model
        class R:
            objects = SimpleNamespace(get=lambda pk: self.original)

        self.rack_model = R

    def test_empty_rules_skips_enforcement(self, mocker):
        """Test that empty RULES skips all enforcement."""

        class S:
            PLUGINS_CONFIG = {"rack_field_guard": {"RULES": []}}

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # Even changing built-in fields should be allowed when RULES is empty
        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_missing_rules_skips_enforcement(self, mocker):
        """Test that missing RULES skips all enforcement."""

        class S:
            PLUGINS_CONFIG = {"rack_field_guard": {}}

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_admin_bypass(self, mocker):
        """Test that superusers and staff bypass all restrictions."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        # Test superuser
        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=True,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: []),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 9}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

        # Test staff
        user.is_superuser = False
        user.is_staff = True
        v.validate(updated, request)  # Should not raise

    def test_unauthenticated_user_skips_enforcement(self, mocker):
        """Test that unauthenticated users are not restricted."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=False,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 9}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_no_request_skips_enforcement(self, mocker):
        """Test that missing request skips enforcement."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 9}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, None)  # Should not raise

    def test_user_not_in_configured_groups_skips_enforcement(self, mocker):
        """Test that users not in any configured group are not restricted."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["OtherGroup"]),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 9}, name="r2"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_creation_denied(self, mocker):
        """Test that rack creation is denied for configured groups."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # New rack (pk=None)
        new_rack = DummyRack(
            pk=None, custom_field_data={"cf_allowed": 1}, name="new_rack"
        )
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RFG-CREATE-DENIED"):
            v.validate(new_rack, request)

    def test_original_not_found(self, mocker):
        """Test behavior when original rack cannot be found."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)

        # Mock Rack.objects.get to raise DoesNotExist
        class DoesNotExist(Exception):
            pass

        class R:
            class DoesNotExist(Exception):
                pass

            objects = SimpleNamespace(
                get=lambda pk: (_ for _ in ()).throw(R.DoesNotExist("DoesNotExist"))
            )

        mocker.patch("rack_field_guard.validators.Rack", R)
        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(pk=999, custom_field_data={"cf_allowed": 1}, name="r1")
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RFG-ORIGINAL-NOT-FOUND"):
            v.validate(updated, request)

    def test_builtin_field_change_denied(self, mocker):
        """Test that built-in field changes are denied."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # Change built-in field (name)
        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r2"
        )
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RFG-BUILTIN-DENIED"):
            v.validate(updated, request)

    def test_allowed_custom_field_change(self, mocker):
        """Test that allowed custom field changes are permitted."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # Change only allowed custom field
        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 3, "cf_blocked": 2}, name="r1"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_disallowed_custom_field_change(self, mocker):
        """Test that disallowed custom field changes are denied."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # Change disallowed custom field
        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 9}, name="r1"
        )
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RFG-CF-DENIED"):
            v.validate(updated, request)

    def test_multiple_custom_field_changes(self, mocker):
        """Test behavior with multiple custom field changes."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [
                        {
                            "group_name": "G1",
                            "allowed_cf": ["cf_allowed", "cf_also_allowed"],
                        }
                    ]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # Change both allowed and disallowed custom fields
        updated = DummyRack(
            pk=1,
            custom_field_data={"cf_allowed": 3, "cf_also_allowed": 4, "cf_blocked": 9},
            name="r1",
        )
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RFG-CF-DENIED"):
            v.validate(updated, request)

    def test_no_custom_field_changes(self, mocker):
        """Test that no custom field changes are allowed when no changes are made."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1", "allowed_cf": ["cf_allowed"]}]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        # No changes at all
        updated = DummyRack(
            pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r1"
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

    def test_invalid_rules_configuration(self, mocker):
        """Test that invalid RULES configuration causes validation to fail."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [{"group_name": "G1"}]  # Missing allowed_cf
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)

        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1"]),
        )
        request = SimpleNamespace(user=user)

        updated = DummyRack(pk=1, custom_field_data={"cf_allowed": 1}, name="r1")
        v = RackFieldWriteGuard()

        with pytest.raises(Exception, match="RULES\\[0\\]\\.allowed_cf must be a list"):
            v.validate(updated, request)

    def test_multiple_groups_union(self, mocker):
        """Test that users in multiple groups get union of allowed custom fields."""

        class S:
            PLUGINS_CONFIG = {
                "rack_field_guard": {
                    "RULES": [
                        {"group_name": "G1", "allowed_cf": ["cf_allowed"]},
                        {"group_name": "G2", "allowed_cf": ["cf_also_allowed"]},
                    ]
                }
            }

        mocker.patch("rack_field_guard.validators.settings", S)
        mocker.patch("rack_field_guard.validators.Rack", self.rack_model)

        # User in both groups
        user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            is_staff=False,
            groups=SimpleNamespace(values_list=lambda *args, **kwargs: ["G1", "G2"]),
        )
        request = SimpleNamespace(user=user)

        # Should be able to change both allowed custom fields
        updated = DummyRack(
            pk=1,
            custom_field_data={"cf_allowed": 3, "cf_also_allowed": 4, "cf_blocked": 2},
            name="r1",
        )
        v = RackFieldWriteGuard()
        v.validate(updated, request)  # Should not raise

        # But not disallowed ones
        updated2 = DummyRack(
            pk=1,
            custom_field_data={"cf_allowed": 1, "cf_also_allowed": 2, "cf_blocked": 9},
            name="r1",
        )
        with pytest.raises(Exception, match="RFG-CF-DENIED"):
            v.validate(updated2, request)
