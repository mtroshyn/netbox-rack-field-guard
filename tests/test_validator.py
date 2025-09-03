from types import SimpleNamespace

import pytest

from rack_field_guard.validators import _validate_rules, _get_allowed_cf_for_user, RackFieldWriteGuard


def test_validate_rules_happy():
    rules = [
        {"group_name": "A", "allowed_cf": ["x", "y"]},
        {"group_name": "B", "allowed_cf": ["z"]},
    ]
    assert _validate_rules(rules) is None


@pytest.mark.parametrize(
    "rules,expected",
    [
        (None, "Missing RULES in plugin configuration."),
        ("oops", "RULES must be a list of rule objects."),
        (["oops"], "RULES[0] must be an object."),
        ([{}], "RULES[0].group_name must be a non-empty string."),
        ([{"group_name": "A"}], "RULES[0].allowed_cf must be a list of custom field slugs."),
    ],
)
def test_validate_rules_errors(rules, expected):
    assert _validate_rules(rules) == expected


def test_get_allowed_cf_for_user_union(mocker):
    user = SimpleNamespace()
    # Mock groups.values_list to return names
    user.groups = SimpleNamespace(values_list=lambda *args, **kwargs: [
        ("A"), ("C"),
    ])
    rules = [
        {"group_name": "A", "allowed_cf": ["x", "y"]},
        {"group_name": "B", "allowed_cf": ["z"]},
        {"group_name": "C", "allowed_cf": ["w"]},
    ]
    allowed = _get_allowed_cf_for_user(rules, user)
    assert allowed == {"x", "y", "w"}


class DummyQuerySet:
    def __init__(self, obj):
        self._obj = obj

    def get(self, pk):
        if self._obj and self._obj.pk == pk:
            return self._obj
        raise Exception("DoesNotExist")


class DummyRack:
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


def test_validator_allows_only_configured_cf(mocker, monkeypatch):
    # Configure RULES
    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "dummy")
    # Mock settings.PLUGINS_CONFIG
    class S:
        PLUGINS_CONFIG = {
            "rack_field_guard": {
                "RULES": [
                    {"group_name": "G1", "allowed_cf": ["cf_allowed"]},
                ]
            }
        }

    mocker.patch("rack_field_guard.validators.settings", S)

    # Prepare original and updated instances
    original = DummyRack(pk=1, custom_field_data={"cf_allowed": 1, "cf_blocked": 2}, name="r1")
    updated = DummyRack(pk=1, custom_field_data={"cf_allowed": 3, "cf_blocked": 2}, name="r1")

    # Patch Rack model access
    class R:
        objects = SimpleNamespace(get=lambda pk: original)

    mocker.patch("rack_field_guard.validators.Rack", R)

    # Mock user and request
    class Groups:
        def values_list(self, *args, **kwargs):
            return ["G1"]

    user = SimpleNamespace(is_authenticated=True, is_superuser=False, is_staff=False, groups=Groups())
    request = SimpleNamespace(user=user)

    v = RackFieldWriteGuard()
    # Should not raise for allowed CF change
    v.validate(updated, request)

    # Now attempt to change a built-in field
    updated2 = DummyRack(pk=1, custom_field_data={"cf_allowed": 3, "cf_blocked": 2}, name="r2")
    with pytest.raises(Exception):
        v.validate(updated2, request)

    # Now attempt to change a disallowed CF
    updated3 = DummyRack(pk=1, custom_field_data={"cf_allowed": 3, "cf_blocked": 9}, name="r1")
    with pytest.raises(Exception):
        v.validate(updated3, request)


