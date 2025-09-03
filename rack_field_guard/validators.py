from django.conf import settings
from dcim.models import Rack
from extras.validators import CustomValidator
from typing import Iterable, Dict, Any, Optional, Set

def _cfg():
    return getattr(settings, "PLUGINS_CONFIG", {}).get("rack_field_guard", {})


def _validate_rules(rules: Any) -> Optional[str]:
    """
    Validate RULES config. Expected format:
    RULES = [
        {"group_name": "Client Service", "allowed_cf": ["soldRackPowerCommit", "another_cf"]},
        {"group_name": "Other Group", "allowed_cf": ["cf1"]},
    ]
    Returns error string if invalid, else None.
    """
    if rules is None:
        # Treat missing as disabled; caller should skip logic.
        return None
    if not isinstance(rules, Iterable) or isinstance(rules, (str, bytes)):
        return "RULES must be a list of rule objects."
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return f"RULES[{idx}] must be an object."
        if "group_name" not in rule or not isinstance(rule["group_name"], str) or not rule["group_name"].strip():
            return f"RULES[{idx}].group_name must be a non-empty string."
        if "allowed_cf" not in rule or not isinstance(rule["allowed_cf"], Iterable) or isinstance(rule["allowed_cf"], (str, bytes)):
            return f"RULES[{idx}].allowed_cf must be a list of custom field slugs."
    return None


def _get_allowed_cf_for_user(rules: Iterable[Dict[str, Any]], user) -> Set[str]:
    """
    Return the union of allowed CF slugs for all rules matching user's groups.
    """
    allowed: Set[str] = set()
    user_group_names = set(user.groups.values_list("name", flat=True))
    for rule in rules:
        group_name = rule.get("group_name")
        if group_name in user_group_names:
            allowed.update([str(slug) for slug in rule.get("allowed_cf", [])])
    return allowed

class RackFieldWriteGuard(CustomValidator):
    """
    Enforce that users can only modify allowed custom fields on dcim.Rack per-group rules.
    RULES config defines which groups may modify which custom field slugs.
    Applies to both UI and REST API.
    """

    def validate(self, instance, request):
        cfg = _cfg()
        rules = cfg.get("RULES")

        # If RULES is missing or empty, skip enforcement entirely
        if not rules:
            return

        err = _validate_rules(rules)
        if err:
            self.fail(err)
            return

        if not request or not request.user.is_authenticated:
            return

        user = request.user

        # Admins bypass
        if user.is_superuser or user.is_staff:
            return

        # Compute allowed CFs for this user via matching group rules
        allowed_cf_set = _get_allowed_cf_for_user(rules, user)
        if not allowed_cf_set:
            # User not in any configured group -> skip enforcement
            return

        # On create: deny by default; adjust if creation should be allowed
        if instance.pk is None:
            self.fail("RFG-CREATE-DENIED: Creation of racks is not permitted for this user's group.")
            return

        # Load original for diff
        try:
            original = Rack.objects.get(pk=instance.pk)
        except Rack.DoesNotExist:
            # If we can't load original, be conservative and block
            self.fail("RFG-ORIGINAL-NOT-FOUND: Original Rack instance not found for validation.")
            return

        # Deny any change outside custom_field_data
        excluded = {"id", "created", "last_updated", "custom_field_data"}
        for field in instance._meta.concrete_fields:
            name = field.name
            if name in excluded:
                continue
            if getattr(instance, name) != getattr(original, name):
                self.fail("RFG-BUILTIN-DENIED: Modifying built-in Rack fields is not permitted for your group.", field=name)

        # Only allow configured custom fields to change
        old_cfd = original.custom_field_data or {}
        new_cfd = instance.custom_field_data or {}
        changed = {k for k in set(old_cfd) | set(new_cfd) if old_cfd.get(k) != new_cfd.get(k)}

        if not changed:
            return

        disallowed = changed - set(allowed_cf_set)
        if disallowed:
            allowed_list = ", ".join(sorted(allowed_cf_set)) or "<none>"
            bad_list = ", ".join(sorted(disallowed))
            self.fail(
                f"RFG-CF-DENIED: Disallowed custom field changes: {bad_list}. Allowed: {allowed_list}",
                field="custom_field_data",
            )