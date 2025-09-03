from netbox.plugins import PluginConfig
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class RackFieldGuardConfig(PluginConfig):
    name = "rack_field_guard"
    verbose_name = "Rack Field Guard"
    description = "Restrict Rack edits to a specific custom field for a specific group"
    version = "0.1.0"
    author = "Your Team"
    base_url = "rack-field-guard"
    required_settings = ("RULES",)

    def ready(self):
        # Validate configuration on startup and log warnings for unknown groups/CF slugs
        cfg = getattr(settings, "PLUGINS_CONFIG", {}).get(self.name, {})
        rules = cfg.get("RULES")
        if not rules:
            # Skip checks if no rules configured
            return
        try:
            from django.contrib.auth.models import Group
            from django.contrib.contenttypes.models import ContentType
            from dcim.models import Rack
            from extras.models import CustomField
        except Exception as exc:
            logger.debug("[RFG-INIT] Skipping deep validation due to import error: %s", exc)
            return

        # Map available groups and CF slugs
        existing_groups = set(Group.objects.values_list("name", flat=True))
        ct = ContentType.objects.get_for_model(Rack)
        # NetBox 4.x uses `object_types` M2M to ContentType and stores keys under `name`
        existing_cf_slugs = set(
            CustomField.objects.filter(object_types=ct).values_list("name", flat=True)
        )

        for idx, rule in enumerate(rules):
            group_name = (rule or {}).get("group_name")
            allowed = set([str(x) for x in (rule or {}).get("allowed_cf", [])])
            if group_name and group_name not in existing_groups:
                logger.warning(
                    "[RFG-CFG-UNKNOWN-GROUP] RULES[%s] references unknown group '%s'", idx, group_name
                )
            unknown_cf = allowed - existing_cf_slugs
            if unknown_cf:
                logger.warning(
                    "[RFG-CFG-UNKNOWN-CF] RULES[%s] references unknown custom fields: %s",
                    idx,
                    ", ".join(sorted(unknown_cf)) or "<none>",
                )

config = RackFieldGuardConfig

__all__ = ["RackFieldGuardConfig"]

# Expose package version for tooling
__version__ = "0.1.0"