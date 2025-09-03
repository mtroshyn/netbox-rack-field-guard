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
        # Avoid DB access during app initialization per Django guidance.
        return

config = RackFieldGuardConfig

__all__ = ["RackFieldGuardConfig"]

# Expose package version for tooling
__version__ = "0.1.0"