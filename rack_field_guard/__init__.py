from netbox.plugins import PluginConfig


class RackFieldGuardConfig(PluginConfig):
    name = "rack_field_guard"
    verbose_name = "Rack Field Guard"
    description = (
        "Restrict Rack edits to specific custom fields for specific user groups"
    )
    version = "0.1.0"
    author = "Maksym Troshyn"
    author_email = "maksym.troshyn@advanced.host"
    # base_url must be a URL path segment used for this plugin's routes, not a homepage URL
    base_url = "rack-field-guard"
    min_version = "4.0.0"
    max_version = "4.3"
    required_settings = ("RULES",)
    default_settings = {
        "RULES": [],
    }

config = RackFieldGuardConfig
