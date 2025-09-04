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
    min_version = "4.0"
    max_version = "4.3"
    base_url = "rack-field-guard"
    required_settings = ("RULES",)
    default_settings = {
        "RULES": [],
    }

config = RackFieldGuardConfig
