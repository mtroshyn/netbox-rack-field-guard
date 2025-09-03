from netbox.plugins import PluginConfig

class RackFieldGuardConfig(PluginConfig):
    name = "rack_field_guard"
    verbose_name = "Rack Field Guard"
    description = "Restrict Rack edits to a specific custom field for a specific group"
    version = "0.1.0"
    author = "Your Team"
    base_url = "rack-field-guard"
    required_settings = ("ALLOWED_GROUP", "ALLOWED_CF")

config = RackFieldGuardConfig