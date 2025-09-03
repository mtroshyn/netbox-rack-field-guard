Example of settings that should be added to plugin configuration
```
PLUGINS = [
    "rack_field_guard",
]

PLUGINS_CONFIG = {
    "rack_field_guard": {
        "ALLOWED_GROUP": "Client Service",             # group name
        "ALLOWED_CF": "soldRackPowerCommit",           # custom field slug
    }
}

CUSTOM_VALIDATORS = {
    "dcim.rack": (
        "rack_field_guard.validators.RackFieldWriteGuard",
    ),
}
```