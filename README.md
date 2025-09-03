Example of settings that should be added to plugin configuration
```
PLUGINS = [
    "rack_field_guard",
]

PLUGINS_CONFIG = {
    "rack_field_guard": {
        # RULES is a list of rule objects. Each rule maps a group to the set
        # of custom field slugs its members are allowed to modify on dcim.Rack.
        # Members of multiple groups receive the union of allowed fields.
        "RULES": [
            {"group_name": "Client Service", "allowed_cf": ["soldRackPowerCommit"]},
            # {"group_name": "Other Group", "allowed_cf": ["cf1", "cf2"]},
        ],
    }
}

CUSTOM_VALIDATORS = {
    "dcim.rack": (
        "rack_field_guard.validators.RackFieldWriteGuard",
    ),
}

Tests (optional, outside NetBox runtime):
```
poetry install --with dev
pytest -q
```
```