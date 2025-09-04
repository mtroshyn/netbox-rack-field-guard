## What this plugin is for

Restrict which custom fields users can edit on `dcim.Rack`, based on their Django group membership. Members of configured groups can modify only the specified custom fields; all built-in Rack fields and any other custom fields are denied.

## Why this plugin was created (and alternatives)

- **Why**: NetBox permissions are model/action oriented and don’t provide per-field write control. Organizations often need to grant limited edit rights to specific custom fields without exposing the entire edit form.
- **Alternatives**:
  - **Custom Scripts / Jobs**: Create a controlled job to update only the allowed field(s) and deny `change` permission on the model. Secure and simple, but the UX detours from the standard edit form.
  - **Permission Constraints**: Limit which objects can be changed, not which fields.
  - **Client-side UI tweaks**: Not secure by themselves (must be enforced server-side).

This plugin leverages request-aware custom validation to enforce per-field edit rules on both the UI and the REST API.

## Features

- **Group-based field allow-list**: Configure multiple rules mapping `group_name` to a list of allowed custom field slugs.
- **Inline form errors**: Disallowed built-in fields show errors under the specific field; disallowed custom fields show errors under their `cf_<slug>` inputs.
- **API covered**: Same enforcement applies to REST API updates.
- **Safe defaults**:
  - Empty or missing `RULES` disables enforcement.
  - Users not in any configured group are unaffected by this plugin.
- **Structured errors**: Error codes like `RFG-BUILTIN-DENIED`, `RFG-CF-DENIED` aid troubleshooting.

## Installation

1) Install the package (choose one):

- From Git (main branch):
  - `pip install "git+https://github.com/mtroshyn/netbox-rack-field-guard@main"`

2) Enable plugin in NetBox configuration (`configuration.py`):
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

3) Restart NetBox services.

4) Permissions:

- Grant the target group(s) these permissions:
  - `dcim | rack | view`
  - `dcim | rack | change`
- The plugin blocks disallowed fields at validation time.

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/mtroshyn/netbox-rack-field-guard.git
cd netbox-rack-field-guard

# Install dependencies
make install

# Run tests
make test

# Run all checks (linting, type checking, tests)
make check
```

### Available Commands

- `make install` - Install dependencies
- `make test` - Run tests
- `make test-cov` - Run tests with coverage
- `make lint` - Run linting
- `make format` - Format code with black
- `make type-check` - Run type checking with mypy
- `make check` - Run all checks
- `make clean` - Clean build artifacts
- `make build` - Build package

### Code Quality

This project uses:
- **Black** for code formatting
- **Flake8** for linting
- **MyPy** for type checking
- **Pytest** for testing
- **Poetry** for dependency management

## Notes

- Replace custom field slugs with your actual CF slugs as defined in NetBox.
- The plugin is compatible with NetBox 4.0+.
- All changes are enforced server-side for security.
```