# conftest.py
import sys
from unittest.mock import MagicMock

# Mock NetBox and Django modules before any imports
netbox_mock = MagicMock()
netbox_plugins_mock = MagicMock()
netbox_plugins_mock.PluginConfig = MagicMock()

django_conf_mock = MagicMock()
dcim_models_mock = MagicMock()
extras_validators_mock = MagicMock()

# Create a mock CustomValidator class
class MockCustomValidator:
    def __init__(self):
        self.context = {}
    
    def fail(self, message, field=None):
        raise Exception(f"ValidationError: {message}")

extras_validators_mock.CustomValidator = MockCustomValidator

sys.modules['netbox'] = netbox_mock
sys.modules['netbox.plugins'] = netbox_plugins_mock
sys.modules['django.conf'] = django_conf_mock
sys.modules['dcim.models'] = dcim_models_mock
sys.modules['extras.validators'] = extras_validators_mock