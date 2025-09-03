from django.conf import settings
from dcim.models import Rack
from extras.validators import CustomValidator

def _cfg():
    return getattr(settings, "PLUGINS_CONFIG", {}).get("rack_field_guard", {})

class RackFieldWriteGuard(CustomValidator):
    """
    Allows members of ALLOWED_GROUP to change only the custom field ALLOWED_CF on dcim.Rack.
    Applies to both UI and REST API.
    """

    def validate(self, instance, request):
        cfg = _cfg()
        allowed_group = cfg.get("ALLOWED_GROUP")
        allowed_cf = cfg.get("ALLOWED_CF")

        if not request or not request.user.is_authenticated:
            return

        user = request.user

        # Admins bypass
        if user.is_superuser or user.is_staff:
            return

        # Only enforce for the configured group
        if not allowed_group or not user.groups.filter(name=allowed_group).exists():
            return

        # On create: deny by default; change if desired
        if instance.pk is None:
            self.fail("Creation of racks is not permitted for this group.")

        # Load original for diff
        try:
            original = Rack.objects.get(pk=instance.pk)
        except Rack.DoesNotExist:
            return

        # Deny any change outside custom_field_data
        excluded = {"id", "created", "last_updated", "custom_field_data"}
        for field in instance._meta.concrete_fields:
            name = field.name
            if name in excluded:
                continue
            if getattr(instance, name) != getattr(original, name):
                self.fail("Only the configured custom field may be modified.", field=name)

        # Only allow the single configured custom field to change
        old_cfd = original.custom_field_data or {}
        new_cfd = instance.custom_field_data or {}
        changed = {k for k in set(old_cfd) | set(new_cfd) if old_cfd.get(k) != new_cfd.get(k)}

        if not changed:
            return

        if not allowed_cf:
            self.fail("Custom field restriction not configured.", field="custom_field_data")

        disallowed = changed - {allowed_cf}
        if disallowed:
            self.fail("Only the configured custom field may be modified.", field="custom_field_data")