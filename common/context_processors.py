from django.conf import settings
from django.utils import timezone


def common_context(request):
    """Common context processor"""
    return {
        "PROJECT_NAME": getattr(settings, "PROJECT_NAME", "Django Boilerplate"),
        "PROJECT_NAME_SHORT": getattr(settings, "PROJECT_NAME_SHORT", "Boilerplate"),
        "CURRENT_YEAR": timezone.now().year,
    }
