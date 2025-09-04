import re
from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings


class MaintenanceModeMiddleware:
    """
    Middleware to display a maintenance page when MAINTENANCE_MODE is enabled in settings.
    Define exempt URLs (regex patterns) in MAINTENANCE_EXEMPT_URLS.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_urls = getattr(settings, "MAINTENANCE_EXEMPT_URLS", [])

    def __call__(self, request):
        if getattr(settings, "MAINTENANCE_MODE", False):
            # Allow exempt URLs
            if getattr(settings, "MAINTENANCE_MODE", False):
                if any(request.path.startswith(url) for url in self.exempt_urls):
                    return self.get_response(request)

            # Allow staff to bypass maintenance mode
            if request.user.is_authenticated and request.user.is_staff:
                return self.get_response(request)

            # Try rendering template, fallback to plain text if missing
            try:
                return render(request, "under_maintenance.html", status=503)
            except Exception:
                return HttpResponse(
                    "Site is under maintenance. Please check back later.", status=503
                )

        return self.get_response(request)
