from django.shortcuts import render
from django.views.generic import TemplateView, View
from django.http import JsonResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings

from common.utils import dashboard


class IndexView(TemplateView):
    template_name = "index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["PUBLIC_REGISTRATION"] = settings.PUBLIC_REGISTRATION
        return context


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard.html"


class DashboardLinksView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        links = dashboard.get_dashboard_links()
        if not isinstance(links, list):
            return JsonResponse({"error": "Invalid or missing links file."}, status=404)

        allowed_prefixes = ("/", "http://", "https://")
        filtered = []

        # Preload all user permissions (avoid N DB queries)
        user_perms = request.user.get_all_permissions()

        for link in links:
            url = link.get("url")
            if not url or not isinstance(url, str):
                continue
            if url.startswith(allowed_prefixes):
                perm = link.get("permission")
                if not perm or perm in user_perms:
                    filtered.append(link)

        return JsonResponse(filtered, safe=False)


class SettingsView(LoginRequiredMixin, TemplateView):
    template_name = "settings.html"


def forbidden_view(request, exception=None):
    return render(request, "forbidden.html", status=403)


def not_found_view(request, exception=None):
    return render(request, "not_found.html", status=404)


def internal_server_error_view(request):
    return render(request, "internal_server_error.html", status=500)
