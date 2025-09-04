from django.urls import resolve, reverse
from django_boilerplate import views


def test_index_url_resolves():
    url = reverse("index")
    assert resolve(url).func.view_class == views.IndexView


def test_dashboard_url_resolves():
    url = reverse("dashboard")
    assert resolve(url).func.view_class == views.DashboardView


def test_dashboard_links_url_resolves():
    url = reverse("dashboard_links")
    assert resolve(url).func.view_class == views.DashboardLinksView


def test_forbidden_url_resolves():
    url = reverse("forbidden")
    assert resolve(url).func == views.forbidden_view


def test_settings_url_resolves():
    url = reverse("settings")
    assert resolve(url).func.view_class == views.SettingsView
