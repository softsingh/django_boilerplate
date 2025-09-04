from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path, include
from django.conf.urls import handler404
from django.conf.urls.static import static
from django.conf import settings

from . import views

admin.site.site_header = "Boilerplate Admin"
admin.site.site_title = "Boilerplate"

# Register the 403 handler
handler403 = views.forbidden_view

# Register the 404 handler
handler404 = views.not_found_view

# Register the 500 handler
handler500 = views.internal_server_error_view

urlpatterns = [
    # Custom admin logout path
    path(
        "admin/logout/",
        LogoutView.as_view(next_page="/admin/login/"),
        name="admin_logout",
    ),
    path("admin/", admin.site.urls),
    path("", views.IndexView.as_view(), name="index"),
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path(
        "dashboard/links/", views.DashboardLinksView.as_view(), name="dashboard_links"
    ),
    path("forbidden/", views.forbidden_view, name="forbidden"),
    path("settings/", views.SettingsView.as_view(), name="settings"),
    path("user/", include("user.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
