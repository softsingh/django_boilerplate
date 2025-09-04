import pytest
from django.urls import reverse
from django.test import RequestFactory
from django_boilerplate.views import internal_server_error_view


def test_index_view_context(client):
    url = reverse("index")
    response = client.get(url)
    assert response.status_code == 200
    assert "PUBLIC_REGISTRATION" in response.context


def test_dashboard_view_requires_login(client):
    url = reverse("dashboard")
    response = client.get(url)
    # Redirect to login
    assert response.status_code == 302
    assert reverse("user_login") in response.url


@pytest.mark.django_db
def test_dashboard_links_view_with_valid_user(admin_client, monkeypatch):

    fake_links = [
        {
            "label": "User List",
            "url": "/user/list",
            "permission": "user.can_view_others_profile",
        },
        {
            "label": "View User Profile",
            "url": "/user",
        },
        {
            "label": "Edit User Profile",
            "url": 123,
            "permission": "user.can_edit_profile",
        },
    ]

    monkeypatch.setattr(
        "django_boilerplate.views.dashboard.get_dashboard_links", lambda: fake_links
    )

    url = reverse("dashboard_links")
    response = admin_client.get(url)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.django_db
def test_dashboard_links_view_missing_data_file(admin_client, monkeypatch):

    monkeypatch.setattr(
        "django_boilerplate.views.dashboard.get_dashboard_links", lambda: None
    )

    url = reverse("dashboard_links")
    response = admin_client.get(url)
    assert response.status_code == 404
    data = response.json()
    assert "Invalid or missing links file" in data.get("error", "")


def test_settings_view_requires_login(client):
    url = reverse("settings")
    response = client.get(url)
    # Redirect to login
    assert response.status_code == 302
    assert reverse("user_login") in response.url


def test_error_views(client):
    assert client.get(reverse("forbidden")).status_code == 403
    assert client.get("/invalid-page").status_code == 404


def test_internal_server_error_view():
    factory = RequestFactory()
    request = factory.get("/")

    response = internal_server_error_view(request)

    assert response.status_code == 500
    assert "Something went wrong" in response.content.decode()
