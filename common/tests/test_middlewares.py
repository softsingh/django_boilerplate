import pytest
from django.test import RequestFactory
from django.http import HttpResponse
from django.contrib.auth.models import User

from common.middlewares import MaintenanceModeMiddleware

pytestmark = pytest.mark.django_db


def get_request(path="/", is_staff=False):
    factory = RequestFactory()
    request = factory.get(path)
    user = User(username="testuser", is_staff=is_staff)
    user.set_password("testpass")
    request.user = user
    return request


def test_blocks_request_when_enabled(settings):
    settings.MAINTENANCE_MODE = True
    middleware = MaintenanceModeMiddleware(lambda r: HttpResponse("ok"))
    response = middleware(get_request())
    assert response.status_code == 503


def test_allows_request_when_disabled(settings):
    settings.MAINTENANCE_MODE = False
    middleware = MaintenanceModeMiddleware(lambda r: HttpResponse("ok"))
    response = middleware(get_request())
    assert response.status_code == 200


def test_allows_request_when_user_is_staff(settings):
    settings.MAINTENANCE_MODE = True
    middleware = MaintenanceModeMiddleware(lambda r: HttpResponse("ok"))
    response = middleware(get_request(is_staff=True))
    assert response.status_code == 200


@pytest.mark.parametrize(
    "url",
    [
        "/admin",
    ],
)
def test_allows_request_when_exempt_url(settings, url):
    settings.MAINTENANCE_MODE = True
    middleware = MaintenanceModeMiddleware(lambda r: HttpResponse("ok"))
    response = middleware(get_request(path=url))
    assert response.status_code == 200
