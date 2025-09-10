import uuid
import tempfile
import shutil
import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import override_settings


pytestmark = pytest.mark.django_db
User = get_user_model()


@pytest.fixture
# @pytest.mark.django_db
def normal_user():
    return User.objects.create_user(
        username="user",
        email="user@example.com",
        password="password",
    )


@pytest.fixture
def create_user():
    def make_user(**kwargs):
        import uuid

        user = User.objects.create_user(
            username=kwargs.get("username", f"user_{uuid.uuid4().hex[:6]}"),
            email=kwargs.get("email", f"user_{uuid.uuid4().hex[:6]}@example.com"),
            password=kwargs.get("password", "password"),
        )

        return user

    return make_user


@pytest.fixture
# @pytest.mark.django_db
def normal_client(client, normal_user):
    client.force_login(normal_user)
    return client


@pytest.fixture
# @pytest.mark.django_db
def user_group():
    return Group.objects.create(name="user_group")


@pytest.fixture
@pytest.mark.django_db
def create_user_group():
    def _create_user_group(**kwargs):
        return Group.objects.create(
            name=kwargs.get("name", f"group_{uuid.uuid4().hex[:6]}")
        )

    return _create_user_group


@pytest.fixture(autouse=True, scope="session")
def setup_test_media():
    """Automatically use temp directory for all tests."""
    temp_dir = tempfile.mkdtemp()
    with override_settings(MEDIA_ROOT=temp_dir):
        yield
    shutil.rmtree(temp_dir, ignore_errors=True)
