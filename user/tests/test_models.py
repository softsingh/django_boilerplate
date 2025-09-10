import pytest
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.contrib.auth import get_user_model
from io import BytesIO
from PIL import Image
from user.models import CustomUser

User = get_user_model()

pytestmark = pytest.mark.django_db


def test_create_user():
    user = User.objects.create_user(
        username="test", email="test@example.com", password="pass"
    )
    assert user.username == "test"
    assert str(user) == "test"
    assert user.email == "test@example.com"
    assert user.check_password("pass")
    assert user.is_active is True
    assert user.is_staff is False
    assert user.is_superuser is False


def test_create_user_with_duplicate_username(normal_user):
    with pytest.raises(ValidationError, match="User with this Username already exists"):
        User.objects.create_user(
            username=normal_user.username,
            email="a" + normal_user.email,
            password="pass",
        )


def test_create_user_with_duplicate_email(normal_user):
    with pytest.raises(ValidationError, match="User with this Email already exists"):
        User.objects.create_user(
            username="a" + normal_user.username,
            email=normal_user.email,
            password="pass",
        )


def test_create_user_without_username():
    with pytest.raises(ValueError, match="The Username field must be set"):
        User.objects.create_user(username="", email="test@example.com", password="pass")


def test_create_user_without_email():
    with pytest.raises(ValueError, match="The Email field must be set"):
        User.objects.create_user(username="test", email="", password="pass")


def test_create_superuser():
    user = User.objects.create_superuser(
        username="admin", email="admin@example.com", password="pass"
    )
    assert user.username == "admin"
    assert user.email == "admin@example.com"
    assert user.check_password("pass")
    assert user.is_active is True
    assert user.is_staff is True
    assert user.is_superuser is True


def test_create_superuser_with_is_staff_false():
    with pytest.raises(ValueError, match="Superuser must have is_staff=True"):
        User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="pass",
            is_staff=False,
        )


def test_create_superuser_with_is_superuser_false():
    with pytest.raises(ValueError, match="Superuser must have is_superuser=True"):
        User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="pass",
            is_superuser=False,
        )


def test_user_model_square_picture_validation(normal_user):
    buffer = BytesIO()
    img = Image.new("RGB", (100, 100), color="blue")
    img.save(buffer, format="JPEG")
    buffer.seek(0)
    normal_user.profile.picture.save("pic.jpg", ContentFile(buffer.read()), save=False)

    try:
        normal_user.profile.full_clean()
        assert normal_user.profile.picture is not None
    except Exception as e:
        pytest.fail(f"Validation unexpectedly failed: {e}")
    finally:
        buffer.close()


def test_user_model_non_square_picture_fails(normal_user):
    buffer = BytesIO()
    img = Image.new("RGBA", (100, 200))  # non-square
    img.save(buffer, format="PNG")
    buffer.seek(0)
    normal_user.profile.picture.save("pic.png", ContentFile(buffer.read()), save=False)

    with pytest.raises(ValidationError) as exc:
        normal_user.profile.full_clean()

    # Depending on img.verify vs img.load in your model
    assert "Invalid image file" in str(exc.value) or "square" in str(exc.value)


def test_user_model_large_picture_fails(normal_user):
    """Image > 100KB should fail validation"""

    buffer = BytesIO()
    # create a big JPEG (large dimensions + high quality)
    img = Image.new("RGB", (3000, 3000), color="red")
    img.save(buffer, format="JPEG", quality=100)
    buffer.seek(0)
    normal_user.profile.picture.save("big.jpg", ContentFile(buffer.read()), save=False)

    with pytest.raises(ValidationError) as exc:
        normal_user.profile.full_clean()

    assert "Image file size must be less than or equal to 100KB" in str(exc.value)


def test_user_model_bad_extension_fails(normal_user):
    """Non-image extension should fail validation"""

    fake_file = ContentFile(b"not an image")
    normal_user.profile.picture.save("bad.txt", fake_file, save=False)

    with pytest.raises(ValidationError) as exc:
        normal_user.profile.full_clean()

    assert "Only JPG, PNG, and GIF images are allowed." in str(exc.value)
