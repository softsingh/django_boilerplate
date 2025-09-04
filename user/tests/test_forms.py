import pytest
from django.test import RequestFactory
from user.forms import (
    UserAddForm,
    UserRegisterForm,
    RequestEmailVerificationForm,
    LoginForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    UserEditForm,
    CustomPasswordChangeForm,
    UserGroupAddForm,
)

pytestmark = pytest.mark.django_db


def test_user_add_form():
    form = UserAddForm(
        {
            "username": "newuser",
            "email": "newuser@example.com",
            "full_name": "New User",
            "gender": "male",
            "password1": "complexpassword",
            "password2": "complexpassword",
        },
    )
    assert form.is_valid(), form.errors


@pytest.mark.parametrize("flag", [False, True])
def test_user_register_form(flag):
    form = UserRegisterForm(
        {
            "username": "newuser",
            "email": "newuser@example.com",
            "full_name": "New User",
            "gender": "male",
            "password1": "complexpassword",
            "password2": "complexpassword",
            "terms_conditions": flag,
        },
    )
    assert form.is_valid() == flag, form.errors


@pytest.mark.parametrize(
    "email, flag",
    [
        ("invalid_email", False),
        ("user@example.com", True),
    ],
)
def test_request_email_verification_form(normal_user, email, flag):

    form = RequestEmailVerificationForm(
        {
            "email": email,
        },
    )
    assert form.is_valid() == flag, form.errors


@pytest.mark.parametrize(
    "username, password, flag",
    [
        ("invalid", "password", False),
        ("user", "password", True),
    ],
)
def test_login_form(normal_user, username, password, flag):
    factory = RequestFactory()
    request = factory.post("/login/")  # dummy request

    form = LoginForm(request, {"username": username, "password": password})
    assert form.is_valid() == flag, form.errors


@pytest.mark.parametrize(
    "email, flag",
    [
        ("invalid_email", False),
        ("user@example.com", True),
    ],
)
def test_forgot_password_form(normal_user, email, flag):

    form = ForgotPasswordForm(
        {
            "email": email,
        },
    )
    assert form.is_valid() == flag, form.errors


@pytest.mark.parametrize(
    "new_password, flag",
    [
        ("new", False),  # too weak
        ("new@1234", True),  # strong enough
    ],
)
def test_reset_password_form(normal_user, new_password, flag):
    form = ResetPasswordForm(
        normal_user,
        {
            "new_password1": new_password,
            "new_password2": new_password,
        },
    )
    assert form.is_valid() == flag, form.errors


def test_user_edit_form(normal_user):
    form = UserEditForm(
        data={
            "username": "edited_user",
            "email": "edited@example.com",
            "full_name": "Edited User",
            "phone_number": "1234567890",
            "gender": "female",
            "remarks": "Something about the new user",
            "is_superuser": False,
            "is_staff": False,
            "is_active": True,
            "groups": [],
            "user_permissions": [],
        },
        instance=normal_user,
    )
    assert form.is_valid(), form.errors


@pytest.mark.parametrize(
    "new_password, flag",
    [
        ("new", False),  # too weak
        ("new@1234", True),  # strong enough
    ],
)
def test_password_change_form(normal_user, new_password, flag):
    form = CustomPasswordChangeForm(
        normal_user,
        {
            "old_password": "password",
            "new_password1": new_password,
            "new_password2": new_password,
        },
    )
    assert form.is_valid() == flag, form.errors


def test_user_group_add_form(user_group):
    form1 = UserGroupAddForm(
        {
            "name": "group1",
            "permissions": [],
        },
    )
    form2 = UserGroupAddForm(
        {
            "name": user_group.name,
            "permissions": [],
        },
    )

    assert form1.is_valid(), form1.errors
    assert not form2.is_valid(), form2.errors
