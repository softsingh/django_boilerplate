import pytest
from django.urls import reverse
from django.contrib.auth.models import Group, Permission

from user.utils import send_verification_email


pytestmark = pytest.mark.django_db


def test_user_view_self_requires_login(client):
    url = reverse("user_view_self")
    response = client.get(url)
    assert response.status_code == 302
    assert reverse("user_login") in response.url


def test_user_view_self_without_permission(client, normal_user):
    client.force_login(normal_user)
    url = reverse("user_view_self")
    response = client.get(url)
    assert response.status_code == 403


def test_user_view_self_with_permission(client, normal_user, admin_client):
    perm = Permission.objects.get(codename="can_view_profile")
    normal_user.user_permissions.add(perm)
    client.force_login(normal_user)
    url = reverse("user_view_self")
    # Normal user with permission
    response = client.get(url)
    assert response.status_code == 200, "Normal user with permissions can view self"
    # Admin can view all without permission
    response = admin_client.get(url)
    assert response.status_code == 200, "Admin can always be able to view self"


def test_user_view_requires_login(client, normal_user):
    kwargs = {"pk": normal_user.pk}
    url = reverse("user_view", kwargs=kwargs)
    response = client.get(url)
    assert response.status_code == 302
    assert reverse("user_login") in response.url


def test_user_view_others_without_permission(client, create_user):
    user1 = create_user()
    user2 = create_user()
    client.force_login(user1)
    kwargs = {"pk": user2.pk}
    url = reverse("user_view", kwargs=kwargs)
    response = client.get(url)
    assert response.status_code == 403


def test_user_view_others_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.filter(
        codename__in=["can_view_profile", "can_view_others_profile"]
    )
    user1.user_permissions.add(*perms)
    client.force_login(user1)
    kwargs = {"pk": user2.pk}
    url = reverse("user_view", kwargs=kwargs)
    # Normal user with permission
    response = client.get(url)
    assert response.status_code == 200, "Normal user with permissions can view others"
    # Admin can view all without permission
    response = admin_client.get(url)
    assert response.status_code == 200, "Admin can always be able to view others"


def test_user_login_view_with_invalid_user(client, normal_user, settings):
    settings.EMAIL_VERIFICATION_REQUIRED = False
    url = reverse("user_login")
    data = {"username": normal_user.username, "password": "wrongpassword"}
    response = client.post(url, data)
    assert response.status_code == 200, "Should renders login page"
    assert "Please enter a correct username and password" in response.content.decode()


def test_user_login_view_with_valid_user(client, normal_user, settings):
    settings.EMAIL_VERIFICATION_REQUIRED = False
    url = reverse("user_login")
    data = {"username": normal_user.username, "password": "password"}
    response = client.post(url, data)
    assert response.status_code == 302


def test_user_login_email_not_verified(client, normal_user, settings):
    settings.EMAIL_VERIFICATION_REQUIRED = True
    normal_user.email_verified = False
    normal_user.save()
    url = reverse("user_login")
    data = {"username": normal_user.username, "password": "password"}
    response = client.post(url, data)
    assert response.status_code == 302
    assert reverse("request_email_verification") in response.url


def test_user_login_email_verified(client, normal_user, settings):
    settings.EMAIL_VERIFICATION_REQUIRED = True
    normal_user.email_verified = True
    normal_user.save()
    url = reverse("user_login")
    data = {"username": normal_user.username, "password": "password"}
    response = client.post(url, data)
    assert response.status_code == 302
    assert reverse("request_email_verification") not in response.url


def test_login_with_next_url(client, admin_user):
    url = reverse("user_login") + "?next=/group/list"
    data = {"username": admin_user.username, "password": "password"}
    response = client.post(url, data)
    assert response.status_code in (302, 303)
    assert response.url.endswith("/group/list")


def test_user_login_remember_me(client, create_user):
    user = create_user(username="user", email="user@example.com", password="password")
    url = reverse("user_login")
    data = {"username": user.username, "password": "password", "remember_me": True}
    response = client.post(url, data)
    assert response.status_code in (302, 303)
    assert client.session.get_expiry_age() > 24 * 3600


def test_user_register_view_no_email_verification_required(client, settings):
    settings.PUBLIC_REGISTRATION = True
    settings.EMAIL_VERIFICATION_REQUIRED = False
    url = reverse("user_register")
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
        "terms_conditions": True,
    }
    response = client.post(url, data)
    assert response.status_code == 302
    assert reverse("user_register_success") in response.url


def test_user_register_view_email_verification_required(client, settings):
    settings.PUBLIC_REGISTRATION = True
    settings.EMAIL_VERIFICATION_REQUIRED = True
    url = reverse("user_register")
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
        "terms_conditions": True,
    }
    response = client.post(url, data)
    assert response.status_code == 302
    assert reverse("email_verification_sent") in response.url


def test_user_register_view_not_allowed(client, settings):
    settings.PUBLIC_REGISTRATION = False
    url = reverse("user_register")
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
        "terms_conditions": True,
    }
    response = client.post(url, data)
    assert response.status_code == 403


def test_user_register_success_view_not_directly_accessible(client):
    url = reverse("user_register_success")
    response = client.get(url)
    assert response.status_code == 403


def test_user_request_email_verification_get(client):
    url = reverse("request_email_verification")
    response = client.get(url)
    assert response.status_code == 200


def test_user_request_email_verification_with_invalid_email(client, normal_user):
    url = reverse("request_email_verification")
    data = {"email": f"a{normal_user.email}"}
    response = client.post(url, data)
    assert response.status_code == 200
    assert "Account with this email address does not exist" in response.content.decode()


def test_user_request_email_verification_with_valid_email(client, normal_user):
    url = reverse("request_email_verification")
    data = {"email": normal_user.email}
    response = client.post(url, data)
    assert response.status_code == 302
    assert reverse("email_verification_sent") in response.url


def test_user_verify_email_with_invalid_token(client):
    kwargs = {"uidb64": "dummy", "token": "dummy"}
    url = reverse("verify_email", kwargs=kwargs)
    response = client.get(url)
    assert response.status_code == 302
    assert reverse("email_verification_token_fail") in response.url


def test_send_verification_email_success(mailoutbox, rf, normal_user, settings):
    req = rf.get("/")
    req.user = normal_user
    # attach messages storage
    from django.contrib.messages.storage.fallback import FallbackStorage

    setattr(req, "session", {})
    req._messages = FallbackStorage(req)

    class Dummy:  # emulate self
        request = req

    send_verification_email(Dummy(), normal_user)
    assert len(mailoutbox) == 1
    assert str(normal_user.pk) not in mailoutbox[0].body  # uidb64 used instead
    assert "verify" in mailoutbox[0].alternatives[0][0].lower()


def test_user_add_requires_login(client):
    url = reverse("user_add")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_add_without_permission(normal_client):
    url = reverse("user_add")
    data = {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
    }
    response = normal_client.post(url, data)
    assert response.status_code == 403, "Normal user can not add new user"


def test_user_add_with_permission(client, normal_user, admin_client):
    perm = Permission.objects.get(codename="can_add_user")
    normal_user.user_permissions.add(perm)
    client.force_login(normal_user)
    url = reverse("user_add")
    data = {
        "username": "newuser1",
        "email": "newuser1@example.com",
        "full_name": "New User1",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
    }
    response = client.post(url, data)
    assert response.status_code == 302, "User with permission can add new user"
    assert reverse("user_list") in response.url
    data = {
        "username": "newuser2",
        "email": "newuser2@example.com",
        "full_name": "New User2",
        "gender": "male",
        "password1": "complexpassword",
        "password2": "complexpassword",
    }
    response = admin_client.post(url, data)
    assert response.status_code == 302, "Admin without any permission can add new user"
    assert reverse("user_list") in response.url


def test_user_edit_requires_login(client):
    url = reverse("user_edit", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_edit_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.filter(
        codename__in=["can_edit_profile", "can_edit_others_profile"]
    )
    user1.user_permissions.add(*perms)
    perms = Permission.objects.get(codename="can_edit_profile")
    user2.user_permissions.add(perms)

    client.force_login(user2)

    # user2 can edit self profile
    url = reverse("user_edit_self")
    new_data = {
        "username": "newuser2",
        "email": "newuser2@example.com",
        "gender": "male",
    }
    response = client.post(url, new_data)
    assert response.status_code == 302, "user2 can edit self profile"
    assert reverse("user_view_self") in response.url

    # user2 can not edit user1 profile
    url = reverse("user_edit", kwargs={"pk": user1.pk})
    new_data = {
        "username": "newuser1",
        "email": "newuser1@example.com",
        "gender": "male",
    }
    response = client.post(url, new_data)
    assert response.status_code == 403, "user2 can not edit user1 profile"

    # user1 can edit user2's profile
    client.force_login(user1)
    url = reverse("user_edit", kwargs={"pk": user2.pk})
    new_data = {
        "username": "by_user1",
        "email": "by_user1@example.com",
        "gender": "male",
    }
    response = client.post(url, new_data)
    assert response.status_code == 302, "user1 can edit user2's profile"
    assert reverse("user_view", kwargs={"pk": user2.pk}) in response.url

    # admin can edit everyone's profile
    url = reverse("user_edit", kwargs={"pk": user1.pk})
    new_data = {
        "username": "by_admin",
        "email": "by_admin@example.com",
        "gender": "male",
    }
    response = admin_client.post(url, new_data)
    assert response.status_code == 302, "admin can edit everyone's profile"
    assert reverse("user_view", kwargs={"pk": user1.pk}) in response.url


def test_user_change_password_requires_login(client):
    url = reverse("user_change_password", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_change_password_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.filter(
        codename__in=["can_change_password", "can_change_others_password"]
    )
    user1.user_permissions.add(*perms)
    perms = Permission.objects.get(codename="can_change_password")
    user2.user_permissions.add(perms)

    client.force_login(user2)

    # user2 can change self password
    url = reverse("user_change_password_self")
    new_data = {
        "old_password": "password",
        "new_password1": "new_password1",
        "new_password2": "new_password1",
    }
    response = client.post(url, new_data)
    user2.refresh_from_db()
    assert user2.check_password("new_password1"), "user2 can change self password"
    assert response.status_code == 302
    assert reverse("user_edit_self") in response.url

    # user2 can not edit user1's password
    url = reverse("user_change_password", kwargs={"pk": user1.pk})
    new_data = {
        "new_password1": "new_password1",
        "new_password2": "new_password1",
    }
    response = client.post(url, new_data)
    user1.refresh_from_db()
    assert (
        user1.check_password("new_password1") == False
    ), "user2 cannot change user1's password"
    assert response.status_code == 403, "user2 can not change user1's password"

    # user1 can change user2's password
    client.force_login(user1)
    url = reverse("user_change_password", kwargs={"pk": user2.pk})
    new_data = {
        "new_password1": "new_password2",
        "new_password2": "new_password2",
    }
    response = client.post(url, new_data)
    user2.refresh_from_db()
    assert user2.check_password("new_password2"), "user1 can change user2's password"
    assert response.status_code == 302, "user1 can change user2's password"
    assert reverse("user_edit", kwargs={"pk": user2.pk}) in response.url

    # admin can change everyone's password
    url = reverse("user_change_password", kwargs={"pk": user1.pk})
    new_data = {
        "new_password1": "by_admin",
        "new_password2": "by_admin",
    }
    response = admin_client.post(url, new_data)
    user1.refresh_from_db()
    assert user1.check_password("by_admin"), "admin can change everyone's password"
    assert response.status_code == 302
    assert reverse("user_edit", kwargs={"pk": user1.pk}) in response.url


def test_user_forgot_password_with_invalid_email(client):
    url = reverse("user_forgot_password")
    response = client.post(url, {"email": "invalid@example.com"})
    assert "Account with this email address does not exist" in response.content.decode()


def test_user_forgot_password_with_valid_email(client, create_user):
    user = create_user(email="user@example.com")
    url = reverse("user_forgot_password")
    response = client.post(url, {"email": user.email})
    assert response.status_code == 302, "Should redirect to forgot password success"
    assert reverse("user_forgot_password_success") in response.url


@pytest.mark.parametrize("uid, token", [(None, None), ("dummy", "dummy")])
def test_user_reset_password_with_invalid_token(client, uid, token):
    kwargs = {"uidb64": uid, "token": token}
    url = reverse("user_reset_password", kwargs=kwargs)
    response = client.get(url)
    assert response.status_code == 200
    assert "Password Reset Failed" in response.content.decode()


def test_user_reset_password_success_view_not_directly_accessible(client):
    url = reverse("user_reset_password_success")
    response = client.get(url)
    assert response.status_code == 403


def test_user_delete_requires_login(client):
    url = reverse("user_delete", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_delete_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_delete_user")
    user1.user_permissions.add(perms)

    client.force_login(user1)

    # User cannot delete self account
    url = reverse("user_delete", kwargs={"pk": user1.pk})
    response = client.get(url)
    assert response.status_code == 403, "User cannot delete self account"

    # user1 can delete user2's account
    url = reverse("user_delete", kwargs={"pk": user2.pk})
    response = client.get(url)
    assert response.status_code == 200
    assert "Are you sure you want to delete" in response.content.decode()

    # User2 cannot delete user1's account
    client.force_login(user2)
    url = reverse("user_delete", kwargs={"pk": user1.pk})
    response = client.get(url)
    assert response.status_code == 403, "User2 cannot delete user1's account"

    # Admin can delete everyone's account
    url = reverse("user_delete", kwargs={"pk": user1.pk})
    response = admin_client.get(url)
    assert response.status_code == 200
    assert "Are you sure you want to delete" in response.content.decode()


def test_user_list_requires_login(client):
    url = reverse("user_list")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_list_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_view_others_profile")
    user1.user_permissions.add(perms)

    url = reverse("user_list")

    # user2 cannot view list of users
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view list of users"

    # user1 can view list of users
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view list of users"

    # Admin can view list of users
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_list_export_as_xlsx_requires_login(client):
    url = reverse("user_list_export_as_xlsx")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_list_export_as_xlsx_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_view_others_profile")
    user1.user_permissions.add(perms)

    url = reverse("user_list_export_as_xlsx")

    # user2 cannot export user list as xlsx
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot export user list as xlsx"

    # user1 can export user list as xlsx
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can export user list as xlsx"

    # Admin can export user list as xlsx
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_list_export_as_csv_requires_login(client):
    url = reverse("user_list_export_as_csv")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_list_export_as_csv_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_view_others_profile")
    user1.user_permissions.add(perms)

    url = reverse("user_list_export_as_csv")

    # user2 cannot export user list as csv
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot export user list as csv"

    # user1 can export user list as csv
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can export user list as csv"

    # Admin can export user list as csv
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_list_print_requires_login(client):
    url = reverse("user_list_print")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_list_print_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_view_others_profile")
    user1.user_permissions.add(perms)

    url = reverse("user_list_print")

    # user2 cannot print user list
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot print user list"

    # user1 can print user list
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can print user list"

    # Admin can print user list
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_list_copy_requires_login(client):
    url = reverse("user_list_copy")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_list_copy_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="can_view_others_profile")
    user1.user_permissions.add(perms)

    url = reverse("user_list_copy")

    # user2 cannot copy user list
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot copy user list"

    # user1 can copy user list
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can copy user list"

    # Admin can copy user list
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_view_requires_login(client):
    url = reverse("user_group_view", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_view_without_and_with_permission(
    client, create_user, create_user_group, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    group = create_user_group()
    url = reverse("user_group_view", kwargs={"pk": group.id})

    # user2 cannot view groups
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view groups"

    # user1 can view groups
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view groups"

    # Admin can view groups
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_list_requires_login(client):
    url = reverse("user_group_list")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_list_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_list")

    # user2 cannot view group list
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view group list"

    # user1 can view group list
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view group list"

    # Admin can view group list
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_list_export_as_xlsx_requires_login(client):
    url = reverse("user_group_list_export_as_xlsx")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_list_export_as_xlsx_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_list_export_as_xlsx")

    # user2 cannot view group list export as xlsx
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view group list export as xlsx"

    # user1 can view group list export as xlsx
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view group list export as xlsx"

    # Admin can view group list export as xlsx
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_list_export_as_csv_requires_login(client):
    url = reverse("user_group_list_export_as_csv")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_list_export_as_csv_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_list_export_as_csv")

    # user2 cannot view group list export as csv
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view group list export as csv"

    # user1 can view group list export as csv
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view group list export as csv"

    # Admin can view group list export as csv
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_list_print_requires_login(client):
    url = reverse("user_group_list_print")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_list_print_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_list_print")

    # user2 cannot view group print
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view group list print"

    # user1 can view group list print
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view group list print"

    # Admin can view group list print
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_list_copy_requires_login(client):
    url = reverse("user_group_list_copy")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_list_copy_without_and_with_permission(
    client, create_user, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="view_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_list_copy")

    # user2 cannot view group copy
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot view group list copy"

    # user1 can view group list copy
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can view group list copy"

    # Admin can view group list copy
    response = admin_client.get(url)
    assert response.status_code == 200


def test_user_group_add_requires_login(client):
    url = reverse("user_group_add")
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_add_without_and_with_permission(client, create_user, admin_client):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="add_group")
    user1.user_permissions.add(perms)

    url = reverse("user_group_add")

    # user2 cannot add group
    client.force_login(user2)
    response = client.post(url, {"name": "group1"})
    assert response.status_code == 403, "user2 cannot add group"

    # user1 can add group
    client.force_login(user1)
    response = client.post(url, {"name": "group1"})
    group = Group.objects.get(name="group1")
    assert group, "Should add group1"
    assert response.status_code == 302, "user1 can add group"
    assert reverse("user_group_list") in response.url

    # Admin can add group
    response = admin_client.get(url)
    response = client.post(url, {"name": "group2"})
    group = Group.objects.get(name="group2")
    assert group, "Should add group2"
    assert response.status_code == 302, "admin can add group"
    assert reverse("user_group_list") in response.url


def test_user_group_edit_requires_login(client):
    url = reverse("user_group_edit", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_edit_without_and_with_permission(
    client, create_user, create_user_group, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="change_group")
    user1.user_permissions.add(perms)

    group = create_user_group()
    url = reverse("user_group_edit", kwargs={"pk": group.id})

    # user2 cannot edit groups
    client.force_login(user2)
    response = client.post(url, {"name": "group1"})
    assert response.status_code == 403, "user2 cannot edit groups"

    # user1 can edit groups
    client.force_login(user1)
    response = client.post(url, {"name": "group1"})
    group.refresh_from_db()
    assert group.name == "group1"
    assert response.status_code == 302, "user1 can edit groups"
    assert reverse("user_group_view", kwargs={"pk": group.id})

    # Admin can edit groups
    response = admin_client.post(url, {"name": "group2"})
    group.refresh_from_db()
    assert group.name == "group2"
    assert response.status_code == 302, "admin can edit groups"
    assert reverse("user_group_view", kwargs={"pk": group.id})


def test_user_group_delete_requires_login(client):
    url = reverse("user_group_delete", kwargs={"pk": 1})
    response = client.get(url)
    assert response.status_code == 302, "Should redirect to login page"
    assert reverse("user_login") in response.url


def test_user_group_delete_without_and_with_permission(
    client, create_user, create_user_group, admin_client
):
    user1 = create_user()
    user2 = create_user()
    perms = Permission.objects.get(codename="delete_group")
    user1.user_permissions.add(perms)

    group = create_user_group()
    url = reverse("user_group_delete", kwargs={"pk": group.id})

    # user2 cannot delete groups
    client.force_login(user2)
    response = client.get(url)
    assert response.status_code == 403, "user2 cannot delete groups"

    # user1 can delete groups
    client.force_login(user1)
    response = client.get(url)
    assert response.status_code == 200, "user1 can delete groups"
    assert "Are you sure you want to delete" in response.content.decode()

    # Admin can delete groups
    response = admin_client.get(url)
    assert response.status_code == 200, "admin can delete groups"
    assert "Are you sure you want to delete" in response.content.decode()
