import pytest
from django.urls import resolve, reverse
from user import views


@pytest.mark.parametrize(
    "view, view_class, kwargs",
    [
        ("user_view_self", views.UserView, {}),
        ("user_view", views.UserView, {"pk": 1}),
        ("user_login", views.UserLoginView, {}),
        ("user_register", views.UserRegisterView, {}),
        ("user_register_success", views.UserRegisterSuccessView, {}),
        ("request_email_verification", views.RequestEmailVerificationView, {}),
        ("email_verification_sent", views.EmailVerificationSentView, {}),
        (
            "verify_email",
            views.EmailVerificationView,
            {"uidb64": "dummy", "token": "dummy"},
        ),
        ("email_verification_token_fail", views.EmailVerificationTokenFailView, {}),
        ("user_logout", views.UserLogoutView, {}),
        ("user_add", views.UserAddView, {}),
        ("user_edit_self", views.UserEditView, {}),
        ("user_edit", views.UserEditView, {"pk": 1}),
        ("user_change_password_self", views.UserChangePasswordView, {}),
        ("user_change_password", views.UserChangePasswordView, {"pk": 1}),
        ("user_forgot_password", views.UserForgotPasswordView, {}),
        ("user_forgot_password_success", views.UserForgotPasswordSuccessView, {}),
        (
            "user_reset_password",
            views.UserResetPasswordView,
            {"uidb64": "dummy", "token": "dummy"},
        ),
        ("user_reset_password_success", views.UserResetPasswordSuccessView, {}),
        ("user_delete", views.UserDeleteView, {"pk": 1}),
        ("user_list", views.UserListView, {}),
        ("user_list_export_as_xlsx", views.UserListExportAsXlsxView, {}),
        ("user_list_export_as_csv", views.UserListExportAsCsvView, {}),
        ("user_list_print", views.UserListPrintView, {}),
        ("user_list_copy", views.UserListCopyView, {}),
        ("user_group_view", views.UserGroupView, {"pk": 1}),
        ("user_group_list", views.UserGroupListView, {}),
        ("user_group_list_export_as_xlsx", views.UserGroupListExportAsXlsxView, {}),
        ("user_group_list_export_as_csv", views.UserGroupListExportAsCsvView, {}),
        ("user_group_list_print", views.UserGroupListPrintView, {}),
        ("user_group_list_copy", views.UserGroupListCopyView, {}),
        ("user_group_add", views.UserGroupAddView, {}),
        ("user_group_edit", views.UserGroupEditView, {"pk": 1}),
        ("user_group_delete", views.UserGroupDeleteView, {"pk": 1}),
    ],
)
def test_user_url_resolves(view, view_class, kwargs):
    url = reverse(view, kwargs=kwargs)
    assert resolve(url).func.view_class == view_class
