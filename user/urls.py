from django.urls import path

from . import views

urlpatterns = [
    path("", views.UserView.as_view(), name="user_view_self"),
    path("<int:pk>/", views.UserView.as_view(), name="user_view"),
    path("login/", views.UserLoginView.as_view(), name="user_login"),
    path("register/", views.UserRegisterView.as_view(), name="user_register"),
    path(
        "register-success/",
        views.UserRegisterSuccessView.as_view(),
        name="user_register_success",
    ),
    path(
        "request-email-verification/",
        views.RequestEmailVerificationView.as_view(),
        name="request_email_verification",
    ),
    path(
        "email-verification-sent/",
        views.EmailVerificationSentView.as_view(),
        name="email_verification_sent",
    ),
    path(
        "verify-email/<uidb64>/<token>/",
        views.EmailVerificationView.as_view(),
        name="verify_email",
    ),
    path(
        "email-verification-token-fail/",
        views.EmailVerificationTokenFailView.as_view(),
        name="email_verification_token_fail",
    ),
    path("logout/", views.UserLogoutView.as_view(), name="user_logout"),
    path("add/", views.UserAddView.as_view(), name="user_add"),
    path("edit/", views.UserEditView.as_view(), name="user_edit_self"),
    path("edit/<int:pk>/", views.UserEditView.as_view(), name="user_edit"),
    path(
        "change-password/",
        views.UserChangePasswordView.as_view(),
        name="user_change_password_self",
    ),
    path(
        "change-password/<int:pk>/",
        views.UserChangePasswordView.as_view(),
        name="user_change_password",
    ),
    path(
        "forgot-password/",
        views.UserForgotPasswordView.as_view(),
        name="user_forgot_password",
    ),
    path(
        "forgot-password-success/",
        views.UserForgotPasswordSuccessView.as_view(),
        name="user_forgot_password_success",
    ),
    path(
        "reset-password/<uidb64>/<token>/",
        views.UserResetPasswordView.as_view(),
        name="user_reset_password",
    ),
    path(
        "reset-password-success",
        views.UserResetPasswordSuccessView.as_view(),
        name="user_reset_password_success",
    ),
    path("delete/<int:pk>/", views.UserDeleteView.as_view(), name="user_delete"),
    path("list/", views.UserListView.as_view(), name="user_list"),
    path(
        "list/export_as_xlsx",
        views.UserListExportAsXlsxView.as_view(),
        name="user_list_export_as_xlsx",
    ),
    path(
        "list/export_as_csv",
        views.UserListExportAsCsvView.as_view(),
        name="user_list_export_as_csv",
    ),
    path(
        "list/print",
        views.UserListPrintView.as_view(),
        name="user_list_print",
    ),
    path(
        "list/copy",
        views.UserListCopyView.as_view(),
        name="user_list_copy",
    ),
    path(
        "group/view/<int:pk>/",
        views.UserGroupView.as_view(),
        name="user_group_view",
    ),
    path(
        "group/list",
        views.UserGroupListView.as_view(),
        name="user_group_list",
    ),
    path(
        "group/list/export_as_xlsx",
        views.UserGroupListExportAsXlsxView.as_view(),
        name="user_group_list_export_as_xlsx",
    ),
    path(
        "group/list/export_as_csv",
        views.UserGroupListExportAsCsvView.as_view(),
        name="user_group_list_export_as_csv",
    ),
    path(
        "group/list/print",
        views.UserGroupListPrintView.as_view(),
        name="user_group_list_print",
    ),
    path(
        "group/list/copy",
        views.UserGroupListCopyView.as_view(),
        name="user_group_list_copy",
    ),
    path(
        "group/add",
        views.UserGroupAddView.as_view(),
        name="user_group_add",
    ),
    path(
        "group/edit/<int:pk>/",
        views.UserGroupEditView.as_view(),
        name="user_group_edit",
    ),
    path(
        "group/delete/<int:pk>/",
        views.UserGroupDeleteView.as_view(),
        name="user_group_delete",
    ),
]
