from django.contrib.auth.views import redirect_to_login
from django.contrib.auth.mixins import UserPassesTestMixin
from django.shortcuts import render
from django.contrib import messages


class MyPermissionRequiredMixin(UserPassesTestMixin):
    permission_required = None
    another_user_permission_required = None
    permission_denied_message = "You do not have permission to perform this action"
    not_authenticated_message = "Please login to proceed further"

    def test_func(self):
        """
        Allow the action if the user is:
        - A superuser or
        - Has permission_required
        """
        # Superusers can perform every task.
        if self.request.user.is_superuser:  # type: ignore
            return True

        # if another user
        if self.another_user_permission_required and hasattr(self, "get_object"):
            obj = getattr(self, "get_object")()
            if self.request.user != obj:  # type: ignore
                return self.request.user.has_perm(  # type: ignore
                    self.permission_required
                ) and self.request.user.has_perm(  # type: ignore
                    self.another_user_permission_required
                )

        # Users with permission_required can perform the action.
        return self.request.user.has_perm(self.permission_required)  # type: ignore

    def handle_no_permission(self):

        if not self.request.user.is_authenticated:  # type: ignore
            messages.error(self.request, self.not_authenticated_message)  # type: ignore
            return redirect_to_login(
                self.request.get_full_path(), login_url=self.get_login_url()  # type: ignore
            )

        referer = self.request.META.get("HTTP_REFERER", "/")  # type: ignore
        return render(
            self.request,  # type: ignore
            "forbidden.html",
            {"referer": referer, "message": self.permission_denied_message},
            status=403,
        )
