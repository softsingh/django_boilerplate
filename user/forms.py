from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    UserCreationForm,
    UserChangeForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

from .models import CustomUser


class UserAddForm(UserCreationForm):
    """Custom user add form based on django UserCreationForm"""

    class Meta:
        model = CustomUser
        fields = [
            "username",
            "email",
            "full_name",
            "gender",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["username"].label = "Username (Login ID)"

        self.fields["username"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Username for Login"}
        )
        self.fields["email"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Email"}
        )
        self.fields["full_name"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Full Name"}
        )
        self.fields["gender"].widget.attrs.update({"class": "form-select"})
        self.fields["password1"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Password"}
        )
        self.fields["password2"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Confirm Password"}
        )


class UserRegisterForm(UserAddForm):
    """Custom user registration form based on django UserAddForm"""

    terms_conditions = forms.BooleanField(required=True, initial=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Update fields
        self.fields["terms_conditions"].widget.attrs.update(
            {"class": "form-check-input"}
        )

        self.fields["terms_conditions"].label = "I agree to terms & conditions"


class RequestEmailVerificationForm(forms.Form):
    """Form to request email verification in case the email is not verified"""

    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={"placeholder": "Enter your Email", "class": "form-control"}
        )
    )

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError(
                "Account with this email address does not exist."
            )

        return email


class LoginForm(AuthenticationForm):
    """Custom user login form based on django AuthenticatioForm"""

    remember_me = forms.BooleanField(required=False, initial=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Customize the widgets for username and password fields
        self.fields["username"].widget = forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your Username",
                "autofocus": "",
            }
        )

        self.fields["password"].widget = forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your Password",
            }
        )

        # Update fields
        self.fields["remember_me"].widget.attrs.update({"class": "form-check-input"})

    class Meta:
        model = CustomUser


class ForgotPasswordForm(PasswordResetForm):
    """Custom forgot password form based on django PasswordResetForm"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["email"].widget = forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your Email",
                "autofocus": "",
            }
        )


class ResetPasswordForm(SetPasswordForm):
    """Custom reset password form based on django SetPasswordForm"""

    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter new Password",
                "autofocus": "",
            }
        ),
    )

    new_password2 = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "Confirm new Password"}
        ),
    )


class UserEditForm(UserChangeForm):
    """Custom user edit form based on django UserChangeForm"""

    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )

    user_permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )

    class Meta:
        model = CustomUser
        fields = [
            "picture",
            "username",
            "email",
            "full_name",
            "phone_number",
            "gender",
            "remarks",
            "is_superuser",
            "is_staff",
            "is_active",
            "groups",
            "user_permissions",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "password" in self.fields:
            self.fields.pop("password")

        self.fields["username"].label = "Username (Login ID)"
        self.fields["username"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Username for Login"}
        )
        self.fields["email"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Email"}
        )
        self.fields["full_name"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Full Name"}
        )
        self.fields["phone_number"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Enter Phone Number"}
        )
        self.fields["gender"].widget.attrs.update({"class": "form-select"})
        self.fields["remarks"].widget.attrs.update(
            {"class": "form-control", "placeholder": "Write something about the User"}
        )
        self.fields["is_superuser"].widget.attrs.update({"class": "form-check-input"})
        self.fields["is_staff"].widget.attrs.update({"class": "form-check-input"})
        self.fields["is_active"].widget.attrs.update({"class": "form-check-input"})

        self.fields["is_superuser"].label = "Superuser"
        self.fields["is_staff"].label = "Staff"
        self.fields["is_active"].label = "Active"


class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):

        user = kwargs.get("user")
        target_user = kwargs.pop("target_user", user)  # fallback to user if not passed
        super().__init__(*args, **kwargs)

        # Remove old_password field if the request.user != target_user
        if user != target_user:
            self.fields.pop("old_password")

        for field in self.fields.values():
            field.widget.attrs.update({"class": "form-control"})


class UserGroupAddForm(forms.ModelForm):
    """User group add form"""

    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )

    class Meta:
        model = Group
        fields = ["name"]
        widgets = {
            "name": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Enter Group Name"}
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        permissions_field = self.fields.get("permissions")
        if isinstance(permissions_field, forms.ModelMultipleChoiceField):
            permissions_field.queryset = Permission.objects.select_related(
                "content_type"
            ).order_by("content_type__app_label", "content_type__model", "codename")

        # Pre-select existing permissions if editing an existing group
        if self.instance and self.instance.pk:
            self.initial["permissions"] = self.instance.permissions.values_list(
                "pk", flat=True
            )

    def clean_name(self):
        name = self.cleaned_data["name"]
        qs = Group.objects.filter(name=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("A group with this name already exists.")
        return name
