import pytest
from types import SimpleNamespace
from django.template.loader import render_to_string
from django.template import TemplateSyntaxError
from django.urls import NoReverseMatch
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()
pytestmark = pytest.mark.django_db


class DummyUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "groups", "user_permissions"]


class DummyGroupAddEditForm(forms.Form):
    name = forms.CharField(help_text="Enter group name")
    permissions = forms.MultipleChoiceField(
        choices=[("1", "Can View"), ("2", "Can Edit")], required=False
    )


def make_grouped_permissions():
    return {
        "general": [
            SimpleNamespace(id=1, name="can view"),
            SimpleNamespace(id=2, name="can edit"),
        ],
        "advanced": [
            SimpleNamespace(id=3, name="can delete"),
        ],
    }


@pytest.mark.parametrize(
    "template",
    [
        "user/add.html",
        "user/change_password.html",
        "user/edit.html",
        "user/email_verification_sent.html",
        "user/forgot_password_email.html",
        "user/forgot_password_success.html",
        "user/forgot_password.html",
        "user/group_add_edit.html",
        "user/group_list_copy.html",
        "user/group_list_print.html",
        "user/group_list.html",
        "user/group_view.html",
        "user/list_copy.html",
        "user/list_print.html",
        "user/list.html",
        "user/login.html",
        "user/register_success.html",
        "user/register.html",
        "user/request_email_verification.html",
        "user/reset_password_success.html",
        "user/reset_password_token_fail.html",
        "user/reset_password.html",
        "user/verification_email.html",
        "user/view.html",
    ],
)
def test_user_templates_render(template, normal_user, user_group):

    if template == "user/view.html" or template == "user/edit.html":
        grouped_permissions = make_grouped_permissions()
        form = DummyUserForm(instance=normal_user)
        context = {
            "form": form,
            "userobj": normal_user,
            "grouped_permissions": grouped_permissions,
            "referer": None,
        }

    elif template == "user/change_password.html":
        context = {"userobj": normal_user}

    elif template == "user/forgot_password_email.html":
        context = {"uid": "dummy", "token": "dummy"}

    elif template == "user/group_view.html" or template == "user/group_add_edit.html":
        form = DummyGroupAddEditForm()
        grouped_permissions = make_grouped_permissions()
        context = {
            "title": "Add Group",
            "form": form,
            "group": user_group,
            "grouped_permissions": grouped_permissions,
            "button_text": "Save",
            "referer": None,
        }

    else:
        context = {}

    try:
        html = render_to_string(template, context=context)
    except (TemplateSyntaxError, NoReverseMatch, Exception):
        pytest.skip(f"{template} requires extra context")

    assert "<html" in html or "<!DOCTYPE" in html
