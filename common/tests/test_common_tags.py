import pytest
from django import forms
from common.templatetags import common_tags

pytestmark = pytest.mark.django_db


# ---------- replace ----------
@pytest.mark.parametrize(
    "value,args,expected",
    [
        ("hello world", "world,there", "hello there"),
        ("hello world", "foo,bar", "hello world"),  # no match
        ("hello world", "invalid", "hello world"),  # bad args
    ],
)
def test_replace_filter(value, args, expected):
    assert common_tags.replace(value, args) == expected


# ---------- class_name ----------
def test_class_name_filter():
    assert common_tags.class_name(123) == "int"
    assert common_tags.class_name("abc") == "str"

    class Dummy:
        pass

    assert common_tags.class_name(Dummy()) == "Dummy"


# ---------- initials ----------
@pytest.mark.parametrize(
    "name,expected",
    [
        ("First Last", "FL"),
        ("First Middle Last", "FL"),
        ("First", "F"),
        ("", ""),
        (None, ""),
    ],
)
def test_initials_filter(name, expected):
    assert common_tags.initials(name) == expected


# ---------- add_error_class ----------
class DummyForm(forms.Form):
    name = forms.CharField(widget=forms.TextInput(attrs={"class": "form-control"}))


def test_add_error_class_with_errors():
    form = DummyForm(data={})  # missing required field -> error
    form.is_valid()  # populates errors
    field = form["name"]
    rendered = common_tags.add_error_class(field, form.errors)
    assert "invalid" in rendered


def test_add_error_class_without_errors():
    form = DummyForm(data={"name": "ok"})
    assert form.is_valid()
    field = form["name"]
    rendered = common_tags.add_error_class(field, form.errors)
    # no 'invalid' class should be added
    assert "invalid" not in rendered
