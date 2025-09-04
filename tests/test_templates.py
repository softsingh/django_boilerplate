import pytest
from django.template.loader import render_to_string


@pytest.mark.parametrize(
    "template",
    [
        "dashboard.html",
        "forbidden.html",
        "index.html",
        "internal_server_error.html",
        "not_found.html",
        "settings.html",
        "under_maintenance.html",
    ],
)
def test_project_templates_render(template):
    html = render_to_string(template, {})
    assert "<html" in html or "<!DOCTYPE" in html
