import json
from common.utils import dashboard


def test_dashboard_links_json(tmp_path, settings):
    data_dir = tmp_path / "data"
    data_dir.mkdir()  # create "data" folder
    data_file = data_dir / "dashboard_links.json"

    links = [
        {
            "label": "User List",
            "url": "/user/list",
            "permission": "user.can_view_others_profile",
        },
        {
            "label": "View User Profile",
            "url": "/user",
        },
        {
            "label": "Edit User Profile",
            "url": "/user/edit",
            "permission": "user.can_edit_profile",
        },
    ]

    data_file.write_text(json.dumps(links), encoding="utf-8")

    settings.BASE_DIR = tmp_path
    links = dashboard.get_dashboard_links()
    assert isinstance(links, list)
    assert links[0]["label"] == "User List"
