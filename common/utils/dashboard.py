import json
import os
import threading
from pathlib import Path
from django.conf import settings

_links_cache = None
_links_mtime = None
_cache_lock = threading.Lock()


def get_dashboard_links():
    """
    Load and cache dashboard links from JSON file.
    Reloads only if file changes. Thread-safe.
    """
    global _links_cache, _links_mtime
    json_path = Path(settings.BASE_DIR) / "data" / "dashboard_links.json"
    try:
        mtime = os.path.getmtime(json_path)
    except OSError:
        return None

    with _cache_lock:
        if _links_cache is None or _links_mtime != mtime:
            try:
                with open(json_path, encoding="utf-8") as f:
                    _links_cache = json.load(f)
                _links_mtime = mtime
            except (OSError, json.JSONDecodeError):
                return None

    return _links_cache or {}
