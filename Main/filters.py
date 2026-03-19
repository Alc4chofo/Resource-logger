"""
Per-app filter management for Privacy Monitor.
Stores which source apps are enabled/disabled in filters.json.
"""

import json
import os
import threading

FILTERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "filters.json")
_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(FILTERS_FILE):
        return {}
    try:
        with open(FILTERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict):
    with open(FILTERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_all_filters() -> dict:
    """Return the full filter dict. {app_name: {"enabled": bool}}"""
    with _lock:
        return _load()


def is_enabled(source: str) -> bool:
    """Check if a source app is enabled (should be logged/displayed)."""
    with _lock:
        data = _load()
    entry = data.get(source)
    if entry is None:
        # new app, auto-enable and save
        set_enabled(source, True)
        return True
    return entry.get("enabled", True)


def set_enabled(source: str, enabled: bool):
    """Enable or disable logging for a source app."""
    with _lock:
        data = _load()
        data[source] = {"enabled": enabled}
        _save(data)


def ensure_source(source: str):
    """Add a source to filters if it doesn't exist yet (default enabled)."""
    with _lock:
        data = _load()
        if source not in data:
            data[source] = {"enabled": True}
            _save(data)


def get_all_sources() -> list[str]:
    """Return sorted list of all known source app names."""
    with _lock:
        data = _load()
    return sorted(data.keys())
