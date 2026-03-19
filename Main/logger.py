"""
Log file management for Privacy Monitor.
Handles writing, reading, and 30-day cleanup of logs.txt.
"""

import os
import threading
from datetime import datetime, timedelta

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs.txt")
_lock = threading.Lock()


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_log(category: str, source: str, message: str):
    """Append a log entry. Thread-safe.
    Format: [2026-03-19 14:30:05] [CAMERA] source_app | message
    """
    line = f"[{_now_str()}] [{category}] {source} | {message}\n"
    with _lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def read_logs() -> list[str]:
    """Return all log lines from the file."""
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.readlines()


def purge_old_entries(days: int = 30):
    """Remove log entries older than `days` days."""
    if not os.path.exists(LOG_FILE):
        return
    cutoff = datetime.now() - timedelta(days=days)
    kept = []
    with _lock:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    # extract timestamp from [YYYY-MM-DD HH:MM:SS]
                    ts_str = line[1:20]
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff:
                        kept.append(line)
                except (ValueError, IndexError):
                    kept.append(line)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.writelines(kept)


def clear_logs():
    """Delete all log entries."""
    with _lock:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")


def parse_log_line(line: str) -> dict | None:
    """Parse a log line into its components.
    Returns dict with keys: timestamp, category, source, message
    or None if parsing fails.
    """
    try:
        # [2026-03-19 14:30:05] [CAMERA] source_app | message
        ts_str = line[1:20]
        rest = line[22:]  # after "] "
        cat_end = rest.index("]")
        category = rest[1:cat_end]
        after_cat = rest[cat_end + 2:]  # after "] "
        pipe_idx = after_cat.index("|")
        source = after_cat[:pipe_idx].strip()
        message = after_cat[pipe_idx + 1:].strip()
        return {
            "timestamp": ts_str,
            "category": category,
            "source": source,
            "message": message,
        }
    except (ValueError, IndexError):
        return None
