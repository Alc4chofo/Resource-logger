"""
Privacy Monitor - Detection Engine
Monitors camera, microphone, screen capture, keyboard hooks,
and suspicious Python processes.
"""

import ctypes
import ctypes.wintypes
import threading
import time
import winreg
from datetime import datetime

import psutil

from logger import write_log
from filters import is_enabled, ensure_source

# Windows FILETIME epoch (Jan 1, 1601) offset from Unix epoch in 100-ns ticks
_FILETIME_UNIX_DIFF = 116444736000000000


def _filetime_to_datetime(ft: int) -> datetime | None:
    """Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if ft <= 0:
        return None
    try:
        timestamp = (ft - _FILETIME_UNIX_DIFF) / 10_000_000
        return datetime.fromtimestamp(timestamp)
    except (OSError, ValueError, OverflowError):
        return None


# ----------------------------------------------------------------
# 1) ConsentStore-based detection (Camera, Mic, Screen Capture)
# ----------------------------------------------------------------

_CONSENT_STORE_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"

_RESOURCE_MAP = {
    "webcam": "CAMERA",
    "microphone": "MICROPHONE",
    "screenCapture": "SCREENSHOT",
}


class ConsentStoreMonitor:
    """Polls the Windows CapabilityAccessManager ConsentStore registry
    to detect which apps have recently accessed camera, mic, or screen capture."""

    def __init__(self):
        # tracks the last seen timestamps per (resource, app) to detect new access
        # key = (resource_key, app_subkey), value = last_used_start filetime
        self._last_seen: dict[tuple[str, str], int] = {}
        self._initialized = False

    def scan(self):
        """Scan all consent store resources and log new accesses.
        First scan only seeds the cache — no logging until we see actual changes."""
        for resource_key, log_tag in _RESOURCE_MAP.items():
            self._scan_resource(resource_key, log_tag)
        if not self._initialized:
            self._initialized = True

    def _scan_resource(self, resource_key: str, log_tag: str):
        base_path = f"{_CONSENT_STORE_BASE}\\{resource_key}"
        self._scan_subkeys(base_path, resource_key, log_tag)
        # also check NonPackaged subkey for desktop apps
        nonpkg_path = f"{base_path}\\NonPackaged"
        self._scan_subkeys(nonpkg_path, resource_key, log_tag)

    def _scan_subkeys(self, reg_path: str, resource_key: str, log_tag: str):
        try:
            key = winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, reg_path, 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
        except OSError:
            return

        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break

                self._check_app_access(
                    reg_path, subkey_name, resource_key, log_tag
                )
        finally:
            winreg.CloseKey(key)

    def _check_app_access(self, parent_path: str, app_key: str,
                          resource_key: str, log_tag: str):
        full_path = f"{parent_path}\\{app_key}"
        try:
            key = winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, full_path, 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
        except OSError:
            return

        try:
            start_ft = self._read_qword(key, "LastUsedTimeStart")
            stop_ft = self._read_qword(key, "LastUsedTimeStop")
        except Exception:
            winreg.CloseKey(key)
            return
        winreg.CloseKey(key)

        if start_ft is None or start_ft == 0:
            return

        cache_key = (resource_key, app_key)
        prev_start = self._last_seen.get(cache_key, 0)

        if start_ft > prev_start:
            self._last_seen[cache_key] = start_ft

            # first scan just seeds the cache — don't log historical entries
            if not self._initialized:
                return

            # clean up the app name for display
            source = self._clean_app_name(app_key)
            ensure_source(source)

            if not is_enabled(source):
                return

            start_dt = _filetime_to_datetime(start_ft)
            stop_dt = _filetime_to_datetime(stop_ft) if stop_ft else None

            resource_name = resource_key.replace("screenCapture", "screen capture")
            if stop_dt and stop_ft > start_ft:
                msg = f"accessed {resource_name} (from {start_dt:%H:%M:%S} to {stop_dt:%H:%M:%S})"
            else:
                msg = f"is accessing {resource_name} (started {start_dt:%H:%M:%S})"

            write_log(log_tag, source, msg)

    @staticmethod
    def _read_qword(key, name: str) -> int | None:
        try:
            val, reg_type = winreg.QueryValueEx(key, name)
            return val
        except OSError:
            return None

    @staticmethod
    def _clean_app_name(raw: str) -> str:
        """Turn registry key names into readable app names.
        e.g. 'C:#Users#me#app.exe' -> 'app.exe'
        e.g. 'Microsoft.WindowsCamera_8wekyb...' -> 'Microsoft.WindowsCamera'
        """
        # NonPackaged paths use # as separator
        if "#" in raw:
            parts = raw.replace("#", "\\").split("\\")
            return parts[-1] if parts else raw
        # UWP apps have version/publisher hash after underscore
        if "_" in raw:
            return raw.split("_")[0]
        return raw


# ----------------------------------------------------------------
# 2) Keyboard Input Monitor
# ----------------------------------------------------------------

# suspicious DLLs commonly loaded by keyloggers / input monitors
_SUSPICIOUS_DLLS = {
    "pynput", "keyboard", "pyhooked", "pyhook",
    "keyhook", "keylog", "hookmanager",
}

_user32 = ctypes.windll.user32


def _get_foreground_process_name() -> str | None:
    """Get the process name of the window that currently has keyboard focus."""
    try:
        hwnd = _user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = ctypes.wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == 0:
            return None
        proc = psutil.Process(pid.value)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None


class KeyboardMonitor:
    """Tracks which application has keyboard focus (foreground window)
    and also detects suspicious keyboard hook DLLs."""

    def __init__(self):
        # foreground tracking
        self._current_fg: str | None = None
        self._fg_start: datetime | None = None
        # hook detection
        self._alerted_pids: set[int] = set()

    def scan(self):
        """Check foreground window and scan for suspicious hooks."""
        self._check_foreground()
        self._check_hooks()

    def _check_foreground(self):
        """Log when a different app gains keyboard focus."""
        fg = _get_foreground_process_name()
        if fg is None:
            return

        if fg != self._current_fg:
            # log the previous app's session if there was one
            if self._current_fg and self._fg_start:
                source = self._current_fg
                ensure_source(source)
                if is_enabled(source):
                    start_s = self._fg_start.strftime("%H:%M:%S")
                    end_s = datetime.now().strftime("%H:%M:%S")
                    write_log("KEYBOARD", source,
                              f"had keyboard focus (from {start_s} to {end_s})")

            self._current_fg = fg
            self._fg_start = datetime.now()

    def flush(self):
        """Log the current foreground session (called when monitoring stops)."""
        if self._current_fg and self._fg_start:
            source = self._current_fg
            ensure_source(source)
            if is_enabled(source):
                start_s = self._fg_start.strftime("%H:%M:%S")
                end_s = datetime.now().strftime("%H:%M:%S")
                write_log("KEYBOARD", source,
                          f"had keyboard focus (from {start_s} to {end_s})")
        self._current_fg = None
        self._fg_start = None

    def _check_hooks(self):
        """Scan for processes loading known keylogger DLLs."""
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if pid in self._alerted_pids:
                    continue

                try:
                    for dll in proc.memory_maps():
                        dll_lower = dll.path.lower()
                        for sus in _SUSPICIOUS_DLLS:
                            if sus in dll_lower:
                                self._alerted_pids.add(pid)
                                source = proc.info["name"] or f"PID:{pid}"
                                ensure_source(source)
                                if is_enabled(source):
                                    write_log("KEYBOARD_HOOK", source,
                                              f"loaded suspicious keyboard hook module: {dll.path}")
                                break
                        if pid in self._alerted_pids:
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # clean up stale PIDs
        alive = {p.pid for p in psutil.process_iter(["pid"])}
        self._alerted_pids &= alive


# ----------------------------------------------------------------
# 3) Python Spyware Library Detection
# ----------------------------------------------------------------

_SPY_LIBRARIES = {
    "pyautogui", "pynput", "keyboard", "mouse",
    "mss", "pyscreenshot", "pydirectinput",
    "PIL.ImageGrab", "cv2.VideoCapture",
    "pyhooked", "pyhook",
}

# match against command lines and memory maps
_SPY_KEYWORDS = {
    "pyautogui", "pynput", "keyboard", "mouse",
    "mss", "pyscreenshot", "imagegrab", "videocapture",
    "pydirectinput", "pyhooked", "pyhook",
    "screenshot", "screen_capture", "screencap",
}


class PythonSpyMonitor:
    """Detects running Python processes that import spy-like libraries."""

    def __init__(self):
        self._alerted_pids: set[int] = set()

    def scan(self):
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info["name"] or "").lower()
                if "python" not in name:
                    continue

                pid = proc.info["pid"]
                if pid in self._alerted_pids:
                    continue

                findings = []

                # check command line args
                cmdline = proc.info.get("cmdline") or []
                cmdline_str = " ".join(cmdline).lower()
                for kw in _SPY_KEYWORDS:
                    if kw in cmdline_str:
                        findings.append(f"cmdline contains '{kw}'")

                # check memory maps for loaded modules
                try:
                    for mmap in proc.memory_maps():
                        path_lower = mmap.path.lower()
                        for kw in _SPY_KEYWORDS:
                            if kw in path_lower:
                                findings.append(f"loaded module: {mmap.path}")
                                break
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass

                # check open files
                try:
                    for of in proc.open_files():
                        path_lower = of.path.lower()
                        for kw in _SPY_KEYWORDS:
                            if kw in path_lower:
                                findings.append(f"open file: {of.path}")
                                break
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass

                if findings:
                    self._alerted_pids.add(pid)
                    # try to get the script name from cmdline
                    source = self._get_script_name(cmdline) or name or f"python(PID:{pid})"
                    ensure_source(source)
                    if is_enabled(source):
                        detail = "; ".join(dict.fromkeys(findings))  # dedupe
                        write_log("SUSPICIOUS_PROCESS", source, detail)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # clean up stale PIDs
        alive = {p.pid for p in psutil.process_iter(["pid"])}
        self._alerted_pids &= alive

    @staticmethod
    def _get_script_name(cmdline: list[str]) -> str | None:
        """Try to extract the script filename from a Python process cmdline."""
        for arg in cmdline:
            if arg.endswith(".py") or arg.endswith(".pyw"):
                parts = arg.replace("\\", "/").split("/")
                return parts[-1]
        return None


# ----------------------------------------------------------------
# Combined Monitor (runs all scanners)
# ----------------------------------------------------------------

class PrivacyMonitor:
    """Runs all detection scanners in a background thread."""

    def __init__(self, on_new_log=None):
        self._consent = ConsentStoreMonitor()
        self._keyboard = KeyboardMonitor()
        self._pyspy = PythonSpyMonitor()
        self._running = False
        self._thread: threading.Thread | None = None
        self._interval = 5  # seconds between scans
        self.on_new_log = on_new_log  # callback for GUI updates

    @property
    def running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        # flush the current keyboard focus session before stopping
        self._keyboard.flush()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    def _loop(self):
        while self._running:
            try:
                self._consent.scan()
                self._keyboard.scan()
                self._pyspy.scan()
                if self.on_new_log:
                    self.on_new_log()
            except Exception:
                pass  # don't crash the monitor thread
            time.sleep(self._interval)
