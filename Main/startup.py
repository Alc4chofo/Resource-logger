"""
Windows auto-start management for Privacy Monitor.
Adds/removes the app from the Windows Run registry key.
"""

import os
import sys
import winreg

_RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_APP_NAME = "PrivacyMonitor"


def _get_exe_path() -> str:
    """Get the path to the current executable or script."""
    if getattr(sys, "frozen", False):
        # running as compiled .exe
        return sys.executable
    else:
        # running as script — use pythonw to avoid console window
        script = os.path.abspath(__file__)
        gui_script = os.path.join(os.path.dirname(script), "gui.py")
        python = sys.executable
        # prefer pythonw if available
        pythonw = python.replace("python.exe", "pythonw.exe")
        if os.path.exists(pythonw):
            python = pythonw
        return f'"{python}" "{gui_script}" --minimized'


def enable_startup():
    """Add the app to Windows startup."""
    try:
        key = winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        winreg.SetValueEx(key, _APP_NAME, 0, winreg.REG_SZ, _get_exe_path())
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


def disable_startup():
    """Remove the app from Windows startup."""
    try:
        key = winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        )
        winreg.DeleteValue(key, _APP_NAME)
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


def is_startup_enabled() -> bool:
    """Check if the app is set to run at startup."""
    try:
        key = winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER, _RUN_KEY, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        winreg.QueryValueEx(key, _APP_NAME)
        winreg.CloseKey(key)
        return True
    except OSError:
        return False
