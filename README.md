# Privacy Monitor

A Windows desktop application that monitors which programs are accessing your computer's sensitive resources — camera, microphone, screen capture, and keyboard. Built to help you catch spyware and keep track of what's using your hardware.

![Windows](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.11+-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

## What it detects

| Category | How it works |
|---|---|
| **Camera** | Reads the Windows ConsentStore registry to detect apps that accessed your webcam |
| **Microphone** | Same ConsentStore approach for microphone access |
| **Screen Capture** | Detects apps using Windows screen capture APIs |
| **Keyboard** | Tracks which application has keyboard focus (foreground window) and logs every switch |
| **Keyboard Hooks** | Scans running processes for suspicious DLLs commonly used by keyloggers (`pynput`, `pyhook`, etc.) |
| **Suspicious Python Processes** | Detects running Python scripts that import spy-like libraries (`pyautogui`, `mss`, `pyscreenshot`, `pydirectinput`, etc.) |

## How it works

- **ConsentStore monitoring** — Polls the Windows `CapabilityAccessManager\ConsentStore` registry keys for camera, microphone, and screen capture access. Only logs *new* access events that occur after monitoring starts (ignores historical entries).
- **Foreground window tracking** — Uses `GetForegroundWindow()` + `GetWindowThreadProcessId()` to detect which app currently has keyboard focus. Logs every time focus switches with timestamps.
- **DLL scanning** — Iterates process memory maps looking for known keylogger/spyware modules.
- **Python process inspection** — Checks command lines, loaded modules, and open files of Python processes for spy-related libraries.

## Installation

### Option 1: Run from source

```bash
pip install -r requirements.txt
python gui.py
```

### Option 2: Download the release

-Go to releases, and download the latest executable file from there.


## Usage

1. **Launch** the app (double-click `PrivacyMonitor.exe` or run `python gui.py`)
2. **Click "Start Detecting"** — the app begins monitoring in the background
3. **Close the window** — when monitoring is active, closing the window minimizes to the system tray (the little arrow in the taskbar)
4. **Open anytime** — right-click the tray icon → "Open" to view the last 30 days of logs
5. **Stop monitoring** — click "Stop Detecting" to halt monitoring, remove from startup, and exit the tray

### System tray

When monitoring is active and you close the window, the app lives in the Windows system tray. Right-click the icon for options:

- **Open** — Show the main window
- **Stop Monitoring** — Stop detection and open the window
- **Exit** — Stop everything and close

### Auto-start with Windows

Clicking "Start Detecting" automatically registers the app to run at Windows startup (via the `HKCU\...\Run` registry key). Clicking "Stop Detecting" removes it.

### Filtering

- **Category filter** — Use the dropdown to show only Camera, Microphone, Keyboard, etc.
- **Per-app filter** — The sidebar lists every detected app. Uncheck any to hide its entries from the log and stop logging future events from it.

Filter settings are saved in `filters.json`.

### Logs

All activity is logged to `logs.txt` in the application directory. Entries older than 30 days are automatically purged on startup. Format:

```
[2026-03-19 21:15:00] [KEYBOARD] chrome.exe | had keyboard focus (from 21:10:30 to 21:15:00)
[2026-03-19 21:15:02] [CAMERA] chrome.exe | accessed webcam (from 21:14:50 to 21:15:01)
[2026-03-19 21:15:02] [MICROPHONE] Discord.exe | is accessing microphone (started 20:30:00)
[2026-03-19 21:15:05] [KEYBOARD_HOOK] sketchy.exe | loaded suspicious keyboard hook module: C:\...\pynput\...
[2026-03-19 21:15:05] [SUSPICIOUS_PROCESS] spy_script.py | cmdline contains 'pyautogui'
```

## Uninstall

Click the **"Uninstall"** button in the toolbar. This removes:

- Windows startup registry entry
- `logs.txt`
- `filters.json`
- System tray icon

After uninstalling, you can safely delete the application files.

## Project structure

```
privacy-monitor/
├── gui.py           # Main window, log viewer, system tray, uninstall
├── monitor.py       # Detection engine (ConsentStore, keyboard, Python spy scanner)
├── logger.py        # Thread-safe log file read/write/purge
├── filters.py       # Per-app enable/disable filter persistence
├── startup.py       # Windows auto-start registry management
├── requirements.txt # Python dependencies
└── README.md
```

## Requirements

- Windows 10/11
- Python 3.11+ (if running from source)
- Dependencies: `pystray`, `Pillow`, `psutil`

## License

MIT License

Copyright (c) 2026 alcachofo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
