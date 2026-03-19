"""
Privacy Monitor - GUI + System Tray
Main application window with log viewer, per-app filters, and tray icon.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from logger import read_logs, parse_log_line, purge_old_entries, clear_logs, LOG_FILE
from filters import get_all_filters, set_enabled, ensure_source, FILTERS_FILE
from monitor import PrivacyMonitor
from startup import enable_startup, disable_startup

FONT = "Segoe UI"
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# category filter options
CATEGORIES = ["All", "CAMERA", "MICROPHONE", "SCREENSHOT", "KEYBOARD", "KEYBOARD_HOOK", "SUSPICIOUS_PROCESS"]
CATEGORY_LABELS = {
    "All": "All",
    "CAMERA": "Camera",
    "MICROPHONE": "Microphone",
    "SCREENSHOT": "Screenshots",
    "KEYBOARD": "Keyboard",
    "KEYBOARD_HOOK": "Keyboard Hooks",
    "SUSPICIOUS_PROCESS": "Suspicious Processes",
}


class PrivacyMonitorApp:
    def __init__(self, root, start_minimized=False):
        self.root = root
        self.root.title("Privacy Monitor by alcachofo")
        self.root.geometry("950x620")
        self.root.minsize(800, 500)

        self.monitor = PrivacyMonitor(on_new_log=self._schedule_refresh)
        self.tray_icon = None
        self.tray_thread = None
        self._current_category = "All"

        # source filter checkboxes: source_name -> BooleanVar
        self._source_vars: dict[str, tk.BooleanVar] = {}
        self._source_widgets: dict[str, ttk.Checkbutton] = {}

        # purge old entries on startup
        purge_old_entries(30)

        self._build_ui()
        self._load_logs()
        self._load_source_filters()

        # handle window close -> minimize to tray if monitoring
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if start_minimized:
            self.root.after(100, self._start_detecting)

    # ---- UI Building ----

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")

        self._build_toolbar()
        self._build_main_layout()
        self._build_statusbar()

    def _build_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill="x", padx=6, pady=(4, 0))

        self.btn_detect = ttk.Button(toolbar, text="Start Detecting",
                                      command=self._toggle_detecting)
        self.btn_detect.pack(side="left", padx=(0, 6))

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6, pady=2)

        ttk.Label(toolbar, text="Filter:", font=(FONT, 9)).pack(side="left", padx=(0, 4))
        self.category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(
            toolbar, textvariable=self.category_var,
            values=[CATEGORY_LABELS[c] for c in CATEGORIES],
            state="readonly", width=20
        )
        self.category_combo.set("All")
        self.category_combo.pack(side="left", padx=(0, 6))
        self.category_combo.bind("<<ComboboxSelected>>", self._on_category_change)

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6, pady=2)

        ttk.Button(toolbar, text="Refresh", command=self._load_logs).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Clear Logs", command=self._clear_logs).pack(side="left", padx=3)

        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6, pady=2)

        ttk.Button(toolbar, text="Uninstall", command=self._uninstall).pack(side="left", padx=3)

        # status indicator
        self.status_dot = tk.Canvas(toolbar, width=14, height=14, highlightthickness=0)
        self.status_dot.pack(side="right", padx=(6, 2))
        self._dot = self.status_dot.create_oval(2, 2, 12, 12, fill="#c0392b", outline="")

        self.status_text = ttk.Label(toolbar, text="Stopped", font=(FONT, 8),
                                      foreground="#c0392b")
        self.status_text.pack(side="right", padx=(0, 2))

    def _build_main_layout(self):
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=4)

        # --- left sidebar: source filters ---
        sidebar = ttk.Frame(paned, width=220)
        paned.add(sidebar, weight=0)

        ttk.Label(sidebar, text="Sources", font=(FONT, 10, "bold")).pack(
            anchor="w", padx=8, pady=(6, 2))
        ttk.Label(sidebar, text="Uncheck to ignore an app",
                  font=(FONT, 8), foreground="#888").pack(anchor="w", padx=8, pady=(0, 4))

        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", padx=4, pady=(0, 2))

        # scrollable frame for source checkboxes
        src_container = ttk.Frame(sidebar)
        src_container.pack(fill="both", expand=True)

        self.src_canvas = tk.Canvas(src_container, highlightthickness=0, bd=0, width=200)
        src_vsb = ttk.Scrollbar(src_container, orient="vertical", command=self.src_canvas.yview)
        self.src_inner = ttk.Frame(self.src_canvas)

        self.src_inner.bind("<Configure>",
                            lambda e: self.src_canvas.configure(scrollregion=self.src_canvas.bbox("all")))
        self.src_canvas_window = self.src_canvas.create_window((0, 0), window=self.src_inner, anchor="nw")
        self.src_canvas.bind("<Configure>",
                             lambda e: self.src_canvas.itemconfig(self.src_canvas_window, width=e.width))

        self.src_canvas.configure(yscrollcommand=src_vsb.set)
        self.src_canvas.pack(side="left", fill="both", expand=True)
        src_vsb.pack(side="right", fill="y")

        # --- right side: log viewer ---
        content = ttk.Frame(paned)
        paned.add(content, weight=1)

        ttk.Label(content, text="Activity Log", font=(FONT, 10, "bold")).pack(
            anchor="w", padx=8, pady=(6, 2))

        self.log_count_label = ttk.Label(content, text="0 entries",
                                          font=(FONT, 8), foreground="#888")
        self.log_count_label.pack(anchor="w", padx=8, pady=(0, 4))

        ttk.Separator(content, orient="horizontal").pack(fill="x", padx=4)

        log_frame = ttk.Frame(content)
        log_frame.pack(fill="both", expand=True, padx=4, pady=4)

        self.log_text = tk.Text(
            log_frame, font=(FONT, 9), wrap="word",
            state="disabled", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#d4d4d4", selectbackground="#264f78",
            relief="flat", bd=0, padx=8, pady=6
        )
        log_vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_vsb.pack(side="right", fill="y")

        # configure text tags for coloring
        self.log_text.tag_configure("timestamp", foreground="#6a9955")
        self.log_text.tag_configure("CAMERA", foreground="#569cd6")
        self.log_text.tag_configure("MICROPHONE", foreground="#ce9178")
        self.log_text.tag_configure("SCREENSHOT", foreground="#dcdcaa")
        self.log_text.tag_configure("KEYBOARD", foreground="#4ec9b0")
        self.log_text.tag_configure("KEYBOARD_HOOK", foreground="#f44747")
        self.log_text.tag_configure("SUSPICIOUS_PROCESS", foreground="#c586c0")
        self.log_text.tag_configure("source", foreground="#9cdcfe")
        self.log_text.tag_configure("message", foreground="#d4d4d4")

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, relief="sunken")
        bar.pack(fill="x", side="bottom")

        self.statusbar_label = ttk.Label(bar, text="Ready", font=(FONT, 8),
                                          foreground="#555", padding=(6, 2))
        self.statusbar_label.pack(side="left")

    # ---- Source Filters ----

    def _load_source_filters(self):
        """Populate the sidebar with checkboxes for each known source app."""
        filters = get_all_filters()

        # also scan current logs for sources not yet in filters
        for line in read_logs():
            parsed = parse_log_line(line)
            if parsed:
                ensure_source(parsed["source"])
        filters = get_all_filters()

        for source_name in sorted(filters.keys()):
            if source_name not in self._source_vars:
                self._add_source_checkbox(source_name, filters[source_name].get("enabled", True))

    def _add_source_checkbox(self, source: str, enabled: bool):
        var = tk.BooleanVar(value=enabled)
        self._source_vars[source] = var

        cb = ttk.Checkbutton(
            self.src_inner, text=source, variable=var,
            command=lambda s=source, v=var: self._on_source_toggle(s, v)
        )
        cb.pack(anchor="w", padx=8, pady=1)
        self._source_widgets[source] = cb

    def _on_source_toggle(self, source: str, var: tk.BooleanVar):
        set_enabled(source, var.get())
        self._load_logs()

    def _refresh_sources(self):
        """Check for newly discovered sources and add checkboxes."""
        filters = get_all_filters()
        for source_name in sorted(filters.keys()):
            if source_name not in self._source_vars:
                self._add_source_checkbox(source_name, filters[source_name].get("enabled", True))

    # ---- Log Display ----

    def _load_logs(self):
        """Read log file and display filtered entries."""
        lines = read_logs()
        enabled_sources = {s for s, v in self._source_vars.items() if v.get()}
        # also include sources we haven't seen yet (new ones are enabled by default)
        all_filters = get_all_filters()
        for s, f in all_filters.items():
            if f.get("enabled", True) and s not in self._source_vars:
                enabled_sources.add(s)

        # determine category filter
        cat_label = self.category_var.get()
        cat_key = None
        for key, label in CATEGORY_LABELS.items():
            if label == cat_label:
                cat_key = key
                break
        if cat_key == "All":
            cat_key = None

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")

        count = 0
        for line in lines:
            parsed = parse_log_line(line)
            if not parsed:
                continue

            # apply source filter
            if parsed["source"] not in enabled_sources:
                continue

            # apply category filter
            if cat_key and parsed["category"] != cat_key:
                continue

            # insert with color tags
            self.log_text.insert("end", f"[{parsed['timestamp']}] ", "timestamp")
            self.log_text.insert("end", f"[{parsed['category']}] ", parsed["category"])
            self.log_text.insert("end", f"{parsed['source']}", "source")
            self.log_text.insert("end", f" | {parsed['message']}\n", "message")
            count += 1

        self.log_text.configure(state="disabled")
        self.log_text.see("end")
        self.log_count_label.configure(text=f"{count} entries")

    def _on_category_change(self, event=None):
        self._load_logs()

    def _clear_logs(self):
        if messagebox.askyesno("Clear Logs",
                               "Delete all log entries? This cannot be undone."):
            clear_logs()
            self._load_logs()
            self.statusbar_label.configure(text="Logs cleared")

    # ---- Detection Toggle ----

    def _toggle_detecting(self):
        if self.monitor.running:
            self._stop_detecting()
        else:
            self._start_detecting()

    def _start_detecting(self):
        self.monitor.start()
        enable_startup()

        self.btn_detect.configure(text="Stop Detecting")
        self.status_dot.itemconfig(self._dot, fill="#2a7d2e")
        self.status_text.configure(text="Monitoring", foreground="#2a7d2e")
        self.statusbar_label.configure(text="Monitoring started — will continue on next boot")

    def _stop_detecting(self):
        self.monitor.stop()
        disable_startup()

        # remove tray icon if active
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

        self.btn_detect.configure(text="Start Detecting")
        self.status_dot.itemconfig(self._dot, fill="#c0392b")
        self.status_text.configure(text="Stopped", foreground="#c0392b")
        self.statusbar_label.configure(text="Monitoring stopped")

    def _schedule_refresh(self):
        """Called from monitor thread — schedule GUI refresh on main thread."""
        try:
            self.root.after(0, self._on_monitor_update)
        except Exception:
            pass

    def _on_monitor_update(self):
        self._refresh_sources()
        self._load_logs()

    # ---- System Tray ----

    def _minimize_to_tray(self):
        """Hide window and show system tray icon."""
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            self.statusbar_label.configure(
                text="pystray/Pillow not installed — cannot minimize to tray")
            return

        self.root.withdraw()

        # create a simple tray icon (green shield)
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # shield shape
        draw.rounded_rectangle([8, 4, 56, 56], radius=12, fill="#2a7d2e")
        draw.text((22, 14), "PM", fill="white")

        menu = pystray.Menu(
            pystray.MenuItem("Open", self._tray_open, default=True),
            pystray.MenuItem("Stop Monitoring", self._tray_stop),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._tray_exit),
        )

        self.tray_icon = pystray.Icon("PrivacyMonitor", img, "Privacy Monitor", menu)
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def _tray_open(self, icon=None, item=None):
        """Show the main window from tray."""
        self.root.after(0, self._show_window)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self._load_logs()
        self._refresh_sources()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

    def _tray_stop(self, icon=None, item=None):
        """Stop monitoring from tray context menu."""
        self.root.after(0, self._stop_detecting)
        self._tray_open()

    def _tray_exit(self, icon=None, item=None):
        """Exit the application from tray."""
        self.monitor.stop()
        disable_startup()
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.after(0, self.root.destroy)

    # ---- Uninstall ----

    def _uninstall(self):
        """Remove everything the app installed or modified."""
        if not messagebox.askyesno(
            "Uninstall Privacy Monitor",
            "This will:\n"
            "- Stop monitoring\n"
            "- Remove from Windows startup\n"
            "- Delete all logs (logs.txt)\n"
            "- Delete all filters (filters.json)\n"
            "- Remove tray icon\n\n"
            "Continue?"):
            return

        # stop monitoring
        if self.monitor.running:
            self.monitor.stop()

        # remove from Windows startup
        disable_startup()

        # remove tray icon
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

        # delete data files
        for path in (LOG_FILE, FILTERS_FILE):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

        messagebox.showinfo("Uninstalled",
                            "Privacy Monitor has been cleaned up.\n"
                            "You can now delete the application files.")
        self.root.destroy()

    def _on_close(self):
        """Handle window close button."""
        if self.monitor.running:
            # minimize to tray instead of closing
            self._minimize_to_tray()
        else:
            self.root.destroy()


def main():
    start_minimized = "--minimized" in sys.argv

    root = tk.Tk()
    app = PrivacyMonitorApp(root, start_minimized=start_minimized)

    if start_minimized:
        root.withdraw()

    root.mainloop()


if __name__ == "__main__":
    main()
