# src/ui/app.py
import os
import re
import sys
import json
import queue
import threading
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any

import customtkinter as ctk
from tkinter import filedialog, messagebox

from tkinterweb import HtmlFrame

# --- FIX: CustomTkinter mousewheel event.widget can be a string (Tk path) ---
try:
    from customtkinter.windows.widgets import ctk_scrollable_frame as _ctk_sf

    _orig_check = _ctk_sf.CTkScrollableFrame.check_if_master_is_canvas

    def _check_if_master_is_canvas_patched(self, widget):
        if isinstance(widget, str):
            try:
                widget = self.winfo_toplevel().nametowidget(widget)
            except Exception:
                return False
        return _orig_check(self, widget)

    _ctk_sf.CTkScrollableFrame.check_if_master_is_canvas = _check_if_master_is_canvas_patched
except Exception:
    pass


# ============================================================
# Parsing + Scoring helpers
# ============================================================

SCORE_RE = re.compile(r"Score:\s*(\d{1,3})\s*/\s*100", re.IGNORECASE)
SEVERITY_RE = re.compile(r"Severity:\s*([A-Z]+)", re.IGNORECASE)

PATH_KEYS = {
    "Artifact": re.compile(r"Artifact:\s*(.+)", re.IGNORECASE),
    "APK Report": re.compile(r"APK Report:\s*(.+)", re.IGNORECASE),
    "Case Report": re.compile(r"Case Report:\s*(.+)", re.IGNORECASE),
    "Ledger": re.compile(r"Ledger:\s*(.+)", re.IGNORECASE),
}

PIPELINE_SUMMARY_START = re.compile(r"==\s*PIPELINE SUMMARY\s*==", re.IGNORECASE)
DONE_RE = re.compile(r"\[DONE\].*return code:\s*(\d+)", re.IGNORECASE)


def clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))


def normalize_score_20(score_100: int) -> int:
    """Convert 0–100 into 0–20 scale (rounded)."""
    s100 = clamp_int(int(score_100), 0, 100)
    s20 = int(round(s100 / 5.0))
    return clamp_int(s20, 0, 20)


def score20_bucket(score20: int) -> Tuple[str, str]:
    """
    0–20 scale buckets
      0–4   SAFE
      5–9   LOW
      10–14 MODERATE
      15–17 HIGH
      18–20 CRITICAL
    """
    s = clamp_int(score20, 0, 20)
    if s <= 4:
        return ("SAFE", "#22C55E")
    if s <= 9:
        return ("LOW", "#84CC16")
    if s <= 14:
        return ("MODERATE", "#EAB308")
    if s <= 17:
        return ("HIGH", "#F97316")
    return ("CRITICAL", "#EF4444")


def severity_color(sev: str) -> str:
    sev = (sev or "").upper().strip()
    if sev == "SAFE":
        return "#22C55E"
    if sev == "LOW":
        return "#84CC16"
    if sev == "MODERATE":
        return "#EAB308"
    if sev == "HIGH":
        return "#F97316"
    if sev == "CRITICAL":
        return "#EF4444"
    return "#94A3B8"


def parse_reason_weight(reason: str) -> int:
    """Accept reasons like 'Something (+45)' OR 'Something +45'."""
    if not isinstance(reason, str):
        return 0
    m = re.search(r"\(\s*\+\s*(\d+)\s*\)", reason)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return 0
    m = re.search(r"\+\s*(\d+)\b", reason)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return 0
    return 0


# ============================================================
# Findings model (extensible)
# ============================================================

@dataclass
class Finding:
    category: str
    name: str
    severity: str
    weight: float
    evidence: str = ""
    recommendation: str = ""

    def to_line(self) -> str:
        return f"- [{self.severity}] {self.category} :: {self.name} (w={self.weight})"


@dataclass
class RunSummary:
    score: Optional[int] = None
    severity: Optional[str] = None
    return_code: Optional[int] = None

    pipeline_kv: Dict[str, str] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)

    findings: List[Finding] = field(default_factory=list)
    top_reasons: List[str] = field(default_factory=list)

    def best_report_path(self) -> Optional[str]:
        for k in ["Case Report", "APK Report"]:
            p = self.paths.get(k)
            if p and os.path.exists(p):
                return p
        for p in self.paths.values():
            if p and p.lower().endswith(".html") and os.path.exists(p):
                return p
        return None


class LogParser:
    """Incremental parsing of CLI output."""
    def __init__(self):
        self.summary = RunSummary()
        self._in_pipeline_summary = False

    def feed_line(self, line: str):
        s = line.strip()

        if PIPELINE_SUMMARY_START.search(s):
            self._in_pipeline_summary = True

        m = SCORE_RE.search(s)
        if m:
            try:
                self.summary.score = clamp_int(int(m.group(1)), 0, 100)
            except Exception:
                pass

        m = SEVERITY_RE.search(s)
        if m:
            self.summary.severity = m.group(1).upper()

        for key, rx in PATH_KEYS.items():
            mm = rx.search(s)
            if mm:
                p = mm.group(1).strip()
                p_abs = os.path.abspath(p) if not os.path.isabs(p) else p
                self.summary.paths[key] = p_abs

        if self._in_pipeline_summary and ":" in s:
            parts = s.split(":", 1)
            if len(parts) == 2:
                k = parts[0].strip()
                v = parts[1].strip()
                if k and v and len(k) <= 60:
                    self.summary.pipeline_kv[k] = v

        m = DONE_RE.search(s)
        if m:
            try:
                self.summary.return_code = int(m.group(1))
            except Exception:
                pass


# ============================================================
# Cyber UI components
# ============================================================

class GlowBadge(ctk.CTkFrame):
    def __init__(self, master, text="—", color="#94A3B8", **kwargs):
        super().__init__(master, fg_color="#0B1220", corner_radius=14, **kwargs)
        self._base = color
        self._hover = self._brighten(color, 1.25)
        self.configure(border_width=2, border_color=self._base)

        self.label = ctk.CTkLabel(
            self,
            text=text,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#E5E7EB"
        )
        self.label.pack(padx=12, pady=8)

        for w in (self, self.label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def set(self, text: str, color: str):
        self._base = color
        self._hover = self._brighten(color, 1.25)
        self.configure(border_color=self._base)
        self.label.configure(text=text)

    def _on_enter(self, _):
        self.configure(border_color=self._hover)

    def _on_leave(self, _):
        self.configure(border_color=self._base)

    @staticmethod
    def _brighten(hex_color: str, factor: float) -> str:
        hc = hex_color.lstrip("#")
        if len(hc) != 6:
            return hex_color
        r = clamp_int(int(int(hc[0:2], 16) * factor), 0, 255)
        g = clamp_int(int(int(hc[2:4], 16) * factor), 0, 255)
        b = clamp_int(int(int(hc[4:6], 16) * factor), 0, 255)
        return f"#{r:02X}{g:02X}{b:02X}"


# ============================================================
# Main App (Hub)
# ============================================================

class CyberShadowHub(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("CYBERSHADOW • Forensic Analysis Hub")
        self.geometry("1500x860")
        self.minsize(1250, 740)
        self.configure(fg_color="#0A0F1A")

        self._proc: Optional[subprocess.Popen] = None
        self._stop_flag = threading.Event()
        self._q: "queue.Queue[str]" = queue.Queue()
        self._parser = LogParser()

        self._report_path: Optional[str] = None

        # Artifact selection state
        self._selected_artifact_path: Optional[str] = None
        self._artifact_radio_var = ctk.StringVar(value="")
        self._artifact_trace_attached = False

        # Summary composition
        self._selected_preview_lines: List[str] = []
        self._run_summary_lines: List[str] = []
        self._pending_summary_text: Optional[str] = None  # in case UI not ready

        self._build_ui()
        self._patch_mousewheel_bug()
        self._set_status("Idle")

        # IMPORTANT: refresh artifacts only AFTER all widgets exist
        try:
            self._refresh_artifacts()
        except Exception:
            pass

        self.after(60, self._drain)

    # ---------------- UI ----------------
    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color="#0B1220", corner_radius=16)
        header.pack(fill="x", padx=16, pady=(16, 10))

        ctk.CTkLabel(
            header,
            text="CYBERSHADOW • Forensic Analysis Hub",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#E5E7EB"
        ).pack(side="left", padx=18, pady=14)

        self.status_label = ctk.CTkLabel(
            header,
            text="Status: Idle",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#94A3B8"
        )
        self.status_label.pack(side="right", padx=18)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        body.grid_columnconfigure(0, weight=0, minsize=460)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # Left: Controls
        left = ctk.CTkFrame(body, fg_color="#0B1220", corner_radius=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.left_tabs = ctk.CTkTabview(
            left,
            fg_color="#0B1220",
            segmented_button_fg_color="#0A1222",
            segmented_button_selected_color="#1E3A8A",
            segmented_button_selected_hover_color="#2563EB",
            segmented_button_unselected_color="#0A1222",
            segmented_button_unselected_hover_color="#111B2F",
        )
        self.left_tabs.pack(fill="both", expand=True, padx=14, pady=14)

        self.tab_apk = self.left_tabs.add("APK Analyzer")
        self.tab_dyn = self.left_tabs.add("Dynamic (Frida)")
        self.tab_img = self.left_tabs.add("Deepfake • Image")
        self.tab_vid = self.left_tabs.add("Deepfake • Video")

        self._build_apk_controls(self.tab_apk)
        self._build_dynamic_controls(self.tab_dyn)
        self._build_placeholder(self.tab_img, "Deepfake Detector (Image)")
        self._build_placeholder(self.tab_vid, "Deepfake Detector (Video)")

        # Right: Tabs (Log / Summary / Report Viewer)
        right = ctk.CTkFrame(body, fg_color="#0B1220", corner_radius=16)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        # Top row: progress + badges
        topbar = ctk.CTkFrame(right, fg_color="transparent")
        topbar.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        topbar.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(topbar, height=14)
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.progress.set(0)

        self.badge_score = GlowBadge(topbar, text="Score: —", color="#94A3B8")
        self.badge_score.grid(row=0, column=1, padx=(0, 10))
        self.badge_sev = GlowBadge(topbar, text="Severity: —", color="#94A3B8")
        self.badge_sev.grid(row=0, column=2)

        self.right_tabs = ctk.CTkTabview(right, fg_color="#0B1220")
        self.right_tabs.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

        self.tab_console = self.right_tabs.add("Console Log")
        self.tab_summary = self.right_tabs.add("Quick Summary")
        self.tab_report = self.right_tabs.add("Report Viewer")

        self._build_console(self.tab_console)
        self._build_summary(self.tab_summary)
        self._build_report_viewer(self.tab_report)

        # if we had pending summary before widgets existed, render it now
        if self._pending_summary_text is not None:
            try:
                self._set_summary_text(self._pending_summary_text)
            except Exception:
                pass
            self._pending_summary_text = None

    def _build_console(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        self.log_text = ctk.CTkTextbox(
            parent,
            fg_color="#050A14",
            text_color="#D1FAE5",
            border_width=1,
            border_color="#1F2A44",
            corner_radius=16
        )
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_text.configure(state="disabled")

    def _build_summary(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        self.summary_text = ctk.CTkTextbox(
            parent,
            fg_color="#050A14",
            text_color="#C7D2FE",
            border_width=1,
            border_color="#1F2A44",
            corner_radius=16
        )
        self.summary_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.summary_text.configure(state="disabled")

    def _patch_mousewheel_bug(self):
        def _safe_mousewheel(event):
            w = getattr(event, "widget", None)
            if isinstance(w, str) or not hasattr(w, "master"):
                return "break"
            return None

        self.bind_all("<MouseWheel>", _safe_mousewheel, add="+")
        self.bind_all("<Button-4>", _safe_mousewheel, add="+")
        self.bind_all("<Button-5>", _safe_mousewheel, add="+")

    def _build_report_viewer(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        container = ctk.CTkFrame(parent, fg_color="#050A14", corner_radius=16)
        container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        container.grid_rowconfigure(2, weight=1)
        container.grid_columnconfigure(0, weight=1)

        row = ctk.CTkFrame(container, fg_color="transparent")
        row.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 8))
        row.grid_columnconfigure(0, weight=1)

        self.report_path_label = ctk.CTkLabel(
            row,
            text="Report: (none)",
            text_color="#94A3B8",
            anchor="w"
        )
        self.report_path_label.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.btn_reload_report = ctk.CTkButton(
            row, text="Reload", command=self._reload_report,
            fg_color="#1E3A8A", hover_color="#2563EB", height=34
        )
        self.btn_reload_report.grid(row=0, column=1, padx=(0, 8))

        self.btn_open_external = ctk.CTkButton(
            row, text="Open External", command=self._open_report_external,
            fg_color="#0F766E", hover_color="#14B8A6", height=34
        )
        self.btn_open_external.grid(row=0, column=2)

        row2 = ctk.CTkFrame(container, fg_color="transparent")
        row2.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
        row2.grid_columnconfigure(0, weight=1)

        self.viewer_bright_var = ctk.BooleanVar(value=True)
        self.viewer_bright_check = ctk.CTkCheckBox(
            row2,
            text="Viewer mode (brighter)",
            variable=self.viewer_bright_var,
            text_color="#94A3B8",
            command=self._reload_report_if_loaded
        )
        self.viewer_bright_check.grid(row=0, column=0, sticky="w")

        self.html_frame = HtmlFrame(
            container,
            horizontal_scrollbar="auto",
            messages_enabled=False
        )
        self.html_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))

        self.html_frame.load_html(
            "<html><body style='background:#0b1020;color:#E5E7EB;font-family:Arial;padding:20px;'>"
            "<h2>Report Viewer</h2><p>No report loaded yet.</p>"
            "<p>Run an analysis, then click <b>LOAD REPORT INTO VIEWER</b>.</p>"
            "</body></html>"
        )

    def _reload_report_if_loaded(self):
        if self._report_path and os.path.exists(self._report_path):
            try:
                self._set_report(self._report_path)
            except Exception:
                pass

    # ---------------- Dynamic Controls (Frida) ----------------
    def _build_dynamic_controls(self, parent):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            wrap, text="Dynamic Analysis (Frida on Emulator/Device)",
            text_color="#E5E7EB",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            wrap,
            text=("Folosește Case Folder + APK File din tab-ul «APK Analyzer».\n"
                  "Aici setezi doar package name + opțiuni Frida.\n"
                  "Runner: python -m src.frida_auto"),
            text_color="#94A3B8",
            justify="left"
        ).pack(anchor="w", pady=(0, 14))

        # ---- Package
        ctk.CTkLabel(
            wrap, text="Package Name",
            text_color="#E5E7EB", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        self.dyn_pkg_entry = ctk.CTkEntry(wrap, placeholder_text="me.hackerchick.catima")
        self.dyn_pkg_entry.pack(fill="x", pady=(0, 12))

        # ---- Dynamic Tag
        ctk.CTkLabel(
            wrap, text="Dynamic Tag",
            text_color="#E5E7EB", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        self.dyn_tag_entry = ctk.CTkEntry(wrap, placeholder_text="dyn")
        self.dyn_tag_entry.pack(fill="x", pady=(0, 12))
        self.dyn_tag_entry.insert(0, "dyn")

        # ---- Mode + Timeout
        row_opts = ctk.CTkFrame(wrap, fg_color="transparent")
        row_opts.pack(fill="x", pady=(0, 12))
        row_opts.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(
            row_opts, text="Mode", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=(0, 8))

        ctk.CTkLabel(
            row_opts, text="Timeout (sec)", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=1, sticky="w", padx=(0, 8))

        ctk.CTkLabel(
            row_opts, text="ADB Serial (optional)", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=2, sticky="w")

        self.dyn_mode_var = ctk.StringVar(value="attach")
        self.dyn_mode_menu = ctk.CTkOptionMenu(
            row_opts,
            values=["attach", "spawn"],
            variable=self.dyn_mode_var,
            fg_color="#0A1222",
            button_color="#1E3A8A",
            button_hover_color="#2563EB",
        )
        self.dyn_mode_menu.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=(6, 0))

        self.dyn_timeout_entry = ctk.CTkEntry(row_opts, placeholder_text="35")
        self.dyn_timeout_entry.grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=(6, 0))
        self.dyn_timeout_entry.insert(0, "35")

        self.dyn_serial_entry = ctk.CTkEntry(row_opts, placeholder_text="emulator-5554 (leave blank for auto)")
        self.dyn_serial_entry.grid(row=1, column=2, sticky="ew", pady=(6, 0))

        # ---- Script + Frida-server (optional)
        ctk.CTkLabel(
            wrap, text="Frida JS Script",
            text_color="#E5E7EB", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(10, 6))

        row_script = ctk.CTkFrame(wrap, fg_color="transparent")
        row_script.pack(fill="x", pady=(0, 12))
        row_script.grid_columnconfigure(0, weight=1)

        self.dyn_script_entry = ctk.CTkEntry(row_script, placeholder_text="src/cybershadow_dyn.js")
        self.dyn_script_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.dyn_script_entry.insert(0, os.path.join("src", "dynamic", "cybershadow_dyn.js"))

        ctk.CTkButton(
            row_script, text="Browse Script", command=self._browse_dyn_script,
            fg_color="#1E3A8A", hover_color="#2563EB", height=36
        ).grid(row=0, column=1)

        ctk.CTkLabel(
            wrap, text="Frida-server (optional push/start)",
            text_color="#E5E7EB", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        row_srv = ctk.CTkFrame(wrap, fg_color="transparent")
        row_srv.pack(fill="x", pady=(0, 14))
        row_srv.grid_columnconfigure(0, weight=1)

        self.dyn_frida_server_entry = ctk.CTkEntry(row_srv, placeholder_text=r"C:\path\to\frida-server-android-x86_64")
        self.dyn_frida_server_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ctk.CTkButton(
            row_srv, text="Browse frida-server", command=self._browse_dyn_frida_server,
            fg_color="#1E3A8A", hover_color="#2563EB", height=36
        ).grid(row=0, column=1)

        # ---- Run/Stop
        ctrl = ctk.CTkFrame(wrap, fg_color="transparent")
        ctrl.pack(fill="x", pady=(4, 0))
        ctrl.grid_columnconfigure(0, weight=1)
        ctrl.grid_columnconfigure(1, weight=1)

        self.btn_run_dyn = ctk.CTkButton(
            ctrl, text="RUN DYNAMIC (FRIDA)", command=self._run_dynamic,
            fg_color="#7C3AED", hover_color="#8B5CF6",
            height=44, font=ctk.CTkFont(size=14, weight="bold")
        )
        self.btn_run_dyn.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.btn_stop_dyn = ctk.CTkButton(
            ctrl, text="STOP", command=self._stop,
            fg_color="#7F1D1D", hover_color="#DC2626",
            height=44, font=ctk.CTkFont(size=14, weight="bold"),
            state="disabled"
        )
        self.btn_stop_dyn.grid(row=0, column=1, sticky="ew")

        ctk.CTkLabel(
            wrap,
            text=("Tip: dacă aplicația moare imediat (anti-frida / crash), mărește timeout și folosește mode=spawn.\n"
                  "Dacă ai frida-server deja pornit manual pe emulator, lasă câmpul frida-server gol."),
            text_color="#94A3B8",
            justify="left"
        ).pack(anchor="w", pady=(12, 0))

    def _browse_dyn_script(self):
        path = filedialog.askopenfilename(
            title="Select Frida JS Script",
            filetypes=[("JavaScript", "*.js"), ("All files", "*.*")]
        )
        if path:
            self.dyn_script_entry.delete(0, "end")
            self.dyn_script_entry.insert(0, path)

    def _browse_dyn_frida_server(self):
        path = filedialog.askopenfilename(
            title="Select frida-server binary",
            filetypes=[("All files", "*.*")]
        )
        if path:
            self.dyn_frida_server_entry.delete(0, "end")
            self.dyn_frida_server_entry.insert(0, path)

    def _build_apk_controls(self, parent):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=10, pady=10)

        # ---- Case Folder
        ctk.CTkLabel(
            wrap, text="Case Folder", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        row_case = ctk.CTkFrame(wrap, fg_color="transparent")
        row_case.pack(fill="x", pady=(0, 12))
        row_case.grid_columnconfigure(0, weight=1)

        self.case_entry = ctk.CTkEntry(row_case, placeholder_text="cases/CASE_005")
        self.case_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.case_entry.insert(0, r"cases/CASE_005")

        ctk.CTkButton(
            row_case, text="Browse Case", command=self._browse_case,
            fg_color="#1E3A8A", hover_color="#2563EB", height=36
        ).grid(row=0, column=1)

        # ---- Risk mode
        ctk.CTkLabel(
            wrap, text="Case Verdict Mode", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        row_risk = ctk.CTkFrame(wrap, fg_color="transparent")
        row_risk.pack(fill="x", pady=(0, 12))
        row_risk.grid_columnconfigure(0, weight=1)

        self.risk_mode_var = ctk.StringVar(value="latest")
        self.risk_mode_menu = ctk.CTkOptionMenu(
            row_risk,
            values=["latest", "max"],
            variable=self.risk_mode_var,
            fg_color="#0A1222",
            button_color="#1E3A8A",
            button_hover_color="#2563EB",
        )
        self.risk_mode_menu.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ctk.CTkLabel(
            row_risk,
            text="latest = last run • max = worst-case",
            text_color="#94A3B8"
        ).grid(row=0, column=1, sticky="e")

        # ---- APK File
        ctk.CTkLabel(
            wrap, text="APK File", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        row_apk = ctk.CTkFrame(wrap, fg_color="transparent")
        row_apk.pack(fill="x", pady=(0, 12))
        row_apk.grid_columnconfigure(0, weight=1)

        self.apk_entry = ctk.CTkEntry(row_apk, placeholder_text=r"C:\path\to\app.apk")
        self.apk_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        ctk.CTkButton(
            row_apk, text="Browse APK", command=self._browse_apk,
            fg_color="#1E3A8A", hover_color="#2563EB", height=36
        ).grid(row=0, column=1)

        # ---- Tag
        ctk.CTkLabel(
            wrap, text="Tag", text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", pady=(0, 6))

        self.tag_entry = ctk.CTkEntry(wrap, placeholder_text="fennec")
        self.tag_entry.pack(fill="x", pady=(0, 14))
        self.tag_entry.insert(0, "fennec")

        # ---- Run/Stop
        ctrl = ctk.CTkFrame(wrap, fg_color="transparent")
        ctrl.pack(fill="x", pady=(4, 0))
        ctrl.grid_columnconfigure(0, weight=1)
        ctrl.grid_columnconfigure(1, weight=1)

        self.btn_run = ctk.CTkButton(
            ctrl, text="RUN APK ANALYSIS", command=self._run_apk,
            fg_color="#1D4ED8", hover_color="#2563EB",
            height=44, font=ctk.CTkFont(size=14, weight="bold")
        )
        self.btn_run.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self.btn_stop = ctk.CTkButton(
            ctrl, text="STOP", command=self._stop,
            fg_color="#7F1D1D", hover_color="#DC2626",
            height=44, font=ctk.CTkFont(size=14, weight="bold"),
            state="disabled"
        )
        self.btn_stop.grid(row=0, column=1, sticky="ew")

        self.btn_load_report = ctk.CTkButton(
            wrap, text="LOAD REPORT INTO VIEWER", command=self._load_report_into_viewer,
            fg_color="#0F766E", hover_color="#14B8A6", height=38,
            state="disabled"
        )
        self.btn_load_report.pack(fill="x", pady=(12, 8))

        # ---- Artifact manager
        self._build_artifact_manager(wrap)

        ctk.CTkLabel(
            wrap,
            text="Tip: Selectează un artifact pentru Preview în Quick Summary; apoi Load Report deschide report-ul lui.",
            text_color="#94A3B8",
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", pady=(8, 0))

        # IMPORTANT: NU mai facem refresh aici (UI-ul nu e complet încă).
        # Refresh se face în __init__ după ce există summary_text etc.

    def _build_artifact_manager(self, parent):
        box = ctk.CTkFrame(parent, fg_color="#050A14", corner_radius=16)
        box.pack(fill="both", expand=False, pady=(8, 0))

        header = ctk.CTkFrame(box, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(10, 6))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="Artifacts (generated)",
            text_color="#E5E7EB",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        self.artifacts_count_label = ctk.CTkLabel(
            header,
            text="—",
            text_color="#94A3B8"
        )
        self.artifacts_count_label.grid(row=0, column=1, sticky="e")

        row_btns = ctk.CTkFrame(box, fg_color="transparent")
        row_btns.pack(fill="x", padx=10, pady=(0, 8))
        row_btns.grid_columnconfigure((0, 1, 2), weight=1)

        self.btn_art_refresh = ctk.CTkButton(
            row_btns, text="Refresh", command=self._refresh_artifacts,
            fg_color="#1E3A8A", hover_color="#2563EB", height=34
        )
        self.btn_art_refresh.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.btn_art_delete = ctk.CTkButton(
            row_btns, text="Delete Selected", command=self._delete_selected_artifact,
            fg_color="#7F1D1D", hover_color="#DC2626", height=34
        )
        self.btn_art_delete.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        self.btn_art_clean = ctk.CTkButton(
            row_btns, text="Clean Generated", command=self._clean_generated_outputs,
            fg_color="#0F766E", hover_color="#14B8A6", height=34
        )
        self.btn_art_clean.grid(row=0, column=2, sticky="ew")

        self.art_scroll = ctk.CTkScrollableFrame(box, fg_color="transparent", corner_radius=0, height=160)
        self.art_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_placeholder(self, parent, title: str):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(
            wrap, text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB"
        ).pack(anchor="w", pady=(0, 10))

        ctk.CTkLabel(
            wrap,
            text=("Placeholder: aici conectăm modelul AI (inference), cu scorare + explainability.\n"
                  "UI-ul rămâne același: select → run → progress/log → verdict/report."),
            text_color="#94A3B8",
            justify="left"
        ).pack(anchor="w")

    # ---------------- Artifact management ----------------
    def _case_abs(self) -> str:
        c = self.case_entry.get().strip()
        if not c:
            return ""
        return os.path.abspath(c)

    def _artifact_paths(self) -> List[str]:
        case_abs = self._case_abs()
        if not case_abs or not os.path.isdir(case_abs):
            return []
        art_dir = os.path.join(case_abs, "artifacts")
        if not os.path.isdir(art_dir):
            return []

        paths: List[str] = []
        for name in os.listdir(art_dir):
            if (name.startswith("apk_static__") or name.startswith("apk_dynamic__")) and name.endswith(".json"):
                paths.append(os.path.join(art_dir, name))

        paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return paths

    @staticmethod
    def _artifact_kind_from_name(name: str) -> str:
        n = (name or "").lower()
        if n.startswith("apk_static__"):
            return "STATIC"
        if n.startswith("apk_dynamic__"):
            return "DYNAMIC"
        return "UNKNOWN"

    def _ensure_artifact_trace(self):
        if self._artifact_trace_attached:
            return

        def _on_change(*_):
            self._selected_artifact_path = self._artifact_radio_var.get().strip() or None
            self._update_selected_artifact_preview()

        try:
            self._artifact_radio_var.trace_add("write", _on_change)
            self._artifact_trace_attached = True
        except Exception:
            pass

    def _refresh_artifacts(self):
        if not hasattr(self, "art_scroll"):
            return

        for child in self.art_scroll.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        self._ensure_artifact_trace()

        paths = self._artifact_paths()
        if hasattr(self, "artifacts_count_label"):
            self.artifacts_count_label.configure(text=f"{len(paths)} items")

        if not paths:
            ctk.CTkLabel(
                self.art_scroll,
                text="No generated artifacts found (apk_static__*.json / apk_dynamic__*.json).",
                text_color="#94A3B8"
            ).pack(anchor="w", pady=6)
            self._artifact_radio_var.set("")
            self._selected_artifact_path = None
            self._selected_preview_lines = ["== SELECTED ARTIFACT PREVIEW ==", "(none)"]
            self._render_summary()
            return

        for p in paths:
            kind = self._artifact_kind_from_name(os.path.basename(p))
            meta = self._read_artifact_meta(p)
            label = f"[{kind}] {os.path.basename(p)}  •  {meta}"
            rb = ctk.CTkRadioButton(
                self.art_scroll,
                text=label,
                variable=self._artifact_radio_var,
                value=p,
                text_color="#E5E7EB"
            )
            rb.pack(anchor="w", pady=4)

        # select latest if current selection invalid
        cur = self._artifact_radio_var.get().strip()
        if not cur or not os.path.exists(cur):
            self._artifact_radio_var.set(paths[0])
            self._selected_artifact_path = paths[0]

        self._update_selected_artifact_preview()

    def _read_artifact_meta(self, artifact_path: str) -> str:
        try:
            obj = self._read_json_safe(artifact_path)
            score = self._extract_score_0_100(obj)
            s20 = normalize_score_20(score)
            sev20, _ = score20_bucket(s20)
            ts = datetime_utc_from_mtime(artifact_path)
            pkg = str(obj.get("package", "") or "")
            tag = str(obj.get("tag") or (obj.get("meta", {}) or {}).get("tag") or "")
            extra = f" • tag={tag}" if tag else ""
            return f"{sev20} • {score}/100 ({s20}/20) • {ts} • {pkg}{extra}"
        except Exception:
            ts = datetime_utc_from_mtime(artifact_path)
            return f"unknown • {ts}"

    def _read_json_safe(self, path: str) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _extract_score_0_100(self, obj: dict) -> int:
        scoring = obj.get("scoring", {}) or {}
        for k in ("score", "final_score"):
            if k in scoring:
                try:
                    return clamp_int(int(scoring.get(k, 0)), 0, 100)
                except Exception:
                    pass
        if "score" in obj:
            try:
                return clamp_int(int(obj.get("score", 0)), 0, 100)
            except Exception:
                pass
        risk = obj.get("risk", {}) or {}
        for k in ("final_score", "score"):
            if k in risk:
                try:
                    return clamp_int(int(risk.get(k, 0)), 0, 100)
                except Exception:
                    pass
        return 0

    def _extract_reasons(self, obj: dict) -> List[str]:
        scoring = obj.get("scoring", {}) or {}
        reasons = scoring.get("reasons")
        if isinstance(reasons, list) and reasons:
            return [str(x) for x in reasons if x is not None]
        for k in ("why", "indicators", "signals"):
            v = obj.get(k)
            if isinstance(v, list) and v:
                return [str(x) for x in v if x is not None]
        return []

    def _extract_iocs(self, obj: dict) -> dict:
        iocs = obj.get("iocs")
        if isinstance(iocs, dict):
            return iocs
        runtime = obj.get("runtime", {}) or {}
        iocs = runtime.get("iocs")
        if isinstance(iocs, dict):
            return iocs
        return {}

    @staticmethod
    def _uniq(items: List[Any]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in items or []:
            if x is None:
                continue
            s = str(x).strip()
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    def _update_selected_artifact_preview(self):
        p = self._selected_artifact_path or self._artifact_radio_var.get().strip()
        if not p or not os.path.exists(p):
            self._selected_preview_lines = ["== SELECTED ARTIFACT PREVIEW ==", "(none)"]
            self._render_summary()
            return

        obj = self._read_json_safe(p)
        name = os.path.basename(p)
        kind = self._artifact_kind_from_name(name)

        score100 = self._extract_score_0_100(obj)
        s20 = normalize_score_20(score100)
        sev20, _col = score20_bucket(s20)

        pkg = str(obj.get("package", "") or "")
        app = str(obj.get("app_name", "") or "")
        tag = str(obj.get("tag") or (obj.get("meta", {}) or {}).get("tag") or "")
        ts = datetime_utc_from_mtime(p)

        reasons = self._extract_reasons(obj)
        weighted = [(r, parse_reason_weight(r)) for r in reasons]
        weighted.sort(key=lambda t: (-t[1], t[0]))
        top = weighted[:6]

        iocs = self._extract_iocs(obj)
        urls = self._uniq(iocs.get("urls", []) or [])
        domains = self._uniq(iocs.get("domains", []) or [])
        ips = self._uniq(iocs.get("ips", []) or [])
        emails = self._uniq(iocs.get("emails", []) or [])

        lines: List[str] = []
        lines.append("== SELECTED ARTIFACT PREVIEW ==")
        lines.append(f"Kind: {kind}")
        lines.append(f"Artifact: {name}")
        lines.append(f"Timestamp (UTC): {ts}")
        if app:
            lines.append(f"App: {app}")
        if pkg:
            lines.append(f"Package: {pkg}")
        if tag:
            lines.append(f"Tag: {tag}")
        lines.append("")
        lines.append("== VERDICT (derived) ==")
        lines.append(f"Score (safe-scale): {s20}/20")
        lines.append(f"Derived severity: {sev20}")
        lines.append(f"Raw score (artifact): {score100}/100")

        lines.append("")
        lines.append("== TOP REASONS ==")
        if top:
            for r, w in top:
                lines.append(f"- +{w} — {r}" if w > 0 else f"- {r}")
        else:
            lines.append("- (none)")

        lines.append("")
        lines.append("== IOC COUNTS ==")
        lines.append(f"URLs: {len(urls)} | Domains: {len(domains)} | IPs: {len(ips)} | Emails: {len(emails)}")

        def _sample(label: str, items: List[str], n: int = 4):
            if not items:
                return
            lines.append(f"{label} sample:")
            for x in items[:n]:
                lines.append(f"  - {x}")

        lines.append("")
        _sample("URLs", urls)
        _sample("Domains", domains)
        _sample("IPs", ips)
        _sample("Emails", emails)

        self._selected_preview_lines = lines
        self._render_summary()

        if self._proc is None:
            self._set_badges(score100, None)

        if self._find_report_for_selected_artifact():
            self.btn_load_report.configure(state="normal")
        else:
            if self._parser.summary.best_report_path():
                self.btn_load_report.configure(state="normal")

    def _render_summary(self):
        blocks: List[str] = []
        if self._selected_preview_lines:
            blocks.extend(self._selected_preview_lines)
        if self._run_summary_lines:
            if blocks:
                blocks.append("\n" + ("-" * 60) + "\n")
            blocks.extend(self._run_summary_lines)
        self._set_summary_text("\n".join(blocks).strip())

    def _delete_selected_artifact(self):
        if self._proc is not None:
            messagebox.showwarning("Running", "Oprește procesul înainte să ștergi artifacts.")
            return
        p = self._selected_artifact_path or self._artifact_radio_var.get().strip()
        if not p or not os.path.exists(p):
            messagebox.showinfo("Delete", "Nu ai selectat un artifact valid.")
            return

        if not messagebox.askyesno("Delete Selected", f"Șterg artifact-ul?\n\n{p}"):
            return

        try:
            os.remove(p)
            self._append_log(f"[INFO] Deleted artifact: {p}\n")
        except Exception as e:
            messagebox.showerror("Delete error", str(e))
            return

        self._refresh_artifacts()

    def _clean_generated_outputs(self):
        if self._proc is not None:
            messagebox.showwarning("Running", "Oprește procesul înainte de Clean.")
            return

        case_abs = self._case_abs()
        if not case_abs or not os.path.isdir(case_abs):
            messagebox.showinfo("Clean", "Case folder invalid.")
            return

        if not messagebox.askyesno(
            "Clean Generated",
            "Șterg DOAR outputs generate?\n\n"
            "- artifacts/apk_static__*.json\n"
            "- artifacts/apk_dynamic__*.json\n"
            "- reports/*.html\n\n"
            "NU atinge evidence/, case.json, ledger.json."
        ):
            return

        removed = 0
        art_dir = os.path.join(case_abs, "artifacts")
        if os.path.isdir(art_dir):
            for name in os.listdir(art_dir):
                if (name.startswith("apk_static__") or name.startswith("apk_dynamic__")) and name.endswith(".json"):
                    try:
                        os.remove(os.path.join(art_dir, name))
                        removed += 1
                    except Exception:
                        pass

        rep_dir = os.path.join(case_abs, "reports")
        if os.path.isdir(rep_dir):
            for name in os.listdir(rep_dir):
                if name.lower().endswith(".html"):
                    try:
                        os.remove(os.path.join(rep_dir, name))
                        removed += 1
                    except Exception:
                        pass

        self._append_log(f"[INFO] Cleaned generated outputs. Removed: {removed}\n")
        self.btn_load_report.configure(state="disabled")
        self._report_path = None
        self.report_path_label.configure(text="Report: (none)")
        self._refresh_artifacts()

    # ---------------- Actions ----------------
    def _browse_case(self):
        path = filedialog.askdirectory(title="Select Case Folder")
        if path:
            self.case_entry.delete(0, "end")
            self.case_entry.insert(0, path)
            self._refresh_artifacts()

    def _browse_apk(self):
        path = filedialog.askopenfilename(
            title="Select APK",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        if path:
            self.apk_entry.delete(0, "end")
            self.apk_entry.insert(0, path)

    def _set_running_ui(self, running: bool):
        # APK tab
        try:
            self.btn_run.configure(state="disabled" if running else "normal")
            self.btn_stop.configure(state="normal" if running else "disabled")
        except Exception:
            pass
        # Dynamic tab
        try:
            self.btn_run_dyn.configure(state="disabled" if running else "normal")
            self.btn_stop_dyn.configure(state="normal" if running else "disabled")
        except Exception:
            pass
        # Report load button
        try:
            if running:
                self.btn_load_report.configure(state="disabled")
        except Exception:
            pass

    def _augment_env_for_tools(self, env: Dict[str, str]) -> Dict[str, str]:
        """
        Make it robust on Windows:
         - add venv Scripts to PATH (so frida/frida-ps found)
         - add Android SDK platform-tools (so adb found by frida_auto if needed)
        """
        env = dict(env or {})
        path = env.get("PATH", "")

        # venv Scripts (Windows) / bin (Linux/mac)
        exe_dir = os.path.dirname(sys.executable)
        if exe_dir and os.path.isdir(exe_dir):
            if exe_dir not in path:
                path = exe_dir + os.pathsep + path

        # common Android SDK platform-tools
        local = os.environ.get("LOCALAPPDATA", "")
        guess_adb = os.path.join(local, "Android", "Sdk", "platform-tools")
        if guess_adb and os.path.isdir(guess_adb):
            if guess_adb not in path:
                path = guess_adb + os.pathsep + path

        env["PATH"] = path
        return env

    def _run_apk(self):
        if self._proc is not None:
            messagebox.showwarning("Already running", "Un proces rulează deja. Apasă STOP.")
            return

        case_folder = self.case_entry.get().strip()
        apk_path = self.apk_entry.get().strip()
        tag = self.tag_entry.get().strip()
        risk_mode = (self.risk_mode_var.get() or "latest").strip()

        if not case_folder:
            messagebox.showerror("Missing input", "Case Folder este gol.")
            return
        if not apk_path or not os.path.exists(apk_path):
            messagebox.showerror("Missing input", "APK File lipsește sau nu există.")
            return
        if not tag:
            messagebox.showerror("Missing input", "Tag este gol.")
            return

        self._parser = LogParser()
        self._stop_flag.clear()

        self._set_status("Running…")
        self._progress_running(True)
        self._set_badges(None, None)
        self._run_summary_lines = []
        self._render_summary()

        self._append_log("------------------------------------------------------------\n")
        self._append_log("[INFO] Starting APK analysis...\n")

        self._set_running_ui(True)

        py = sys.executable
        cmd = [
            py, "-m", "src.main",
            "run-apk",
            "--case", case_folder,
            "--apk", apk_path,
            "--tag", tag,
            "--risk-mode", risk_mode
        ]

        env = self._augment_env_for_tools(os.environ.copy())
        env["ANDROGUARD_LOGLEVEL"] = "ERROR"
        env["LOGURU_LEVEL"] = "ERROR"

        t = threading.Thread(target=self._runner, args=(cmd, env), daemon=True)
        t.start()

    def _run_dynamic(self):
        if self._proc is not None:
            messagebox.showwarning("Already running", "Un proces rulează deja. Apasă STOP.")
            return

        case_folder = self.case_entry.get().strip()
        apk_path = self.apk_entry.get().strip()
        risk_mode = (self.risk_mode_var.get() or "latest").strip()

        pkg = (self.dyn_pkg_entry.get() if hasattr(self, "dyn_pkg_entry") else "").strip()
        tag = (self.dyn_tag_entry.get() if hasattr(self, "dyn_tag_entry") else "").strip() or "dyn"
        mode = (self.dyn_mode_var.get() if hasattr(self, "dyn_mode_var") else "attach").strip() or "attach"
        script_path = (self.dyn_script_entry.get() if hasattr(self, "dyn_script_entry") else "").strip()
        frida_server = (self.dyn_frida_server_entry.get() if hasattr(self, "dyn_frida_server_entry") else "").strip()
        serial = (self.dyn_serial_entry.get() if hasattr(self, "dyn_serial_entry") else "").strip()
        timeout_s = (self.dyn_timeout_entry.get() if hasattr(self, "dyn_timeout_entry") else "35").strip()

        if not case_folder:
            messagebox.showerror("Missing input", "Case Folder este gol (tab APK Analyzer).")
            return
        if not os.path.isdir(case_folder) and not os.path.isdir(os.path.abspath(case_folder)):
            messagebox.showerror("Missing input", "Case Folder nu există.")
            return
        if not pkg:
            messagebox.showerror("Missing input", "Package Name este gol.")
            return
        if not script_path:
            messagebox.showerror("Missing input", "Frida JS Script lipsește.")
            return
        # allow relative; just check if exists relative to cwd
        if not os.path.exists(script_path):
            # try project-root style (cwd)
            if not os.path.exists(os.path.abspath(script_path)):
                messagebox.showerror("Missing input", f"Frida JS Script nu există:\n{script_path}")
                return

        if frida_server and not os.path.exists(frida_server):
            messagebox.showerror("Missing input", f"frida-server nu există:\n{frida_server}")
            return

        try:
            timeout_i = int(timeout_s)
            timeout_i = max(5, min(timeout_i, 600))
        except Exception:
            timeout_i = 35

        self._parser = LogParser()
        self._stop_flag.clear()

        self._set_status("Running…")
        self._progress_running(True)
        self._set_badges(None, None)
        self._run_summary_lines = []
        self._render_summary()

        self._append_log("------------------------------------------------------------\n")
        self._append_log("[INFO] Starting Dynamic (Frida) analysis...\n")

        self._set_running_ui(True)

        py = sys.executable
        cmd = [
            py, "-m", "src.frida_auto",
            "--case", case_folder,
            "--package", pkg,
            "--tag", tag,
            "--mode", mode,
            "--timeout", str(timeout_i),
            "--risk-mode", risk_mode,
            "--script", script_path
        ]

        # optional apk install
        if apk_path and os.path.exists(apk_path):
            cmd.extend(["--apk", apk_path])

        # optional serial
        if serial:
            cmd.extend(["--serial", serial])

        # optional frida-server push/start
        if frida_server:
            cmd.extend(["--frida-server", frida_server])

        env = self._augment_env_for_tools(os.environ.copy())
        env["LOGURU_LEVEL"] = "ERROR"

        t = threading.Thread(target=self._runner, args=(cmd, env), daemon=True)
        t.start()

    def _stop(self):
        self._stop_flag.set()
        if self._proc is not None:
            try:
                self._append_log("[WARN] Stopping process...\n")
                self._proc.terminate()
            except Exception:
                pass

    def _runner(self, cmd, env):
        try:
            self._q.put(f"[CMD] {self._fmt_cmd(cmd)}\n")
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env
            )

            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if self._stop_flag.is_set():
                    break
                self._q.put(line)
                self._parser.feed_line(line)

            try:
                rc = self._proc.wait(timeout=5)
            except Exception:
                rc = None

            if rc is not None:
                self._parser.summary.return_code = rc

        except FileNotFoundError as e:
            self._q.put(f"[ERROR] Command not found: {e}\n")
        except Exception as e:
            self._q.put(f"[ERROR] {e}\n")
        finally:
            try:
                if self._proc is not None and self._proc.poll() is None:
                    self._proc.kill()
            except Exception:
                pass
            self._proc = None
            self._q.put("[UI] __RUN_FINISHED__\n")

    def _drain(self):
        changed = False
        while True:
            try:
                line = self._q.get_nowait()
            except queue.Empty:
                break

            if line == "[UI] __RUN_FINISHED__\n":
                self._on_finish()
                continue

            self._append_log(line)
            changed = True
            self._refresh_live()

        if changed:
            self._scroll_end()

        self.after(60, self._drain)

    def _on_finish(self):
        self._progress_running(False)
        self._set_running_ui(False)

        rc = self._parser.summary.return_code
        if self._stop_flag.is_set():
            self._set_status("Stopped")
            self._append_log("[INFO] Stopped by user.\n")
        else:
            if rc == 0:
                self._set_status("Completed")
            else:
                self._set_status(f"Finished (rc={rc})")

        if self._parser.summary.best_report_path() or self._find_report_for_selected_artifact():
            try:
                self.btn_load_report.configure(state="normal")
            except Exception:
                pass

        self._refresh_live(force=True)
        self._refresh_artifacts()

    def _refresh_live(self, force: bool = False):
        s = self._parser.summary
        if s.score is not None or force:
            self._set_badges(s.score, None)

        lines: List[str] = []
        if s.pipeline_kv:
            lines.append("== PIPELINE SUMMARY ==")
            preferred = ["Case", "Risk mode", "Evidence", "APK", "Severity", "Score", "Artifact", "APK Report", "Case Report", "Ledger"]
            used = set()
            for k in preferred:
                if k in s.pipeline_kv:
                    lines.append(f"{k}: {s.pipeline_kv[k]}")
                    used.add(k)
            for k, v in s.pipeline_kv.items():
                if k not in used:
                    lines.append(f"{k}: {v}")

        if s.paths:
            lines.append("\n== OUTPUT PATHS ==")
            for k, v in s.paths.items():
                lines.append(f"{k}: {v}")

        if s.return_code is not None:
            lines.append(f"\nReturn code: {s.return_code}")

        if s.score is not None:
            s20 = normalize_score_20(s.score)
            sev20, _ = score20_bucket(s20)
            lines.append(f"\n== LAST RUN VERDICT ==")
            lines.append(f"Score (safe-scale): {s20}/20")
            lines.append(f"Derived severity: {sev20}")
            lines.append(f"Raw score (engine): {s.score}/100")
            if s.severity:
                lines.append(f"Raw severity (engine): {s.severity}")

        self._run_summary_lines = lines
        self._render_summary()

    # ---------------- Report selection logic ----------------
    def _find_report_for_selected_artifact(self) -> Optional[str]:
        p = self._selected_artifact_path or self._artifact_radio_var.get().strip()
        if not p or not os.path.exists(p):
            return None

        case_abs = self._case_abs()
        if not case_abs:
            return None

        rep_dir = os.path.join(case_abs, "reports")
        if not os.path.isdir(rep_dir):
            return None

        name = os.path.basename(p)
        kind = self._artifact_kind_from_name(name)

        if kind == "STATIC":
            stem = os.path.splitext(name)[0]
            candidate = os.path.join(rep_dir, f"apk_report__{stem}.html")
            if os.path.exists(candidate):
                return candidate
            cands = [os.path.join(rep_dir, x) for x in os.listdir(rep_dir) if x.startswith("apk_report__") and x.endswith(".html")]
            cands.sort(key=lambda fp: os.path.getmtime(fp), reverse=True)
            return cands[0] if cands else None

        if kind == "DYNAMIC":
                stem = os.path.splitext(name)[0]
                cand1 = os.path.join(rep_dir, f"apk_dynamic_report__{stem}.html")
                if os.path.exists(cand1):
                    return cand1

                # fallback: case_report.html (dacă există)
                candidate = os.path.join(rep_dir, "case_report.html")
                if os.path.exists(candidate):
                    return candidate

                cands = [os.path.join(rep_dir, x) for x in os.listdir(rep_dir) if x.lower().endswith(".html")]
                cands.sort(key=lambda fp: os.path.getmtime(fp), reverse=True)
                return cands[0] if cands else None


        return None

    def _load_report_into_viewer(self):
        p = self._find_report_for_selected_artifact()
        if not p:
            p = self._parser.summary.best_report_path()

        if not p:
            messagebox.showinfo("Report", "Nu am găsit un report HTML valid încă.")
            return

        try:
            self._set_report(p)
            self.right_tabs.set("Report Viewer")
        except Exception as e:
            messagebox.showerror("Report Viewer Error", str(e))

    def _set_report(self, path: str):
        path = os.path.abspath(path)
        self._report_path = path
        self.report_path_label.configure(text=f"Report: {path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            html = f.read()

        viewer_on = bool(getattr(self, "viewer_bright_var", None) and self.viewer_bright_var.get())
        if viewer_on:
            html = inject_viewer_override_css(html)

        self.html_frame.load_html(html)

    def _reload_report(self):
        p = self._report_path or self._find_report_for_selected_artifact() or self._parser.summary.best_report_path()
        if not p or not os.path.exists(p):
            messagebox.showinfo("Reload", "Nu există report detectat încă.")
            return
        self._set_report(p)

    def _open_report_external(self):
        p = self._report_path or self._find_report_for_selected_artifact() or self._parser.summary.best_report_path()
        if not p or not os.path.exists(p):
            messagebox.showinfo("Open", "Nu există report detectat încă.")
            return
        try:
            import webbrowser
            webbrowser.open(f"file:///{p.replace(os.sep, '/')}")
        except Exception as e:
            messagebox.showerror("Open External Error", str(e))

    # ---------------- UI helpers ----------------
    def _set_status(self, text: str):
        self.status_label.configure(text=f"Status: {text}")

    def _progress_running(self, running: bool):
        if running:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            try:
                self.progress.stop()
            except Exception:
                pass
            self.progress.configure(mode="determinate")
            self.progress.set(0)

    def _set_badges(self, score_100: Optional[int], _unused_severity: Optional[str]):
        if score_100 is None:
            self.badge_score.set("Score: —", "#94A3B8")
            self.badge_sev.set("Severity: —", "#94A3B8")
            return

        s20 = normalize_score_20(score_100)
        sev, col = score20_bucket(s20)

        self.badge_score.set(f"Score: {s20}/20 (raw {score_100}/100)", col)
        self.badge_sev.set(f"Severity: {sev}", severity_color(sev))

    def _append_log(self, text: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.configure(state="disabled")

    def _scroll_end(self):
        try:
            self.log_text._textbox.see("end")
        except Exception:
            pass

    def _set_summary_text(self, text: str):
        # if UI isn't ready yet, store and render later
        if not hasattr(self, "summary_text"):
            self._pending_summary_text = text
            return
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", text)
        self.summary_text.configure(state="disabled")

    @staticmethod
    def _fmt_cmd(cmd: List[str]) -> str:
        def q(x: str) -> str:
            return f"\"{x}\"" if (" " in x or "\t" in x) else x
        return " ".join(q(x) for x in cmd)


# ============================================================
# Helpers (viewer brightness)
# ============================================================

def datetime_utc_from_mtime(path: str) -> str:
    try:
        ts = os.path.getmtime(path)
        from datetime import datetime, timezone
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "unknown"


def inject_viewer_override_css(html: str) -> str:
    override = """
<style id="viewer_override_css">
  * { box-sizing: border-box !important; }
  html, body { background: #0b1020 !important; color: #E5E7EB !important; }
  .muted { color: #AAB6CC !important; }
  .small { color: #B7C2D6 !important; }
  a { color: #93C5FD !important; }
  .row, .why-meta { display: block !important; }
  .pill, .badge {
    display: inline-block !important;
    margin: 6px 10px 0 0 !important;
    vertical-align: middle !important;
    border: 1px solid rgba(255,255,255,0.12) !important;
  }
  .card {
    background: rgba(18,24,40,0.92) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 16px !important;
    box-shadow: none !important;
  }
  table, th, td { color: #E5E7EB !important; }
  th { background: rgba(255,255,255,0.06) !important; }
  td { border-bottom: 1px solid rgba(255,255,255,0.08) !important; }
  code {
    color: #E5E7EB !important;
    background: rgba(255,255,255,0.08) !important;
    border: 1px solid rgba(255,255,255,0.10) !important;
    border-radius: 10px !important;
  }
  .LOW { background: rgba(0,255,160,0.10) !important; color: rgba(140,255,210,0.95) !important; }
  .MEDIUM { background: rgba(255,190,0,0.12) !important; color: rgba(255,210,110,0.95) !important; }
  .HIGH { background: rgba(255,80,80,0.12) !important; color: rgba(255,170,170,0.95) !important; }
  .CRITICAL { background: rgba(255,40,120,0.14) !important; color: rgba(255,170,210,0.95) !important; }
  .UNKNOWN { background: rgba(255,255,255,0.06) !important; color: rgba(255,255,255,0.82) !important; }
  .SCORE_GREEN { background: rgba(0,255,170,0.10) !important; border-color: rgba(0,255,170,0.22) !important; }
  .SCORE_YELLOW { background: rgba(255,205,0,0.12) !important; border-color: rgba(255,205,0,0.22) !important; }
  .SCORE_ORANGE { background: rgba(255,130,0,0.12) !important; border-color: rgba(255,130,0,0.22) !important; }
  .SCORE_RED { background: rgba(255,60,60,0.12) !important; border-color: rgba(255,60,60,0.22) !important; }
</style>
"""
    m = re.search(r"<head[^>]*>", html, flags=re.IGNORECASE)
    if m:
        idx = m.end()
        return html[:idx] + override + html[idx:]
    return override + html


def main():
    app = CyberShadowHub()
    app.mainloop()


if __name__ == "__main__":
    main()
