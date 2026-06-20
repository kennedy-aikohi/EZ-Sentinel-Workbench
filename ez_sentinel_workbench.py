#!/usr/bin/env python3
"""
EZ Sentinel Workbench v6.2 — Hayabusa Integration Edition
Author: KENNEDY AIKOHI
LinkedIn: https://www.linkedin.com/in/aikohikennedy/
"""
from __future__ import annotations

import os
import fnmatch
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "EZ Sentinel Workbench"
APP_VERSION = "6.2"
AUTHOR = "KENNEDY AIKOHI"
LINKEDIN = "https://www.linkedin.com/in/aikohikennedy/"

DANGEROUS_TOKENS = {"|", "&", "&&", "||", ";", ">", ">>", "<", "`"}
EXE_RE = re.compile(r"(^[A-Za-z]:\\.*\.exe$)|(^.*\.exe$)", re.IGNORECASE)
MAX_LOG_LINES = 6000
MAX_PENDING_LOG_EVENTS = 1500
SCAN_SKIP_DIRS = {"System Volume Information", "$RECYCLE.BIN"}


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_roots() -> List[Path]:
    roots = [app_dir()]
    pyinstaller_root = getattr(sys, "_MEIPASS", None)
    if pyinstaller_root:
        roots.append(Path(pyinstaller_root).resolve())
    return roots


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.lower()).strip("_") or "output"


def quote_cmd(parts: Iterable[str]) -> str:
    # Windows display preview only — execution always uses shell=False array.
    out = []
    for item in parts:
        s = str(item)
        if not s:
            out.append('""')
        elif any(c.isspace() for c in s) or any(c in s for c in '()$&;'):
            out.append('"' + s.replace('"', '\\"') + '"')
        else:
            out.append(s)
    return " ".join(out)


def safe_split_extra(extra: str) -> List[str]:
    extra = (extra or "").strip()
    if not extra:
        return []
    try:
        parts = shlex.split(extra, posix=False)
    except ValueError as e:
        raise ValueError(f"Could not parse Extra Args: {e}")
    cleaned: List[str] = []
    for token in parts:
        stripped = token.strip().strip('"')
        if stripped in DANGEROUS_TOKENS:
            raise ValueError(f"Blocked dangerous shell token: {token!r}")
        if EXE_RE.match(stripped):
            raise ValueError("Do not paste full commands or .exe paths into Extra Args.")
        cleaned.append(stripped)
    return cleaned


def classify_result(return_code: Optional[int], stdout_tail: str, stderr_tail: str) -> Tuple[str, str]:
    combined = f"{stdout_tail}\n{stderr_tail}".lower()
    fail_terms = [
        "unrecognized command or argument", "required argument missing", "expects a single argument",
        "not found. exiting", "file not found. exiting", "does not exist", "maps directory",
        "verify the command line", "option '-d' expects", "option '--csv' expects",
        "no such file", "access denied",
    ]
    warn_terms = ["warning", "unable to delete", "processed 0", "found 0 files", "entries found: 0"]
    if return_code not in (0, None):
        return "FAILED", f"Process returned exit code {return_code}."
    if any(t in combined for t in fail_terms):
        return "FAILED", "Parser reported invalid arguments, missing files, or configuration problems."
    if any(t in combined for t in warn_terms):
        return "SUCCESS WITH WARNING", "Completed but parser reported warnings or no records."
    return "SUCCESS", "Completed."


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOL_ALIASES: Dict[str, List[str]] = {
    "AmcacheParser":       ["AmcacheParser.exe"],
    "AppCompatCacheParser":["AppCompatCacheParser.exe"],
    "bstrings":            ["bstrings.exe"],
    "EvtxECmd":            ["EvtxECmd.exe", "EvtxeCmd.exe"],
    "Hayabusa":            ["hayabusa.exe", "hayabusa-*-win-x64.exe",
                            "hayabusa-*-win-x86.exe", "hayabusa-*-win-aarch64.exe"],
    "iisGeoLocate":        ["iisGeoLocate.exe", "iisGeolocate.exe"],
    "JLECmd":              ["JLECmd.exe"],
    "LECmd":               ["LECmd.exe"],
    "MFTECmd":             ["MFTECmd.exe"],
    "PECmd":               ["PECmd.exe"],
    "RBCmd":               ["RBCmd.exe"],
    "RecentFileCacheParser":["RecentFileCacheParser.exe"],
    "RECmd":               ["RECmd.exe"],
    "rla":                 ["rla.exe", "RLA.exe"],
    "SBECmd":              ["SBECmd.exe"],
    "SQLECmd":             ["SQLECmd.exe"],
    "SrumECmd":            ["SrumECmd.exe"],
    "SumECmd":             ["SumECmd.exe"],
    "VSCMount":            ["VSCMount.exe"],
    "WxTCmd":              ["WxTCmd.exe"],
}

GUI_VIEWERS = {
    "EZViewer.exe", "JumpListExplorer.exe", "MFTExplorer.exe",
    "RegistryExplorer.exe", "SDBExplorer.exe", "ShellBagsExplorer.exe",
    "TimelineExplorer.exe",
}

# Tools that use a dedicated builder panel instead of a profile dropdown
BUILDER_TOOLS = {"RECmd", "Hayabusa"}


@dataclass(frozen=True)
class Profile:
    name: str
    tool: str
    target_type: str
    args_template: List[str]
    description: str = ""


# Hayabusa is handled by its own builder — not in PROFILES
PROFILES: List[Profile] = [
    Profile("Amcache.hve to CSV",             "AmcacheParser",        "amcache",          ["-f", "{target}", "--csv", "{out}"]),
    Profile("Shimcache live SYSTEM hive to CSV","AppCompatCacheParser","system_hive_live",  ["-f", "{target}", "--csv", "{out}"]),
    Profile("bstrings IPv4 scan",              "bstrings",            "evidence_root",     ["-d", "{target}", "--ls", "ipv4"], "Captured to text file."),
    Profile("bstrings URL scan",               "bstrings",            "evidence_root",     ["-d", "{target}", "--ls", "url"],  "Captured to text file."),
    Profile("bstrings email scan",             "bstrings",            "evidence_root",     ["-d", "{target}", "--ls", "email"],"Captured to text file."),
    Profile("EVTX folder to CSV",              "EvtxECmd",            "evtx_dir",          ["-d", "{target}", "--csv", "{out}"]),
    Profile("IIS logs to CSV",                 "iisGeoLocate",        "iis_logs",          ["-d", "{target}", "--csv", "{out}"]),
    Profile("Jump Lists to CSV",               "JLECmd",              "recent_dir",        ["-d", "{target}", "--csv", "{out}"]),
    Profile("LNK files from Users to CSV",     "LECmd",               "users_dir",         ["-d", "{target}", "--csv", "{out}"]),
    Profile("LNK files from Users to CSV --all","LECmd",              "users_dir",         ["-d", "{target}", "--csv", "{out}", "--all"]),
    Profile("LNK high precision timestamps",   "LECmd",               "users_dir",         ["-d", "{target}", "--csv", "{out}", "--mp"]),
    Profile("LNK files to JSON pretty",        "LECmd",               "users_dir",         ["-d", "{target}", "--json", "{out}", "--pretty"]),
    Profile("$MFT to CSV",                     "MFTECmd",             "mft",               ["-f", "{target}", "--csv", "{out}"]),
    Profile("$MFT to CSV + resident dump",     "MFTECmd",             "mft",               ["-f", "{target}", "--csv", "{out}", "--dr", "--fl"]),
    Profile("USN Journal $J to CSV",           "MFTECmd",             "usnjrnl",           ["-f", "{target}", "--csv", "{out}"]),
    Profile("$Boot to CSV",                    "MFTECmd",             "boot",              ["-f", "{target}", "--csv", "{out}"]),
    Profile("$SDS to CSV",                     "MFTECmd",             "sds",               ["-f", "{target}", "--csv", "{out}"]),
    Profile("First discovered $I30 to CSV",    "MFTECmd",             "i30_any",           ["-f", "{target}", "--csv", "{out}"]),
    Profile("Prefetch folder to CSV",          "PECmd",               "prefetch_dir",      ["-d", "{target}", "--csv", "{out}"]),
    Profile("Recycle Bin to CSV",              "RBCmd",               "recycle_bin",       ["-d", "{target}", "--csv", "{out}"]),
    Profile("RecentFileCache.bcf to CSV",      "RecentFileCacheParser","recent_file_cache", ["-f", "{target}", "--csv", "{out}"]),
    Profile("RLA replay registry logs",        "rla",                 "config_dir",        ["-d", "{target}", "--out", "{out}"]),
    Profile("ShellBags from Users folder to CSV","SBECmd",            "users_dir",         ["-d", "{target}", "--csv", "{out}"]),
    Profile("SQLECmd mapped parse from Users", "SQLECmd",             "users_dir",         ["-d", "{target}", "--csv", "{out}", "--maps", "{maps_sql}"]),
    Profile("SRUM to CSV with SOFTWARE hive",  "SrumECmd",            "srum",              ["-f", "{target}", "-r", "{software_hive}", "--csv", "{out}"]),
    Profile("SUM databases to CSV",            "SumECmd",             "sum_dir",           ["-d", "{target}", "--csv", "{out}"]),
    Profile("Windows Timeline ActivitiesCache.db to CSV","WxTCmd",   "activities_db",     ["-f", "{target}", "--csv", "{out}"]),
    Profile("VSCMount shadow copies",          "VSCMount",            "evidence_root",     ["-l", "{target}", "--mp", "{out}"]),
]


# ---------------------------------------------------------------------------
# Tool scanner
# ---------------------------------------------------------------------------

class ToolScanner:
    def __init__(self, root: Path):
        self.root = root
        self.tools: Dict[str, Path] = {}
        self.all_exes: List[Path] = []
        self.reb_files: List[Path] = []
        self.sql_maps_dir: Optional[Path] = None

    def scan(self) -> "ToolScanner":
        roots = []
        if self.root.exists():
            roots.append(self.root)
        for base in resource_roots():
            bundled = base / "tools"
            if bundled.exists():
                roots.append(bundled)
        seen: set = set()
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                for exe in root.rglob("*.exe"):
                    self.all_exes.append(exe)
            except OSError:
                continue
        for tool, names in TOOL_ALIASES.items():
            allowed = [n.lower() for n in names]
            candidates = [
                p for p in self.all_exes
                if p.name not in GUI_VIEWERS
                and any(fnmatch.fnmatch(p.name.lower(), pat) for pat in allowed)
            ]
            if not candidates:
                continue
            root_cands = [p for p in candidates if p.parent.resolve() == self.root.resolve()]
            chosen = sorted(root_cands or candidates, key=lambda x: (len(str(x)), str(x).lower()))[0]
            self.tools[tool] = chosen
        try:
            self.reb_files = sorted(self.root.rglob("*.reb"), key=lambda p: str(p).lower())
        except OSError:
            self.reb_files = []
        self.sql_maps_dir = self._find_sql_maps_dir()
        return self

    def _find_sql_maps_dir(self) -> Optional[Path]:
        candidates: List[Path] = []
        for rel in ["Maps/SQLECmd", "SQLECmd/Maps", "SQLECmd", "SQLECmd/Maps/SQLECmd"]:
            p = self.root / rel
            if p.exists() and p.is_dir():
                candidates.append(p)
        if candidates:
            return sorted(candidates, key=lambda p: (len(str(p)), str(p).lower()))[0]
        try:
            for dirpath, _, filenames in os.walk(self.root):
                p = Path(dirpath)
                if p.name.lower() in {"sqlecmd", "maps"}:
                    exts = {Path(f).suffix.lower() for f in filenames}
                    if exts.intersection({".smap", ".map", ".json", ".xml"}):
                        candidates.append(p)
                        break
        except OSError:
            pass
        return candidates[0] if candidates else None


# ---------------------------------------------------------------------------
# Evidence artifact index
# ---------------------------------------------------------------------------

class ArtifactIndex:
    def __init__(self, root: Path):
        self.root = root
        self.paths: Dict[str, Path] = {}
        self.count_dirs = 0
        self.count_files = 0
        self.duration = 0.0

    def get(self, key: str) -> Optional[Path]:
        if key == "evidence_root":
            return self.root if self.root.exists() else None
        return self.paths.get(key)

    def _set_if_exists(self, key: str, rels: List[str]) -> None:
        for rel in rels:
            p = self.root / Path(rel)
            if p.exists() and key not in self.paths:
                self.paths[key] = p
                return

    def build(self, progress=None, max_files: int = 500000) -> "ArtifactIndex":
        start = time.time()
        if not self.root.exists():
            self.duration = time.time() - start
            return self
        self._set_if_exists("amcache",          ["Windows/AppCompat/Programs/Amcache.hve"])
        self._set_if_exists("system_hive_live", ["Windows/System32/config/SYSTEM"])
        self._set_if_exists("software_hive",    ["Windows/System32/config/SOFTWARE"])
        self._set_if_exists("config_dir",       ["Windows/System32/config"])
        self._set_if_exists("evtx_dir",         ["Windows/System32/winevt/Logs", "Windows/System32/Winevt/Logs"])
        self._set_if_exists("iis_logs",         ["inetpub/logs/LogFiles"])
        self._set_if_exists("users_dir",        ["Users"])
        self._set_if_exists("recent_dir",       ["Users"])
        self._set_if_exists("prefetch_dir",     ["Windows/Prefetch"])
        self._set_if_exists("recycle_bin",      ["$Recycle.Bin", "Recycler"])
        self._set_if_exists("recent_file_cache",["Windows/AppCompat/Programs/RecentFileCache.bcf"])
        self._set_if_exists("srum",             ["Windows/System32/sru/SRUDB.dat"])
        self._set_if_exists("sum_dir",          ["Windows/System32/LogFiles/SUM"])
        self._set_if_exists("mft",              ["$MFT", "C/$MFT", "C_/$MFT"])
        self._set_if_exists("boot",             ["$Boot", "C/$Boot"])
        self._set_if_exists("usnjrnl",          ["$Extend/$UsnJrnl_$J", "C/$Extend/$UsnJrnl_$J",
                                                  "$Extend/$UsnJrnl:$J",  "C/$Extend/$UsnJrnl:$J"])
        self._set_if_exists("sds",              ["$Secure_$SDS", "C/$Secure_$SDS"])
        evtx_dir = self.paths.get("evtx_dir")
        if evtx_dir and "evtx_file" not in self.paths:
            try:
                for name in ["Security.evtx", "System.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx"]:
                    c = evtx_dir / name
                    if c.exists():
                        self.paths["evtx_file"] = c
                        break
                if "evtx_file" not in self.paths:
                    first = next(evtx_dir.glob("*.evtx"), None)
                    if first:
                        self.paths["evtx_file"] = first
            except OSError:
                pass
        needed = {"activities_db", "i30_any", "mft", "boot", "usnjrnl", "sds",
                  "evtx_file", "hayabusa_json_dir"} - set(self.paths)
        if needed:
            for dirpath, dirnames, filenames in os.walk(self.root):
                self.count_dirs += 1
                dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS]
                if progress and self.count_dirs % 250 == 0:
                    progress(f"[SCAN] {self.count_dirs} folders, {self.count_files} files...")
                for fn in filenames:
                    self.count_files += 1
                    full = Path(dirpath) / fn
                    low = fn.lower()
                    dir_low = str(dirpath).lower()
                    suffix = full.suffix.lower()
                    if "activities_db" not in self.paths and low == "activitiescache.db":
                        self.paths["activities_db"] = full
                    if "evtx_file" not in self.paths and suffix == ".evtx":
                        self.paths["evtx_file"] = full
                    if "hayabusa_json_dir" not in self.paths and suffix in {".json", ".jsonl"} \
                            and any(t in dir_low or t in low for t in ["evtx", "event", "winevt", "windows"]):
                        self.paths["hayabusa_json_dir"] = full.parent
                    if "i30_any" not in self.paths and fn == "$I30":
                        self.paths["i30_any"] = full
                    if "mft" not in self.paths and fn == "$MFT":
                        self.paths["mft"] = full
                    if "boot" not in self.paths and fn == "$Boot":
                        self.paths["boot"] = full
                    if "usnjrnl" not in self.paths and "usnjrnl" in low and "$j" in low:
                        self.paths["usnjrnl"] = full
                    if "sds" not in self.paths and "sds" in low:
                        self.paths["sds"] = full
                    if self.count_files >= max_files:
                        if progress:
                            progress("[SCAN] Hit file limit — partial index created.")
                        self.duration = time.time() - start
                        return self
                if needed.issubset(set(self.paths)):
                    break
        self.duration = time.time() - start
        return self


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class EZSentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION} - {AUTHOR}")
        self.geometry("1320x850")
        self.minsize(1120, 720)

        self.event_q: queue.Queue = queue.Queue()
        self.proc: Optional[subprocess.Popen] = None
        self.running = False
        self.tools: Dict[str, Path] = {}
        self.reb_files: List[Path] = []
        self.sql_maps_dir: Optional[Path] = None
        self.artifacts = ArtifactIndex(Path("."))
        self.artifact_root: Optional[Path] = None
        self.scanning_ez = False
        self.scanning_evidence = False
        self.line_count = 0
        self.dropped_log_events = 0

        self.vars: Dict[str, tk.Variable] = {
            "ez_root":        tk.StringVar(value=r"C:\Users\kenne\Desktop\EZ TOOLS\net9"),
            "evidence_root":  tk.StringVar(value=r"C:\Users\kenne\Desktop\DC01_Kape\C"),
            "output_root":    tk.StringVar(value=r"C:\Users\kenne\Desktop\Results"),
            "theme":          tk.StringVar(value="Midnight Blue"),
            "timeout":        tk.IntVar(value=1800),
            "dry_run":        tk.BooleanVar(value=False),
            "extra_args":     tk.StringVar(value=""),
            # RECmd
            "recmd_mode":     tk.StringVar(value="Search all: --sa"),
            "recmd_keyword":  tk.StringVar(value="powershell"),
            "recmd_batch":    tk.StringVar(value=""),
            "recmd_regex":    tk.BooleanVar(value=False),
            "recmd_recover":  tk.BooleanVar(value=False),
            "recmd_nl":       tk.BooleanVar(value=False),
            "recmd_details":  tk.BooleanVar(value=False),
            # Hayabusa
            "haya_mode":      tk.StringVar(value="auto_dir"),
            "haya_path":      tk.StringVar(value=""),
            "haya_fmt":       tk.StringVar(value="CSV"),
            "haya_level":     tk.StringVar(value="informational"),
        }

        self.selected_tool    = tk.StringVar(value="Hayabusa")
        self.selected_profile = tk.StringVar(value="")

        self._build_style()
        self._build_ui()

        self.after(50,  self.scan_tools_async)
        self.after(80,  self.scan_evidence_async)
        self.after(150, self._poll_events)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _build_style(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.apply_theme()

    def apply_theme(self):
        t = self.vars["theme"].get()
        if t == "Forensic Light":
            self.bg, self.panel, self.fg, self.accent, self.muted, self.ok_fg = \
                "#f4f6f8", "#ffffff", "#1f2937", "#2563eb", "#64748b", "#16a34a"
        elif t == "Graphite Pro":
            self.bg, self.panel, self.fg, self.accent, self.muted, self.ok_fg = \
                "#1f2329", "#2b3038", "#f5f7fa", "#38bdf8", "#a9b3c1", "#4ade80"
        else:  # Midnight Blue
            self.bg, self.panel, self.fg, self.accent, self.muted, self.ok_fg = \
                "#0f172a", "#182235", "#e5e7eb", "#60a5fa", "#94a3b8", "#4ade80"

        self.configure(bg=self.bg)
        s = self.style
        s.configure("TFrame",        background=self.bg)
        s.configure("Panel.TFrame",  background=self.panel)
        s.configure("TLabel",        background=self.bg,    foreground=self.fg)
        s.configure("Panel.TLabel",  background=self.panel, foreground=self.fg)
        s.configure("Muted.TLabel",  background=self.panel, foreground=self.muted)
        s.configure("SBar.TLabel",   background=self.bg,    foreground=self.muted)
        s.configure("Title.TLabel",  background=self.bg,    foreground=self.fg,
                    font=("Segoe UI", 17, "bold"))
        s.configure("TButton",       padding=5)
        s.configure("Accent.TButton",padding=8, font=("Segoe UI", 10, "bold"))
        s.configure("TEntry",        padding=4)
        s.configure("TCombobox",     padding=4)
        s.configure("TLabelframe",        background=self.panel)
        s.configure("TLabelframe.Label",   background=self.panel, foreground=self.accent,
                    font=("Segoe UI", 9, "bold"))
        s.configure("TCheckbutton",        background=self.panel, foreground=self.fg)
        s.configure("TRadiobutton",        background=self.panel, foreground=self.fg)
        s.configure("Header.TLabel",       background=self.bg,    foreground=self.fg,
                    font=("Segoe UI", 11, "bold"))
        s.configure("HeaderSub.TLabel",    background=self.bg,    foreground=self.muted,
                    font=("Segoe UI", 9))

        if hasattr(self, "tool_list"):
            self.tool_list.configure(bg=self.panel, fg=self.fg,
                                     selectbackground=self.accent,
                                     selectforeground=self.bg)
            self._recolor_tool_list()
        if hasattr(self, "preview"):
            self.preview.configure(bg=self.panel, fg=self.fg,
                                   insertbackground=self.fg)
        if hasattr(self, "log"):
            self.log.configure(bg=self.panel, fg=self.fg,
                               insertbackground=self.fg)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        root = ttk.Frame(self, padding=(8, 6, 8, 4))
        root.pack(fill="both", expand=True)

        # ── Toolbar ────────────────────────────────────────────────────
        toolbar = ttk.Frame(root)
        toolbar.pack(fill="x", pady=(0, 4))

        logo_path = next(
            (b / "assets" / "ez_sentinel_logo.png" for b in resource_roots()
             if (b / "assets" / "ez_sentinel_logo.png").exists()),
            app_dir() / "assets" / "ez_sentinel_logo.png",
        )
        self.logo_img = None
        if logo_path.exists():
            try:
                raw = tk.PhotoImage(file=str(logo_path))
                w, h = raw.width(), raw.height()
                factor = max(1, min(w, h) // 28)
                self.logo_img = raw.subsample(factor, factor)
                ttk.Label(toolbar, image=self.logo_img, background=self.bg).pack(
                    side="left", padx=(0, 6))
            except Exception:
                pass

        ttk.Label(toolbar, text=APP_NAME, style="Header.TLabel").pack(side="left")
        ttk.Label(toolbar, text=f"v{APP_VERSION}", style="HeaderSub.TLabel").pack(
            side="left", padx=(5, 0))
        ttk.Label(toolbar, text=" | ", style="HeaderSub.TLabel").pack(side="left")
        ttk.Label(toolbar, text=AUTHOR, style="HeaderSub.TLabel").pack(side="left")

        ttk.Button(toolbar, text="LinkedIn",
                   command=lambda: webbrowser.open(LINKEDIN)).pack(side="right", padx=(4, 0))
        ttk.Combobox(toolbar, textvariable=self.vars["theme"],
                     values=["Midnight Blue", "Graphite Pro", "Forensic Light"],
                     width=16, state="readonly").pack(side="right", padx=4)
        ttk.Button(toolbar, text="Theme",
                   command=self.apply_theme).pack(side="right")

        ttk.Separator(root, orient="horizontal").pack(fill="x", pady=(0, 6))

        # ── Case Paths ─────────────────────────────────────────────────
        paths = ttk.LabelFrame(root, text="Case Paths & Execution Settings", padding=(8, 4))
        paths.pack(fill="x", pady=(0, 6))

        self._path_row(paths, "EZ Tools Root",  self.vars["ez_root"],       0, self.scan_tools_async)
        self._path_row(paths, "Evidence Root",  self.vars["evidence_root"], 1, self.scan_evidence_async)
        self._path_row(paths, "Output Root",    self.vars["output_root"],   2, self.refresh_preview)

        ttk.Label(paths, text="Timeout seconds").grid(
            row=0, column=3, sticky="w", padx=(14, 4))
        ttk.Entry(paths, textvariable=self.vars["timeout"], width=8).grid(
            row=0, column=4, sticky="w")
        ttk.Checkbutton(paths, text="Dry run", variable=self.vars["dry_run"],
                        command=self.refresh_preview).grid(
            row=1, column=3, columnspan=2, sticky="w", padx=(14, 4))
        ttk.Button(paths, text="Scan EZ Tools",
                   command=self.scan_tools_async).grid(
            row=2, column=3, sticky="ew", padx=(14, 4))
        ttk.Button(paths, text="Index Evidence",
                   command=self.scan_evidence_async).grid(
            row=2, column=4, sticky="ew", padx=(4, 4))
        paths.columnconfigure(1, weight=1)

        # ── Three-pane body ────────────────────────────────────────────
        body = ttk.PanedWindow(root, orient="horizontal")
        body.pack(fill="both", expand=True)

        # ── Left: Tool Lock ────────────────────────────────────────────
        left = ttk.Frame(body, padding=8, style="Panel.TFrame")
        body.add(left, weight=1)

        ttk.Label(left, text="Tool Lock", style="Panel.TLabel",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")

        list_wrap = ttk.Frame(left, style="Panel.TFrame")
        list_wrap.pack(fill="both", expand=True, pady=6)
        self.tool_list = tk.Listbox(
            list_wrap, height=18, exportselection=False,
            font=("Consolas", 9), activestyle="none",
            bg=self.panel, fg=self.fg,
            selectbackground=self.accent, selectforeground=self.bg,
        )
        vsb_tools = ttk.Scrollbar(list_wrap, orient="vertical",
                                   command=self.tool_list.yview)
        self.tool_list.configure(yscrollcommand=vsb_tools.set)
        vsb_tools.pack(side="right", fill="y")
        self.tool_list.pack(side="left", fill="both", expand=True)
        self.tool_list.bind("<<ListboxSelect>>", self._on_tool_select)

        ttk.Button(left, text="Help for Selected Tool",
                   command=self.run_help).pack(fill="x", pady=3)
        ttk.Button(left, text="Open Tool Output Folder",
                   command=self.open_tool_output).pack(fill="x", pady=3)

        self.scan_label = ttk.Label(left, text="Not scanned yet",
                                    style="Muted.TLabel", wraplength=300)
        self.scan_label.pack(anchor="w", pady=8)

        # ── Middle: Command Builder ────────────────────────────────────
        middle = ttk.Frame(body, padding=10, style="Panel.TFrame")
        body.add(middle, weight=2)

        ttk.Label(middle, text="Command Builder", style="Panel.TLabel",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(middle,
                  text="Profiles are locked to a parser. "
                       "Heavy evidence discovery is cached so the UI stays responsive.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        ttk.Label(middle, text="Profile", style="Panel.TLabel").pack(anchor="w")
        self.profile_combo = ttk.Combobox(middle, textvariable=self.selected_profile,
                                           state="readonly")
        self.profile_combo.pack(fill="x", pady=(2, 8))
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_builder())

        self.builder_frame = ttk.LabelFrame(middle, text="Argument Builder", padding=10)
        self.builder_frame.pack(fill="x", pady=6)
        self._build_default_builder()

        expert = ttk.LabelFrame(
            middle,
            text="Expert Extra Args (optional, arguments only — never paste full command)",
            padding=8,
        )
        expert.pack(fill="x", pady=6)
        ttk.Entry(expert, textvariable=self.vars["extra_args"]).pack(fill="x")
        ttk.Label(expert,
                  text="Blocked: .exe paths, shell pipes, redirection, &, ;  "
                       "— prevents command injection and parser mixing.",
                  style="Muted.TLabel").pack(anchor="w")

        acts = ttk.Frame(middle, style="Panel.TFrame")
        acts.pack(fill="x", pady=8)
        ttk.Button(acts, text="Analyze Selected",
                   style="Accent.TButton", command=self.run_selected).pack(side="left", padx=(0, 6))
        ttk.Button(acts, text="Stop",
                   command=self.stop_process).pack(side="left", padx=6)
        ttk.Button(acts, text="Refresh Preview",
                   command=self.refresh_preview).pack(side="left", padx=6)

        ttk.Label(middle, text="Command Preview", style="Panel.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        self.preview = tk.Text(middle, height=10, wrap="word",
                               font=("Consolas", 10),
                               bg=self.panel, fg=self.fg,
                               insertbackground=self.fg)
        self.preview.pack(fill="both", expand=False)

        # ── Right: Execution Log ───────────────────────────────────────
        right = ttk.Frame(body, padding=8, style="Panel.TFrame")
        body.add(right, weight=2)

        ttk.Label(right, text="Execution Log", style="Panel.TLabel",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")

        log_wrap = ttk.Frame(right, style="Panel.TFrame")
        log_wrap.pack(fill="both", expand=True, pady=6)
        self.log = tk.Text(log_wrap, wrap="word", font=("Consolas", 9),
                           bg=self.panel, fg=self.fg,
                           insertbackground=self.fg)
        vsb_log = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=vsb_log.set)
        vsb_log.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

        bottom = ttk.Frame(right, style="Panel.TFrame")
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Clear Log",
                   command=self._clear_log).pack(side="right")

    def _path_row(self, parent, label, var, row, callback):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=var).grid(
            row=row, column=1, sticky="ew", padx=6, pady=3)
        def browse():
            initial = var.get() if Path(var.get()).exists() else str(Path.home())
            p = filedialog.askdirectory(initialdir=initial)
            if p:
                var.set(p)
                callback()
        ttk.Button(parent, text="Browse", command=browse).grid(
            row=row, column=2, sticky="ew", pady=3)

    def _clear_log(self):
        self.log.delete("1.0", "end")
        self.line_count = 0

    # ------------------------------------------------------------------
    # Builder panels
    # ------------------------------------------------------------------

    def _clear_builder(self):
        for w in self.builder_frame.winfo_children():
            w.destroy()

    def _build_default_builder(self):
        self._clear_builder()
        self.builder_frame.configure(text="Argument Builder")
        ttk.Label(self.builder_frame,
                  text="Profile-based execution",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(self.builder_frame,
                  text="Select a profile above. Arguments are validated before execution.\n"
                       "Use 'Help for Selected Tool' to view the full argument list.",
                  style="Muted.TLabel").pack(anchor="w", pady=4)

    def _build_hayabusa_builder(self):
        self._clear_builder()
        self.builder_frame.configure(text="Argument Builder")

        ttk.Label(self.builder_frame, text="Hayabusa scan args",
                  font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))

        # Row 1: Input mode
        ttk.Label(self.builder_frame, text="Input").grid(row=1, column=0, sticky="w")
        modes = [
            ("auto_dir",    "EVTX folder — auto-indexed from Evidence Root"),
            ("browse_dir",  "EVTX folder — browse to folder"),
            ("browse_file", "Single .evtx/.evt file — browse to file"),
            ("json_dir",    "JSON/JSONL folder — browse to folder"),
        ]
        mode_frame = ttk.Frame(self.builder_frame)
        mode_frame.grid(row=1, column=1, columnspan=2, sticky="ew", padx=6, pady=2)
        for val, lbl in modes:
            ttk.Radiobutton(mode_frame, text=lbl,
                            variable=self.vars["haya_mode"], value=val,
                            command=self._on_haya_mode_change).pack(anchor="w")

        # Row 2: Path
        ttk.Label(self.builder_frame, text="Path").grid(row=2, column=0, sticky="w")
        self.haya_path_entry = ttk.Entry(self.builder_frame,
                                         textvariable=self.vars["haya_path"])
        self.haya_path_entry.grid(row=2, column=1, sticky="ew", padx=6, pady=2)
        self.haya_browse_btn = ttk.Button(self.builder_frame, text="Browse…", width=9,
                                          command=self._browse_haya_target)
        self.haya_browse_btn.grid(row=2, column=2, sticky="w", pady=2)

        # Row 3: Output format
        ttk.Label(self.builder_frame, text="Output").grid(row=3, column=0, sticky="w")
        fmt_frame = ttk.Frame(self.builder_frame)
        fmt_frame.grid(row=3, column=1, columnspan=2, sticky="ew", padx=6, pady=2)
        for val, lbl in [("CSV", "CSV only"), ("CSV + HTML", "CSV + HTML report")]:
            ttk.Radiobutton(fmt_frame, text=lbl,
                            variable=self.vars["haya_fmt"], value=val,
                            command=self.refresh_preview).pack(side="left", padx=(0, 12))

        # Row 4: Min level
        ttk.Label(self.builder_frame, text="Level").grid(row=4, column=0, sticky="w")
        lvl_cb = ttk.Combobox(self.builder_frame, textvariable=self.vars["haya_level"],
                               values=["informational", "low", "medium", "high", "critical"],
                               state="readonly", width=18)
        lvl_cb.grid(row=4, column=1, sticky="w", padx=6, pady=2)
        lvl_cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_preview())

        # Row 5: Update Rules button
        update_frame = ttk.Frame(self.builder_frame)
        update_frame.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Button(update_frame, text="Update Rules",
                   command=self.run_hayabusa_update_rules).pack(side="left")
        ttk.Label(update_frame,
                  text="  Downloads/updates detection rules from Hayabusa GitHub",
                  style="Muted.TLabel").pack(side="left")

        # Row 6: Example
        ttk.Label(self.builder_frame,
                  text="Example:  hayabusa.exe csv-timeline -d <evtx_folder> -o out.csv -w -q",
                  style="Muted.TLabel").grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

        self.builder_frame.columnconfigure(1, weight=1)
        self._on_haya_mode_change()

    def _on_haya_mode_change(self, *_):
        if not hasattr(self, "haya_path_entry"):
            return
        is_auto = self.vars["haya_mode"].get() == "auto_dir"
        st = "disabled" if is_auto else "normal"
        self.haya_path_entry.configure(state=st)
        self.haya_browse_btn.configure(state=st)
        self.refresh_preview()

    def _browse_haya_target(self):
        mode = self.vars["haya_mode"].get()
        if mode == "browse_file":
            path = filedialog.askopenfilename(
                title="Select event log file",
                filetypes=[("Windows Event Log", "*.evtx *.evt"),
                           ("All files", "*.*")],
            )
        else:
            path = filedialog.askdirectory(title="Select folder containing event logs")
        if path:
            self.vars["haya_path"].set(path)
            self.refresh_preview()

    def run_hayabusa_update_rules(self):
        exe = self.tools.get("Hayabusa")
        if not exe:
            messagebox.showerror(
                "Hayabusa not found",
                "Hayabusa executable not found. Scan EZ Tools Root first.",
            )
            return
        rules_dir = exe.parent / "rules"
        if rules_dir.exists() and not (rules_dir / ".git").exists():
            backup = exe.parent / f"rules_backup_{now_stamp()}"
            try:
                rules_dir.rename(backup)
                self._log(f"[INFO] Existing rules/ backed up to {backup.name} — cloning fresh copy.")
            except OSError as exc:
                messagebox.showerror(
                    "Backup failed",
                    f"Could not rename rules/ before update:\n{exc}\n\n"
                    "Manually rename or delete the rules/ folder then try again.",
                )
                return
        cmd = [str(exe), "update-rules"]
        self._run_command(cmd, None, "Hayabusa Update Rules")

    def _build_recmd_builder(self):
        self._clear_builder()
        self.builder_frame.configure(text="Argument Builder")

        ttk.Label(self.builder_frame, text="RECmd smart args",
                  font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        modes = [
            "Search all: --sa", "Search key names: --sk", "Search value names: --sv",
            "Search value data: --sd", "Search slack: --ss", "Batch file: --bn",
            "Key details: --kn", "Base64 minimum bytes: --base64", "Minimum value size: --minSize",
        ]
        ttk.Label(self.builder_frame, text="Mode").grid(row=1, column=0, sticky="w")
        cb = ttk.Combobox(self.builder_frame, textvariable=self.vars["recmd_mode"],
                          values=modes, state="readonly", width=34)
        cb.grid(row=1, column=1, sticky="ew", padx=6, pady=2)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_preview())

        ttk.Label(self.builder_frame, text="Keyword / key path / size").grid(
            row=2, column=0, sticky="w")
        ttk.Entry(self.builder_frame, textvariable=self.vars["recmd_keyword"]).grid(
            row=2, column=1, sticky="ew", padx=6, pady=2)

        ttk.Label(self.builder_frame, text="Batch .reb file").grid(row=3, column=0, sticky="w")
        self.reb_combo = ttk.Combobox(
            self.builder_frame, textvariable=self.vars["recmd_batch"],
            values=[str(p) for p in self.reb_files], state="readonly")
        self.reb_combo.grid(row=3, column=1, sticky="ew", padx=6, pady=2)

        checks = ttk.Frame(self.builder_frame)
        checks.grid(row=4, column=0, columnspan=2, sticky="w", pady=4)
        for text, key in [("--regex", "recmd_regex"), ("--recover", "recmd_recover"),
                          ("--nl", "recmd_nl"), ("--details", "recmd_details")]:
            ttk.Checkbutton(checks, text=text, variable=self.vars[key],
                            command=self.refresh_preview).pack(side="left", padx=3)

        ttk.Label(self.builder_frame,
                  text="Example:  RECmd.exe -f <hive> --sa <keyword> --csv <out_dir>",
                  style="Muted.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.builder_frame.columnconfigure(1, weight=1)

    # ------------------------------------------------------------------
    # Async scans
    # ------------------------------------------------------------------

    def scan_tools_async(self):
        if self.scanning_ez:
            return
        self.scanning_ez = True
        root = Path(self.vars["ez_root"].get()).expanduser()
        self._log(f"[INFO] Scanning EZ Tools: {root}")
        self._set_status_right("Scanning EZ Tools…")
        def worker():
            scanner = ToolScanner(root)
            try:
                scanner.scan()
            except Exception as exc:
                self.event_q.put(("log", f"[ERROR] EZ tools scan failed: {exc}"))
            self.event_q.put(("tools_done", scanner))
        threading.Thread(target=worker, daemon=True).start()

    def scan_evidence_async(self):
        if self.scanning_evidence:
            return
        self.scanning_evidence = True
        root = Path(self.vars["evidence_root"].get()).expanduser()
        self.artifact_root = root
        self._log(f"[INFO] Indexing evidence: {root}")
        self._set_status_right("Indexing evidence…")
        def progress(msg: str):
            self.event_q.put(("log", msg))
        def worker():
            index = ArtifactIndex(root)
            try:
                index.build(progress=progress)
            except Exception as exc:
                self.event_q.put(("log", f"[ERROR] Evidence index failed: {exc}"))
            self.event_q.put(("artifacts_done", index))
        threading.Thread(target=worker, daemon=True).start()

    def _on_tools_done(self, scanner: ToolScanner):
        self.scanning_ez = False
        self.tools = scanner.tools
        self.reb_files = scanner.reb_files
        self.sql_maps_dir = scanner.sql_maps_dir

        self.tool_list.delete(0, "end")
        for tool in sorted(TOOL_ALIASES):
            found = tool in self.tools
            self.tool_list.insert("end", f"{'✓' if found else '--'} {tool}")
        self._recolor_tool_list()

        total = len(TOOL_ALIASES)
        found_count = len(self.tools)
        locked = sum(1 for t in self.tools if t in BUILDER_TOOLS)
        maps_path = str(self.sql_maps_dir) if self.sql_maps_dir else "not found"
        self.scan_label.config(
            text=f"EZ Tools: {self.vars['ez_root'].get()}\n"
                 f"Executables found: {found_count}\n"
                 f"Locked tools found: {locked}\n"
                 f".reb files: {len(self.reb_files)}\n"
                 f"SQLECmd maps: {maps_path}\n"
                 f"Evidence index: {len(self.artifacts.paths)} artifact types"
        )
        self._log(f"[INFO] Tool scan done — {found_count}/{total} parsers located.")

        # Keep current selection or fall back to Hayabusa
        current = self.selected_tool.get()
        if current in self.tools or current in BUILDER_TOOLS:
            pass
        else:
            self.selected_tool.set("Hayabusa")

        self._refresh_profiles()
        self.refresh_preview()

    def _on_artifacts_done(self, index: ArtifactIndex):
        self.scanning_evidence = False
        self.artifacts = index
        self._log(f"[INFO] Evidence index done in {index.duration:.2f}s — "
                  f"{index.count_dirs} folders, {index.count_files} files, "
                  f"{len(index.paths)} artifact types found.")
        found_count = len(self.tools)
        locked = sum(1 for t in self.tools if t in BUILDER_TOOLS)
        maps_path = str(self.sql_maps_dir) if self.sql_maps_dir else "not found"
        self.scan_label.config(
            text=f"EZ Tools: {self.vars['ez_root'].get()}\n"
                 f"Executables found: {found_count}\n"
                 f"Locked tools found: {locked}\n"
                 f".reb files: {len(self.reb_files)}\n"
                 f"SQLECmd maps: {maps_path}\n"
                 f"Evidence index: {len(index.paths)} artifact types"
        )
        self.refresh_preview()

    def _recolor_tool_list(self):
        for i in range(self.tool_list.size()):
            text = self.tool_list.get(i)
            name = text.split()[-1]
            if name in self.tools:
                fg = "#4ade80" if name == "Hayabusa" else self.accent
            else:
                fg = self.muted
            self.tool_list.itemconfigure(i, foreground=fg, background=self.panel)

    def _set_status_left(self, msg: str):
        if hasattr(self, "status_left"):
            self.status_left.configure(text=msg)

    def _set_status_right(self, msg: str):
        if hasattr(self, "status_right"):
            self.status_right.configure(text=msg)

    # ------------------------------------------------------------------
    # Tool / profile selection
    # ------------------------------------------------------------------

    def _on_tool_select(self, event=None):
        sel = self.tool_list.curselection()
        if not sel:
            return
        text = self.tool_list.get(sel[0])
        self.selected_tool.set(text.split()[-1])
        self._refresh_profiles()

    def _refresh_profiles(self):
        tool = self.selected_tool.get()
        if tool == "RECmd":
            values = ["RECmd Argument Builder"]
            self.profile_combo["values"] = values
            self.selected_profile.set(values[0])
            self._build_recmd_builder()
        elif tool == "Hayabusa":
            values = ["Hayabusa Scan Builder"]
            self.profile_combo["values"] = values
            self.selected_profile.set(values[0])
            self._build_hayabusa_builder()
        else:
            values = [p.name for p in PROFILES if p.tool == tool]
            self.profile_combo["values"] = values
            if values and self.selected_profile.get() not in values:
                self.selected_profile.set(values[0])
            self._build_default_builder()
        self.refresh_preview()

    def refresh_builder(self):
        self.refresh_preview()

    def _selected_profile_obj(self) -> Optional[Profile]:
        sel = self.selected_profile.get()
        for p in PROFILES:
            if p.name == sel:
                return p
        return None

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def _tool_output_dir(self, tool: str) -> Path:
        return ensure_dir(Path(self.vars["output_root"].get()).expanduser() / tool)

    def _context(self, profile: Profile) -> Dict[str, str]:
        out_dir = self._tool_output_dir(profile.tool)
        base = f"{safe_filename(profile.name)}_{now_stamp()}"
        return {
            "target":        str(self.artifacts.get(profile.target_type) or ""),
            "out":           str(out_dir),
            "out_file":      str(out_dir / f"{base}.csv"),
            "html_report":   str(out_dir / f"{base}.html"),
            "maps_sql":      str(self.sql_maps_dir or ""),
            "software_hive": str(self.artifacts.get("software_hive") or ""),
        }

    def build_hayabusa_command(self) -> Tuple[List[str], List[str], Optional[Path]]:
        errors: List[str] = []
        exe = self.tools.get("Hayabusa")
        if not exe:
            return [], ["Hayabusa executable not found. Scan EZ Tools Root or check the bundled tools/ folder."], None

        exe_parent = exe.parent
        rules_dir = exe_parent / "rules"
        if not rules_dir.exists():
            errors.append(
                f"rules/ folder not found next to Hayabusa ({exe_parent}). "
                "Click 'Update Rules' to download detection rules."
            )
        elif not (rules_dir / "config").exists() or not any((rules_dir / "config").iterdir()):
            errors.append(
                "rules/config/ is missing or empty — Hayabusa cannot start. "
                "Click 'Update Rules' in the builder to download the required config files, "
                "or manually copy them from the Hayabusa GitHub release."
            )
        if not (exe_parent / "config").exists():
            errors.append(f"config/ folder not found next to Hayabusa: {exe_parent}")

        mode       = self.vars["haya_mode"].get()
        browse_path = self.vars["haya_path"].get().strip()
        out_fmt    = self.vars["haya_fmt"].get()
        min_level  = self.vars["haya_level"].get()

        target   = ""
        is_file  = False
        add_json = False

        if mode == "auto_dir":
            auto = self.artifacts.get("evtx_dir")
            if auto:
                target = str(auto)
            else:
                errors.append(
                    "EVTX folder not auto-indexed. Click ↺ Re-index Evidence, "
                    "verify Evidence Root, or switch to 'Browse' mode and pick a folder."
                )
        elif mode == "browse_file":
            target  = browse_path
            is_file = True
            if not target:
                errors.append("Browse to a .evtx / .evt file using the Browse… button.")
            elif not Path(target).is_file():
                errors.append(f"File not found: {target}")
        elif mode == "browse_dir":
            target = browse_path
            if not target:
                errors.append("Browse to an EVTX folder using the Browse… button.")
            elif not Path(target).is_dir():
                errors.append(f"Folder not found: {target}")
        elif mode == "json_dir":
            target   = browse_path
            add_json = True
            if not target:
                errors.append("Browse to a JSON/JSONL folder using the Browse… button.")
            elif not Path(target).is_dir():
                errors.append(f"Folder not found: {target}")

        out_dir    = self._tool_output_dir("Hayabusa")
        base       = f"hayabusa_{now_stamp()}"
        out_file   = str(out_dir / f"{base}.csv")
        html_file  = str(out_dir / f"{base}.html")

        args = [str(exe), "csv-timeline"]
        if is_file:
            args += ["-f", target]
        else:
            args += ["-d", target]
        if add_json:
            args.append("-J")
        args += ["-o", out_file, "-w", "-q", "--no-color", "-C"]
        if min_level and min_level != "informational":
            args += ["-l", min_level]
        if out_fmt == "CSV + HTML":
            args += ["-H", html_file]

        try:
            args.extend(safe_split_extra(self.vars["extra_args"].get()))
        except ValueError as e:
            errors.append(str(e))

        return args, errors, None

    def build_recmd_command(self) -> Tuple[List[str], List[str], Optional[Path]]:
        errors: List[str] = []
        exe = self.tools.get("RECmd")
        if not exe:
            return [], ["RECmd.exe not found. Scan EZ Tools Root."], None
        config_dir = self.artifacts.get("config_dir")
        if not config_dir:
            errors.append("Registry config folder not indexed. "
                          "Expected: EvidenceRoot\\Windows\\System32\\config")
        out  = str(self._tool_output_dir("RECmd"))
        args = [str(exe), "-d", str(config_dir or ""), "--csv", out]
        mode    = self.vars["recmd_mode"].get()
        keyword = self.vars["recmd_keyword"].get().strip()
        if mode.startswith("Batch"):
            reb = self.vars["recmd_batch"].get().strip()
            if not reb: errors.append("Select a .reb batch file for --bn mode.")
            args += ["--bn", reb]
        elif mode.startswith("Search all"):
            if not keyword: errors.append("Enter a keyword for --sa.")
            args += ["--sa", keyword]
        elif mode.startswith("Search key"):
            if not keyword: errors.append("Enter a keyword for --sk.")
            args += ["--sk", keyword]
        elif mode.startswith("Search value names"):
            if not keyword: errors.append("Enter a keyword for --sv.")
            args += ["--sv", keyword]
        elif mode.startswith("Search value data"):
            if not keyword: errors.append("Enter a keyword for --sd.")
            args += ["--sd", keyword]
        elif mode.startswith("Search slack"):
            if not keyword: errors.append("Enter a keyword for --ss.")
            args += ["--ss", keyword]
        elif mode.startswith("Key details"):
            if not keyword: errors.append("Enter a registry key path for --kn.")
            args += ["--kn", keyword]
        elif mode.startswith("Base64"):
            if not keyword.isdigit(): errors.append("Enter a numeric minimum byte size for --base64.")
            args += ["--base64", keyword]
        elif mode.startswith("Minimum"):
            if not keyword.isdigit(): errors.append("Enter a numeric minimum byte size for --minSize.")
            args += ["--minSize", keyword]
        if self.vars["recmd_regex"].get() and any(x in args for x in ["--sk","--sv","--sd","--ss"]):
            args.append("--regex")
        if self.vars["recmd_recover"].get(): args.append("--recover")
        if self.vars["recmd_nl"].get():      args.append("--nl")
        if self.vars["recmd_details"].get(): args.append("--details")
        try:
            args.extend(safe_split_extra(self.vars["extra_args"].get()))
        except ValueError as e:
            errors.append(str(e))
        return args, errors, None

    def build_command(self) -> Tuple[List[str], List[str], Optional[Path]]:
        tool = self.selected_tool.get()
        if tool == "RECmd":
            return self.build_recmd_command()
        if tool == "Hayabusa":
            return self.build_hayabusa_command()

        profile = self._selected_profile_obj()
        if not profile:
            return [], ["No profile selected."], None
        exe = self.tools.get(profile.tool)
        if not exe:
            return [], [f"{profile.tool}.exe not found. Scan EZ Tools Root."], None
        ctx    = self._context(profile)
        errors: List[str] = []
        if not ctx["target"]:
            errors.append(
                f"Artifact not indexed for '{profile.target_type}'. "
                "Click ↺ Re-index Evidence or verify Evidence Root."
            )
        if "{maps_sql}" in profile.args_template and not ctx["maps_sql"]:
            errors.append("SQLECmd maps directory not found.")
        if "{software_hive}" in profile.args_template and not ctx["software_hive"]:
            errors.append("SOFTWARE hive not indexed for SRUM profile.")
        args = [str(exe)]
        for token in profile.args_template:
            try:
                args.append(token.format(**ctx))
            except KeyError as e:
                errors.append(f"Missing template value: {e}")
        try:
            args.extend(safe_split_extra(self.vars["extra_args"].get()))
        except ValueError as e:
            errors.append(str(e))
        capture = None
        if profile.tool == "bstrings":
            capture = (self._tool_output_dir("bstrings")
                       / f"{safe_filename(profile.name)}_{now_stamp()}.txt")
        return args, errors, capture

    # ------------------------------------------------------------------
    # Preview
    # ------------------------------------------------------------------

    def refresh_preview(self):
        cmd, errors, capture = self.build_command()
        self.preview.delete("1.0", "end")
        tool = self.selected_tool.get()
        exe  = self.tools.get(tool)
        self.preview.insert("end", f"{APP_NAME} v{APP_VERSION}  |  {AUTHOR}\n")
        self.preview.insert("end", f"Tool: {exe or 'NOT FOUND'}\n")
        self.preview.insert("end",
            f"Evidence index: {len(self.artifacts.paths)} artifact types "
            f"from {self.artifacts.root}\n\n")
        if cmd:
            self.preview.insert("end", quote_cmd(cmd) + "\n")
        if capture:
            self.preview.insert("end", f"\nCapture stdout → {capture}\n")
        if errors:
            self.preview.insert("end", "\nVALIDATION ERRORS:\n")
            for e in errors:
                self.preview.insert("end", f"  • {e}\n")

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run_help(self):
        tool = self.selected_tool.get()
        exe  = self.tools.get(tool)
        if not exe:
            messagebox.showerror("Tool not found", f"{tool} executable not found.")
            return
        help_args = [str(exe), "help"] if tool == "Hayabusa" else [str(exe), "-h"]
        self._run_command(help_args, None, f"Help: {exe.name}")

    def run_selected(self):
        cmd, errors, capture = self.build_command()
        self.refresh_preview()
        if errors:
            messagebox.showerror("Validation blocked execution", "\n".join(errors))
            return
        if not cmd:
            messagebox.showerror("No command", "No command was built.")
            return
        if self.vars["dry_run"].get():
            self._log("[DRY RUN] " + quote_cmd(cmd))
            return
        self._run_command(cmd, capture,
                          self.selected_profile.get() or self.selected_tool.get())

    def _run_command(self, cmd: List[str], stdout_capture: Optional[Path], title: str):
        if self.running:
            messagebox.showwarning("Busy", "A command is already running. Stop it first.")
            return
        exe_path = Path(cmd[0])
        if not exe_path.exists():
            messagebox.showerror("Executable missing", str(exe_path))
            return
        log_dir  = ensure_dir(Path(self.vars["output_root"].get()).expanduser() / "_EZSentinelLogs")
        case_log = log_dir / f"run_{now_stamp()}.log"
        try:
            timeout = int(self.vars["timeout"].get() or 1800)
        except Exception:
            timeout = 1800
        self.running = True
        self._set_status_right(f"Running: {title}")
        self._log("\n" + "=" * 88)
        self._log(f"[{now_stamp()}] {title}")
        self._log(quote_cmd(cmd))
        if stdout_capture:
            ensure_dir(stdout_capture.parent)
            self._log(f"Capture → {stdout_capture}")

        def queue_log(text: str) -> None:
            if self.event_q.qsize() >= MAX_PENDING_LOG_EVENTS:
                self.dropped_log_events += 1
                return
            if self.dropped_log_events:
                dropped = self.dropped_log_events
                self.dropped_log_events = 0
                self.event_q.put(("log",
                    f"[INFO] Suppressed {dropped} log lines to keep UI responsive."))
            self.event_q.put(("log", text))

        def worker():
            out_tail: List[str] = []
            err_tail: List[str] = []
            start      = time.time()
            return_code: Optional[int] = None
            stdout_fh  = None
            try:
                if stdout_capture:
                    stdout_fh  = open(stdout_capture, "w", encoding="utf-8", errors="replace")
                    stdout_pipe = stdout_fh
                else:
                    stdout_pipe = subprocess.PIPE

                self.proc = subprocess.Popen(
                    cmd, shell=False,
                    stdout=stdout_pipe,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True, encoding="utf-8", errors="replace",
                    cwd=str(exe_path.parent),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                                  if os.name == "nt" else 0,
                )

                if stdout_capture:
                    assert self.proc.stderr is not None
                    try:
                        while True:
                            if time.time() - start > timeout:
                                self.proc.kill()
                                err_tail.append(f"[TIMEOUT] Killed after {timeout}s")
                                break
                            line = self.proc.stderr.readline()
                            if line:
                                err_tail.append(line[-500:])
                                queue_log("[STDERR] " + line.rstrip())
                            elif self.proc.poll() is not None:
                                break
                            else:
                                time.sleep(0.05)
                        try:
                            return_code = self.proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self.proc.kill()
                            return_code = self.proc.wait()
                    finally:
                        stdout_fh.close()
                        stdout_fh = None
                else:
                    assert self.proc.stdout is not None and self.proc.stderr is not None

                    def reader(stream, label, tail):
                        for line in iter(stream.readline, ""):
                            tail.append(line[-500:])
                            if len(tail) > 300:
                                del tail[:100]
                            queue_log((label + line.rstrip()) if label else line.rstrip())

                    t1 = threading.Thread(target=reader,
                                         args=(self.proc.stdout, "", out_tail), daemon=True)
                    t2 = threading.Thread(target=reader,
                                         args=(self.proc.stderr, "[STDERR] ", err_tail), daemon=True)
                    t1.start(); t2.start()
                    while self.proc.poll() is None:
                        if time.time() - start > timeout:
                            self.proc.kill()
                            err_tail.append(f"[TIMEOUT] Killed after {timeout}s")
                            break
                        time.sleep(0.1)
                    try:
                        return_code = self.proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        return_code = self.proc.wait()
                    t1.join(timeout=1); t2.join(timeout=1)

                status, reason = classify_result(
                    return_code, "".join(out_tail[-300:]), "".join(err_tail[-300:]))
                case_log.write_text(
                    f"Title: {title}\nCommand: {quote_cmd(cmd)}\n"
                    f"ReturnCode: {return_code}\nStatus: {status}\nReason: {reason}\n"
                    f"Capture: {stdout_capture or ''}\n\n"
                    f"STDOUT_TAIL:\n{''.join(out_tail[-300:])}\n\n"
                    f"STDERR_TAIL:\n{''.join(err_tail[-300:])}\n",
                    encoding="utf-8", errors="replace",
                )
                self.event_q.put(("proc_done", status, reason, str(case_log)))
            except Exception as exc:
                if stdout_fh is not None:
                    try:
                        stdout_fh.close()
                    except OSError:
                        pass
                self.event_q.put(("proc_done", "FAILED", str(exc), str(case_log)))

        threading.Thread(target=worker, daemon=True).start()

    def stop_process(self):
        if self.proc and self.running:
            try:
                self.proc.terminate()
                self._log("[STOP] Termination requested.")
            except Exception as e:
                self._log(f"[STOP ERROR] {e}")

    # ------------------------------------------------------------------
    # Event loop (non-blocking, batched)
    # ------------------------------------------------------------------

    def _log_batch(self, lines: List[str]) -> None:
        if not hasattr(self, "log"):
            return
        block = "\n".join(str(l) for l in lines) + "\n"
        self.log.insert("end", block)
        self.line_count += block.count("\n")
        if self.line_count > MAX_LOG_LINES:
            self.log.delete("1.0", "1200.0")
            self.line_count -= 1200
        self.log.see("end")

    def _poll_events(self):
        log_batch: List[str] = []
        processed = 0
        try:
            while processed < 200:
                item = self.event_q.get_nowait()
                processed += 1
                kind = item[0]
                if kind == "log":
                    log_batch.append(item[1])
                else:
                    if log_batch:
                        self._log_batch(log_batch)
                        log_batch = []
                    if kind == "tools_done":
                        self._on_tools_done(item[1])
                    elif kind == "artifacts_done":
                        self._on_artifacts_done(item[1])
                    elif kind == "proc_done":
                        _, status, reason, log_path = item
                        self.running = False
                        self.proc    = None
                        self._log(f"\n[{now_stamp()}] {status} — {reason}")
                        self._log(f"Run log: {log_path}")
                        self._set_status_right(f"Last run: {status}")
        except queue.Empty:
            pass
        if log_batch:
            self._log_batch(log_batch)
        self.after(100, self._poll_events)

    def _log(self, text: str):
        if not hasattr(self, "log"):
            return
        self.log.insert("end", str(text) + "\n")
        self.line_count += str(text).count("\n") + 1
        if self.line_count > MAX_LOG_LINES:
            self.log.delete("1.0", "1200.0")
            self.line_count -= 1200
        self.log.see("end")

    def open_tool_output(self):
        p = self._tool_output_dir(self.selected_tool.get())
        try:
            if os.name == "nt":
                os.startfile(str(p))
            else:
                webbrowser.open(p.as_uri())
        except Exception as e:
            messagebox.showerror("Open failed", str(e))


if __name__ == "__main__":
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    app = EZSentinelApp()
    app.mainloop()
