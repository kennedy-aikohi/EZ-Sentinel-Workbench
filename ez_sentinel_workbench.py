#!/usr/bin/env python3
"""
EZ Sentinel Workbench v6.0 - Performance & Hardening Edition
Author: KENNEDY AIKOHI
LinkedIn: https://www.linkedin.com/in/aikohikennedy/

A Windows desktop GUI wrapper for Eric Zimmerman command-line tools.
Design goals: production-friendly UX, no parser mixing, non-blocking UI, exact
argument arrays, bounded logs, and tool-specific validation.
"""
from __future__ import annotations

import os
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
APP_VERSION = "6.0"
AUTHOR = "KENNEDY AIKOHI"
LINKEDIN = "https://www.linkedin.com/in/aikohikennedy/"

DANGEROUS_TOKENS = {"|", "&", "&&", "||", ";", ">", ">>", "<", "`"}
EXE_RE = re.compile(r"(^[A-Za-z]:\\.*\.exe$)|(^.*\.exe$)", re.IGNORECASE)
MAX_LOG_LINES = 6000
SCAN_SKIP_DIRS = {"System Volume Information", "$RECYCLE.BIN"}  # Recycle is found directly first; avoid deep deleted-file crawls.


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def quote_cmd(parts: Iterable[str]) -> str:
    # Windows preview only. Execution always uses an argument list with shell=False.
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
    """Split optional expert arguments and block shell metacharacters/full commands."""
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
            raise ValueError(f"Blocked dangerous shell token in Extra Args: {token}")
        if EXE_RE.match(stripped):
            raise ValueError("Do not paste full commands or .exe paths into Extra Args. Select a profile and enter arguments only.")
        cleaned.append(stripped)
    return cleaned


def classify_result(return_code: Optional[int], stdout_tail: str, stderr_tail: str) -> Tuple[str, str]:
    combined = f"{stdout_tail}\n{stderr_tail}".lower()
    fail_terms = [
        "unrecognized command or argument", "required argument missing", "expects a single argument",
        "not found. exiting", "file not found. exiting", "does not exist", "maps directory", "verify the command line",
        "option '-d' expects", "option '--csv' expects", "no such file", "access denied"
    ]
    warn_terms = ["warning", "unable to delete", "processed 0", "found 0 files", "entries found: 0"]
    if return_code not in (0, None):
        return "FAILED", f"Process returned exit code {return_code}."
    if any(t in combined for t in fail_terms):
        return "FAILED", "Parser reported invalid arguments, missing files, or configuration problems."
    if any(t in combined for t in warn_terms):
        return "SUCCESS WITH WARNING", "Completed, but parser reported warnings, no files, or no records."
    return "SUCCESS", "Completed."


TOOL_ALIASES: Dict[str, List[str]] = {
    "AmcacheParser": ["AmcacheParser.exe"],
    "AppCompatCacheParser": ["AppCompatCacheParser.exe"],
    "bstrings": ["bstrings.exe"],
    "EvtxECmd": ["EvtxECmd.exe", "EvtxeCmd.exe"],
    "iisGeoLocate": ["iisGeoLocate.exe", "iisGeolocate.exe"],
    "JLECmd": ["JLECmd.exe"],
    "LECmd": ["LECmd.exe"],
    "MFTECmd": ["MFTECmd.exe"],
    "PECmd": ["PECmd.exe"],
    "RBCmd": ["RBCmd.exe"],
    "RecentFileCacheParser": ["RecentFileCacheParser.exe"],
    "RECmd": ["RECmd.exe"],
    "rla": ["rla.exe", "RLA.exe"],
    "SBECmd": ["SBECmd.exe"],
    "SQLECmd": ["SQLECmd.exe"],
    "SrumECmd": ["SrumECmd.exe"],
    "SumECmd": ["SumECmd.exe"],
    "VSCMount": ["VSCMount.exe"],
    "WxTCmd": ["WxTCmd.exe"],
}
GUI_VIEWERS = {"EZViewer.exe", "JumpListExplorer.exe", "MFTExplorer.exe", "RegistryExplorer.exe", "SDBExplorer.exe", "ShellBagsExplorer.exe", "TimelineExplorer.exe"}


@dataclass(frozen=True)
class Profile:
    name: str
    tool: str
    target_type: str
    args_template: List[str]
    description: str = ""


PROFILES: List[Profile] = [
    Profile("Amcache.hve to CSV", "AmcacheParser", "amcache", ["-f", "{target}", "--csv", "{out}"], "CSV only for your AmcacheParser build."),
    Profile("Shimcache live SYSTEM hive to CSV", "AppCompatCacheParser", "system_hive_live", ["-f", "{target}", "--csv", "{out}"], "Uses live SYSTEM, avoids RegBack by default."),
    Profile("bstrings IPv4 scan", "bstrings", "evidence_root", ["-d", "{target}", "--ls", "ipv4"], "Captured to text file."),
    Profile("bstrings URL scan", "bstrings", "evidence_root", ["-d", "{target}", "--ls", "url"], "Captured to text file."),
    Profile("bstrings email scan", "bstrings", "evidence_root", ["-d", "{target}", "--ls", "email"], "Captured to text file."),
    Profile("EVTX folder to CSV", "EvtxECmd", "evtx_dir", ["-d", "{target}", "--csv", "{out}"], "Parses Windows event logs."),
    Profile("IIS logs to CSV", "iisGeoLocate", "iis_logs", ["-d", "{target}", "--csv", "{out}"], "Geolocates IIS log IPs."),
    Profile("Jump Lists to CSV", "JLECmd", "recent_dir", ["-d", "{target}", "--csv", "{out}"], "Parses Automatic/Custom Destinations."),
    Profile("LNK files from Users to CSV", "LECmd", "users_dir", ["-d", "{target}", "--csv", "{out}"], "Standard LNK parse."),
    Profile("LNK files from Users to CSV --all", "LECmd", "users_dir", ["-d", "{target}", "--csv", "{out}", "--all"], "Broad mode for non-standard filenames."),
    Profile("LNK high precision timestamps", "LECmd", "users_dir", ["-d", "{target}", "--csv", "{out}", "--mp"], "Uses valid --mp switch."),
    Profile("LNK files to JSON pretty", "LECmd", "users_dir", ["-d", "{target}", "--json", "{out}", "--pretty"], "JSON export."),
    Profile("$MFT to CSV", "MFTECmd", "mft", ["-f", "{target}", "--csv", "{out}"], "Parses $MFT."),
    Profile("$MFT to CSV + resident dump", "MFTECmd", "mft", ["-f", "{target}", "--csv", "{out}", "--dr", "--fl"], "Creates Resident subfolder."),
    Profile("USN Journal $J to CSV", "MFTECmd", "usnjrnl", ["-f", "{target}", "--csv", "{out}"], "Parses USN journal if collected."),
    Profile("$Boot to CSV", "MFTECmd", "boot", ["-f", "{target}", "--csv", "{out}"], "Parses NTFS boot metadata."),
    Profile("$SDS to CSV", "MFTECmd", "sds", ["-f", "{target}", "--csv", "{out}"], "Security descriptor stream."),
    Profile("First discovered $I30 to CSV", "MFTECmd", "i30_any", ["-f", "{target}", "--csv", "{out}"], "Uses first discovered $I30 file."),
    Profile("Prefetch folder to CSV", "PECmd", "prefetch_dir", ["-d", "{target}", "--csv", "{out}"], "Parses .pf files."),
    Profile("Recycle Bin to CSV", "RBCmd", "recycle_bin", ["-d", "{target}", "--csv", "{out}"], "Parses $I/INFO2 metadata."),
    Profile("RecentFileCache.bcf to CSV", "RecentFileCacheParser", "recent_file_cache", ["-f", "{target}", "--csv", "{out}"], "Legacy execution artifact."),
    Profile("RLA replay registry logs", "rla", "config_dir", ["-d", "{target}", "--out", "{out}"], "Replays transaction logs."),
    Profile("ShellBags from Users folder to CSV", "SBECmd", "users_dir", ["-d", "{target}", "--csv", "{out}"], "Parses NTUSER/UsrClass ShellBags."),
    Profile("SQLECmd mapped parse from Users", "SQLECmd", "users_dir", ["-d", "{target}", "--csv", "{out}", "--maps", "{maps_sql}"], "Requires maps directory."),
    Profile("SRUM to CSV with SOFTWARE hive", "SrumECmd", "srum", ["-f", "{target}", "-r", "{software_hive}", "--csv", "{out}"], "Adds SOFTWARE hive for resolution."),
    Profile("SUM databases to CSV", "SumECmd", "sum_dir", ["-d", "{target}", "--csv", "{out}"], "Windows Server SUM."),
    Profile("Windows Timeline ActivitiesCache.db to CSV", "WxTCmd", "activities_db", ["-f", "{target}", "--csv", "{out}"], "WxTCmd accepts -f only in your build."),
]


class ToolScanner:
    def __init__(self, root: Path):
        self.root = root
        self.tools: Dict[str, Path] = {}
        self.all_exes: List[Path] = []
        self.reb_files: List[Path] = []
        self.sql_maps_dir: Optional[Path] = None

    def scan(self) -> "ToolScanner":
        if not self.root.exists():
            return self
        for exe in self.root.rglob("*.exe"):
            self.all_exes.append(exe)
        for tool, names in TOOL_ALIASES.items():
            allowed = {n.lower() for n in names}
            candidates = [p for p in self.all_exes if p.name.lower() in allowed and p.name not in GUI_VIEWERS]
            if not candidates:
                continue
            root_candidates = [p for p in candidates if p.parent.resolve() == self.root.resolve()]
            chosen = sorted(root_candidates or candidates, key=lambda x: (len(str(x)), str(x).lower()))[0]
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
        try:
            for p in self.root.rglob("*"):
                if not p.is_dir():
                    continue
                if p.name.lower() in {"sqlecmd", "maps"}:
                    try:
                        names = {x.suffix.lower() for x in p.rglob("*") if x.is_file()}
                    except OSError:
                        continue
                    if names.intersection({".smap", ".map", ".json", ".xml"}):
                        candidates.append(p)
        except OSError:
            pass
        unique = sorted(set(candidates), key=lambda p: (len(str(p)), str(p).lower()))
        return unique[0] if unique else None


class ArtifactIndex:
    """Caches evidence artifact locations so the GUI never does heavy rglob work in preview paths."""
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
        # Fast deterministic checks first.
        self._set_if_exists("amcache", ["Windows/AppCompat/Programs/Amcache.hve"])
        self._set_if_exists("system_hive_live", ["Windows/System32/config/SYSTEM"])
        self._set_if_exists("software_hive", ["Windows/System32/config/SOFTWARE"])
        self._set_if_exists("config_dir", ["Windows/System32/config"])
        self._set_if_exists("evtx_dir", ["Windows/System32/winevt/Logs", "Windows/System32/Winevt/Logs"])
        self._set_if_exists("iis_logs", ["inetpub/logs/LogFiles"])
        self._set_if_exists("users_dir", ["Users"])
        self._set_if_exists("recent_dir", ["Users"])
        self._set_if_exists("prefetch_dir", ["Windows/Prefetch"])
        self._set_if_exists("recycle_bin", ["$Recycle.Bin", "Recycler"])
        self._set_if_exists("recent_file_cache", ["Windows/AppCompat/Programs/RecentFileCache.bcf"])
        self._set_if_exists("srum", ["Windows/System32/sru/SRUDB.dat"])
        self._set_if_exists("sum_dir", ["Windows/System32/LogFiles/SUM"])
        self._set_if_exists("mft", ["$MFT", "C/$MFT", "C_/$MFT"])
        self._set_if_exists("boot", ["$Boot", "C/$Boot"])
        self._set_if_exists("usnjrnl", ["$Extend/$UsnJrnl_$J", "C/$Extend/$UsnJrnl_$J", "$Extend/$UsnJrnl:$J", "C/$Extend/$UsnJrnl:$J"])
        self._set_if_exists("sds", ["$Secure_$SDS", "C/$Secure_$SDS"])
        needed_recursive = {"activities_db", "i30_any", "mft", "boot", "usnjrnl", "sds"} - set(self.paths)
        if needed_recursive:
            for dirpath, dirnames, filenames in os.walk(self.root):
                self.count_dirs += 1
                dirnames[:] = [d for d in dirnames if d not in SCAN_SKIP_DIRS]
                if progress and self.count_dirs % 250 == 0:
                    progress(f"[SCAN] Evidence index: {self.count_dirs} folders, {self.count_files} files...")
                for fn in filenames:
                    self.count_files += 1
                    full = Path(dirpath) / fn
                    low = fn.lower()
                    if "activities_db" not in self.paths and low == "activitiescache.db":
                        self.paths["activities_db"] = full
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
                            progress("[SCAN] Evidence index hit safety file limit; partial index created.")
                        self.duration = time.time() - start
                        return self
                if needed_recursive.issubset(set(self.paths)):
                    break
        self.duration = time.time() - start
        return self


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
        self.vars = {
            "ez_root": tk.StringVar(value=r"C:\Users\kenne\Desktop\EZ TOOLS\net9"),
            "evidence_root": tk.StringVar(value=r"C:\Users\kenne\Desktop\DC01_Kape\C"),
            "output_root": tk.StringVar(value=r"C:\Users\kenne\Desktop\Results"),
            "theme": tk.StringVar(value="Midnight Blue"),
            "timeout": tk.IntVar(value=1800),
            "dry_run": tk.BooleanVar(value=False),
            "extra_args": tk.StringVar(value=""),
            "recmd_mode": tk.StringVar(value="Search all: --sa"),
            "recmd_keyword": tk.StringVar(value="powershell"),
            "recmd_batch": tk.StringVar(value=""),
            "recmd_regex": tk.BooleanVar(value=False),
            "recmd_recover": tk.BooleanVar(value=False),
            "recmd_nl": tk.BooleanVar(value=False),
            "recmd_details": tk.BooleanVar(value=False),
        }
        self.selected_tool = tk.StringVar(value="RECmd")
        self.selected_profile = tk.StringVar(value="")
        self._build_style()
        self._build_ui()
        self.after(50, self.scan_tools_async)
        self.after(80, self.scan_evidence_async)
        self.after(150, self._poll_events)

    def _build_style(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.apply_theme()

    def apply_theme(self):
        theme = self.vars["theme"].get()
        if theme == "Forensic Light":
            self.bg, self.panel, self.fg, self.accent, self.muted = "#f4f6f8", "#ffffff", "#1f2937", "#2563eb", "#64748b"
        elif theme == "Graphite Pro":
            self.bg, self.panel, self.fg, self.accent, self.muted = "#1f2329", "#2b3038", "#f5f7fa", "#38bdf8", "#a9b3c1"
        else:
            self.bg, self.panel, self.fg, self.accent, self.muted = "#0f172a", "#182235", "#e5e7eb", "#60a5fa", "#94a3b8"
        self.configure(bg=self.bg)
        self.style.configure("TFrame", background=self.bg)
        self.style.configure("Panel.TFrame", background=self.panel)
        self.style.configure("TLabel", background=self.bg, foreground=self.fg)
        self.style.configure("Panel.TLabel", background=self.panel, foreground=self.fg)
        self.style.configure("Muted.TLabel", background=self.panel, foreground=self.muted)
        self.style.configure("Title.TLabel", background=self.bg, foreground=self.fg, font=("Segoe UI", 18, "bold"))
        self.style.configure("TButton", padding=6)
        self.style.configure("Accent.TButton", padding=7, font=("Segoe UI", 10, "bold"))
        self.style.configure("TEntry", padding=4)
        self.style.configure("TCombobox", padding=4)

    def _build_ui(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        header = ttk.Frame(root)
        header.pack(fill="x")
        logo_path = app_dir() / "assets" / "ez_sentinel_logo.png"
        self.logo_img = None
        if logo_path.exists():
            try:
                self.logo_img = tk.PhotoImage(file=str(logo_path))
                ttk.Label(header, image=self.logo_img).pack(side="left", padx=(0, 8))
            except Exception:
                pass
        ttk.Label(header, text=f"{APP_NAME} v{APP_VERSION}", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=f"  |  Author: {AUTHOR}", font=("Segoe UI", 11, "bold")).pack(side="left", padx=10)
        ttk.Button(header, text="LinkedIn", command=lambda: webbrowser.open(LINKEDIN)).pack(side="right")
        ttk.Combobox(header, textvariable=self.vars["theme"], values=["Midnight Blue", "Graphite Pro", "Forensic Light"], width=18, state="readonly").pack(side="right", padx=6)
        ttk.Button(header, text="Apply Theme", command=self.apply_theme).pack(side="right")

        paths = ttk.LabelFrame(root, text="Case Paths & Execution Settings", padding=10)
        paths.pack(fill="x", pady=(10, 8))
        self._path_row(paths, "EZ Tools Root", self.vars["ez_root"], 0, self.scan_tools_async)
        self._path_row(paths, "Evidence Root", self.vars["evidence_root"], 1, self.scan_evidence_async)
        self._path_row(paths, "Output Root", self.vars["output_root"], 2, self.refresh_preview)
        ttk.Label(paths, text="Timeout seconds").grid(row=0, column=3, sticky="w", padx=(14, 4))
        ttk.Entry(paths, textvariable=self.vars["timeout"], width=8).grid(row=0, column=4, sticky="w")
        ttk.Checkbutton(paths, text="Dry run", variable=self.vars["dry_run"], command=self.refresh_preview).grid(row=1, column=3, columnspan=2, sticky="w", padx=(14, 4))
        ttk.Button(paths, text="Scan EZ Tools", command=self.scan_tools_async).grid(row=2, column=3, sticky="ew", padx=(14, 4))
        ttk.Button(paths, text="Index Evidence", command=self.scan_evidence_async).grid(row=2, column=4, sticky="ew", padx=(4, 4))
        paths.columnconfigure(1, weight=1)

        body = ttk.PanedWindow(root, orient="horizontal")
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, padding=8, style="Panel.TFrame")
        body.add(left, weight=1)
        ttk.Label(left, text="Tool Lock", style="Panel.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.tool_list = tk.Listbox(left, height=18, exportselection=False)
        self.tool_list.pack(fill="both", expand=True, pady=6)
        self.tool_list.bind("<<ListboxSelect>>", self._on_tool_select)
        ttk.Button(left, text="Help for Selected Tool", command=self.run_help).pack(fill="x", pady=3)
        ttk.Button(left, text="Open Tool Output Folder", command=self.open_tool_output).pack(fill="x", pady=3)
        self.scan_label = ttk.Label(left, text="Not scanned yet", style="Muted.TLabel", wraplength=300)
        self.scan_label.pack(anchor="w", pady=8)

        middle = ttk.Frame(body, padding=10, style="Panel.TFrame")
        body.add(middle, weight=2)
        ttk.Label(middle, text="Command Builder", style="Panel.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(middle, text="Profiles are locked to a parser. Heavy evidence discovery is cached so the UI stays responsive.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(middle, text="Profile", style="Panel.TLabel").pack(anchor="w")
        self.profile_combo = ttk.Combobox(middle, textvariable=self.selected_profile, state="readonly")
        self.profile_combo.pack(fill="x", pady=(2, 8))
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_builder())
        self.builder_frame = ttk.LabelFrame(middle, text="Argument Builder", padding=10)
        self.builder_frame.pack(fill="x", pady=6)
        self._build_default_builder()
        expert = ttk.LabelFrame(middle, text="Expert Extra Args (optional, arguments only - never paste full command)", padding=8)
        expert.pack(fill="x", pady=6)
        ttk.Entry(expert, textvariable=self.vars["extra_args"]).pack(fill="x")
        ttk.Label(expert, text="Blocked: .exe paths, shell pipes, redirection, &, ;. This prevents command injection and parser mixing.", style="Muted.TLabel").pack(anchor="w")
        actions = ttk.Frame(middle, style="Panel.TFrame")
        actions.pack(fill="x", pady=8)
        ttk.Button(actions, text="Analyze Selected", style="Accent.TButton", command=self.run_selected).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Stop", command=self.stop_process).pack(side="left", padx=6)
        ttk.Button(actions, text="Refresh Preview", command=self.refresh_preview).pack(side="left", padx=6)
        ttk.Label(middle, text="Command Preview", style="Panel.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 2))
        self.preview = tk.Text(middle, height=10, wrap="word", font=("Consolas", 10))
        self.preview.pack(fill="both", expand=False)

        right = ttk.Frame(body, padding=8, style="Panel.TFrame")
        body.add(right, weight=2)
        ttk.Label(right, text="Execution Log", style="Panel.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.log = tk.Text(right, wrap="word", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, pady=6)
        bottom = ttk.Frame(right, style="Panel.TFrame")
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Clear Log", command=lambda: self.log.delete("1.0", "end")).pack(side="right")

    def _path_row(self, parent, label, var, row, callback):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", padx=6, pady=3)
        def browse():
            initial = var.get() if Path(var.get()).exists() else str(Path.home())
            p = filedialog.askdirectory(initialdir=initial)
            if p:
                var.set(p)
                callback()
        ttk.Button(parent, text="Browse", command=browse).grid(row=row, column=2, sticky="ew", pady=3)

    def _clear_builder(self):
        for w in self.builder_frame.winfo_children():
            w.destroy()

    def _build_recmd_builder(self):
        self._clear_builder()
        modes = [
            "Search all: --sa", "Search key names: --sk", "Search value names: --sv", "Search value data: --sd", "Search slack: --ss",
            "Batch file: --bn", "Key details: --kn", "Base64 minimum bytes: --base64", "Minimum value size: --minSize"
        ]
        ttk.Label(self.builder_frame, text="RECmd smart args", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(self.builder_frame, text="Mode").grid(row=1, column=0, sticky="w")
        cb = ttk.Combobox(self.builder_frame, textvariable=self.vars["recmd_mode"], values=modes, state="readonly", width=34)
        cb.grid(row=1, column=1, sticky="ew", padx=6, pady=2)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_preview())
        ttk.Label(self.builder_frame, text="Keyword / key path / size").grid(row=2, column=0, sticky="w")
        ttk.Entry(self.builder_frame, textvariable=self.vars["recmd_keyword"]).grid(row=2, column=1, sticky="ew", padx=6, pady=2)
        ttk.Label(self.builder_frame, text="Batch .reb").grid(row=3, column=0, sticky="w")
        self.reb_combo = ttk.Combobox(self.builder_frame, textvariable=self.vars["recmd_batch"], values=[str(p) for p in self.reb_files], state="readonly")
        self.reb_combo.grid(row=3, column=1, sticky="ew", padx=6, pady=2)
        checks = ttk.Frame(self.builder_frame)
        checks.grid(row=4, column=0, columnspan=2, sticky="w", pady=4)
        for text, var in [("--regex", "recmd_regex"), ("--recover", "recmd_recover"), ("--nl", "recmd_nl"), ("--details", "recmd_details")]:
            ttk.Checkbutton(checks, text=text, variable=self.vars[var], command=self.refresh_preview).pack(side="left", padx=3)
        ttk.Label(self.builder_frame, text="Example: Search all + powershell builds: RECmd -d <config> --csv <out> --sa powershell", style="Muted.TLabel").grid(row=5, column=0, columnspan=2, sticky="w")
        self.builder_frame.columnconfigure(1, weight=1)

    def _build_default_builder(self):
        self._clear_builder()
        ttk.Label(self.builder_frame, text="This profile uses a locked, validated argument template.", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(self.builder_frame, text="Use the tool's -h output before adding Expert Extra Args.", style="Muted.TLabel").pack(anchor="w")

    def scan_tools_async(self):
        if self.scanning_ez:
            return
        self.scanning_ez = True
        root = Path(self.vars["ez_root"].get()).expanduser()
        self._log(f"[INFO] Scanning EZ Tools asynchronously: {root}")
        def worker():
            scanner = ToolScanner(root).scan()
            self.event_q.put(("tools_done", scanner))
        threading.Thread(target=worker, daemon=True).start()

    def scan_evidence_async(self):
        if self.scanning_evidence:
            return
        self.scanning_evidence = True
        root = Path(self.vars["evidence_root"].get()).expanduser()
        self.artifact_root = root
        self._log(f"[INFO] Indexing evidence asynchronously: {root}")
        def progress(msg: str):
            self.event_q.put(("log", msg))
        def worker():
            index = ArtifactIndex(root).build(progress=progress)
            self.event_q.put(("artifacts_done", index))
        threading.Thread(target=worker, daemon=True).start()

    def _on_tools_done(self, scanner: ToolScanner):
        self.scanning_ez = False
        self.tools = scanner.tools
        self.reb_files = scanner.reb_files
        self.sql_maps_dir = scanner.sql_maps_dir
        self.tool_list.delete(0, "end")
        for tool in sorted(TOOL_ALIASES):
            status = "✓" if tool in self.tools else "✗"
            self.tool_list.insert("end", f"{status} {tool}")
        self.scan_label.config(text=f"EZ Tools: {self.vars['ez_root'].get()}\nExecutables found: {len(scanner.all_exes)}\nLocked tools found: {len(self.tools)}\n.reb files: {len(self.reb_files)}\nSQLECmd maps: {self.sql_maps_dir or 'not found'}\nEvidence index: {len(self.artifacts.paths)} artifact types")
        self._log(f"[INFO] EZ tools scan complete. Executables: {len(scanner.all_exes)}, locked parsers: {len(self.tools)}")
        if self.selected_tool.get() == "RECmd":
            self._build_recmd_builder()
        self._refresh_profiles()
        self.refresh_preview()

    def _on_artifacts_done(self, index: ArtifactIndex):
        self.scanning_evidence = False
        self.artifacts = index
        self._log(f"[INFO] Evidence index complete in {index.duration:.2f}s. Folders: {index.count_dirs}, files: {index.count_files}, artifact types: {len(index.paths)}")
        self.scan_label.config(text=f"EZ Tools locked: {len(self.tools)}\n.reb files: {len(self.reb_files)}\nSQLECmd maps: {self.sql_maps_dir or 'not found'}\nEvidence root: {index.root}\nArtifact types indexed: {len(index.paths)}")
        self.refresh_preview()

    def _on_tool_select(self, event=None):
        sel = self.tool_list.curselection()
        if not sel:
            return
        text = self.tool_list.get(sel[0])
        self.selected_tool.set(text[2:].strip())
        self._refresh_profiles()

    def _refresh_profiles(self):
        tool = self.selected_tool.get()
        values = [p.name for p in PROFILES if p.tool == tool]
        if tool == "RECmd":
            values = ["RECmd Argument Builder"]
        self.profile_combo["values"] = values
        if values and self.selected_profile.get() not in values:
            self.selected_profile.set(values[0])
        if tool == "RECmd":
            self._build_recmd_builder()
        else:
            self._build_default_builder()
        self.refresh_preview()

    def refresh_builder(self):
        self.refresh_preview()

    def _selected_profile_obj(self) -> Optional[Profile]:
        selected = self.selected_profile.get()
        for p in PROFILES:
            if p.name == selected:
                return p
        return None

    def _tool_output_dir(self, tool: str) -> Path:
        return ensure_dir(Path(self.vars["output_root"].get()).expanduser() / tool)

    def _context(self, profile: Profile) -> Dict[str, str]:
        return {
            "target": str(self.artifacts.get(profile.target_type) or ""),
            "out": str(self._tool_output_dir(profile.tool)),
            "maps_sql": str(self.sql_maps_dir or ""),
            "software_hive": str(self.artifacts.get("software_hive") or ""),
        }

    def build_recmd_command(self) -> Tuple[List[str], List[str], Optional[Path]]:
        errors: List[str] = []
        exe = self.tools.get("RECmd")
        if not exe:
            return [], ["RECmd.exe not found. Scan EZ Tools Root."], None
        config_dir = self.artifacts.get("config_dir")
        if not config_dir:
            errors.append("Registry config folder not indexed. Expected: EvidenceRoot\\Windows\\System32\\config. Click Index Evidence.")
        out = str(self._tool_output_dir("RECmd"))
        args = [str(exe), "-d", str(config_dir or ""), "--csv", out]
        mode = self.vars["recmd_mode"].get()
        keyword = self.vars["recmd_keyword"].get().strip()
        if mode.startswith("Batch"):
            reb = self.vars["recmd_batch"].get().strip()
            if not reb:
                errors.append("Select a .reb batch file for RECmd --bn mode.")
            args += ["--bn", reb]
        elif mode.startswith("Search all"):
            if not keyword: errors.append("Enter a search keyword for --sa.")
            args += ["--sa", keyword]
        elif mode.startswith("Search key"):
            if not keyword: errors.append("Enter a search keyword for --sk.")
            args += ["--sk", keyword]
        elif mode.startswith("Search value names"):
            if not keyword: errors.append("Enter a search keyword for --sv.")
            args += ["--sv", keyword]
        elif mode.startswith("Search value data"):
            if not keyword: errors.append("Enter a search keyword for --sd.")
            args += ["--sd", keyword]
        elif mode.startswith("Search slack"):
            if not keyword: errors.append("Enter a search keyword for --ss.")
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
        if self.vars["recmd_regex"].get() and any(x in args for x in ["--sk", "--sv", "--sd", "--ss"]):
            args.append("--regex")
        if self.vars["recmd_recover"].get(): args.append("--recover")
        if self.vars["recmd_nl"].get(): args.append("--nl")
        if self.vars["recmd_details"].get(): args.append("--details")
        try:
            args.extend(safe_split_extra(self.vars["extra_args"].get()))
        except ValueError as e:
            errors.append(str(e))
        return args, errors, None

    def build_command(self) -> Tuple[List[str], List[str], Optional[Path]]:
        if self.selected_tool.get() == "RECmd":
            return self.build_recmd_command()
        profile = self._selected_profile_obj()
        if not profile:
            return [], ["No profile selected."], None
        exe = self.tools.get(profile.tool)
        if not exe:
            return [], [f"{profile.tool}.exe not found. Scan EZ Tools Root."], None
        ctx = self._context(profile)
        errors: List[str] = []
        if not ctx["target"]:
            errors.append(f"Artifact not indexed for {profile.target_type}. Click Index Evidence, verify Evidence Root, or artifact was not collected.")
        if "{maps_sql}" in profile.args_template and not ctx["maps_sql"]:
            errors.append("SQLECmd maps directory not found. Place maps under SQLECmd or Maps\\SQLECmd.")
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
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile.name.lower()).strip("_")
            capture = self._tool_output_dir("bstrings") / f"{safe_name}_{now_stamp()}.txt"
        return args, errors, capture

    def refresh_preview(self):
        cmd, errors, capture = self.build_command()
        self.preview.delete("1.0", "end")
        tool = self.selected_tool.get()
        exe = self.tools.get(tool)
        self.preview.insert("end", f"Software: {APP_NAME} v{APP_VERSION}\nAuthor: {AUTHOR}\n")
        self.preview.insert("end", f"Tool locked to: {exe or 'NOT FOUND'}\n")
        self.preview.insert("end", f"Evidence indexed: {len(self.artifacts.paths)} artifact types from {self.artifacts.root}\n\n")
        if cmd:
            self.preview.insert("end", quote_cmd(cmd) + "\n")
        if capture:
            self.preview.insert("end", f"\nCaptured stdout -> {capture}\n")
        if errors:
            self.preview.insert("end", "\nVALIDATION ERRORS:\n")
            for e in errors:
                self.preview.insert("end", f" - {e}\n")

    def run_help(self):
        tool = self.selected_tool.get()
        exe = self.tools.get(tool)
        if not exe:
            messagebox.showerror("Tool not found", f"{tool}.exe not found.")
            return
        self._run_command([str(exe), "-h"], None, f"Help for {exe.name}")

    def run_selected(self):
        cmd, errors, capture = self.build_command()
        self.refresh_preview()
        if errors:
            messagebox.showerror("Validation blocked execution", "\n".join(errors))
            return
        if not cmd:
            messagebox.showerror("No command", "No command built.")
            return
        if self.vars["dry_run"].get():
            self._log("[DRY RUN] " + quote_cmd(cmd))
            return
        self._run_command(cmd, capture, self.selected_profile.get() or self.selected_tool.get())

    def _run_command(self, cmd: List[str], stdout_capture: Optional[Path], title: str):
        if self.running:
            messagebox.showwarning("Busy", "A command is already running. Use Stop first or wait for completion.")
            return
        exe = Path(cmd[0])
        if not exe.exists():
            messagebox.showerror("Executable missing", str(exe))
            return
        log_dir = ensure_dir(Path(self.vars["output_root"].get()).expanduser() / "_EZSentinelLogs")
        case_log = log_dir / f"run_{now_stamp()}.log"
        try:
            timeout = int(self.vars["timeout"].get() or 1800)
        except Exception:
            timeout = 1800
        self.running = True
        self._log("\n" + "=" * 92)
        self._log(f"[{now_stamp()}] Running: {title}")
        self._log(quote_cmd(cmd))
        if stdout_capture:
            ensure_dir(stdout_capture.parent)
            self._log(f"Captured stdout: {stdout_capture}")

        def worker():
            out_tail: List[str] = []
            err_tail: List[str] = []
            start = time.time()
            return_code: Optional[int] = None
            try:
                stdout_target = open(stdout_capture, "w", encoding="utf-8", errors="replace") if stdout_capture else subprocess.PIPE
                self.proc = subprocess.Popen(
                    cmd,
                    shell=False,
                    stdout=stdout_target,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    cwd=str(exe.parent),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
                )
                if stdout_capture:
                    # stdout goes directly to file; only stderr is streamed.
                    assert self.proc.stderr is not None
                    while True:
                        if time.time() - start > timeout:
                            self.proc.kill(); err_tail.append(f"[TIMEOUT] Killed after {timeout}s"); break
                        line = self.proc.stderr.readline()
                        if line:
                            err_tail.append(line[-500:])
                            self.event_q.put(("log", "[STDERR] " + line.rstrip()))
                        elif self.proc.poll() is not None:
                            break
                        else:
                            time.sleep(0.05)
                    return_code = self.proc.wait(timeout=5)
                    stdout_target.close()  # type: ignore[union-attr]
                else:
                    assert self.proc.stdout is not None and self.proc.stderr is not None
                    def reader(stream, label, tail):
                        for line in iter(stream.readline, ''):
                            tail.append(line[-500:])
                            if len(tail) > 300:
                                del tail[:100]
                            self.event_q.put(("log", (label + line.rstrip()) if label else line.rstrip()))
                    t1 = threading.Thread(target=reader, args=(self.proc.stdout, "", out_tail), daemon=True)
                    t2 = threading.Thread(target=reader, args=(self.proc.stderr, "[STDERR] ", err_tail), daemon=True)
                    t1.start(); t2.start()
                    while self.proc.poll() is None:
                        if time.time() - start > timeout:
                            self.proc.kill(); err_tail.append(f"[TIMEOUT] Killed after {timeout}s"); break
                        time.sleep(0.1)
                    return_code = self.proc.wait()
                    t1.join(timeout=1); t2.join(timeout=1)
                status, reason = classify_result(return_code, "".join(out_tail[-300:]), "".join(err_tail[-300:]))
                case_log.write_text(
                    f"Title: {title}\nCommand: {quote_cmd(cmd)}\nReturnCode: {return_code}\nStatus: {status}\nReason: {reason}\nOutputCapture: {stdout_capture or ''}\n\nSTDOUT_TAIL:\n{''.join(out_tail[-300:])}\n\nSTDERR_TAIL:\n{''.join(err_tail[-300:])}\n",
                    encoding="utf-8", errors="replace"
                )
                self.event_q.put(("proc_done", status, reason, str(case_log)))
            except Exception as e:
                self.event_q.put(("proc_done", "FAILED", str(e), str(case_log)))
        threading.Thread(target=worker, daemon=True).start()

    def stop_process(self):
        if self.proc and self.running:
            try:
                self.proc.terminate()
                self._log("[STOP] Termination requested.")
            except Exception as e:
                self._log(f"[STOP ERROR] {e}")

    def _poll_events(self):
        try:
            while True:
                item = self.event_q.get_nowait()
                kind = item[0]
                if kind == "log":
                    self._log(item[1])
                elif kind == "tools_done":
                    self._on_tools_done(item[1])
                elif kind == "artifacts_done":
                    self._on_artifacts_done(item[1])
                elif kind == "proc_done":
                    _, status, reason, log_path = item
                    self.running = False
                    self.proc = None
                    self._log(f"\n[{now_stamp()}] Finished: {status} - {reason}")
                    self._log(f"Run log: {log_path}")
        except queue.Empty:
            pass
        self.after(150, self._poll_events)

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
            os.startfile(str(p)) if os.name == "nt" else webbrowser.open(p.as_uri())
        except Exception as e:
            messagebox.showerror("Open failed", str(e))


if __name__ == "__main__":
    app = EZSentinelApp()
    app.mainloop()
