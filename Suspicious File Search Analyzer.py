"""Suspicious File Search Analyzer - Digital Forensics micro-project.

Read-only metadata/content screening. Files are never executed or modified.
Optional PDF dependencies: pip install reportlab matplotlib
"""
import os
import csv
import time
import math
import hashlib
import statistics
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

APP_TITLE = "Suspicious File Search Analyzer"
DEFAULT_KEYWORDS = "malware, payload, keylogger, trojan, exploit"
DEFAULT_EXTENSIONS = ".exe, .bat, .vbs, .ps1, .dll, .scr"
DEFAULT_SIZE_KB = 500
CHUNK_SIZE = 1024 * 1024

SAMPLE_FILES = [
    ("report.pdf", ".pdf", 45000), ("photo.jpg", ".jpg", 120000),
    ("malware_sample.exe", ".exe", 850000), ("notes.txt", ".txt", 2000),
    ("payload_test.bat", ".bat", 3000), ("project.docx", ".docx", 56000),
    ("keylogger_demo.vbs", ".vbs", 5000), ("holiday.png", ".png", 95000),
    ("system.dll", ".dll", 625000), ("setup.exe", ".exe", 737500),
    ("data.vbs", ".vbs", 12750), ("image.jpg", ".jpg", 88600),
]

# File signatures (magic bytes) for common formats. This is a screening heuristic,
# not a complete file-format validator.
MAGIC = {
    ".exe": [(b"MZ", "Windows executable")], ".dll": [(b"MZ", "Windows executable/DLL")],
    ".scr": [(b"MZ", "Windows executable")], ".jpg": [(b"\xff\xd8\xff", "JPEG image")],
    ".jpeg": [(b"\xff\xd8\xff", "JPEG image")], ".png": [(b"\x89PNG\r\n\x1a\n", "PNG image")],
    ".gif": [(b"GIF87a", "GIF image"), (b"GIF89a", "GIF image")],
    ".pdf": [(b"%PDF-", "PDF document")], ".zip": [(b"PK\x03\x04", "ZIP archive")],
    ".docx": [(b"PK\x03\x04", "ZIP-based Office document")],
    ".xlsx": [(b"PK\x03\x04", "ZIP-based Office document")],
    ".pptx": [(b"PK\x03\x04", "ZIP-based Office document")],
}

class SuspiciousFileAnalyzer:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("1440x900")
        root.minsize(1100, 720)
        root.configure(bg="#071426")
        self.files = []
        self.current_page = "Dashboard"
        self.scan_folder = tk.StringVar(value="No folder selected")
        self.search_text = tk.StringVar()
        self.search_field = tk.StringVar(value="Filename")
        self.search_algorithm = tk.StringVar(value="Linear Search")
        self.keyword_text = tk.StringVar(value=DEFAULT_KEYWORDS)
        self.extension_text = tk.StringVar(value=DEFAULT_EXTENSIONS)
        self.size_threshold = tk.StringVar(value=str(DEFAULT_SIZE_KB))
        self.hash_list_text = tk.StringVar(value="")
        self.status_text = tk.StringVar(value="Ready — scan a folder or load demonstration data.")
        self.total_text = tk.StringVar(value="0")
        self.flagged_text = tk.StringVar(value="0")
        self.normal_text = tk.StringVar(value="0")
        self.min_score = tk.StringVar(value="4")
        self.benchmark_sizes = [1000, 10000, 50000, 100000]
        self.benchmark_results = []
        self._setup_style()
        self._build_shell()
        self.load_sample_data()
        self.show_page("Dashboard")

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#0b1f37", foreground="#e5efff",
                        fieldbackground="#0b1f37", rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background="#12345a", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", "#1459a8")], foreground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground="#0b1f37", background="#12345a",
                        foreground="#ffffff", arrowcolor="#ffffff", padding=5)
        style.map("TCombobox",
                  fieldbackground=[("readonly", "#0b1f37"), ("focus", "#12345a")],
                  foreground=[("readonly", "#ffffff"), ("focus", "#ffffff")],
                  selectbackground=[("readonly", "#12345a")],
                  selectforeground=[("readonly", "#ffffff")],
                  background=[("readonly", "#12345a"), ("active", "#1459a8")])
        # The expanded ttk combobox list uses a Tk listbox on Windows.
        self.root.option_add("*TCombobox*Listbox.background", "#0b1f37")
        self.root.option_add("*TCombobox*Listbox.foreground", "#ffffff")
        self.root.option_add("*TCombobox*Listbox.selectBackground", "#1459a8")
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        style.configure("TScrollbar", background="#12345a", troughcolor="#071426")

    def _button(self, parent, text, command, color="#1266d6"):
        return tk.Button(parent, text=text, command=command, bg=color, fg="white",
                         activebackground="#2185ff", activeforeground="white", relief="flat",
                         bd=0, cursor="hand2", font=("Segoe UI", 10, "bold"), padx=12, pady=8)

    def _label(self, parent, text, size=10, color="#dceaff", bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", "#0b1f37"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kwargs)

    def _panel(self, parent, title):
        frame = tk.Frame(parent, bg="#0b1f37", highlightbackground="#1d4b7a", highlightthickness=1)
        self._label(frame, title, 11, "#55d7ff", True).pack(anchor="w", padx=13, pady=(10, 8))
        return frame

    def _build_shell(self):
        header = tk.Frame(self.root, bg="#081b32", height=78)
        header.pack(fill="x")
        header.pack_propagate(False)
        self._label(header, "◈", 30, "#21b8ff", True, bg="#081b32").pack(side="left", padx=(18, 12))
        title_area = tk.Frame(header, bg="#081b32")
        title_area.pack(side="left", pady=10)
        self._label(title_area, APP_TITLE, 20, "#f0f6ff", True, bg="#081b32").pack(anchor="w")
        self._label(title_area, "DIGITAL FORENSICS  |  METADATA  |  SEARCH ALGORITHMS", 9, "#38cfff", True, bg="#081b32").pack(anchor="w")
        self._label(header, "READ-ONLY SCREENING • NEVER EXECUTES FILES", 9, "#a9c1de", False, bg="#081b32").pack(side="right", padx=18)
        body = tk.Frame(self.root, bg="#071426")
        body.pack(fill="both", expand=True, padx=12, pady=10)
        self.sidebar = tk.Frame(body, bg="#091a2e", width=190)
        self.sidebar.pack(side="left", fill="y", padx=(0, 12))
        self.sidebar.pack_propagate(False)
        self._label(self.sidebar, "NAVIGATION", 9, "#91a9c8", True, bg="#091a2e").pack(anchor="w", padx=14, pady=(15, 10))
        for label, page in [("Dashboard", "Dashboard"), ("Scan & Analyze", "Scan & Analyze"),
                            ("File Search", "File Search"), ("Search Efficiency", "Search Efficiency"),
                            ("Detection Rules", "Detection Rules")]:
            self._button(self.sidebar, label, lambda p=page: self.show_page(p), "#0d2948").pack(fill="x", padx=8, pady=4)
        self._label(self.sidebar, "LOCAL FILES ONLY\nContent is read-only; files are never run.", 9, "#9ab2cf", False,
                    justify="left", bg="#091a2e").pack(side="bottom", anchor="w", padx=13, pady=16)
        self.content = tk.Frame(body, bg="#071426")
        self.content.pack(side="left", fill="both", expand=True)
        footer = tk.Frame(self.root, bg="#06101e", height=30)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        self._label(footer, "", 9, "#a9c1de", bg="#06101e").pack(side="left", padx=13)
        tk.Label(footer, textvariable=self.status_text, bg="#06101e", fg="#a9c1de", font=("Segoe UI", 9)).pack(side="left", padx=8)
        self._label(footer, "Heuristic indicators are not proof of malware", 9, "#9ab2cf", bg="#06101e").pack(side="right", padx=13)
        self.pages = {}
        for name in ("Dashboard", "Scan & Analyze", "File Search", "Search Efficiency", "Detection Rules"):
            frame = tk.Frame(self.content, bg="#071426")
            self.pages[name] = frame
        self._build_dashboard()
        self._build_scan_page()
        self._build_search_page()
        self._build_efficiency_page()
        self._build_rules_page()

    def show_page(self, name):
        for frame in self.pages.values():
            frame.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self.current_page = name
        if name == "Dashboard":
            self.refresh_dashboard_table()
        elif name == "Search Efficiency":
            self._draw_benchmark_graph()

    def _build_dashboard(self):
        page = self.pages["Dashboard"]
        self._label(page, "Dashboard", 18, "#f0f6ff", True, bg="#071426").pack(anchor="w", pady=(3, 10))
        cards = tk.Frame(page, bg="#071426")
        cards.pack(fill="x", pady=(0, 10))
        for label, var, color in [("Files indexed", self.total_text, "#49d5ff"),
                                  ("Flagged for review", self.flagged_text, "#ff7e8a"),
                                  ("Not flagged", self.normal_text, "#28d9b0")]:
            card = self._panel(cards, label)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            self._label(card, "0", 22, color, True).pack(anchor="w", padx=14, pady=(0, 12))
            # Bind the value via a label below; this keeps the summary live.
            for child in card.winfo_children():
                if isinstance(child, tk.Label) and child.cget("text") == "0":
                    child.configure(textvariable=var)
        actions = self._panel(page, "QUICK ACTIONS")
        actions.pack(fill="x", pady=(0, 10))
        row = tk.Frame(actions, bg="#0b1f37")
        row.pack(fill="x", padx=12, pady=(0, 12))
        self._button(row, "Export PDF Report", self.export_pdf, "#087e76").pack(side="left", padx=(0, 8))
        self._button(row, "Export CSV", self.export_csv, "#174a80").pack(side="left")
        panel = self._panel(page, "FILE METADATA & RISK REVIEW")
        panel.pack(fill="both", expand=True)
        self.dashboard_tree = self._make_tree(panel, ("filename", "extension", "size", "modified", "risk", "score", "reasons"),
            {"filename": 190, "extension": 75, "size": 85, "modified": 150, "risk": 90, "score": 65, "reasons": 350})
        self.dashboard_tree._wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _make_tree(self, parent, columns, widths):
        wrap = tk.Frame(parent, bg="#0b1f37")
        tree = ttk.Treeview(wrap, columns=columns, show="headings", selectmode="browse")
        titles = {"filename":"Filename", "extension":"Extension", "size":"Size (KB)", "modified":"Modified",
                  "risk":"Risk", "score":"Score", "reasons":"Reasons", "path":"Path", "hash":"SHA-256"}
        for col in columns:
            tree.heading(col, text=titles.get(col, col.title()))
            tree.column(col, width=widths.get(col, 120), minwidth=60, anchor="w")
        scroll_y = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        scroll_x = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1); wrap.columnconfigure(0, weight=1)
        tree.tag_configure("high", foreground="#ff8b91")
        tree.tag_configure("medium", foreground="#ffd166")
        tree.tag_configure("low", foreground="#4ee0ba")
        tree._wrap = wrap
        return tree

    def _build_scan_page(self):
        page = self.pages["Scan & Analyze"]
        self._label(page, "Scan & Analyze", 18, "#f0f6ff", True, bg="#071426").pack(anchor="w", pady=(3, 10))
        panel = self._panel(page, "SELECT A FOLDER TO INDEX")
        panel.pack(fill="x", pady=(0, 10))
        row = tk.Frame(panel, bg="#0b1f37"); row.pack(fill="x", padx=12, pady=(0, 10))
        self.scan_entry = tk.Entry(row, textvariable=self.scan_folder, bg="#06162a", fg="#e5efff", insertbackground="white", relief="flat", font=("Segoe UI", 10))
        self.scan_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self._button(row, "Browse", self.choose_folder, "#174a80").pack(side="left", padx=(0, 8))
        self._button(row, "Scan & Analyze", self.scan_selected_folder).pack(side="left", padx=(0, 8))
        note = self._label(panel, "The scanner reads metadata and selected file bytes for SHA-256, signature and entropy checks. It never executes or changes files.", 10, "#b8cbe5", bg="#0b1f37", wraplength=1000, justify="left")
        note.pack(anchor="w", padx=13, pady=(0, 12))
        summary = self._panel(page, "SCAN RESULTS")
        summary.pack(fill="both", expand=True)
        self.scan_tree = self._make_tree(summary, ("filename", "extension", "size", "modified", "risk", "score", "reasons"),
            {"filename":190,"extension":75,"size":85,"modified":150,"risk":90,"score":65,"reasons":350})
        self.scan_tree._wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_search_page(self):
        page = self.pages["File Search"]
        self._label(page, "File Search", 18, "#f0f6ff", True, bg="#071426").pack(anchor="w", pady=(3, 10))
        panel = self._panel(page, "SEARCH INDEXED FILES")
        panel.pack(fill="x", pady=(0, 10))
        row = tk.Frame(panel, bg="#0b1f37"); row.pack(fill="x", padx=12, pady=(0, 8))
        self.search_entry = tk.Entry(row, textvariable=self.search_text, bg="#06162a", fg="#e5efff", insertbackground="white", relief="flat", font=("Segoe UI", 10))
        self.search_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self.search_entry.bind("<Return>", lambda _e: self.search_files())
        self.search_field_box = ttk.Combobox(row, textvariable=self.search_field, state="readonly", values=("Filename", "Extension", "SHA-256"), width=12)
        self.search_field_box.pack(side="left", padx=(0, 8), ipady=4)
        self.search_algo_box = ttk.Combobox(row, textvariable=self.search_algorithm, state="readonly", values=("Linear Search", "Binary Search", "Hash Lookup"), width=15)
        self.search_algo_box.pack(side="left", padx=(0, 8), ipady=4)
        self._button(row, "Search", self.search_files).pack(side="left")
        self.search_output = tk.Text(panel, height=5, wrap="word", bg="#06162a", fg="#dceaff", insertbackground="white", relief="flat", font=("Consolas", 10), padx=9, pady=8)
        self.search_output.pack(fill="x", padx=12, pady=(0, 12))
        self.search_output.insert("1.0", "Search by filename, extension or a full SHA-256 hash. Binary Search is exact-match only.")
        self.search_output.configure(state="disabled")
        result_panel = self._panel(page, "MATCHING FILES")
        result_panel.pack(fill="both", expand=True)
        self.search_tree = self._make_tree(result_panel, ("filename", "extension", "size", "modified", "risk", "score", "reasons"),
            {"filename":190,"extension":75,"size":85,"modified":150,"risk":90,"score":65,"reasons":350})
        self.search_tree._wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_efficiency_page(self):
        page = self.pages["Search Efficiency"]
        self._label(page, "Search Efficiency Benchmark", 18, "#f0f6ff", True, bg="#071426").pack(anchor="w", pady=(3, 10))
        info = self._panel(page, "BENCHMARK SETUP")
        info.pack(fill="x", pady=(0, 10))
        row = tk.Frame(info, bg="#0b1f37"); row.pack(fill="x", padx=12, pady=(0, 12))
        self._label(row, "Synthetic dataset sizes: 1k, 10k, 50k and 100k records. Measures average lookup time, comparisons and sorting time.", 10, "#c6d7ed", bg="#0b1f37", wraplength=950, justify="left").pack(side="left", fill="x", expand=True)
        self._button(row, "Run Benchmark", self.run_benchmark, "#6044c8").pack(side="right", padx=(10, 0))
        result = self._panel(page, "RESULTS")
        result.pack(fill="both", expand=True)
        self.bench_tree = self._make_tree(result, ("n", "linear_ms", "linear_cmp", "sort_ms", "binary_ms", "binary_cmp", "hash_ms"),
            {"n":110,"linear_ms":140,"linear_cmp":130,"sort_ms":130,"binary_ms":140,"binary_cmp":130,"hash_ms":130})
        self.bench_tree._wrap.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.graph_holder = tk.Frame(result, bg="#0b1f37", height=230)
        self.graph_holder.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_rules_page(self):
        page = self.pages["Detection Rules"]
        self._label(page, "Detection Rules", 18, "#f0f6ff", True, bg="#071426").pack(anchor="w", pady=(3, 10))
        panel = self._panel(page, "EDIT SCREENING RULES")
        panel.pack(fill="x", pady=(0, 10))
        self._rule_entry(panel, "Filename keywords (comma-separated)", self.keyword_text)
        self._rule_entry(panel, "Extensions requiring review (comma-separated)", self.extension_text)
        self._rule_entry(panel, "Large-file threshold (KB; 0 disables size rule)", self.size_threshold)
        self._rule_entry(panel, "High-risk threshold score (default 4)", self.min_score)
        self._rule_entry(panel, "Known-bad SHA-256 hashes (comma-separated; optional)", self.hash_list_text)
        row = tk.Frame(panel, bg="#0b1f37"); row.pack(fill="x", padx=12, pady=(8, 12))
        self._button(row, "Apply Rules & Re-analyze", self.apply_rules).pack(side="left", padx=(0, 8))
        self._button(row, "Reset Defaults", self.reset_rules, "#174a80").pack(side="left")
        explain = self._panel(page, "RISK SCORING GUIDE")
        explain.pack(fill="both", expand=True)
        text = ("Keyword in filename: +2\nExtension requires review: +1\nLarge file: +1\nDouble extension: +4\nExtension/signature mismatch: +5\nKnown-bad SHA-256 match: +10\nSuspicious location (Temp/AppData/Downloads/Recycle Bin): +2\nHidden file: +1\nHigh entropy: +2\nTimestamp anomaly: +2\nZero-byte file: +1\nVery long or unusual Unicode filename: +2\n\nRisk labels: Low = 0–1; Medium = 2–3; High = 4+. These are educational heuristics, not a malware verdict. Adjust the high-risk threshold above.")
        self.rules_help = tk.Text(explain, height=13, wrap="word", bg="#06162a", fg="#dceaff", relief="flat", font=("Segoe UI", 10), padx=12, pady=10)
        self.rules_help.pack(fill="both", expand=True, padx=12, pady=(0, 12)); self.rules_help.insert("1.0", text); self.rules_help.configure(state="disabled")

    def _rule_entry(self, parent, label, variable):
        self._label(parent, label, 10, "#c6d7ed").pack(anchor="w", padx=13, pady=(3, 2))
        tk.Entry(parent, textvariable=variable, bg="#06162a", fg="#e5efff", insertbackground="white", relief="flat", font=("Segoe UI", 10)).pack(fill="x", padx=12, pady=(0, 6), ipady=6)

    def load_sample_data(self):
        # Synthetic demonstration records have no real file bytes, so hashes/signatures are unavailable.
        self.files = []
        for i, (name, ext, size) in enumerate(SAMPLE_FILES):
            self.files.append({"filename": name, "path": f"SampleFiles/{name}", "extension": ext,
                "size_bytes": size, "modified": f"2026-10-20 {10+i:02d}:00:00", "created": "Unknown",
                "sha256": "", "hidden": name.startswith("."), "entropy": None, "magic": "Unavailable (demo)",
                "is_demo": True, "timestamp_anomaly": False})
        self.scan_folder.set("Built-in demonstration dataset")
        self.refresh_all_tables(); self.update_summary()
        self.status_text.set("Demo dataset loaded. Scan a real folder to calculate hashes and inspect signatures.")

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Select a folder to analyze")
        if folder:
            self.scan_folder.set(folder)
            self.status_text.set("Folder selected. Click Scan & Analyze.")

    def scan_selected_folder(self):
        folder = self.scan_folder.get()
        if not folder or folder in ("No folder selected", "Built-in demonstration dataset") or not os.path.isdir(folder):
            folder = filedialog.askdirectory(title="Choose a folder to scan")
            if not folder: return
            self.scan_folder.set(folder)
        found = []
        self.status_text.set("Scanning metadata and reading file bytes for hashes/signatures…")
        self.root.update_idletasks()
        try:
            for current, dirs, filenames in os.walk(folder, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current, d))]
                for filename in filenames:
                    path = os.path.join(current, filename)
                    try:
                        if os.path.islink(path) or not os.path.isfile(path): continue
                        st = os.stat(path, follow_symlinks=False)
                        ext = os.path.splitext(filename)[1].lower() or "(none)"
                        record = {"filename": filename, "path": path, "extension": ext, "size_bytes": st.st_size,
                                  "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                  "created": datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                                  "sha256": "", "hidden": filename.startswith("."), "entropy": None,
                                  "magic": "Unknown", "is_demo": False, "timestamp_anomaly": False}
                        try:
                            record["timestamp_anomaly"] = st.st_mtime > time.time() + 86400 or st.st_mtime < st.st_ctime - 86400
                        except Exception: pass
                        self._inspect_content(record)
                        found.append(record)
                    except (OSError, PermissionError):
                        continue
        except Exception as exc:
            messagebox.showerror("Scan error", f"Could not scan this folder:\n{exc}")
            self.status_text.set("Scan failed."); return
        self.files = found
        self.refresh_all_tables(); self.update_summary()
        self.status_text.set(f"Scan complete — {len(found)} file(s) indexed. Files were read-only and never executed.")
        if not found: messagebox.showinfo("Scan complete", "No accessible files were found in this folder.")

    def _inspect_content(self, record):
        path = record["path"]
        digest = hashlib.sha256()
        first = b""
        counts = [0] * 256
        total = 0
        try:
            with open(path, "rb") as f:
                first = f.read(16)
                digest.update(first)
                total += len(first)
                for b in first: counts[b] += 1
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    digest.update(chunk); total += len(chunk)
                    for b in chunk: counts[b] += 1
            record["sha256"] = digest.hexdigest()
            if total:
                entropy = -sum((c/total) * math.log2(c/total) for c in counts if c)
                record["entropy"] = entropy
            else: record["entropy"] = 0.0
            ext = record["extension"]
            if ext in MAGIC:
                signatures = MAGIC[ext]
                record["magic"] = next((label for sig, label in signatures if first.startswith(sig)), "Signature mismatch")
            else:
                record["magic"] = "Not checked for this type"
            # Windows hidden/system attributes, where available.
            attrs = getattr(os.stat(path, follow_symlinks=False), "st_file_attributes", 0)
            record["hidden"] = record["hidden"] or bool(attrs & getattr(__import__('stat'), "FILE_ATTRIBUTE_HIDDEN", 2))
        except (OSError, PermissionError):
            record["sha256"] = "Unreadable"; record["magic"] = "Unreadable"; record["entropy"] = None

    def get_rules(self):
        keywords = [x.strip().lower() for x in self.keyword_text.get().split(",") if x.strip()]
        extensions = [x.strip().lower() for x in self.extension_text.get().split(",") if x.strip()]
        extensions = [x if x.startswith(".") else "." + x for x in extensions]
        try:
            threshold = float(self.size_threshold.get().strip())
            score_threshold = int(self.min_score.get().strip())
            if threshold < 0 or score_threshold < 1: raise ValueError
        except ValueError:
            raise ValueError("Size threshold must be non-negative and high-risk threshold must be an integer of at least 1.")
        hashes = {x.strip().lower() for x in self.hash_list_text.get().split(",") if x.strip()}
        for h in hashes:
            if len(h) != 64 or any(ch not in "0123456789abcdef" for ch in h):
                raise ValueError("Each known-bad SHA-256 hash must contain exactly 64 hexadecimal characters.")
        return keywords, extensions, threshold, score_threshold, hashes

    def analyze(self, record):
        try: keywords, extensions, threshold, high_threshold, hashes = self.get_rules()
        except ValueError: return {"score": 0, "risk": "Invalid rules", "reasons": ["Invalid detection rules"]}
        reasons, score = [], 0
        name = record["filename"].lower(); ext = record["extension"].lower(); path = record["path"].lower()
        def add(reason, points):
            nonlocal score
            reasons.append(reason); score += points
        if any(word in name for word in keywords): add("Keyword in filename (+2)", 2)
        if ext in extensions: add("Extension requires review (+1)", 1)
        if threshold > 0 and record["size_bytes"] / 1024 >= threshold: add("Large file (+1)", 1)
        parts = name.split(".")
        if len(parts) >= 3 and parts[-1] in {"exe","scr","bat","cmd","vbs","ps1","dll"}:
            add("Double extension (+4)", 4)
        if record.get("magic") == "Signature mismatch": add("Extension/signature mismatch (+5)", 5)
        if record.get("sha256", "").lower() in hashes and record.get("sha256") not in ("", "Unreadable"):
            add("Known-bad SHA-256 match (+10)", 10)
        if any(part in path for part in ("/temp/", "\\temp\\", "appdata", "downloads", "$recycle.bin", "recycler")):
            if ext in extensions or ext in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr"):
                add("Executable/script in a commonly abused location (+2)", 2)
        if record.get("hidden"): add("Hidden file (+1)", 1)
        if record.get("entropy") is not None and record["size_bytes"] >= 4096 and record["entropy"] >= 7.5:
            add("High byte entropy; may be packed/encrypted (+2)", 2)
        if record.get("timestamp_anomaly"): add("Timestamp anomaly (+2)", 2)
        if record["size_bytes"] == 0: add("Zero-byte file (+1)", 1)
        if len(record["filename"]) > 120 or "\u202e" in record["filename"] or any(ord(c) < 32 for c in record["filename"]):
            add("Very long or unusual filename (+2)", 2)
        risk = "High" if score >= high_threshold else ("Medium" if score >= 2 else "Low")
        return {"score": score, "risk": risk, "reasons": reasons}

    def refresh_all_tables(self):
        self._populate_tree(self.dashboard_tree, self.files)
        self._populate_tree(self.scan_tree, self.files)

    def refresh_dashboard_table(self): self._populate_tree(self.dashboard_tree, self.files)

    def _populate_tree(self, tree, records):
        for iid in tree.get_children(): tree.delete(iid)
        for i, rec in enumerate(records):
            analysis = self.analyze(rec)
            reason_text = "; ".join(analysis["reasons"]) if analysis["reasons"] else "No configured indicators"
            tree.insert("", "end", iid=f"{id(rec)}_{i}", values=(rec["filename"], rec["extension"], f"{rec['size_bytes']/1024:.2f}",
                rec["modified"], analysis["risk"], analysis["score"], reason_text), tags=(analysis["risk"].lower(),))

    def update_summary(self):
        self.total_text.set(str(len(self.files)))
        flagged = sum(bool(self.analyze(f)["reasons"]) for f in self.files)
        self.flagged_text.set(str(flagged)); self.normal_text.set(str(len(self.files)-flagged))

    def apply_rules(self):
        try: self.get_rules()
        except ValueError as exc:
            messagebox.showerror("Invalid rule", str(exc)); return
        self.refresh_all_tables(); self.update_summary()
        if hasattr(self, "search_tree"): self._populate_tree(self.search_tree, [])
        self.status_text.set("Rules applied. Files re-analyzed using the updated risk score.")
        messagebox.showinfo("Rules applied", "Detection rules have been validated and applied.")

    def reset_rules(self):
        self.keyword_text.set(DEFAULT_KEYWORDS); self.extension_text.set(DEFAULT_EXTENSIONS)
        self.size_threshold.set(str(DEFAULT_SIZE_KB)); self.min_score.set("4"); self.hash_list_text.set("")
        self.apply_rules()

    def search_files(self):
        query = self.search_text.get().strip().lower()
        if not query:
            messagebox.showinfo("Search", "Enter a filename, extension or SHA-256 hash first."); return
        field, algorithm = self.search_field.get(), self.search_algorithm.get()
        key = {"Filename": lambda f: f["filename"].lower(), "Extension": lambda f: f["extension"].lower(), "SHA-256": lambda f: f.get("sha256", "").lower()}[field]
        start = time.perf_counter(); comparisons = 0
        matches = []
        if algorithm == "Linear Search":
            for rec in self.files:
                comparisons += 1
                value = key(rec)
                if (query in value) if field != "SHA-256" else (query == value): matches.append(rec)
        elif algorithm == "Binary Search":
            if field == "SHA-256":
                messagebox.showinfo("Binary Search", "Choose Filename or Extension for Binary Search. Use Hash Lookup for SHA-256."); return
            ordered = sorted(self.files, key=key)
            low, high = 0, len(ordered)-1
            while low <= high:
                mid = (low+high)//2; comparisons += 1; value = key(ordered[mid])
                if value == query:
                    # Return every duplicate exact match around the located index.
                    left = mid
                    while left > 0 and key(ordered[left-1]) == query: left -= 1
                    right = mid
                    while right+1 < len(ordered) and key(ordered[right+1]) == query: right += 1
                    matches = ordered[left:right+1]; break
                if value < query: low = mid+1
                else: high = mid-1
        else:  # Hash table/dictionary lookup; hash index built once for the current search.
            if field != "SHA-256":
                messagebox.showinfo("Hash Lookup", "Hash Lookup is intended for exact SHA-256 hash searches. Select SHA-256 as the field."); return
            index = {}
            for rec in self.files:
                h = rec.get("sha256", "").lower()
                if h and h not in ("unreadable",): index.setdefault(h, []).append(rec)
            matches = index.get(query, [])
            comparisons = 1
        elapsed = time.perf_counter()-start
        self._populate_tree(self.search_tree, matches)
        output = (f"Field: {field}\nQuery: {query}\nAlgorithm: {algorithm}\nMatches: {len(matches)}\n"
                  f"Elapsed: {elapsed*1000:.6f} ms\nComparisons/lookup steps: {comparisons}\n\n"
                  "Binary Search requires sorted data and exact matching. Hash Lookup is for exact SHA-256 values.\n"
                  "Risk scores are screening indicators, not proof of malware.")
        self._set_text(self.search_output, output)
        self.status_text.set(f"Search complete — {len(matches)} result(s), {comparisons} comparisons/steps.")

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal"); widget.delete("1.0", tk.END); widget.insert("1.0", text); widget.configure(state="disabled")

    def run_benchmark(self):
        self.status_text.set("Running search benchmark…"); self.root.update_idletasks()
        results = []
        for n in self.benchmark_sizes:
            records = [f"file_{i:06d}.dat" for i in range(n)]
            target = records[-2]
            repeats = max(3, min(50, 200000 // n))
            # Linear search with comparison counting.
            linear_comps = 0; start = time.perf_counter()
            for _ in range(repeats):
                for name in records:
                    linear_comps += 1
                    if name == target: break
            linear_ms = (time.perf_counter()-start)*1000/repeats
            start = time.perf_counter(); ordered = sorted(records); sort_ms = (time.perf_counter()-start)*1000
            binary_comps = 0; start = time.perf_counter()
            for _ in range(repeats):
                lo, hi = 0, len(ordered)-1
                while lo <= hi:
                    mid = (lo+hi)//2; binary_comps += 1
                    if ordered[mid] == target: break
                    if ordered[mid] < target: lo = mid+1
                    else: hi = mid-1
            binary_ms = (time.perf_counter()-start)*1000/repeats
            start = time.perf_counter(); index = {name: i for i, name in enumerate(records)}; hash_build_ms = (time.perf_counter()-start)*1000
            start = time.perf_counter()
            for _ in range(repeats): index.get(target)
            hash_ms = (time.perf_counter()-start)*1000/repeats
            results.append({"n":n, "linear_ms":linear_ms, "linear_cmp":linear_comps/repeats,
                            "sort_ms":sort_ms, "binary_ms":binary_ms, "binary_cmp":binary_comps/repeats,
                            "hash_ms":hash_ms, "hash_build_ms":hash_build_ms})
        self.benchmark_results = results
        for iid in self.bench_tree.get_children(): self.bench_tree.delete(iid)
        for r in results:
            self.bench_tree.insert("", "end", values=(f"{r['n']:,}", f"{r['linear_ms']:.4f}", f"{r['linear_cmp']:.0f}",
                f"{r['sort_ms']:.3f}", f"{r['binary_ms']:.4f}", f"{r['binary_cmp']:.1f}", f"{r['hash_ms']:.5f}"))
        self._draw_benchmark_graph()
        self.status_text.set("Benchmark complete. Sorting and hash-index build costs are reported separately.")

    def _draw_benchmark_graph(self):
        if not hasattr(self, "graph_holder") or not self.benchmark_results: return
        for child in self.graph_holder.winfo_children(): child.destroy()
        try:
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            fig = Figure(figsize=(8, 2.5), dpi=90)
            ax = fig.add_subplot(111)
            xs = [r["n"] for r in self.benchmark_results]
            ax.plot(xs, [r["linear_ms"] for r in self.benchmark_results], marker="o", label="Linear lookup")
            ax.plot(xs, [r["binary_ms"] for r in self.benchmark_results], marker="o", label="Binary lookup")
            ax.plot(xs, [r["hash_ms"] for r in self.benchmark_results], marker="o", label="Hash lookup")
            ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Number of records (log scale)")
            ax.set_ylabel("Average lookup time (ms, log scale)"); ax.grid(True, alpha=.25); ax.legend(loc="upper left", ncol=3, fontsize=8)
            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=self.graph_holder); canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)
        except ImportError:
            # Draw a dependency-free graph so this screen still visualizes results
            # when Matplotlib is not installed.
            canvas = tk.Canvas(self.graph_holder, bg="#0b1f37", highlightthickness=0, height=230)
            canvas.pack(fill="both", expand=True)

            def draw_native_graph(_event=None):
                canvas.delete("all")
                width = max(canvas.winfo_width(), 520)
                height = max(canvas.winfo_height(), 200)
                left, right, top, bottom = 65, width - 25, 28, height - 45
                if right <= left or bottom <= top:
                    return
                canvas.create_text(width / 2, 12, text="Search Algorithm Lookup Time", fill="#e5efff", font=("Segoe UI", 10, "bold"))
                for i in range(5):
                    y = top + (bottom - top) * i / 4
                    canvas.create_line(left, y, right, y, fill="#243d59")
                canvas.create_line(left, top, left, bottom, fill="#8ba6c4", width=1)
                canvas.create_line(left, bottom, right, bottom, fill="#8ba6c4", width=1)
                xs = [r["n"] for r in self.benchmark_results]
                all_values = [max(r[k], 0.000001) for r in self.benchmark_results for k in ("linear_ms", "binary_ms", "hash_ms")]
                low, high = math.log10(min(all_values)), math.log10(max(all_values))
                if high == low:
                    high += 1
                colors = {"linear_ms": "#ffab00", "binary_ms": "#00e5ff", "hash_ms": "#28d9b0"}
                labels = {"linear_ms": "Linear", "binary_ms": "Binary", "hash_ms": "Hash"}
                for key in ("linear_ms", "binary_ms", "hash_ms"):
                    points = []
                    for i, record in enumerate(self.benchmark_results):
                        x = left + (right - left) * i / max(len(xs) - 1, 1)
                        value = math.log10(max(record[key], 0.000001))
                        y = bottom - (value - low) / (high - low) * (bottom - top)
                        points.extend((x, y))
                        canvas.create_oval(x-3, y-3, x+3, y+3, fill=colors[key], outline=colors[key])
                        if i == 0:
                            canvas.create_text(left - 8, y, text=f"{record[key]:.4g}", fill=colors[key], anchor="e", font=("Segoe UI", 8))
                    if len(points) >= 4:
                        canvas.create_line(*points, fill=colors[key], width=2, smooth=False)
                    canvas.create_text(right - 150 + (len(labels)-1) * 0, top + 10, text="", fill=colors[key])
                for i, key in enumerate(("linear_ms", "binary_ms", "hash_ms")):
                    x = left + i * 110
                    canvas.create_line(x, height - 17, x + 18, height - 17, fill=colors[key], width=3)
                    canvas.create_text(x + 24, height - 17, text=labels[key], fill="#e5efff", anchor="w", font=("Segoe UI", 8))
                for i, n in enumerate(xs):
                    x = left + (right - left) * i / max(len(xs) - 1, 1)
                    canvas.create_text(x, bottom + 15, text=f"{n:,}", fill="#c6d7ed", font=("Segoe UI", 8))
                canvas.create_text(15, (top + bottom) / 2, text="Time (ms, log scale)", fill="#c6d7ed", angle=90, font=("Segoe UI", 8))

            canvas.bind("<Configure>", draw_native_graph)
            draw_native_graph()

    def export_csv(self):
        if not self.files:
            messagebox.showinfo("Export", "There are no file records to export."); return
        path = filedialog.asksaveasfilename(title="Export CSV report", defaultextension=".csv", filetypes=[("CSV report", "*.csv")], initialfile="suspicious_file_analysis_report.csv")
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as out:
                writer = csv.writer(out)
                writer.writerow(["Filename","Path","Extension","Size (bytes)","Created","Modified","SHA-256","Hidden","Entropy","Magic/signature","Risk","Score","Reasons"])
                for rec in self.files:
                    a = self.analyze(rec)
                    writer.writerow([rec["filename"],rec["path"],rec["extension"],rec["size_bytes"],rec.get("created"),rec["modified"],rec.get("sha256"),rec.get("hidden"),rec.get("entropy"),rec.get("magic"),a["risk"],a["score"],"; ".join(a["reasons"])])
            messagebox.showinfo("Export complete", f"CSV report saved successfully:\n{path}")
        except OSError as exc: messagebox.showerror("Export failed", str(exc))

    def export_pdf(self):
        if not self.files:
            messagebox.showinfo("PDF report", "Scan a folder or load demo data first."); return
        path = filedialog.asksaveasfilename(title="Export PDF report", defaultextension=".pdf", filetypes=[("PDF report", "*.pdf")], initialfile="suspicious_file_analysis_report.pdf")
        if not path: return
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        except ImportError:
            messagebox.showerror("PDF dependency missing", "Install ReportLab first:\n\npython -m pip install reportlab")
            return
        try:
            doc = SimpleDocTemplate(path, pagesize=landscape(A4), rightMargin=12*mm, leftMargin=12*mm, topMargin=12*mm, bottomMargin=12*mm)
            styles = getSampleStyleSheet(); styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7, leading=9))
            story = [Paragraph(APP_TITLE, styles["Title"]), Paragraph("Digital Forensics — File metadata screening report", styles["Heading2"]),
                     Paragraph("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), styles["BodyText"]), Spacer(1, 5*mm)]
            flagged = [(f, self.analyze(f)) for f in self.files]
            flagged_count = sum(bool(a["reasons"]) for _,a in flagged)
            story += [Paragraph("Scan summary", styles["Heading2"]), Paragraph(f"Records indexed: {len(self.files)} | Flagged for review: {flagged_count} | Not flagged: {len(self.files)-flagged_count}", styles["BodyText"]), Spacer(1, 4*mm)]
            data = [["Filename","Extension","Size KB","Modified","Risk","Score","Reasons"]]
            for rec, a in flagged:
                reason = "; ".join(a["reasons"]) if a["reasons"] else "No configured indicators"
                data.append([Paragraph(rec["filename"], styles["Small"]), rec["extension"], f"{rec['size_bytes']/1024:.1f}", rec["modified"], a["risk"], str(a["score"]), Paragraph(reason, styles["Small"])])
            table = Table(data, repeatRows=1, colWidths=[40*mm, 18*mm, 17*mm, 33*mm, 17*mm, 12*mm, 110*mm])
            table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12345a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7),("GRID",(0,0),(-1,-1),.25,colors.grey),
                ("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f1f5f9")]),
                ("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
            story += [table, Spacer(1, 5*mm), Paragraph("Methodology and limitations", styles["Heading2"]),
                Paragraph("The scanner collects metadata and reads file bytes for SHA-256, basic file-signature and byte-entropy checks. Files are never executed or modified. Rules are heuristic indicators: a flag is not proof of malicious activity, and a clean result does not guarantee safety. Known-bad hash matching works only when a trustworthy hash list is supplied. Synthetic benchmark results compare lookup time; sorting and hash-index construction costs are reported separately.", styles["BodyText"])]
            if self.benchmark_results:
                story += [Spacer(1, 4*mm), Paragraph("Search efficiency benchmark", styles["Heading2"])]
                bdata = [["Records","Linear ms","Linear comparisons","Sort ms","Binary ms","Binary comparisons","Hash ms","Hash index build ms"]]
                for r in self.benchmark_results:
                    bdata.append([f"{r['n']:,}",f"{r['linear_ms']:.4f}",f"{r['linear_cmp']:.0f}",f"{r['sort_ms']:.3f}",f"{r['binary_ms']:.4f}",f"{r['binary_cmp']:.1f}",f"{r['hash_ms']:.5f}",f"{r['hash_build_ms']:.3f}"])
                bt = Table(bdata, repeatRows=1)
                bt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#12345a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP")]))
                story += [bt]
                try:
                    import matplotlib.pyplot as plt
                    from reportlab.platypus import Image
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp: graph_path = tmp.name
                    fig, ax = plt.subplots(figsize=(7,2.4))
                    xs=[r["n"] for r in self.benchmark_results]
                    ax.plot(xs,[r["linear_ms"] for r in self.benchmark_results],marker="o",label="Linear")
                    ax.plot(xs,[r["binary_ms"] for r in self.benchmark_results],marker="o",label="Binary")
                    ax.plot(xs,[r["hash_ms"] for r in self.benchmark_results],marker="o",label="Hash")
                    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Records"); ax.set_ylabel("Lookup ms"); ax.grid(True,alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(graph_path,dpi=120); plt.close(fig)
                    story += [Spacer(1, 3*mm), Image(graph_path, width=165*mm, height=56*mm)]
                except ImportError: pass
            doc.build(story)
            messagebox.showinfo("PDF exported", f"PDF report saved successfully:\n{path}")
        except Exception as exc:
            messagebox.showerror("PDF export failed", f"Could not create PDF:\n{exc}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SuspiciousFileAnalyzer(root)
    root.mainloop()
