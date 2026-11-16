"""Password Sentinel — professional PyQt6 desktop interface.

The analysis and wordlist engines remain in strength.py and wordlist.py.
Passwords are never written to the local history database; only metadata and
SHA-256 fingerprints are stored. Use only for accounts/systems you own or are
authorized to assess.
"""
from __future__ import annotations

import csv
import hashlib
import os
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QScrollArea, QSpinBox, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QListWidget,
    QListWidgetItem, QHeaderView, QAbstractItemView, QSplitter, QLayout,
)

from strength import analyze_password, check_pwned
from wordlist import export_wordlist, generate_wordlist, wordlist_stats

APP_NAME = "PASSWORD SENTINEL"
APP_VERSION = "3.1.0"
def app_data_dir() -> Path:
    """Return the conventional per-user application data directory on each OS."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "PasswordSentinel"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "PasswordSentinel"
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "password-sentinel"


DB_PATH = app_data_dir() / "history.sqlite3"

STYLE = """
QWidget { background: #0b1120; color: #e5edf7; font-family: 'Segoe UI'; font-size: 10pt; }
QLabel { background-color: transparent; }
QMainWindow { background: #0b1120; }
QFrame#Sidebar { background: #080e1a; border-right: 1px solid #1d2a3d; }
QFrame#Topbar { background: #0e1728; border-bottom: 1px solid #1d2a3d; }
QFrame#Card { background: #111d30; border: 1px solid #22334b; border-radius: 12px; }
QFrame#Card:hover { border-color: #315477; }
QLabel#Brand { color: #f1f7ff; font-size: 15pt; font-weight: 800; letter-spacing: 1px; }
QLabel#BrandAccent { color: #35d0ba; font-size: 8pt; font-weight: 700; letter-spacing: 2px; }
QLabel#PageTitle { color: #f4f8ff; font-size: 20pt; font-weight: 750; }
QLabel#SectionTitle { color: #dce9f8; font-size: 11pt; font-weight: 700; }
QLabel#Muted { color: #8294ad; }
QLabel#Metric { color: #f4f8ff; font-size: 22pt; font-weight: 750; }
QLabel#Accent { color: #35d0ba; font-weight: 700; }
QLabel#Good { color: #45d6a1; font-weight: 700; }
QLabel#Warn { color: #f6bd60; font-weight: 700; }
QLabel#Bad { color: #ff7185; font-weight: 700; }
QPushButton { background: #17263c; color: #dce9f8; border: 1px solid #2a405c; border-radius: 8px; padding: 9px 14px; font-weight: 650; }
QPushButton:hover { background: #203652; border-color: #3d6688; }
QPushButton:pressed { background: #142238; }
QPushButton#Primary { background: #087f78; border: 1px solid #16a69b; color: white; }
QPushButton#Primary:hover { background: #0a968d; }
QPushButton#Nav { text-align: left; padding: 12px 14px; background: transparent; border: 0; color: #93a5bc; border-radius: 8px; }
QPushButton#Nav:hover { background: #142238; color: #eaf3ff; }
QPushButton#Nav:checked { background: #123b42; color: #56e0ce; border-left: 3px solid #35d0ba; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background: #0b1627; color: #e5edf7; border: 1px solid #2a3d57; border-radius: 7px; padding: 7px 9px; selection-background-color: #087f78; min-height: 22px; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #35d0ba; }
QCheckBox { spacing: 8px; color: #bdcadd; }
QCheckBox::indicator { width: 16px; height: 16px; }
QProgressBar { background: #0a1525; border: 1px solid #263951; border-radius: 6px; min-height: 16px; text-align: center; color: #dce9f8; }
QProgressBar::chunk { background: #20b8a8; border-radius: 5px; }
QTableWidget { background: #0d192a; alternate-background-color: #101f32; border: 1px solid #24364e; border-radius: 8px; gridline-color: #1d2d42; selection-background-color: #174b54; selection-color: white; }
QHeaderView::section { background: #15243a; color: #9fb5ce; padding: 9px; border: 0; border-bottom: 1px solid #2a405c; font-weight: 700; }
QListWidget { background: #0d192a; border: 1px solid #24364e; border-radius: 8px; padding: 6px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: #0b1627; width: 11px; margin: 2px; border-radius: 5px; }
QScrollBar::handle:vertical { background: #30445f; min-height: 28px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: #3e607d; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
"""


class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)


class Worker(QRunnable):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn
        self.signals = WorkerSignals()

    def run(self):
        try:
            self.signals.finished.emit(self.fn(self.signals.progress))
        except Exception as exc:
            self.signals.error.emit(f"{type(exc).__name__}: {exc}")


def db_init():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL,
            fingerprint TEXT NOT NULL, password_length INTEGER NOT NULL,
            score INTEGER NOT NULL, label TEXT NOT NULL, entropy REAL NOT NULL,
            crack_time TEXT NOT NULL, method TEXT NOT NULL, breach_count INTEGER
        )""")


def save_history(password: str, result):
    # Store a one-way fingerprint and assessment metadata, never plaintext.
    fingerprint = hashlib.sha256(password.encode("utf-8")).hexdigest()[:16]
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""INSERT INTO scans
            (scanned_at,fingerprint,password_length,score,label,entropy,crack_time,method,breach_count)
            VALUES (?,?,?,?,?,?,?,?,?)""", (
            datetime.now().isoformat(timespec="seconds"), fingerprint,
            result.password_len, result.score, result.label, result.entropy_bits,
            result.crack_time_display, result.method, result.pwned_count))


def history_rows(limit=500):
    with sqlite3.connect(DB_PATH) as con:
        return con.execute("SELECT scanned_at,fingerprint,password_length,score,label,entropy,crack_time,method,breach_count FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def card(title: str, value: str, hint: str = "") -> tuple[QFrame, QLabel]:
    frame = QFrame(); frame.setObjectName("Card")
    lay = QVBoxLayout(frame); lay.setContentsMargins(17, 14, 17, 14); lay.setSpacing(5)
    t = QLabel(title.upper()); t.setObjectName("Muted")
    v = QLabel(value); v.setObjectName("Metric")
    h = QLabel(hint); h.setObjectName("Muted")
    lay.addWidget(t); lay.addWidget(v); lay.addWidget(h)
    return frame, v


def section_title(text: str):
    label = QLabel(text); label.setObjectName("SectionTitle"); return label


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSortingEnabled(True)
    return table


class PasswordSentinel(QMainWindow):
    def __init__(self):
        super().__init__()
        db_init()
        self.pool = QThreadPool.globalInstance()
        self.last_result = None
        self.last_password = ""
        self.batch_results = []
        self.generated_words = []
        self._build_shell()
        self._build_pages()
        self._connect_navigation()
        self.refresh_overview()
        self.refresh_history()
        self.statusBar().showMessage("Ready  •  Local analysis enabled  •  Authorized testing only")
        self.resize(1320, 860)
        self.setMinimumSize(900, 620)

    def _build_shell(self):
        root = QWidget(); self.setCentralWidget(root)
        outer = QHBoxLayout(root); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(230)
        side = QVBoxLayout(sidebar); side.setContentsMargins(17, 24, 17, 18); side.setSpacing(8)
        brand = QLabel("◈  PASSWORD\n    SENTINEL"); brand.setObjectName("Brand")
        sub = QLabel("SECURITY ASSESSMENT SUITE"); sub.setObjectName("BrandAccent")
        side.addWidget(brand); side.addWidget(sub); side.addSpacing(24)
        self.nav_buttons = []
        for name, glyph in [("Overview", "⌂"), ("Password Analyzer", "◎"), ("Wordlist Lab", "⌘"), ("Batch Audit", "▤"), ("Assessment History", "◷"), ("Settings & About", "⚙")]:
            btn = QPushButton(f"{glyph}   {name}"); btn.setObjectName("Nav"); btn.setCheckable(True)
            side.addWidget(btn); self.nav_buttons.append(btn)
        side.addStretch(1)
        auth = QLabel("●  LOCAL WORKSPACE\n\nUse only on systems you own\nor are authorized to assess.")
        auth.setObjectName("Muted"); auth.setWordWrap(True); side.addWidget(auth)
        outer.addWidget(sidebar)

        main = QWidget(); main_lay = QVBoxLayout(main); main_lay.setContentsMargins(0, 0, 0, 0); main_lay.setSpacing(0)
        top = QFrame(); top.setObjectName("Topbar"); top.setFixedHeight(66)
        top_lay = QHBoxLayout(top); top_lay.setContentsMargins(25, 8, 25, 8)
        self.breadcrumb = QLabel("WORKSPACE  /  OVERVIEW"); self.breadcrumb.setObjectName("Muted")
        top_lay.addWidget(self.breadcrumb); top_lay.addStretch(1)
        self.top_status = QLabel("●  SYSTEM READY"); self.top_status.setObjectName("Good")
        top_lay.addWidget(self.top_status)
        main_lay.addWidget(top)
        self.stack = QStackedWidget(); main_lay.addWidget(self.stack, 1)
        outer.addWidget(main, 1)
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")

    def _page(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(28, 24, 28, 24); layout.setSpacing(16)
        return page, layout

    def _build_pages(self):
        self.pages = []
        self._build_overview(); self._build_analyzer(); self._build_wordlist(); self._build_batch(); self._build_history(); self._build_settings()

    def _add_page(self, page):
        """Add each workspace inside a resizable scroll area.

        This keeps every control reachable on maximized, restored, and
        lower-resolution displays instead of allowing the stacked page to
        compress its contents out of view.
        """
        page.setMinimumWidth(0)
        if page.layout() is not None:
            page.layout().setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(page)
        self.pages.append(scroll)
        self.stack.addWidget(scroll)

    def _build_overview(self):
        p, l = self._page()
        title = QLabel("Security overview"); title.setObjectName("PageTitle")
        desc = QLabel("A focused workspace for password-strength assessment and authorized audit preparation."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        grid = QGridLayout(); grid.setSpacing(12)
        c1, self.metric_scans = card("Assessments stored", "0", "Local history metadata")
        c2, self.metric_strength = card("Average score", "—", "Across saved assessments")
        c3, self.metric_breaches = card("Known breach hits", "0", "From completed HIBP checks")
        c4, self.metric_words = card("Last wordlist", "—", "Candidate count")
        for i, c in enumerate((c1,c2,c3,c4)): grid.addWidget(c, 0, i)
        l.addLayout(grid)
        panel = QFrame(); panel.setObjectName("Card"); pl = QVBoxLayout(panel); pl.setContentsMargins(20,18,20,18)
        pl.addWidget(section_title("QUICK ACTIONS"))
        actions = QHBoxLayout()
        for text, idx in [("Analyze a password",1),("Open Wordlist Lab",2),("Start batch audit",3)]:
            b = QPushButton(text); b.setObjectName("Primary" if idx == 1 else ""); b.clicked.connect(lambda checked=False, n=idx: self.navigate(n)); actions.addWidget(b)
        pl.addLayout(actions)
        pl.addSpacing(8)
        note = QLabel("Privacy by design: the history database stores assessment metadata and a truncated SHA-256 fingerprint. It does not store plaintext passwords.")
        note.setWordWrap(True); note.setObjectName("Muted"); pl.addWidget(note)
        l.addWidget(panel)
        recent = QFrame(); recent.setObjectName("Card"); rl = QVBoxLayout(recent); rl.setContentsMargins(18,16,18,16)
        rl.addWidget(section_title("RECENT ASSESSMENTS"))
        self.overview_table = make_table(["DATE", "FINGERPRINT", "LENGTH", "SCORE", "VERDICT"]); self.overview_table.setMaximumHeight(250)
        rl.addWidget(self.overview_table); l.addWidget(recent); l.addStretch(1)
        self._add_page(p)

    def _build_analyzer(self):
        p, l = self._page()
        title = QLabel("Password analyzer"); title.setObjectName("PageTitle")
        desc = QLabel("Evaluate password strength, attack resistance, and known breach exposure."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        panel = QFrame(); panel.setObjectName("Card"); pl = QVBoxLayout(panel); pl.setContentsMargins(20,18,20,18); pl.setSpacing(10)
        pl.addWidget(section_title("TARGET CREDENTIAL"))
        row = QHBoxLayout(); self.password_input = QLineEdit(); self.password_input.setPlaceholderText("Enter a password to assess…"); self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password = QCheckBox("Show password"); self.show_password.toggled.connect(lambda v: self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password))
        row.addWidget(self.password_input,1); row.addWidget(self.show_password); pl.addLayout(row)
        pl.addWidget(QLabel("Optional personal context (comma-separated; used only for local dictionary matching):"))
        self.personal_input = QLineEdit(); self.personal_input.setPlaceholderText("e.g. name, pet, company, memorable date"); pl.addWidget(self.personal_input)
        btnrow = QHBoxLayout(); self.analyze_btn = QPushButton("RUN FULL ASSESSMENT"); self.analyze_btn.setObjectName("Primary"); self.analyze_btn.clicked.connect(self.run_analysis)
        self.breach_btn = QPushButton("CHECK BREACH DATABASE"); self.breach_btn.clicked.connect(self.run_breach_check)
        self.export_report_btn = QPushButton("EXPORT REPORT"); self.export_report_btn.clicked.connect(self.export_report)
        btnrow.addWidget(self.analyze_btn); btnrow.addWidget(self.breach_btn); btnrow.addWidget(self.export_report_btn); btnrow.addStretch(1); pl.addLayout(btnrow)
        l.addWidget(panel)
        grid = QGridLayout(); grid.setSpacing(12)
        c1,self.score_value=card("Strength verdict","Not assessed","Score range 0–4")
        c2,self.entropy_value=card("Estimated entropy","—","Bits (estimator output)")
        c3,self.crack_value=card("Offline fast-hash estimate","—","Modelled at 10¹⁰ guesses/second")
        c4,self.method_value=card("Analysis engine","—","zxcvbn or fallback")
        for i,c in enumerate((c1,c2,c3,c4)): grid.addWidget(c,0,i)
        l.addLayout(grid)
        meter_panel=QFrame(); meter_panel.setObjectName("Card"); ml=QVBoxLayout(meter_panel); ml.setContentsMargins(18,14,18,14)
        ml.addWidget(section_title("STRENGTH PROFILE")); self.strength_bar=QProgressBar(); self.strength_bar.setRange(0,4); self.strength_bar.setValue(0); self.strength_bar.setFormat("%v / 4"); ml.addWidget(self.strength_bar)
        self.warning_label=QLabel("Enter a password and run an assessment."); self.warning_label.setWordWrap(True); self.warning_label.setObjectName("Muted"); ml.addWidget(self.warning_label)
        l.addWidget(meter_panel)
        split=QSplitter(Qt.Orientation.Horizontal)
        crack_panel=QFrame(); crack_panel.setObjectName("Card"); cl=QVBoxLayout(crack_panel); cl.setContentsMargins(16,14,16,14); cl.addWidget(section_title("ATTACK SCENARIO ESTIMATES"))
        self.crack_table=make_table(["SCENARIO","ESTIMATED TIME"]); cl.addWidget(self.crack_table)
        feedback=QFrame(); feedback.setObjectName("Card"); fl=QVBoxLayout(feedback); fl.setContentsMargins(16,14,16,14); fl.addWidget(section_title("ASSESSMENT FEEDBACK"))
        self.feedback_text=QTextEdit(); self.feedback_text.setReadOnly(True); self.feedback_text.setPlaceholderText("Suggestions and warnings will appear here."); fl.addWidget(self.feedback_text)
        split.addWidget(crack_panel); split.addWidget(feedback); split.setSizes([600,500]); l.addWidget(split,1)
        self._add_page(p)
        self.debounce=QTimer(self); self.debounce.setSingleShot(True); self.debounce.setInterval(450); self.debounce.timeout.connect(self._live_assess)
        self.password_input.textChanged.connect(lambda: self.debounce.start())

    def _build_wordlist(self):
        p,l=self._page(); title=QLabel("Wordlist lab"); title.setObjectName("PageTitle"); desc=QLabel("Build bounded candidate lists for controlled password-audit exercises."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        panel=QFrame(); panel.setObjectName("Card"); pl=QVBoxLayout(panel); pl.setContentsMargins(20,18,20,18); pl.addWidget(section_title("SEED DATA"))
        self.seeds_input=QLineEdit(); self.seeds_input.setPlaceholderText("Enter authorized test seeds separated by commas"); pl.addWidget(self.seeds_input)
        opts=QGridLayout(); self.opt_years=QCheckBox("Append year patterns"); self.opt_years.setChecked(True); self.opt_leet=QCheckBox("Leetspeak variants"); self.opt_leet.setChecked(True); self.opt_suffix=QCheckBox("Common prefixes / suffixes"); self.opt_suffix.setChecked(True); self.opt_combine=QCheckBox("Combine seed pairs"); self.opt_combine.setChecked(True)
        for i,w in enumerate((self.opt_years,self.opt_leet,self.opt_suffix,self.opt_combine)): opts.addWidget(w,i//2,i%2)
        pl.addLayout(opts)
        controls=QHBoxLayout(); controls.addWidget(QLabel("Maximum candidates")); self.word_limit=QSpinBox(); self.word_limit.setRange(100,200000); self.word_limit.setSingleStep(1000); self.word_limit.setValue(50000); controls.addWidget(self.word_limit)
        controls.addWidget(QLabel("Min length")); self.min_len=QSpinBox(); self.min_len.setRange(1,64); self.min_len.setValue(4); controls.addWidget(self.min_len)
        controls.addWidget(QLabel("Max length")); self.max_len=QSpinBox(); self.max_len.setRange(1,128); self.max_len.setValue(32); controls.addWidget(self.max_len); controls.addStretch(1)
        pl.addLayout(controls)
        actions=QHBoxLayout(); self.generate_btn=QPushButton("GENERATE CANDIDATES"); self.generate_btn.setObjectName("Primary"); self.generate_btn.clicked.connect(self.generate_words); self.save_words_btn=QPushButton("SAVE WORDLIST (.TXT)"); self.save_words_btn.setEnabled(False); self.save_words_btn.clicked.connect(self.save_words); actions.addWidget(self.generate_btn); actions.addWidget(self.save_words_btn); actions.addStretch(1); pl.addLayout(actions)
        self.word_progress=QProgressBar(); self.word_progress.setRange(0,0); self.word_progress.hide(); pl.addWidget(self.word_progress)
        l.addWidget(panel)
        stats=QHBoxLayout(); self.word_count=QLabel("0 candidates"); self.word_count.setObjectName("Metric"); self.word_range=QLabel("Length range: —"); self.word_range.setObjectName("Muted"); stats.addWidget(self.word_count); stats.addWidget(self.word_range); stats.addStretch(1); l.addLayout(stats)
        preview=QFrame(); preview.setObjectName("Card"); vl=QVBoxLayout(preview); vl.setContentsMargins(16,14,16,14); vl.addWidget(section_title("CANDIDATE PREVIEW (FIRST 100)")); self.word_preview=QListWidget(); vl.addWidget(self.word_preview); l.addWidget(preview,1)
        self._add_page(p)

    def _build_batch(self):
        p,l=self._page(); title=QLabel("Batch audit"); title.setObjectName("PageTitle"); desc=QLabel("Assess a local text file of passwords. Mask values before displaying or exporting where possible."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        panel=QFrame(); panel.setObjectName("Card"); pl=QHBoxLayout(panel); pl.setContentsMargins(16,12,16,12)
        self.load_batch_btn=QPushButton("LOAD PASSWORD FILE"); self.load_batch_btn.setObjectName("Primary"); self.load_batch_btn.clicked.connect(self.load_batch)
        self.mask_batch=QCheckBox("Mask password values"); self.mask_batch.setChecked(True)
        self.batch_source=QLabel("No file loaded"); self.batch_source.setObjectName("Muted")
        self.scan_batch_btn=QPushButton("RUN BATCH AUDIT"); self.scan_batch_btn.clicked.connect(self.run_batch); self.scan_batch_btn.setEnabled(False)
        self.export_batch_btn=QPushButton("EXPORT CSV"); self.export_batch_btn.clicked.connect(self.export_batch); self.export_batch_btn.setEnabled(False)
        pl.addWidget(self.load_batch_btn); pl.addWidget(self.mask_batch); pl.addWidget(self.batch_source,1); pl.addWidget(self.scan_batch_btn); pl.addWidget(self.export_batch_btn); l.addWidget(panel)
        self.batch_progress=QProgressBar(); self.batch_progress.hide(); l.addWidget(self.batch_progress)
        cards=QHBoxLayout();
        for title2,attr in [("Records", "batch_total"),("Strong / very strong","batch_strong"),("Weak / very weak","batch_weak")]:
            c,v=card(title2,"0", "Current batch"); setattr(self,attr,v); cards.addWidget(c)
        l.addLayout(cards)
        self.batch_table=make_table(["PASSWORD","SCORE","VERDICT","ENTROPY (BITS)","FAST-HASH ESTIMATE"]); l.addWidget(self.batch_table,1)
        self._add_page(p)

    def _build_history(self):
        p,l=self._page(); title=QLabel("Assessment history"); title.setObjectName("PageTitle"); desc=QLabel("Local audit trail. Plaintext passwords are not retained."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        bar=QHBoxLayout(); self.history_count=QLabel("0 records"); self.history_count.setObjectName("Muted"); bar.addWidget(self.history_count); bar.addStretch(1)
        refresh=QPushButton("REFRESH"); refresh.clicked.connect(self.refresh_history); clear=QPushButton("CLEAR HISTORY"); clear.clicked.connect(self.clear_history); bar.addWidget(refresh); bar.addWidget(clear); l.addLayout(bar)
        self.history_table=make_table(["DATE","FINGERPRINT","LENGTH","SCORE","VERDICT","ENTROPY","CRACK TIME","ENGINE","BREACH HITS"]); l.addWidget(self.history_table,1)
        self._add_page(p)

    def _build_settings(self):
        p,l=self._page(); title=QLabel("Settings & about"); title.setObjectName("PageTitle"); desc=QLabel("Application configuration, privacy notes, and operational guidance."); desc.setObjectName("Muted")
        l.addWidget(title); l.addWidget(desc)
        for heading,body in [
            ("APPLICATION",f"Password Sentinel {APP_VERSION}\nDesktop password-strength assessment and authorized audit preparation."),
            ("PRIVACY MODEL","Password values are processed locally. The assessment history stores a truncated SHA-256 fingerprint and result metadata, not the original password. The optional Have I Been Pwned check uses the Pwned Passwords range API: only the first five hexadecimal characters of the SHA-1 hash are sent."),
            ("ESTIMATION LIMITATIONS","Crack-time figures are model-based estimates, not guarantees. Real attack feasibility depends on hashing algorithm, salts, rate limits, hardware, attacker resources, and password reuse. Entropy values from zxcvbn represent guessability-derived estimates, not a literal measurement of randomness."),
            ("RESPONSIBLE USE","Use this application only to assess passwords you own or systems for which you have explicit authorization. Generated candidate lists should remain within the approved audit scope."),
            ("LOCAL DATA","History database: " + str(DB_PATH)),
        ]:
            box=QFrame(); box.setObjectName("Card"); bl=QVBoxLayout(box); bl.setContentsMargins(18,15,18,15); h=QLabel(heading); h.setObjectName("Accent"); b=QLabel(body); b.setWordWrap(True); b.setObjectName("Muted"); bl.addWidget(h); bl.addWidget(b); l.addWidget(box)
        l.addStretch(1); self._add_page(p)

    def _connect_navigation(self):
        for i,b in enumerate(self.nav_buttons): b.clicked.connect(lambda checked=False,n=i:self.navigate(n))
        self.navigate(0)

    def navigate(self,index):
        self.stack.setCurrentIndex(index)
        for i,b in enumerate(self.nav_buttons): b.setChecked(i==index)
        labels=["OVERVIEW","PASSWORD ANALYZER","WORDLIST LAB","BATCH AUDIT","ASSESSMENT HISTORY","SETTINGS & ABOUT"]
        self.breadcrumb.setText("WORKSPACE  /  "+labels[index])
        if index==0: self.refresh_overview()
        if index==4: self.refresh_history()

    def refresh_overview(self):
        rows=history_rows()
        self.metric_scans.setText(str(len(rows)))
        avg=(sum(r[3] for r in rows)/len(rows)) if rows else None
        self.metric_strength.setText(f"{avg:.1f} / 4" if avg is not None else "—")
        self.metric_breaches.setText(str(sum((r[8] or 0) for r in rows)))
        self.overview_table.setRowCount(min(8,len(rows)))
        for i,r in enumerate(rows[:8]):
            vals=[r[0],r[1],str(r[2]),f"{r[3]}/4",r[4]]
            for j,v in enumerate(vals): self.overview_table.setItem(i,j,QTableWidgetItem(v))

    def _live_assess(self):
        pw=self.password_input.text()
        if not pw:
            self.score_value.setText("Not assessed"); self.entropy_value.setText("—"); self.crack_value.setText("—"); self.method_value.setText("—"); self.strength_bar.setValue(0); return
        try:
            result=analyze_password(pw,[x.strip() for x in self.personal_input.text().split(",") if x.strip()])
            self.last_password=pw
            self._display_result(result,save=False)
        except Exception as exc: self.statusBar().showMessage(f"Assessment error: {exc}")

    def run_analysis(self):
        pw=self.password_input.text()
        if not pw: QMessageBox.warning(self,"Missing password","Enter a password to assess."); return
        self.analyze_btn.setEnabled(False); self.top_status.setText("●  ANALYZING")
        personal=[x.strip() for x in self.personal_input.text().split(",") if x.strip()]
        worker=Worker(lambda _progress: analyze_password(pw,user_inputs=personal))
        worker.signals.finished.connect(lambda result,pw=pw:self._analysis_done(pw,result))
        worker.signals.error.connect(self._worker_error)
        self.pool.start(worker)

    def _analysis_done(self,pw,result):
        self.analyze_btn.setEnabled(True); self.top_status.setText("●  SYSTEM READY")
        self.last_password=pw; self._display_result(result,save=True)
        self.statusBar().showMessage(f"Assessment complete: {result.label} ({result.score}/4)")

    def _display_result(self,result,save=False):
        self.last_result=result
        self.score_value.setText(f"{result.label}  ·  {result.score}/4")
        self.entropy_value.setText(f"{result.entropy_bits:.1f} bits")
        self.crack_value.setText(result.crack_time_display)
        self.method_value.setText(result.method)
        self.strength_bar.setValue(result.score)
        self.warning_label.setText(result.feedback_warning or "No specific pattern warning reported by the analysis engine.")
        self.crack_table.setRowCount(len(result.crack_times_table))
        for i,(scenario,display) in enumerate(result.crack_times_table):
            self.crack_table.setItem(i,0,QTableWidgetItem(scenario)); self.crack_table.setItem(i,1,QTableWidgetItem(display))
        feedback=[]
        if result.feedback_warning: feedback.append("WARNING\n"+result.feedback_warning)
        if result.feedback_suggestions: feedback.append("RECOMMENDATIONS\n"+"\n".join("• "+s for s in result.feedback_suggestions))
        if not feedback: feedback.append("No additional recommendations were returned. Use a unique passphrase and enable multi-factor authentication where available.")
        if result.pwned_count is not None: feedback.append("BREACH DATABASE\n"+(f"Found {result.pwned_count:,} occurrences." if result.pwned_count else "No match returned by the breach corpus."))
        self.feedback_text.setPlainText("\n\n".join(feedback))
        if save and self.last_password:
            save_history(self.last_password,result); self.refresh_history(); self.refresh_overview()

    def run_breach_check(self):
        pw=self.password_input.text()
        if not pw: QMessageBox.warning(self,"Missing password","Enter a password before checking breach exposure."); return
        self.breach_btn.setEnabled(False); self.statusBar().showMessage("Querying breach corpus using k-anonymity…")
        worker=Worker(lambda _progress: check_pwned(pw))
        worker.signals.finished.connect(lambda data,pw=pw:self._breach_done(pw,data)); worker.signals.error.connect(self._worker_error); self.pool.start(worker)

    def _breach_done(self,pw,data):
        self.breach_btn.setEnabled(True); count,err=data
        if err: QMessageBox.warning(self,"Breach check unavailable",err); self.statusBar().showMessage("Breach check could not be completed."); return
        if pw==self.password_input.text() and self.last_result:
            self.last_result.pwned_count=count; self.last_password=pw; self._display_result(self.last_result,save=True)
        msg=(f"This password appears {count:,} times in known breach records." if count else "No match was returned by the queried breach corpus.")
        QMessageBox.information(self,"Breach check complete",msg)
        self.statusBar().showMessage("Breach check complete.")

    def export_report(self):
        if not self.last_result: QMessageBox.information(self,"No report","Run an assessment first."); return
        path,_=QFileDialog.getSaveFileName(self,"Export assessment report","password_assessment.txt","Text report (*.txt)")
        if not path:return
        safe_result=self.last_result.pretty()
        content=("PASSWORD SENTINEL — ASSESSMENT REPORT\n"+"="*48+"\n"+
                 f"Generated: {datetime.now().isoformat(timespec='seconds')}\n"+
                 f"Password fingerprint: {hashlib.sha256(self.last_password.encode()).hexdigest()[:16]}\n\n"+
                 safe_result+"\n\nNOTE: Crack-time values are estimates, not guarantees.\n")
        Path(path).write_text(content,encoding="utf-8"); self.statusBar().showMessage(f"Report exported: {path}")

    def generate_words(self):
        seeds=[x.strip() for x in self.seeds_input.text().split(",") if x.strip()]
        if not seeds: QMessageBox.warning(self,"Missing seed data","Enter at least one seed value."); return
        if self.min_len.value()>self.max_len.value(): QMessageBox.warning(self,"Invalid length range","Minimum length cannot exceed maximum length."); return
        self.generate_btn.setEnabled(False); self.word_progress.show(); self.statusBar().showMessage("Generating candidate list…")
        args=dict(include_years=self.opt_years.isChecked(),include_leet=self.opt_leet.isChecked(),include_suffixes=self.opt_suffix.isChecked(),combine_pairs=self.opt_combine.isChecked(),min_length=self.min_len.value(),max_length=self.max_len.value(),limit=self.word_limit.value())
        worker=Worker(lambda _progress: generate_wordlist(seeds,**args))
        worker.signals.finished.connect(self._words_done); worker.signals.error.connect(self._worker_error); self.pool.start(worker)

    def _words_done(self,words):
        self.generated_words=words; stats=wordlist_stats(words); self.generate_btn.setEnabled(True); self.word_progress.hide(); self.save_words_btn.setEnabled(bool(words))
        self.word_count.setText(f"{stats['count']:,} candidates"); self.word_range.setText(f"Length range: {stats['min_length']}–{stats['max_length']} characters")
        self.word_preview.clear()
        for word in words[:100]: self.word_preview.addItem(QListWidgetItem(word))
        self.statusBar().showMessage(f"Generated {len(words):,} unique candidates.")
        self.metric_words.setText(f"{len(words):,}")

    def save_words(self):
        if not self.generated_words:return
        path,_=QFileDialog.getSaveFileName(self,"Save generated wordlist","password_candidates.txt","Text files (*.txt)")
        if not path:return
        count=export_wordlist(self.generated_words,path); self.statusBar().showMessage(f"Saved {count:,} candidates to {path}")

    def load_batch(self):
        path,_=QFileDialog.getOpenFileName(self,"Load password list","","Text files (*.txt);;All files (*)")
        if not path:return
        try:
            with open(path,"r",encoding="utf-8",errors="ignore") as f:self.batch_passwords=[line.rstrip("\r\n") for line in f if line.strip()]
        except OSError as exc: QMessageBox.critical(self,"File error",str(exc)); return
        self.batch_source.setText(f"{Path(path).name}  ·  {len(self.batch_passwords):,} records"); self.scan_batch_btn.setEnabled(bool(self.batch_passwords)); self.statusBar().showMessage("Batch source loaded. No scan started yet.")

    def run_batch(self):
        passwords=getattr(self,"batch_passwords",[])
        if not passwords:return
        self.scan_batch_btn.setEnabled(False); self.load_batch_btn.setEnabled(False); self.batch_progress.setRange(0,len(passwords)); self.batch_progress.setValue(0); self.batch_progress.show()
        def work(progress):
            out=[]
            for i,pw in enumerate(passwords,1):
                r=analyze_password(pw); out.append((pw,r)); progress.progress.emit(i)
            return out
        worker=Worker(work); worker.signals.progress.connect(self.batch_progress.setValue); worker.signals.finished.connect(self._batch_done); worker.signals.error.connect(self._worker_error); self.pool.start(worker)

    def _batch_done(self,results):
        self.batch_results=results; self.batch_table.setSortingEnabled(False); self.batch_table.setRowCount(len(results)); strong=weak=0
        for i,(pw,r) in enumerate(results):
            shown=(pw[:2]+"•"*max(0,len(pw)-2)) if self.mask_batch.isChecked() else pw
            vals=[shown,f"{r.score}/4",r.label,f"{r.entropy_bits:.1f}",r.crack_time_display]
            for j,val in enumerate(vals):self.batch_table.setItem(i,j,QTableWidgetItem(val))
            if r.score>=3:strong+=1
            if r.score<=1:weak+=1
        self.batch_table.setSortingEnabled(True); self.batch_total.setText(str(len(results))); self.batch_strong.setText(str(strong)); self.batch_weak.setText(str(weak))
        self.batch_progress.hide(); self.scan_batch_btn.setEnabled(True); self.load_batch_btn.setEnabled(True); self.export_batch_btn.setEnabled(bool(results)); self.statusBar().showMessage(f"Batch audit complete: {len(results):,} records.")

    def export_batch(self):
        if not self.batch_results:return
        path,_=QFileDialog.getSaveFileName(self,"Export batch results","batch_audit.csv","CSV files (*.csv)")
        if not path:return
        try:
            with open(path,"w",newline="",encoding="utf-8") as f:
                writer=csv.writer(f); writer.writerow(["password","score","verdict","entropy_bits","fast_hash_crack_time"])
                for pw,r in self.batch_results:
                    shown=(pw[:2]+"•"*max(0,len(pw)-2)) if self.mask_batch.isChecked() else pw
                    writer.writerow([shown,r.score,r.label,f"{r.entropy_bits:.1f}",r.crack_time_display])
            self.statusBar().showMessage(f"Batch report exported: {path}")
        except OSError as exc: QMessageBox.critical(self,"Export failed",str(exc))

    def refresh_history(self):
        rows=history_rows(); self.history_count.setText(f"{len(rows)} records")
        self.history_table.setRowCount(len(rows))
        for i,r in enumerate(rows):
            vals=[r[0],r[1],str(r[2]),f"{r[3]}/4",r[4],f"{r[5]:.1f}",r[6],r[7],("—" if r[8] is None else str(r[8]))]
            for j,v in enumerate(vals):self.history_table.setItem(i,j,QTableWidgetItem(v))

    def clear_history(self):
        answer=QMessageBox.question(self,"Clear assessment history","Delete all locally stored assessment metadata? This cannot be undone.")
        if answer!=QMessageBox.StandardButton.Yes:return
        with sqlite3.connect(DB_PATH) as con:con.execute("DELETE FROM scans")
        self.refresh_history(); self.refresh_overview(); self.statusBar().showMessage("Assessment history cleared.")

    def _worker_error(self,message):
        self.analyze_btn.setEnabled(True); self.breach_btn.setEnabled(True); self.generate_btn.setEnabled(True); self.load_batch_btn.setEnabled(True); self.scan_batch_btn.setEnabled(True); self.word_progress.hide(); self.batch_progress.hide(); self.top_status.setText("●  SYSTEM READY")
        QMessageBox.critical(self,"Operation failed",message); self.statusBar().showMessage("Operation failed.")


def main():
    app=QApplication(sys.argv); app.setStyle("Fusion"); app.setStyleSheet(STYLE)
    app.setFont(QFont("Segoe UI",10))
    window=PasswordSentinel(); window.show(); sys.exit(app.exec())


if __name__=="__main__": main()
