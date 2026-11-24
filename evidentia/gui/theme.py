"""Dark professional theme."""

BG = "#0b1020"
SURFACE = "#111829"
SURFACE2 = "#172036"
RAISED = "#1d2842"
BORDER = "#243049"
TEXT = "#e6ebf5"
MUTED = "#8a97b1"
ACCENT = "#3b82f6"
ACCENT2 = "#22d3ee"
OK = "#22c55e"
WARN = "#f59e0b"
BAD = "#ef4444"


def conf_color(v: int | None) -> str:
    v = v or 0
    return OK if v >= 80 else WARN if v >= 50 else BAD


QSS = f"""
* {{ color: {TEXT}; font-size: 13px; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget#page {{ background: {BG}; }}
QFrame#sidebar {{ background: {SURFACE}; border-right: 1px solid {BORDER}; }}
QLabel#brand {{ font-size: 19px; font-weight: 800; letter-spacing: 3px; color: {TEXT}; }}
QLabel#brandSub {{ color: {MUTED}; font-size: 11px; }}
QPushButton#nav {{ text-align: left; padding: 10px 14px; border: none; border-radius: 8px; color: {MUTED};
                   background: transparent; font-size: 13.5px; }}
QPushButton#nav:hover {{ background: {SURFACE2}; color: {TEXT}; }}
QPushButton#nav:checked {{ background: {RAISED}; color: {TEXT}; border-left: 3px solid {ACCENT}; }}
QFrame#topbar {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}
QLabel#pageTitle {{ font-size: 20px; font-weight: 700; }}
QLabel#pageSub {{ color: {MUTED}; }}
QLabel#muted, QLabel[muted="true"] {{ color: {MUTED}; }}
QLabel#h2 {{ font-size: 14.5px; font-weight: 700; }}
QLabel#mono {{ font-family: Menlo, 'DejaVu Sans Mono', Consolas, monospace; font-size: 11.5px; color: #b8c4dc; }}
QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
QFrame#cardInner {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 10px; }}
QLabel#statValue {{ font-size: 28px; font-weight: 800; }}
QLabel#statLabel {{ color: {MUTED}; font-size: 12px; text-transform: uppercase; }}
QPushButton {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 7px 14px; }}
QPushButton:hover {{ background: {RAISED}; border-color: #34436a; }}
QPushButton:disabled {{ color: #56617a; background: {SURFACE}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: white; font-weight: 600; }}
QPushButton#primary:hover {{ background: #4f8ff7; }}
QPushButton#primary:disabled {{ background: #1e3a6b; border-color: #1e3a6b; color: #8aa3cc; }}
QPushButton#danger {{ background: #b91c1c; border: 1px solid #dc2626; color: white; font-weight: 700; }}
QPushButton#danger:hover {{ background: {BAD}; }}
QPushButton#danger:disabled {{ background: #3a1a1f; border-color: #4b2128; color: #a07a80; }}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 7px; padding: 6px 8px;
    selection-background-color: {ACCENT}; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox QAbstractItemView {{ background: {SURFACE2}; border: 1px solid {BORDER}; selection-background-color: {RAISED}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 16px; height: 16px; }}
QCheckBox::indicator {{ border: 1px solid #3a4867; border-radius: 4px; background: {SURFACE2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QRadioButton::indicator {{ border: 1px solid #3a4867; border-radius: 8px; background: {SURFACE2}; }}
QRadioButton::indicator:checked {{ background: {ACCENT}; border: 4px solid {SURFACE2}; outline: 1px solid {ACCENT}; }}
QTableView, QTableWidget, QListWidget, QTreeWidget {{ background: {SURFACE}; alternate-background-color: #131c30;
    border: 1px solid {BORDER}; border-radius: 10px; gridline-color: transparent;
    selection-background-color: #23345a; selection-color: {TEXT}; }}
QTableView::item, QTableWidget::item {{ padding: 4px; border-bottom: 1px solid #1a2338; }}
QListWidget::item {{ padding: 8px; border-radius: 6px; }}
QListWidget::item:selected {{ background: {RAISED}; }}
QHeaderView::section {{ background: {SURFACE}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px 6px; font-weight: 600; font-size: 12px; }}
QTableCornerButton::section {{ background: {SURFACE}; border: none; }}
QProgressBar {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 6px; height: 12px;
    text-align: center; font-size: 11px; color: {TEXT}; }}
QProgressBar::chunk {{ border-radius: 5px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
    stop:0 {ACCENT}, stop:1 {ACCENT2}); }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #2a3756; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #2a3756; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QSplitter::handle {{ background: {BG}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 10px; background: {SURFACE}; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 8px 14px; border: none; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT}; }}
QToolTip {{ background: {RAISED}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 10px; margin-top: 14px; padding: 12px 10px 10px 10px;
    background: {SURFACE}; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {MUTED}; }}
QFrame#jobbar {{ background: {SURFACE}; border-top: 1px solid {BORDER}; }}
QMessageBox, QDialog {{ background: {SURFACE}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
"""
