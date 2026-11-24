"""Light institutional theme: terracotta primary, slate secondary, warm neutral surfaces.

Tokens follow a Material 3 style palette (primary #9e3d00, secondary #4e6073). Headline text uses Geist and
body text uses Inter when they are installed; otherwise the platform UI font is used.
"""

# ---- surfaces
BG = "#f8f9fa"            # background / surface
SURFACE = "#ffffff"       # surface-container-lowest (cards, tables)
SURFACE2 = "#f3f4f5"      # surface-container-low (inputs, inner cards, alternate rows)
RAISED = "#e7e8e9"        # surface-container-high (hover)
BORDER = "#e0c0b2"        # outline-variant
DIVIDER = "#edeeef"       # surface-container (row separators)

# ---- text
TEXT = "#191c1d"          # on-surface
MUTED = "#7a6156"         # outline, darkened slightly so small text keeps 4.5:1 contrast on white
SUBTLE = "#594238"        # on-surface-variant

# ---- brand
ACCENT = "#9e3d00"        # primary
ACCENT_HOVER = "#b54a0a"
ACCENT_SOFT = "#ffdbcd"   # primary-fixed (icon tiles, selection)
ON_ACCENT_SOFT = "#351000"
ACCENT2 = "#4e6073"       # secondary (slate)
SECONDARY_SOFT = "#cfe2f9"
SIDEBAR = "#4e6073"
ON_SIDEBAR = "#ffffff"

# ---- status
OK = "#1e8e4e"            # success text/bars (the draft's #27AE60, darkened for legibility on white)
OK_SOFT = "#eaf7ee"
WARN = "#a46700"          # tertiary-container (amber)
WARN_SOFT = "#fff8e1"
BAD = "#ba1a1a"           # error
BAD_SOFT = "#ffdad6"      # error-container

HEAD_FONT = "Geist"
BODY_FONTS = ["Inter", "Geist", ".AppleSystemUIFont", "Segoe UI", "Helvetica Neue", "Arial"]
MONO = "Menlo, 'DejaVu Sans Mono', Consolas, monospace"

_ASSETS = __import__("pathlib").Path(__file__).with_name("assets").as_posix()


def conf_color(v: int | None) -> str:
    v = v or 0
    return OK if v >= 80 else WARN if v >= 50 else BAD


def apply_fonts(app) -> None:
    """Prefer Inter for body text, falling back to the platform UI font."""
    import sys

    from PySide6.QtGui import QFont
    f = QFont()
    f.setFamilies(BODY_FONTS)
    f.setPointSize(13 if sys.platform == "darwin" else 10)
    app.setFont(f)


def apply(app) -> None:
    """Fusion style, a light palette (so macOS dark mode does not leak into dialogs), fonts and the QSS."""
    from PySide6.QtGui import QColor, QPalette
    app.setStyle("Fusion")
    try:
        from PySide6.QtCore import Qt
        app.styleHints().setColorScheme(Qt.ColorScheme.Light)
    except (AttributeError, ImportError):  # Qt < 6.8
        pass
    pal = app.style().standardPalette()
    for role, col in ((QPalette.Window, BG), (QPalette.Base, SURFACE), (QPalette.AlternateBase, SURFACE2),
                      (QPalette.Text, TEXT), (QPalette.WindowText, TEXT), (QPalette.ButtonText, TEXT),
                      (QPalette.Button, SURFACE), (QPalette.Highlight, ACCENT_SOFT),
                      (QPalette.HighlightedText, ON_ACCENT_SOFT), (QPalette.ToolTipBase, "#2e3132"),
                      (QPalette.ToolTipText, "#f0f1f2"), (QPalette.PlaceholderText, MUTED), (QPalette.Link, ACCENT)):
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    apply_fonts(app)
    app.setStyleSheet(QSS)


QSS = f"""
* {{ color: {TEXT}; font-size: 13px; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget#page {{ background: {BG}; }}

/* ---- top navigation bar */
QFrame#topnav {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}
QLabel#brand {{ font-family: {HEAD_FONT}; font-size: 20px; font-weight: 700; color: {ACCENT}; }}
QLabel#topLink {{ color: {ACCENT}; font-weight: 700; padding: 4px 0; border-bottom: 2px solid {ACCENT}; }}
QLabel#topUser {{ color: {ACCENT2}; }}

/* ---- slate sidebar */
QFrame#sidebar {{ background: {SIDEBAR}; border: none; }}
QFrame#sidebar QLabel {{ color: {ON_SIDEBAR}; }}
QLabel#sideRole {{ font-family: {HEAD_FONT}; font-size: 14px; font-weight: 700; letter-spacing: 0.5px; }}
QLabel#sideSession {{ font-size: 10.5px; color: rgba(255,255,255,0.7); }}
QLabel#sideFoot {{ font-size: 11px; color: rgba(255,255,255,0.75); }}
QPushButton#nav {{ text-align: left; padding: 9px 14px; border: none; border-radius: 8px;
                   color: rgba(255,255,255,0.82); background: transparent; font-size: 13.5px; font-weight: 600;
                   letter-spacing: 0.3px; }}
QPushButton#nav:hover {{ background: rgba(255,255,255,0.10); color: white; }}
QPushButton#nav:checked {{ background: {ACCENT}; color: white; }}

/* ---- page header */
QFrame#pagehead {{ background: {BG}; }}
QLabel#pageTitle {{ font-family: {HEAD_FONT}; font-size: 28px; font-weight: 600; color: {TEXT}; }}
QLabel#pageSub {{ color: {ACCENT2}; font-size: 14px; }}
QLabel#muted, QLabel[muted="true"] {{ color: {MUTED}; }}
QLabel#h2 {{ font-family: {HEAD_FONT}; font-size: 15px; font-weight: 600; color: {TEXT}; }}
QLabel#mono {{ font-family: {MONO}; font-size: 11.5px; color: {SUBTLE}; }}

/* ---- cards */
QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 4px; }}
QFrame#card:hover {{ border-color: {ACCENT}; }}
QFrame#cardInner {{ background: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 4px; }}
QFrame#statCard {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 4px; }}
QFrame#statCard:hover {{ border-color: {ACCENT}; }}
QLabel#statValue {{ font-family: {HEAD_FONT}; font-size: 28px; font-weight: 700; }}
QLabel#statLabel {{ color: {MUTED}; font-size: 11.5px; font-weight: 600; letter-spacing: 0.6px; }}
QLabel#iconTile {{ border-radius: 8px; font-size: 20px; font-weight: 700; }}

/* ---- buttons */
QPushButton {{ background: {SURFACE}; color: {ACCENT2}; border: 1px solid {ACCENT2}; border-radius: 4px;
               padding: 7px 13px; font-weight: 600; }}
QPushButton:hover {{ background: rgba(78,96,115,0.06); }}
QPushButton:pressed {{ background: rgba(78,96,115,0.12); }}
QPushButton:disabled {{ color: #a9b2bc; border-color: {BORDER}; background: {SURFACE}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: white; font-weight: 700; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#primary:disabled {{ background: #d9b7a6; border-color: #d9b7a6; color: #fff5f0; }}
QPushButton#cta {{ background: {ACCENT}; border: none; color: white; font-weight: 700; border-radius: 17px;
                   min-height: 34px; max-height: 34px; padding: 0 26px; letter-spacing: 0.6px; }}
QPushButton#cta:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#danger {{ background: {BAD}; border: 1px solid {BAD}; color: white; font-weight: 700; }}
QPushButton#danger:hover {{ background: #d32222; }}
QPushButton#danger:disabled {{ background: {BAD_SOFT}; border-color: {BAD_SOFT}; color: #b07a76; }}
QPushButton#link {{ background: transparent; border: none; color: {ACCENT2}; padding: 4px 6px; }}
QPushButton#link:hover {{ color: {ACCENT}; }}

/* ---- inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextBrowser {{
    background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 4px; padding: 6px 8px;
    selection-background-color: {ACCENT_SOFT}; selection-color: {ON_ACCENT_SOFT}; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QComboBox QAbstractItemView {{ background: {SURFACE}; border: 1px solid {BORDER};
    selection-background-color: {ACCENT_SOFT}; selection-color: {ON_ACCENT_SOFT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QCheckBox, QRadioButton {{ spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{ width: 16px; height: 16px; }}
QCheckBox::indicator {{ border: 1px solid {MUTED}; border-radius: 3px; background: {SURFACE}; }}
QCheckBox::indicator:checked {{ border: none; image: url({_ASSETS}/check.svg); }}
QCheckBox::indicator:disabled {{ background: {SURFACE2}; border-color: {BORDER}; }}
QCheckBox::indicator:checked:disabled {{ border: none; image: url({_ASSETS}/check_disabled.svg); }}
QRadioButton::indicator {{ border: 1px solid {MUTED}; border-radius: 8px; background: {SURFACE}; }}
QRadioButton::indicator:checked {{ border: none; image: url({_ASSETS}/radio.svg); }}

/* ---- tables and lists */
QTableView, QTableWidget, QListWidget, QTreeWidget {{ background: {SURFACE}; alternate-background-color: #fafbfb;
    border: 1px solid {BORDER}; border-radius: 4px; gridline-color: transparent;
    selection-background-color: {ACCENT_SOFT}; selection-color: {ON_ACCENT_SOFT}; }}
QTableView::item, QTableWidget::item {{ padding: 4px; border-bottom: 1px solid {DIVIDER}; }}
QListWidget::item {{ padding: 8px; border-radius: 4px; border-bottom: 1px solid {DIVIDER}; }}
QListWidget::item:selected {{ background: {ACCENT_SOFT}; color: {ON_ACCENT_SOFT}; }}
QListWidget::item:hover {{ background: {SURFACE2}; }}
QHeaderView::section {{ background: {SURFACE2}; color: {ACCENT2}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px 6px; font-weight: 700; font-size: 12px; }}
QTableCornerButton::section {{ background: {SURFACE2}; border: none; }}

/* ---- progress, scrollbars, tabs */
QProgressBar {{ background: {RAISED}; border: none; border-radius: 4px; height: 10px;
    text-align: center; font-size: 11px; color: {TEXT}; }}
QProgressBar::chunk {{ border-radius: 4px; background: {ACCENT}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #cfd3d6; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #b5bbc0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #cfd3d6; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QSplitter::handle {{ background: {BG}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 4px; background: {SURFACE}; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {ACCENT2}; padding: 8px 14px; border: none; font-weight: 600; }}
QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {ACCENT}; }}
QToolTip {{ background: #2e3132; color: #f0f1f2; border: none; padding: 6px; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 4px; margin-top: 14px; padding: 12px 10px 10px 10px;
    background: {SURFACE}; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {ACCENT2}; }}

/* ---- fixed footer with job progress */
QFrame#footer {{ background: {BG}; border-top: 1px solid {BORDER}; }}
QLabel#footNote {{ color: {MUTED}; font-size: 12px; font-weight: 600; letter-spacing: 0.4px; }}
QLabel#footHint {{ color: {ACCENT2}; font-size: 12px; }}
QMessageBox, QDialog {{ background: {SURFACE}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
"""
