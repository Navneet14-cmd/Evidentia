"""Reusable widgets."""
from __future__ import annotations

import os

from PySide6.QtCore import QRectF, QSize, Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter, QPainterPath
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton,
                               QSizePolicy, QStyledItemDelegate, QVBoxLayout, QWidget)

from . import theme as T


def open_path(path: str) -> None:
    if path and os.path.exists(path):
        QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))


def rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    return f"rgba({int(h[0:2], 16)}, {int(h[2:4], 16)}, {int(h[4:6], 16)}, {alpha})"


def label(text: str = "", obj: str | None = None, wrap: bool = False, sel: bool = False) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    if sel:
        lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lb


def button(text: str, kind: str | None = None, slot=None, tip: str | None = None) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if slot:
        b.clicked.connect(slot)
    if tip:
        b.setToolTip(tip)
    b.setCursor(Qt.PointingHandCursor)
    return b


class Card(QFrame):
    def __init__(self, title: str | None = None, inner: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("cardInner" if inner else "card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(10)
        if title:
            self.title = label(title, "h2")
            self.lay.addWidget(self.title)

    def add(self, w):
        if isinstance(w, QWidget):
            self.lay.addWidget(w)
        else:
            self.lay.addLayout(w)
        return w


class StatCard(QFrame):
    """Metric card: a tinted icon tile beside an uppercase caption, a large value and a sub-line."""

    def __init__(self, caption: str, accent: str = T.ACCENT, icon: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        self.accent = accent
        outer = QHBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(14)
        self.tile = QLabel(icon)
        self.tile.setObjectName("iconTile")
        self.tile.setFixedSize(44, 44)
        self.tile.setAlignment(Qt.AlignCenter)
        self._paint_tile(accent)
        outer.addWidget(self.tile, 0, Qt.AlignTop)
        lay = QVBoxLayout()
        lay.setSpacing(2)
        self.value = label("–", "statValue")
        self.value.setStyleSheet(f"color: {accent};")
        self.caption = label(caption.upper(), "statLabel")
        self.sub = label("", "muted", wrap=True)
        self.sub.setStyleSheet("font-size: 12px;")
        lay.addWidget(self.caption)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)
        outer.addLayout(lay, 1)
        self.setMinimumHeight(112)

    def _paint_tile(self, color: str):
        self.tile.setStyleSheet(f"background: {rgba(color, 0.12)}; color: {color};")

    def set(self, value, sub: str = "", color: str | None = None):
        self.value.setText(str(value))
        self.sub.setText(sub)
        if color:
            self.value.setStyleSheet(f"color: {color};")
            self._paint_tile(color)


class Pill(QLabel):
    """Rounded status chip. Soft (tinted) by default; ``filled`` gives a solid chip with white text."""

    def __init__(self, text="", color=T.ACCENT, parent=None, filled: bool = False):
        super().__init__(text, parent)
        self.set(text, color, filled)

    def set(self, text, color, filled: bool = False):
        self.setText(text)
        if filled:
            style = f"background: {color}; color: white; border: 1px solid {color};"
        else:
            style = f"background: {rgba(color, 0.10)}; color: {color}; border: 1px solid {rgba(color, 0.28)};"
        self.setStyleSheet(style + " border-radius: 11px; padding: 3px 12px; font-weight: 700; font-size: 11.5px;"
                           " letter-spacing: 0.4px;")
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)


class Banner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self.icon = QLabel()
        self.icon.setStyleSheet("font-size: 18px; font-weight: 800;")
        self.text = label("", wrap=True)
        lay.addWidget(self.icon)
        lay.addWidget(self.text, 1)
        self.hide()

    def show_msg(self, text: str, color: str = T.ACCENT2, icon: str = "ℹ"):
        self.icon.setText(icon)
        self.icon.setStyleSheet(f"font-size: 18px; font-weight: 800; color: {color}; background: transparent;")
        self.text.setText(text)
        self.text.setStyleSheet(f"color: {T.TEXT}; background: transparent;")
        self.setStyleSheet(f"Banner {{ background: {rgba(color, 0.08)}; border: 1px solid {rgba(color, 0.30)};"
                           f" border-left: 4px solid {color}; border-radius: 4px; }}")
        self.show()


class ScoreBreakdown(QWidget):
    """Four horizontal bars (metadata / validation / fragmentation / entropy) with reasons."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(14)
        self.total = QLabel()
        self.lay.addWidget(self.total)
        self.rows = []

    def set_score(self, score: dict | None):
        for w in self.rows:
            w.setParent(None)
        self.rows = []
        if not score:
            self.total.setText("")
            return
        c = T.conf_color(score["total"])
        self.total.setText(f"<span style='font-size:30px;font-weight:800;color:{c}'>{score['total']}</span>"
                           f"<span style='color:{T.MUTED}'> / 100 &nbsp; {score['grade'].upper()} confidence</span>")
        for comp in score["components"]:
            w = QWidget()
            v = QVBoxLayout(w)
            v.setContentsMargins(0, 0, 0, 0)
            v.setSpacing(4)
            w.setMinimumHeight(64 if len(comp["reason"]) <= 64 else 80)
            head = QHBoxLayout()
            head.addWidget(label(comp["label"]))
            head.addStretch()
            head.addWidget(label(f"<b>{comp['points']}</b> <span style='color:{T.MUTED}'>/ {comp['max']}</span>"))
            v.addLayout(head)
            bar = QProgressBar()
            bar.setRange(0, comp["max"])
            bar.setValue(comp["points"])
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            frac = comp["points"] / comp["max"] if comp["max"] else 0
            col = T.OK if frac >= 0.8 else T.WARN if frac >= 0.45 else T.BAD
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {col}; border-radius: 4px; }}")
            v.addWidget(bar)
            r = label(comp["reason"], "muted", wrap=True)
            r.setStyleSheet("font-size: 11.5px;")
            r.ensurePolished()
            r.setMinimumHeight(r.fontMetrics().height() * (2 if len(comp["reason"]) > 64 else 1) + 4)
            v.addWidget(r)
            self.lay.addWidget(w)
            self.rows.append(w)


class ConfidenceDelegate(QStyledItemDelegate):
    """Paints a 0-100 confidence value as a coloured bar with the number."""

    def paint(self, painter: QPainter, option, index):
        v = index.data(Qt.UserRole)
        if v is None:
            return super().paint(painter, option, index)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        r = option.rect.adjusted(8, option.rect.height() // 2 - 5, -36, -(option.rect.height() // 2 - 5))
        path = QPainterPath()
        path.addRoundedRect(QRectF(r), 4, 4)
        painter.fillPath(path, QColor(T.RAISED))
        fill = QRectF(r.x(), r.y(), r.width() * max(0, min(100, v)) / 100, r.height())
        p2 = QPainterPath()
        p2.addRoundedRect(fill, 4, 4)
        painter.fillPath(p2, QColor(T.conf_color(v)))
        painter.setPen(QColor(T.TEXT))
        f = QFont(option.font)
        f.setBold(True)
        painter.setFont(f)
        painter.drawText(option.rect.adjusted(0, 0, -6, 0), Qt.AlignRight | Qt.AlignVCenter, str(v))
        painter.restore()

    def sizeHint(self, option, index):
        return QSize(120, 34)


def error_box(parent, title: str, msg: str):
    QMessageBox.critical(parent, title, msg)


def human(n: int | None) -> str:
    if n is None:
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)
