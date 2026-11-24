from __future__ import annotations

import os
import zipfile

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSize, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QSizePolicy, QComboBox, QFileDialog, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QScrollArea, QSplitter,
                               QStackedWidget, QTableView, QTabWidget, QTextBrowser, QVBoxLayout, QWidget)

from ...recovery.engine import RecoveryOptions
from ...recovery.signatures import SIGS
from .. import theme as T
from ..widgets import Card, ConfidenceDelegate, Pill, ScoreBreakdown, button, human, label

try:
    from PySide6.QtPdf import QPdfDocument
except ImportError:  # pragma: no cover
    QPdfDocument = None

COLS = ["", "Name", "Source", "Type", "Validation", "Confidence", "Size", "SHA-256"]
STATUS_COL = {"intact": T.OK, "partial": T.WARN, "corrupt": T.BAD, "unknown": T.MUTED}


class FilesModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.rows: list[dict] = []
        self._icons: dict[int, QIcon] = {}

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self._icons = {}
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(COLS)

    def headerData(self, s, o, role=Qt.DisplayRole):
        if o == Qt.Horizontal and role == Qt.DisplayRole:
            return COLS[s]
        return None

    def _icon(self, r):
        if r["id"] not in self._icons:
            p = r.get("thumbnail_path")
            self._icons[r["id"]] = QIcon(QPixmap(p).scaled(48, 36, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)) \
                if p and os.path.exists(p) else QIcon()
        return self._icons[r["id"]]

    def data(self, idx, role=Qt.DisplayRole):
        r = self.rows[idx.row()]
        c = idx.column()
        if role == Qt.DecorationRole and c == 0:
            return self._icon(r)
        if role == Qt.UserRole:
            return r["confidence"] if c == 5 else r
        if role == Qt.UserRole + 1:  # sort key
            return [None, r["name"].lower(), r["source"], r["detected_type"], r["validation_status"], r["confidence"] or 0,
                    r["size"], r["sha256"]][c]
        if role == Qt.ForegroundRole:
            if c == 4:
                return QColor(STATUS_COL.get(r["validation_status"], T.TEXT))
            if c == 3 and r["ext_mismatch"]:
                return QColor(T.BAD)
            if c in (2, 7) or r["superseded_by"]:
                return QColor(T.MUTED)
        if role == Qt.ToolTipRole:
            if c == 3 and r["ext_mismatch"]:
                return f"Content is {r['detected_type'].upper()} but the name says .{r['claimed_ext']}"
            if c == 7:
                return f"SHA-256 {r['sha256']}\nMD5     {r['md5']}"
            if r["superseded_by"]:
                return f"Superseded by / duplicate of item {r['superseded_by']}"
        if role == Qt.DisplayRole:
            if c == 1:
                return r["name"] + ("   (duplicate)" if r["superseded_by"] else "")
            if c == 2:
                return {"filesystem": "File system", "carved": "Carved", "reconstructed": "Reconstructed"}.get(r["source"], r["source"])
            if c == 3:
                return r["detected_type"].upper() + ("  ⚠ ext" if r["ext_mismatch"] else "")
            if c == 4:
                return r["validation_status"]
            if c == 5:
                return ""
            if c == 6:
                return human(r["size"])
            if c == 7:
                return r["sha256"][:20] + "…"
        return None


class SortProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.text = ""
        self.show_dupes = False
        self.setSortRole(Qt.UserRole + 1)

    def filterAcceptsRow(self, row, parent):
        r = self.sourceModel().rows[row]
        if r["superseded_by"] and not self.show_dupes:
            return False
        if self.text:
            hay = f"{r['name']} {r['path']} {r['detected_type']} {r['sha256']} {r['validation_status']}".lower()
            return self.text.lower() in hay
        return True


class Preview(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.img = QLabel(alignment=Qt.AlignCenter)
        self.img.setFixedHeight(250)
        self.img.setStyleSheet(f"background: {T.SURFACE2}; border-radius: 8px;")
        self.text = QPlainTextEdit(readOnly=True)
        self.text.setStyleSheet("font-family: Menlo, monospace; font-size: 11.5px;")
        self.addWidget(self.img)
        self.addWidget(self.text)
        self.setFixedHeight(250)
        self._pdf = QPdfDocument(self) if QPdfDocument else None

    def show_file(self, r):
        p = r.get("output_path")
        if not p or not os.path.exists(p):
            return self._msg("file not available")
        t = r["detected_type"]
        if t in ("jpeg", "png", "gif"):
            img = QImage(p)
            if img.isNull() and r.get("thumbnail_path"):
                img = QImage(r["thumbnail_path"])
            if not img.isNull():
                self.img.setPixmap(QPixmap.fromImage(img).scaled(440, 240, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                return self.setCurrentWidget(self.img)
        if t == "pdf" and self._pdf is not None:
            self._pdf.load(p)
            if self._pdf.pageCount() > 0:
                sz = self._pdf.pagePointSize(0)
                w = 760  # zoom into the top-left of page 1 so the text is legible
                im = self._pdf.render(0, QSize(w, int(w * sz.height() / sz.width())))
                self.img.setPixmap(QPixmap.fromImage(im.copy(int(w * 0.06), int(w * 0.03), 440, 240)))
                return self.setCurrentWidget(self.img)
        if t in ("docx", "xlsx", "pptx", "zip"):
            try:
                with zipfile.ZipFile(p) as z:
                    return self._msg("Archive contents:\n\n" + "\n".join(
                        f"{i.file_size:>10,}  {i.filename}" for i in z.infolist()))
            except Exception:  # noqa: BLE001 - not a readable archive: fall through to hex
                pass
        data = open(p, "rb").read(4096)
        if t == "text":
            return self._msg(data.decode("utf-8", "replace"))
        lines = [f"{o:08x}  {' '.join(f'{b:02x}' for b in data[o:o + 16]):<48}  "
                 f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in data[o:o + 16])}" for o in range(0, len(data), 16)]
        self._msg("\n".join(lines))

    def _msg(self, s):
        self.text.setPlainText(s)
        self.setCurrentWidget(self.text)


class RecoveryPage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 18, 26, 18)
        v.setSpacing(12)

        cfg = Card()
        r1 = QHBoxLayout()
        r1.addWidget(label("Evidence", "muted"))
        self.evbox = QComboBox()
        self.evbox.setMinimumWidth(360)
        r1.addWidget(self.evbox, 1)
        self.run_btn = button("▶  Run recovery", "primary", self.run)
        r1.addWidget(self.run_btn)
        cfg.add(r1)
        r2 = QHBoxLayout()
        r2.setSpacing(18)
        self.o_fs = QCheckBox("File-system recovery (TSK)")
        self.o_carve = QCheckBox("Signature carving")
        self.o_rec = QCheckBox("Fragment reconstruction")
        self.o_unalloc = QCheckBox("Carve unallocated space only")
        self.o_live = QCheckBox("Include live files")
        for cb in (self.o_fs, self.o_carve, self.o_rec, self.o_unalloc):
            cb.setChecked(True)
        for cb in (self.o_fs, self.o_carve, self.o_rec, self.o_unalloc, self.o_live):
            r2.addWidget(cb)
        r2.addStretch()
        cfg.add(r2)
        r3 = QHBoxLayout()
        r3.setSpacing(18)
        r3.addWidget(label("Carving signatures", "muted"))
        self.types = {}
        for name in SIGS:
            cb = QCheckBox(name.upper())
            cb.setChecked(True)
            cb.setToolTip(SIGS[name].description)
            self.types[name] = cb
            r3.addWidget(cb)
        r3.addStretch()
        cfg.add(r3)
        v.addWidget(cfg)

        bar = QHBoxLayout()
        bar.addWidget(label("Run", "muted"))
        self.runbox = QComboBox()
        self.runbox.setMinimumWidth(260)
        self.runbox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.runbox.currentIndexChanged.connect(self._load_run)
        bar.addWidget(self.runbox)
        self.integrity = Pill("", T.OK)
        bar.addWidget(self.integrity)
        self.stats = label("", "muted")
        self.stats.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bar.addWidget(self.stats, 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, type, hash…")
        self.search.setFixedWidth(220)
        self.search.textChanged.connect(self._filter)
        bar.addWidget(self.search)
        self.dupes = QCheckBox("Duplicates")
        self.dupes.setToolTip("Show carved copies that duplicate or were superseded by another result")
        self.dupes.toggled.connect(self._filter)
        bar.addWidget(self.dupes)
        bar.addWidget(button("Export selected…", None, self.export))
        v.addLayout(bar)

        split = QSplitter()
        self.model = FilesModel()
        self.proxy = SortProxy()
        self.proxy.setSourceModel(self.model)
        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setAlternatingRowColors(True)
        self.view.verticalHeader().hide()
        self.view.verticalHeader().setDefaultSectionSize(44)
        self.view.setIconSize(QSize(48, 36))
        self.view.setItemDelegateForColumn(5, ConfidenceDelegate(self.view))
        self.view.setShowGrid(False)
        h = self.view.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.resizeSection(5, 140)
        h.setSectionResizeMode(5, QHeaderView.Fixed)
        self.view.selectionModel().currentRowChanged.connect(self._select)
        split.addWidget(self.view)

        det = QWidget()
        det.setMinimumWidth(470)
        dv = QVBoxLayout(det)
        dv.setContentsMargins(12, 0, 0, 0)
        dv.setSpacing(8)
        self.d_title = label("Select a recovered file", "h2", wrap=True)
        dv.addWidget(self.d_title)
        self.d_pills = QHBoxLayout()
        self.p_status, self.p_src, self.p_mm = Pill(), Pill(), Pill()
        for p in (self.p_status, self.p_src, self.p_mm):
            self.d_pills.addWidget(p)
            p.hide()
        self.d_pills.addStretch()
        dv.addLayout(self.d_pills)
        self.preview = Preview()
        dv.addWidget(self.preview)
        self.tabs = QTabWidget()
        sw = QWidget()
        sl = QVBoxLayout(sw)
        sl.setContentsMargins(14, 12, 14, 12)
        self.score = ScoreBreakdown()
        sl.addWidget(self.score)
        sl.addStretch()
        ss = QScrollArea()
        ss.setWidget(sw)
        ss.setWidgetResizable(True)
        ss.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tabs.addTab(ss, "Confidence breakdown")
        self.d_info = QTextBrowser()
        self.d_info.setOpenLinks(False)
        self.d_info.setStyleSheet("QTextBrowser { border: none; background: transparent; font-size: 12px; }")
        self.tabs.addTab(self.d_info, "Details && hashes")
        dv.addWidget(self.tabs, 1)
        split.addWidget(det)
        split.setSizes([900, 500])
        v.addWidget(split, 1)
        state.case_changed.connect(lambda _: self.refresh())
        state.data_changed.connect(self.refresh)

    def on_show(self):
        self.refresh()

    def refresh(self):
        svc, cid = self.state.svc, self.state.case_id
        cur = self.evbox.currentData()
        self.evbox.clear()
        if cid:
            for e in svc.list_evidence(cid):
                if not e["sanitized"]:
                    self.evbox.addItem(f"#{e['id']} {e['label']}  ({e['kind']}, {human(e['size'])})", e["id"])
        if cur is not None and self.evbox.findData(cur) >= 0:
            self.evbox.setCurrentIndex(self.evbox.findData(cur))
        cur_run = self.runbox.currentData()
        self.runbox.blockSignals(True)
        self.runbox.clear()
        runs = svc.list_runs(cid) if cid else []
        for r in reversed(runs):
            self.runbox.addItem(f"Run #{r['id']} · evidence #{r['evidence_id']} · "
                                f"{(r.get('finished_at') or r['status'])[:16].replace('T', ' ')}", r["id"])
        self.runbox.blockSignals(False)
        if runs:
            idx = self.runbox.findData(cur_run)
            self.runbox.setCurrentIndex(idx if idx >= 0 else 0)
            self._load_run()
        else:
            self.model.set_rows([])
            self.integrity.hide()
            self.stats.setText("No recovery runs for this case yet.")
        self.run_btn.setEnabled(self.evbox.count() > 0)

    def _load_run(self, *_):
        rid = self.runbox.currentData()
        if rid is None:
            return
        svc = self.state.svc
        run = svc.get_run(rid)
        self.model.set_rows(svc.recovered_files(rid))
        self.view.sortByColumn(5, Qt.DescendingOrder)
        s = run.get("stats") or {}
        if run.get("status") == "complete":
            ok = bool(run["source_unchanged"])
            self.integrity.set("SOURCE UNCHANGED ✓" if ok else "SOURCE CHANGED ✗", T.OK if ok else T.BAD)
            self.integrity.setToolTip(f"pre  {run['pre_sha256']}\npost {run['post_sha256']}")
            self.integrity.show()
        self.stats.setText(f"{s.get('total', 0) - s.get('superseded', 0)} unique · {s.get('intact', 0)} intact · "
                           f"{s.get('reconstructed', 0)} reconstructed · {s.get('ext_mismatch', 0)} ext mismatch")
        self._filter()

    def _filter(self, *_):
        self.proxy.text = self.search.text()
        self.proxy.show_dupes = self.dupes.isChecked()
        self.proxy.invalidate()

    def _select(self, cur, _prev):
        if not cur.isValid():
            return
        r = self.model.rows[self.proxy.mapToSource(cur).row()]
        d = r["detail"]
        self.d_title.setText(r["name"])
        self.p_status.set(r["validation_status"].upper(), STATUS_COL.get(r["validation_status"], T.MUTED))
        self.p_src.set(r["source"].upper(), T.ACCENT2)
        self.p_mm.set(f"CONTENT {r['detected_type'].upper()} ≠ .{r['claimed_ext']}", T.BAD)
        self.p_status.show()
        self.p_src.show()
        self.p_mm.setVisible(bool(r["ext_mismatch"]))
        self.preview.show_file(r)
        self.score.set_score(d.get("score"))
        v = d.get("validation", {})
        frags = d.get("fragments") or []
        times = {k: x for k, x in (d.get("times") or {}).items() if x}
        rows = [("Path", r["path"]), ("Offset", f"0x{r['offset']:x} ({r['offset']:,})" if r["offset"] is not None else "-"),
                ("Size", f"{r['size']:,} bytes"), ("MIME", r["mime"]),
                ("Validator", "; ".join(v.get("issues") or []) or v.get("info", {}).get("entropy_check") or "no issues"),
                ("Fragments", "<br>".join(f"#{i + 1}: offset 0x{a:x}, {b:,} bytes" for i, (a, b) in enumerate(frags[:6])) or "-"),
                ("Entropy", f"{d.get('entropy', 0):.3f} bits/byte"),
                ("Timestamps", "<br>".join(f"{k}: {x[:19].replace('T', ' ')}" for k, x in times.items()) or "-"),
                ("Notes", "<br>".join(d.get("notes") or []) or "-"),
                ("SHA-256", f"<span style='font-family:Menlo,monospace'>{r['sha256']}</span>"),
                ("MD5", f"<span style='font-family:Menlo,monospace'>{r['md5']}</span>"),
                ("Saved to", r["output_path"])]
        self.d_info.setText("<table cellspacing='4'>" + "".join(
            f"<tr><td style='color:{T.MUTED};padding-right:10px;vertical-align:top'>{k}</td><td>{val}</td></tr>"
            for k, val in rows) + "</table>")

    def run(self):
        eid = self.evbox.currentData()
        if eid is None:
            return
        opts = RecoveryOptions(filesystem=self.o_fs.isChecked(), carving=self.o_carve.isChecked(),
                               reconstruct=self.o_rec.isChecked(), unallocated_only=self.o_unalloc.isChecked(),
                               include_allocated=self.o_live.isChecked(),
                               types=[n for n, cb in self.types.items() if cb.isChecked()])
        svc = self.state.svc

        def done(run):
            self.refresh()
            st = run.get("stats") or {}
            QMessageBox.information(self, "Recovery complete",
                                    f"{st.get('total', 0)} items ({st.get('intact', 0)} intact, {st.get('reconstructed', 0)} "
                                    f"reconstructed).\nSource evidence {'UNCHANGED' if run['source_unchanged'] else 'CHANGED'} "
                                    f"(SHA-256 verified before and after).")
        self.state.jobs.start("Recovering files", lambda ctx: svc.run_recovery(eid, opts, ctx), done)

    def export(self):
        rows = {self.proxy.mapToSource(i).row() for i in self.view.selectionModel().selectedRows()}
        if not rows:
            QMessageBox.information(self, "Export", "Select one or more files to export.")
            return
        dest = QFileDialog.getExistingDirectory(self, "Export recovered files to…")
        if not dest:
            return
        ids = [self.model.rows[r]["id"] for r in rows]
        self.state.jobs.start("Exporting files", lambda ctx: self.state.svc.export_files(ids, dest, ctx),
                              lambda out: QMessageBox.information(
                                  self, "Export complete", f"{len(out)} file(s) exported; hashes re-verified: "
                                  f"{'all match' if all(o['verified'] for o in out) else 'MISMATCH'}.\n"
                                  "The export is recorded in the chain of custody."))
