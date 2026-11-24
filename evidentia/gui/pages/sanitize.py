from __future__ import annotations

import html
import json
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
                               QFormLayout, QGridLayout, QHBoxLayout, QHeaderView, QLineEdit, QListWidget, QMessageBox,
                               QRadioButton, QScrollArea, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from ...core.devices import SafetyError, list_devices
from ...sanitize import certificate
from ...sanitize.engine import Request, Target, image_partitions
from ...sanitize.media import APPLICABLE, METHODS, PROFILES, guidance, method_warning
from .. import theme as T
from ..confirm_dialogs import run_erase_confirmation
from ..widgets import Banner, Card, Pill, button, human, label, open_path

TARGETS = [("copy", "Evidence working copy"), ("image", "Image file"), ("partition", "Partition inside an image"),
           ("files", "Files / folders"), ("device", "Physical device (advanced)")]


class SanitizePage(QWidget):
    def __init__(self, state):
        super().__init__()
        self.setObjectName("page")
        self.state = state
        self.last = None
        root = QHBoxLayout(self)
        root.setContentsMargins(32, 14, 32, 18)
        split = QSplitter()

        form = QWidget()
        fv = QVBoxLayout(form)
        fv.setContentsMargins(0, 0, 10, 0)
        fv.setSpacing(12)
        # 1. target
        c1 = Card("1 · Target")
        self.tgroup = QButtonGroup(self)
        trow = QGridLayout()
        self.tbtn = {}
        for i, (key, text) in enumerate(TARGETS):
            rb = QRadioButton(text)
            self.tgroup.addButton(rb)
            self.tbtn[key] = rb
            rb.toggled.connect(self._target_changed)
            trow.addWidget(rb, i // 3, i % 3)
        c1.add(trow)
        self.tstack = QStackedWidget()
        # copy
        self.copybox = QComboBox()
        self.copybox.currentIndexChanged.connect(self._update)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(self.copybox, 1)
        l.addWidget(button("Create working copy…", None, lambda: self.state.navigate.emit("cases")))
        self.tstack.addWidget(w)
        # image
        self.imgpath = QLineEdit(); self.imgpath.setPlaceholderText("Choose a disk image to erase…")
        self.imgpath.textChanged.connect(self._update)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(self.imgpath, 1); l.addWidget(button("Browse…", None, lambda: self._browse(self.imgpath)))
        self.tstack.addWidget(w)
        # partition
        self.ppath = QLineEdit(); self.ppath.setPlaceholderText("Image containing a partition table…")
        self.ppath.editingFinished.connect(self._load_parts)
        self.pbox = QComboBox()
        self.pbox.currentIndexChanged.connect(self._update)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(self.ppath, 1); l.addWidget(button("Browse…", None, lambda: (self._browse(self.ppath), self._load_parts())))
        l.addWidget(self.pbox, 1)
        self.tstack.addWidget(w)
        # files
        self.flist = QListWidget(); self.flist.setFixedHeight(80)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(self.flist, 1)
        col = QVBoxLayout()
        col.addWidget(button("Add files…", None, self._add_files))
        col.addWidget(button("Add folder…", None, self._add_folder))
        col.addWidget(button("Clear", None, lambda: (self.flist.clear(), self._update())))
        l.addLayout(col)
        self.tstack.addWidget(w)
        # device
        self.devbox = QComboBox()
        self.devbox.currentIndexChanged.connect(self._update)
        w = QWidget(); l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
        l.addWidget(self.devbox, 1); l.addWidget(button("Refresh", None, self._load_devices))
        self.tstack.addWidget(w)
        c1.add(self.tstack)
        fv.addWidget(c1)
        # 2. media
        c2 = Card("2 · Media type")
        mrow = QHBoxLayout()
        self.profile = QComboBox()
        for k, v in PROFILES.items():
            self.profile.addItem(v, k)
        self.profile.currentIndexChanged.connect(self._profile_changed)
        mrow.addWidget(self.profile, 1)
        c2.add(mrow)
        self.simnote = label("", "muted")
        c2.add(self.simnote)
        self.guide = Banner()
        c2.add(self.guide)
        fv.addWidget(c2)
        # 3. method
        c3 = Card("3 · Method (NIST SP 800-88 Rev. 2)")
        self.mgroup = QButtonGroup(self)
        self.mbtn = {}
        for mid, m in METHODS.items():
            rb = QRadioButton(f"{m.label}")
            rb.setToolTip(m.description)
            rb.toggled.connect(self._update)
            self.mgroup.addButton(rb)
            self.mbtn[mid] = rb
            row = QHBoxLayout()
            row.addWidget(rb)
            row.addWidget(Pill(m.category.upper(), T.ACCENT2 if m.category == "Clear" else T.ACCENT))
            row.addStretch()
            c3.add(row)
        self.mdesc = label("", "muted", wrap=True)
        self.mwarn = Banner()
        c3.add(self.mdesc)
        c3.add(self.mwarn)
        fv.addWidget(c3)
        # 4. verification + safety
        c4 = Card("4 · Verification & safety")
        f = QFormLayout()
        vrow = QHBoxLayout()
        self.vmode = QComboBox()
        self.vmode.addItem("Sample read-back", "sample")
        self.vmode.addItem("Full read-back", "full")
        self.vpct = QDoubleSpinBox(); self.vpct.setRange(1, 100); self.vpct.setValue(10); self.vpct.setSuffix(" % of blocks")
        self.vmode.currentIndexChanged.connect(lambda: self.vpct.setEnabled(self.vmode.currentData() == "sample"))
        vrow.addWidget(self.vmode); vrow.addWidget(self.vpct); vrow.addStretch()
        f.addRow("Verification", vrow)
        self.dry = QCheckBox("Dry run — show the plan, write nothing")
        self.dry.setChecked(True)
        self.dry.toggled.connect(self._update)
        f.addRow("Mode", self.dry)
        self.confirm = QLineEdit()
        self.confirm.textChanged.connect(self._update)
        self.confirm_lbl = label("Device name", "muted")
        f.addRow(self.confirm_lbl, self.confirm)
        f.addRow("", label("Erasing always asks twice: a Yes/No summary, then typing CONFIRM.", "muted", wrap=True))
        c4.add(f)
        brow = QHBoxLayout()
        self.go = button("Run dry run", "primary", self.run)
        brow.addStretch()
        brow.addWidget(self.go)
        c4.add(brow)
        fv.addWidget(c4)
        fv.addStretch()
        sc = QScrollArea(); sc.setWidget(form); sc.setWidgetResizable(True)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        sc.setMinimumWidth(640)
        split.addWidget(sc)

        # right: result
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(10, 0, 0, 0)
        rv.setSpacing(12)
        res = Card("Plan & result")
        self.verdict = label("", wrap=True)
        res.add(self.verdict)
        self.out = label("Configure a target and method. Start with a dry run.", "muted", wrap=True)
        self.out.setTextInteractionFlags(Qt.TextSelectableByMouse)
        res.add(self.out)
        crow = QHBoxLayout()
        self.b_pdf = button("Open certificate PDF", None, lambda: open_path(self.last and self.last["certificate_pdf"]))
        self.b_json = button("Open JSON", None, lambda: open_path(self.last and self.last["certificate_json"]))
        self.b_ver = button("Verify signature", None, self._verify_cert)
        for b in (self.b_pdf, self.b_json, self.b_ver):
            b.setEnabled(False)
            crow.addWidget(b)
        crow.addStretch()
        res.add(crow)
        res.lay.addStretch()
        rv.addWidget(res, 3)
        hist = Card("Sanitization history (this case)")
        self.hist = QTableWidget(0, 6)
        self.hist.setHorizontalHeaderLabels(["Certificate", "Method", "NIST", "Target", "Result", "Finished"])
        self.hist.verticalHeader().hide()
        self.hist.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.hist.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.hist.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.hist.horizontalHeader().setStretchLastSection(True)
        self.hist.cellDoubleClicked.connect(lambda r, c: open_path(self.hist.item(r, 0).data(Qt.UserRole)))
        hist.add(self.hist)
        hist.add(label("Double-click a row to open its certificate.", "muted"))
        rv.addWidget(hist, 2)
        split.addWidget(right)
        split.setSizes([720, 620])
        root.addWidget(split)
        self.tbtn["copy"].setChecked(True)
        self.profile.setCurrentIndex(self.profile.findData("image"))
        state.case_changed.connect(lambda _: self.refresh())
        state.data_changed.connect(self.refresh)
        state.settings_changed.connect(self.refresh)

    # ----------------------------------------------------------------- data
    def on_show(self):
        self.refresh()

    def refresh(self):
        svc, cid = self.state.svc, self.state.case_id
        cur = self.copybox.currentData()
        self.copybox.blockSignals(True)
        self.copybox.clear()
        for e in (svc.list_evidence(cid) if cid else []):
            if e["kind"] == "working-copy":
                tag = " — already sanitized" if e["sanitized"] else ""
                self.copybox.addItem(f"#{e['id']} {e['label']} ({human(e['size'])}){tag}", e["id"])
        if not self.copybox.count():
            self.copybox.addItem("No working copies — create one on the Cases page", None)
        i = self.copybox.findData(cur)
        self.copybox.setCurrentIndex(max(0, i))
        self.copybox.blockSignals(False)
        adv = svc.settings.advanced_device_access
        self.tbtn["device"].setEnabled(adv)
        self.tbtn["device"].setToolTip("" if adv else "Enable Advanced device access in Settings")
        if not adv and self.tbtn["device"].isChecked():
            self.tbtn["copy"].setChecked(True)
        self.hist.setRowCount(0)
        for s in svc.sanitizations(cid) if cid else []:
            r = self.hist.rowCount()
            self.hist.insertRow(r)
            vals = [s["certificate_id"], METHODS[s["method"]].label, s["nist_category"],
                    f"{s['target'].get('kind')}: {os.path.basename(s['target'].get('path') or '')}", s["result"],
                    (s["finished_at"] or "")[:19].replace("T", " ")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setData(Qt.UserRole, s["certificate_pdf"])
                if c == 4:
                    it.setForeground(QColor(T.OK) if v == "PASS" else QColor(T.WARN) if v == "DRY-RUN" else QColor(T.BAD))
                self.hist.setItem(r, c, it)
        self._update()

    def _kind(self):
        return next(k for k, b in self.tbtn.items() if b.isChecked())

    def _target_changed(self):
        k = self._kind()
        self.tstack.setCurrentIndex([t[0] for t in TARGETS].index(k))
        if k == "device":
            self._load_devices()
        self._update()

    def _browse(self, edit):
        p, _ = QFileDialog.getOpenFileName(self, "Choose image", "", "Disk images (*.dd *.img *.raw *.bin);;All files (*)")
        if p:
            edit.setText(p)

    def _load_parts(self):
        self.pbox.clear()
        p = self.ppath.text().strip()
        if p and os.path.isfile(p):
            try:
                for part in image_partitions(p):
                    self.pbox.addItem(f"#{part['index']} {part['fs_type'] or '?'} — {part['description']} — "
                                      f"{human(part['length'])} @ {part['offset']}", part)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.warning(self, "Partitions", str(exc))
        self._update()

    def _add_files(self):
        for p in QFileDialog.getOpenFileNames(self, "Files to erase")[0]:
            self.flist.addItem(p)
        self._update()

    def _add_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Folder to erase")
        if p:
            self.flist.addItem(p)
        self._update()

    def _load_devices(self):
        self.devbox.clear()
        for d in list_devices():
            ok = d.allowed
            self.devbox.addItem(("" if ok else "⛔ ") + f"{d.name} — {d.model} — {human(d.size)} — {d.media_type}"
                                + ("" if ok else f"  (refused: {'; '.join(d.refusal_reasons())})"), d.to_dict())
        self._update()

    def _profile_changed(self):
        prof = self.profile.currentData()
        allowed = set(APPLICABLE[prof])
        first = None
        for mid, rb in self.mbtn.items():
            rb.setEnabled(mid in allowed)
            if mid in allowed and first is None:
                first = rb
        if not any(rb.isChecked() and rb.isEnabled() for rb in self.mbtn.values()) and first:
            first.setChecked(True)
        g = guidance(prof)
        color = T.WARN if prof in ("SSD", "NVMe", "USB") else T.ACCENT2
        if g:
            self.guide.show_msg("<br>".join(g), color, "⚠" if color == T.WARN else "ℹ")
        else:
            self.guide.hide()
        self._update()

    def _target(self) -> Target | None:
        k = self._kind()
        if k == "copy":
            eid = self.copybox.currentData()
            if eid is None:
                return None
            ev = self.state.svc.get_evidence(eid)
            return Target("image", ev["path"], label=ev["label"])
        if k == "image":
            p = self.imgpath.text().strip()
            return Target("image", p) if p else None
        if k == "partition":
            part = self.pbox.currentData()
            p = self.ppath.text().strip()
            return Target("partition", p, part["offset"], part["length"], partition=part) if part and p else None
        if k == "files":
            paths = [self.flist.item(i).text() for i in range(self.flist.count())]
            return Target("files", paths[0], paths=paths) if paths else None
        d = self.devbox.currentData()
        return Target("device", d["path"]) if d else None

    def _method(self):
        return next((m for m, b in self.mbtn.items() if b.isChecked()), None)

    def _update(self, *_):
        k = self._kind()
        if k == "device" and self.devbox.currentData():
            mt = self.devbox.currentData().get("media_type")
            if mt in PROFILES and self.profile.currentData() != mt:
                self.profile.setCurrentIndex(self.profile.findData(mt))
        self.profile.setEnabled(k != "device")
        self.simnote.setText("Purge commands are simulated on images" if k != "device" else "detected from device")
        m = self._method()
        prof = self.profile.currentData()
        if m:
            self.mdesc.setText(METHODS[m].description)
            w = method_warning(m, prof)
            if w:
                self.mwarn.show_msg(w, T.WARN, "⚠")
            else:
                self.mwarn.hide()
        t = self._target()
        dry = self.dry.isChecked()
        is_dev = t is not None and t.kind == "device"
        token = t.device_name if is_dev else ""
        self.confirm.setVisible(is_dev)
        self.confirm_lbl.setVisible(is_dev)
        self.confirm.setEnabled(not dry)
        self.confirm.setPlaceholderText("not required for a dry run" if dry else f"type “{token}” (device name)")
        ok = t is not None and m is not None and (dry or not is_dev or self.confirm.text().strip() == token)
        self.go.setEnabled(ok and not self.state.jobs.busy)
        self.go.setText("Run dry run" if dry else "⚠  ERASE & VERIFY")
        self.go.setObjectName("primary" if dry else "danger")
        self.go.style().unpolish(self.go)
        self.go.style().polish(self.go)

    # ----------------------------------------------------------------- run
    def run(self):
        t, m = self._target(), self._method()
        if not t or not m:
            return
        dry = self.dry.isChecked()
        req = Request(t, m, media_profile=self.profile.currentData(), verify_mode=self.vmode.currentData(),
                      sample_percent=self.vpct.value(), dry_run=dry,
                      confirm=self.confirm.text().strip() if t.kind == "device" else "")
        eid = self.copybox.currentData() if self._kind() == "copy" else None
        cid = self.state.case_id
        svc = self.state.svc
        auth = None
        if not dry:
            # Two-step confirmation (core-enforced): Yes/No summary, then typed CONFIRM.
            try:
                session = svc.begin_sanitize_confirmation(req, evidence_id=eid, case_id=cid)
            except SafetyError as e:
                self._fail(str(e))
                return
            ok = run_erase_confirmation(self, session)
            self.state.changed()  # the ledger now holds the confirmation steps
            if not ok:
                step = 1 if session.abort_reason.startswith("operator cancelled the Yes") else 2
                self.verdict.setText(f"<div style='font-size:20px;font-weight:800;color:{T.WARN}'>CANCELLED</div>")
                self.out.setText(f"Erase aborted at step {step}: {html.escape(session.abort_reason)}.<br>"
                                 "Nothing was written. The decision was recorded in the audit ledger.")
                return
            auth = session.authorization
        self.verdict.setText("")
        self.out.setText("Running…")
        self.state.jobs.start("Dry run" if dry else "Sanitizing", lambda ctx: svc.sanitize(
            req, evidence_id=eid, case_id=cid, ctx=ctx, authorization=auth), self._done,
            lambda msg, tb: self._fail(msg))

    def _fail(self, msg: str):
        self.out.setText(f"<span style='color:{T.BAD}'><b>Refused / failed:</b> {html.escape(msg)}</span>")

    def _done(self, out):
        self.last = out
        r, cert = out["result"], out["certificate"]
        res = cert["result"]
        col = T.OK if res == "PASS" else T.WARN if res == "DRY-RUN" else T.BAD
        self.verdict.setText(f"<div style='font-size:26px;font-weight:800;color:{col}'>{res}</div>"
                             f"<div style='color:{T.MUTED}'>{cert['nist_category']} · {cert['certificate_id']} · "
                             f"{'simulated firmware command' if r['simulated'] else 'host overwrite'}</div>")
        v = r["verification"]
        esc = html.escape
        lines = ["<b>Plan</b><br>" + "<br>".join(f"· {esc(p)}" for p in r["plan"])]
        if r["warnings"]:
            lines.append(f"<span style='color:{T.WARN}'>" + "<br>".join("⚠ " + esc(w) for w in r["warnings"]) + "</span>")
        if not r["dry_run"]:
            lines.append("<b>Passes</b><br>" + "<br>".join(
                f"· #{p['pass']} {p['pattern']} {'✓ verified' if p.get('verified') else ''}" for p in r["passes"]))
            vb = (f"{v.get('blocks_checked', v.get('files_verified'))} / {v.get('blocks_total', v.get('files_total'))} "
                  f"checked, {v.get('mismatched_blocks', 0)} mismatches")
            lines.append(f"<b>Verification ({v.get('mode')})</b><br>· {vb}<br>· residual file signatures: "
                         f"{v.get('residual_signatures') if v.get('residual_signatures') is not None else 'n/a'}<br>"
                         f"· SHA-256 before <span style='font-family:Menlo'>{(r.get('pre_sha256') or '-')[:32]}…</span><br>"
                         f"· SHA-256 after&nbsp;&nbsp; <span style='font-family:Menlo'>{(r.get('post_sha256') or '-')[:32]}…</span>")
            lines.append(f"<b>Timing</b><br>· {r['bytes_written']:,} bytes written in {r['duration_s']} s")
        if r["commands"]:
            lines.append("<b>Firmware commands</b>" + (" (simulated)" if r["simulated"] else "") + "<br>" + "<br>".join(
                f"<span style='font-family:Menlo'>$ {esc(' '.join(c))}</span>" for c in r["commands"]))
        self.out.setText("<br><br>".join(lines))
        for b in (self.b_pdf, self.b_json, self.b_ver):
            b.setEnabled(True)
        self.confirm.clear()
        self.dry.setChecked(True)

    def _verify_cert(self):
        if not self.last:
            return
        ok, why = certificate.verify(json.loads(open(self.last["certificate_json"]).read()))
        (QMessageBox.information if ok else QMessageBox.critical)(self, "Certificate signature",
                                                                  ("VALID — " if ok else "INVALID — ") + why)
