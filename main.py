#!/usr/bin/env python3
# fvs_network_tools_qt.py
"""
FVS Network Tools — PyQt5
May 11 2025  | Entirely self‑contained: all persistent data
(users, saved login, and application logs) lives in users.db.

CHANGES (May 11 2025)
────────────────────────────────────────────────────────────
• Saved‑credentials are now **encrypted** with Fernet (AES‑128 GCM).
  The key is machine‑specific: SHA‑256( SALT + hostname ).
• Database schema updated: saved_creds now stores a single
  encrypted TEXT field (`enc_blob`).
• Login auto‑fill now decrypts on start‑up; failure to decrypt
  simply yields empty fields rather than crashing.
• No placeholders; every function fully implemented.
"""

import base64
import ctypes
import hashlib
import logging
import os
import platform
import socket
import sqlite3
import subprocess
import sys
import threading

import bcrypt
import psutil
import requests
from cryptography.fernet import Fernet, InvalidToken
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QLabel, QLineEdit, QTextEdit, QPushButton,
    QCheckBox, QComboBox, QMenuBar, QMenu, QAction,
    QSplitter, QHBoxLayout, QVBoxLayout
)

# ---------------------------------------------------------------------- #
#                           CONSTANTS / PATHS                            #
# ---------------------------------------------------------------------- #

APP_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(APP_DIR, "users.db")
LOG_PATH  = os.path.join(APP_DIR, "app.log")
SALT      = b"FVS\x00SALTED\x00KEY"          # keep short & non‑obvious

# ---------------------------------------------------------------------- #
#                             ENCRYPTION CORE                            #
# ---------------------------------------------------------------------- #

def _get_cipher() -> Fernet:
    """
    Derive a per‑machine Fernet key:
        key = SHA‑256( SALT + hostname )  →  first 32 bytes → urlsafe_b64
    Fernet expects 32‑byte URL‑safe base64 key.
    """
    host = socket.gethostname().encode()
    raw  = hashlib.sha256(SALT + host).digest()       # 32 bytes
    token = base64.urlsafe_b64encode(raw)
    return Fernet(token)


def _encrypt_blob(plain: str) -> str:
    return _get_cipher().encrypt(plain.encode()).decode()


def _decrypt_blob(blob: str) -> str | None:
    try:
        return _get_cipher().decrypt(blob.encode()).decode()
    except InvalidToken:
        return None


# ---------------------------------------------------------------------- #
#                           DATABASE HELPERS                             #
# ---------------------------------------------------------------------- #

def init_db() -> None:
    """Create required tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL           -- bcrypt hash (utf‑8)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS saved_creds (
                id       INTEGER PRIMARY KEY CHECK (id = 1),
                enc_blob TEXT NOT NULL           -- encrypted "user||pass"
            )
        """)
        conn.commit()


def add_user(username: str, password_plain: str) -> None:
    """Insert or replace a user (stored with bcrypt hash)."""
    hashed = bcrypt.hashpw(password_plain.encode(), bcrypt.gensalt()).decode()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()


def verify_user(username: str, password_plain: str) -> bool:
    """Return True if credentials match DB entry."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()
    return bool(row and bcrypt.checkpw(password_plain.encode(), row[0].encode()))


def save_login(username: str, password_plain: str) -> None:
    """Persist last successful login (encrypted)."""
    blob = _encrypt_blob(f"{username}||{password_plain}")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM saved_creds WHERE id = 1")
        conn.execute(
            "INSERT INTO saved_creds (id, enc_blob) VALUES (1, ?)",
            (blob,)
        )
        conn.commit()


def load_login() -> tuple[str | None, str | None]:
    """Return (username, password) or (None, None) if nothing stored / decrypt fails."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT enc_blob FROM saved_creds WHERE id = 1"
        ).fetchone()
    if not row:
        return (None, None)
    plain = _decrypt_blob(row[0])
    if plain and "||" in plain:
        return tuple(plain.split("||", 1))
    return (None, None)


# initialise DB immediately
init_db()

# ---------------------------------------------------------------------- #
#                           PRIVILEGE ESCALATION                         #
# ---------------------------------------------------------------------- #

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if not is_admin():
    # relaunch self with admin rights
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

# ---------------------------------------------------------------------- #
#                           NON‑GUI UTILITIES                            #
# ---------------------------------------------------------------------- #

def wifi_tools():
    logging.info('Net Tools button clicked')
    script_path = os.path.join(APP_DIR, 'network_gui.py')
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch network_gui.py:", str(e))


def ping_host(host: str, text_widget: QTextEdit):
    cmd = ['ping', '-n', '4', host] if platform.system() == "Windows" else \
          ['ping', '-c', '4', host]
    result = subprocess.run(cmd, stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    append_to_widget(text_widget, result.stdout)


def whois_search(domain: str, text_widget: QTextEdit):
    result = subprocess.run(f"wsl whois {domain}",
                            stdout=subprocess.PIPE,
                            text=True, shell=True)
    append_to_widget(text_widget, result.stdout)


def get_nmap(ip: str) -> str:
    ip_range = f"{ip}/24"
    result = subprocess.run(['nmap', '-T4', '-F', ip_range],
                            stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    return result.stdout


def open_nmap_scan(text_widget: QTextEdit, entry_widget: QLineEdit):
    ip = get_active_ip(entry_widget)
    results = get_nmap(ip)
    display_nmap_results(text_widget, results, entry_widget)


def display_nmap_results(text_widget: QTextEdit, results: str, entry_widget: QLineEdit):
    ip_range = get_active_ip(entry_widget)
    nmap_text = get_nmap(ip_range)
    text_widget.clear()
    colors = ['#3399ff', '#00ff99', '#cc66ff', '#ff6666', '#ff9933']
    for idx, line in enumerate(nmap_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def get_netstat_ano() -> str:
    result = subprocess.run(['netstat', '-ano'], stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    return result.stdout


def update_text_with_netstat(text_widget: QTextEdit):
    ano_text = get_netstat_ano()
    text_widget.clear()
    colors = ['#3399ff', '#00ff99', '#cc66ff', '#ff6666']
    for idx, line in enumerate(ano_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def get_ipconfig() -> str:
    if os.name == 'nt':
        result = subprocess.run(['ipconfig', '/all'],
                                stdout=subprocess.PIPE,
                                text=True, encoding='utf-8')
    else:
        result = subprocess.run(['ifconfig', '-a'],
                                stdout=subprocess.PIPE,
                                text=True, encoding='utf-8')
    return result.stdout


def display_ipconfig(text_widget: QTextEdit):
    text_widget.clear()
    ipconfig_text = get_ipconfig()
    colors = ['#3399ff', '#00ff99', '#cc66ff', '#ff6666']
    for idx, line in enumerate(ipconfig_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def flush_dns(text_widget: QTextEdit):
    result = os.popen('ipconfig /flushdns').read()
    text_widget.append(result)


def ipconfig_release(text_widget: QTextEdit):
    result = subprocess.run(['ipconfig', '/release'],
                            stdout=subprocess.PIPE, text=True, encoding='utf-8')
    append_to_widget(text_widget, result.stdout)


def ipconfig_renew(text_widget: QTextEdit):
    result = subprocess.run(['ipconfig', '/renew'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8')
    output = result.stdout + result.stderr
    if not output.strip():
        output = "Renewal successful!"
    append_to_widget(text_widget, output)


def display_netstat(right_text_widget: QTextEdit):
    result = subprocess.run(['netstat', '-b'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, shell=True)
    lines = result.stdout.split('\n') + result.stderr.split('\n')
    for line in lines:
        if '.exe' in line:
            right_text_widget.append(f'<span style="color:#3399ff">{line}</span>')
        else:
            right_text_widget.append(line)


def get_mac_vendor(mac: str) -> str:
    url = f"https://api.macvendors.com/{mac}"
    try:
        response = requests.get(url, timeout=3)
        return response.text if response.status_code == 200 else "Unknown"
    except requests.RequestException:
        return "Unknown"


def get_active_ip(entry_widget: QLineEdit) -> str:
    return entry_widget.text().strip()


def get_active_connections() -> str:
    conns = psutil.net_connections(kind='inet')
    port_services = {
        20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client',
        69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 119: 'NNTP',
        123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS', 138: 'NetBIOS',
        139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'SMTP (Submission)', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1433: 'SQL Server', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
        5060: 'SIP', 5061: 'SIPS', 5432: 'PostgreSQL', 5500: 'VNC',
        5900: 'VNC', 8080: 'HTTP (Alt)', 8443: 'HTTPS (Alt)'
    }

    conns = sorted(conns, key=lambda c: c.laddr.port)
    summary = "Active Network Connections:\n---------------------------\n"
    for c in conns:
        local_port = c.laddr.port
        svc = port_services.get(local_port, 'Unknown')
        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
        summary += (f"Local: {c.laddr.ip}:{local_port} ({svc}) ➜ "
                    f"Remote: {remote}  Status: {c.status}\n")
    return summary


def display_connections(text_widget: QTextEdit):
    text_widget.clear()
    for line in get_active_connections().splitlines():
        external = ("Remote: " in line and "N/A" not in line and
                    not line.startswith("Active"))
        listen = "Status: LISTEN" in line
        if listen:
            text_widget.append(f'<span style="color:#ff6666">{line}</span>')
        elif external:
            text_widget.append(f'<span style="color:#3399ff">{line}  (External)</span>')
        else:
            text_widget.append(line)


def get_ip_and_subnet_mask(interface_name: str | None = None) -> tuple[str | None, str | None]:
    for iface, addrs in psutil.net_if_addrs().items():
        if interface_name and iface != interface_name:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address, addr.netmask
    return None, None


def scan_network_results(text_widget: QTextEdit, iface: str):
    text_widget.clear()
    text_widget.append("Scanning network, please wait…")
    threading.Thread(target=_perform_scan, args=(text_widget, iface),
                     daemon=True).start()


def _perform_scan(text_widget: QTextEdit, iface: str):
    ip, mask = get_ip_and_subnet_mask(iface)
    if not ip or not mask:
        text_widget.append(f"No valid interface found for {iface}.")
        return
    text_widget.append(f"Scanning {ip}/24 …")
    ip_range = ip.rsplit('.', 1)[0] + '.1/24'
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                      ARP(pdst=ip_range), timeout=2, verbose=False,
                      iface=iface)
    text_widget.append("Devices found:")
    for _, rcv in answered:
        vendor = get_mac_vendor(rcv.hwsrc)
        text_widget.append(f"IP: {rcv.psrc:15}  MAC: {rcv.hwsrc}  Vendor: {vendor}")
    text_widget.append("Scan completed.")


# ---------------------------------------------------------------------- #
#                             QT HELPERS                                 #
# ---------------------------------------------------------------------- #

def append_to_widget(widget: QTextEdit, text: str):
    widget.clear()
    widget.append(text)
    widget.verticalScrollBar().setValue(
        widget.verticalScrollBar().maximum())


# ---------------------------------------------------------------------- #
#                         REGISTER DIALOG                                #
# ---------------------------------------------------------------------- #

class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register")
        self.setStyleSheet("background:#0d0d0d;color:#00ff99;")
        layout = QVBoxLayout(self)

        self.username = QLineEdit(self)
        self.username.setPlaceholderText("Username")
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Password")
        self.confirm = QLineEdit(self)
        self.confirm.setEchoMode(QLineEdit.Password)
        self.confirm.setPlaceholderText("Confirm Password")
        self.status = QLabel("", self)

        reg_btn = QPushButton("Register", self)
        reg_btn.clicked.connect(self.register)

        for w in (self.username, self.password, self.confirm, reg_btn, self.status):
            layout.addWidget(w)

    def register(self):
        user = self.username.text().strip()
        pw = self.password.text()
        cpw = self.confirm.text()
        if not user or not pw:
            self.status.setText("Username / password required")
            return
        if pw != cpw:
            self.status.setText("Passwords do not match")
            return
        add_user(user, pw)
        self.status.setText("Registration successful!")
        LoginWindow.username_entry.setText(user)
        self.accept()


# ---------------------------------------------------------------------- #
#                      LOGIN & MAIN WINDOWS                              #
# ---------------------------------------------------------------------- #

class LoginWindow(QWidget):
    username_entry: QLineEdit = None
    password_entry: QLineEdit = None
    save_creds_var: QCheckBox = None

    def __init__(self):
        super().__init__()
        self.setWindowTitle("FVS Networking Tools – Login")
        self.resize(800, 450)

        # overall window style
        self.setStyleSheet("""
            QWidget {
                background:qlineargradient(x1:0,y1:0,x2:1,y2:1,
                    stop:0 #0d0d0d, stop:1 #1a1a1a);
                color:#00ff99;
                font-family:"Consolas",monospace;
            }
            QLabel#title       {font-size:28px;color:#00ffcc;margin-bottom:20px;}
            QLabel#status      {font-size:16px;color:#ff3366;margin-bottom:20px;}
            QLineEdit          {background:#1e1e1e;border:1px solid #00ff99;
                                border-radius:5px;padding:8px;font-size:16px;}
            QLineEdit:focus    {border:1px solid #ffcc00;}
            QPushButton        {background:#00ff99;border:none;border-radius:5px;
                                padding:10px;font-size:16px;font-weight:bold;
                                color:#0d0d0d;margin-top:10px;}
            QPushButton:hover  {background:#66ffb2;}
            QPushButton:pressed{background:#00cc7a;}
            QCheckBox          {spacing:5px;padding:5px;}
            QCheckBox::indicator{
                width:16px;height:16px;border:1px solid #00ff99;background:#1e1e1e;}
            QCheckBox::indicator:checked{background:#00ff99;}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 30, 50, 30)
        layout.setSpacing(15)

        title = QLabel("FVS Networking Tools", self)
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.status = QLabel("INITIALIZING…", self)
        self.status.setObjectName("status")
        self.status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status)

        # rotating messages
        self.messages = [
            "SCAN NETWORK", "ACTIVE CONNECTIONS", "IP CONFIGURATION",
            "IP RELEASE", "IP RENEW", "NETSTAT -b", "NETSTAT -ano",
            "OPEN Nmap", "PING", "WHOIS", "NET TOOLS", "PROCESS ID CHECK",
            "PASS GENERATOR", "PACKET SNIFFER", "NETSH", "WIFI BRUTE FORCER",
            "SHOW WIFI PROFILE", "SHOW BSSID"
        ]
        self.msg_idx = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._animate_status)
        self.timer.start(1000)

        # credential fields
        LoginWindow.username_entry = QLineEdit(self)
        LoginWindow.username_entry.setPlaceholderText("Username")
        layout.addWidget(LoginWindow.username_entry)

        LoginWindow.password_entry = QLineEdit(self)
        LoginWindow.password_entry.setEchoMode(QLineEdit.Password)
        LoginWindow.password_entry.setPlaceholderText("Password")
        layout.addWidget(LoginWindow.password_entry)

        LoginWindow.save_creds_var = QCheckBox("Remember me", self)
        layout.addWidget(LoginWindow.save_creds_var)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(30)
        btn_login = QPushButton("Login", self)
        btn_reg   = QPushButton("Register", self)
        btn_login.clicked.connect(self._login)
        btn_reg.clicked.connect(self._open_register)
        btn_layout.addWidget(btn_login)
        btn_layout.addWidget(btn_reg)
        layout.addLayout(btn_layout)

        # preload saved login
        u, p = load_login()
        if u and p:
            LoginWindow.username_entry.setText(u)
            LoginWindow.password_entry.setText(p)
            LoginWindow.save_creds_var.setChecked(True)

    # ---------------- internal helpers ---------------- #
    def _animate_status(self):
        self.status.setText(self.messages[self.msg_idx])
        self.msg_idx = (self.msg_idx + 1) % len(self.messages)

    def _login(self):
        user = LoginWindow.username_entry.text().strip()
        pw_plain = LoginWindow.password_entry.text()
        if verify_user(user, pw_plain):
            if LoginWindow.save_creds_var.isChecked():
                save_login(user, pw_plain)
            else:
                # clear any previously saved creds
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("DELETE FROM saved_creds WHERE id = 1")
                    conn.commit()
            self.timer.stop()
            self.hide()
            self.main_win = MainWindow()
            self.main_win.showMaximized()
        else:
            self.status.setText("LOGIN FAILED")

    def _open_register(self):
        dlg = RegisterDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            LoginWindow.username_entry.setText(dlg.username.text())


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s")
        logging.info('Starting MainWindow')
        self.setWindowTitle("FVS Network Tools")
        self.setStyleSheet("background:#000;color:#00ff99;")

        # ---------------- Menu bar ---------------- #
        mb = QMenuBar(self)
        self.setMenuBar(mb)
        actions_menu = QMenu("IP Actions", self)
        mb.addMenu(actions_menu)

        # central widget
        central = QWidget(self)
        self.setCentralWidget(central)
        v_root = QVBoxLayout(central)

        # top toolbar line
        top_line = QHBoxLayout()
        v_root.addLayout(top_line)

        # interface dropdown
        self.iface_combo = QComboBox(self)
        for iface in self._get_network_interfaces():
            self.iface_combo.addItem(iface)
        top_line.addWidget(self.iface_combo)

        # toolbar buttons
        btns = [
            ("Scan Network", self._scan_click),
            ("Active Connections", self._active_conn_click),
            ("Netstat -b", self._netstat_b_click),
            ("Netstat -ano", self._netstat_ano_click),
            ("Open Nmap Scan", self._nmap_click),
            ("Ping", self._ping_click),
            ("WHOIS", self._whois_click),
            ("Net Tools", wifi_tools),
            ("Process ID Check", self._taskmgr_click)
        ]
        for text, slot in btns:
            b = QPushButton(text, self)
            b.clicked.connect(slot)
            top_line.addWidget(b)

        # IP / Domain entry
        self.input_entry = QLineEdit(self)
        self.input_entry.setPlaceholderText("Enter IP / domain / host …")
        v_root.addWidget(self.input_entry)

        # add IP action menu items
        actions_menu.addAction("IP Configuration",
                               lambda: display_ipconfig(self.middle_top))
        actions_menu.addAction("Release IP",
                               lambda: ipconfig_release(self.middle_top))
        actions_menu.addAction("Renew IP",
                               lambda: ipconfig_renew(self.middle_top))
        actions_menu.addAction("Flush DNS",
                               lambda: flush_dns(self.middle_top))

        # splitters for panes
        h_split = QSplitter(Qt.Horizontal, self)
        v_root.addWidget(h_split, 1)

        v_split = QSplitter(Qt.Vertical, h_split)

        self.middle_top = QTextEdit(self)
        self.middle_top.setReadOnly(False)
        self.middle_top.setStyleSheet("background:#000;color:#00ff99;")
        v_split.addWidget(self.middle_top)

        self.middle_bottom = QTextEdit(self)
        self.middle_bottom.setReadOnly(False)
        self.middle_bottom.setStyleSheet("background:#000;color:#00ff99;")
        v_split.addWidget(self.middle_bottom)

        self.right_text = QTextEdit(self)
        self.right_text.setReadOnly(False)
        self.right_text.setStyleSheet("background:#000;color:#00ff99;")
        h_split.addWidget(v_split)
        h_split.addWidget(self.right_text)
        h_split.setStretchFactor(0, 3)
        h_split.setStretchFactor(1, 1)

    # ------------ toolbar handlers ------------ #
    def _scan_click(self):
        scan_network_results(self.middle_top, self.iface_combo.currentText())

    def _active_conn_click(self):
        display_connections(self.middle_top)

    def _netstat_b_click(self):
        display_netstat(self.right_text)

    def _netstat_ano_click(self):
        update_text_with_netstat(self.right_text)

    def _nmap_click(self):
        open_nmap_scan(self.middle_top, self.input_entry)

    def _ping_click(self):
        ping_host(self.input_entry.text(), self.middle_bottom)

    def _whois_click(self):
        whois_search(self.input_entry.text(), self.middle_bottom)

    def _taskmgr_click(self):
        os.system("start taskmgr /7")

    # ------------ helpers ------------ #
    @staticmethod
    def _get_network_interfaces():
        return [i for i in psutil.net_if_addrs().keys() if i.lower() not in ('lo', 'loopback')]


# ---------------------------------------------------------------------- #
#                               MAIN ENTRY                               #
# ---------------------------------------------------------------------- #

if __name__ == '__main__':
    qt_app = QApplication(sys.argv)
    login = LoginWindow()
    login.showMaximized()
    sys.exit(qt_app.exec_())
