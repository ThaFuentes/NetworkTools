import ctypes
import logging
import json
import bcrypt
import psutil
import socket
import threading
import requests
import subprocess
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import os
import sys
import platform

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QLabel, QLineEdit, QTextEdit, QPushButton,
    QCheckBox, QComboBox, QMenuBar, QMenu, QAction,
    QSplitter, QHBoxLayout, QVBoxLayout
)

# --------------------------- NON‑GUI HELPERS --------------------------- #

active_ip = ''


def load_credentials():
    try:
        with open('credentials.txt', 'r') as file:
            username = file.readline().strip()
            password = file.readline().strip()
            return username, password
    except FileNotFoundError:
        return None, None


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)


def wifi_tools():
    logging.info('Net Tools button clicked')
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'network_gui.py')
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch network_gui.py:", str(e))


# --------------------------- COMMAND FUNCTIONS --------------------------- #

def ping_host(host, text_widget):
    cmd = ['ping', '-n', '4', host] if platform.system() == "Windows" else [
        'ping', '-c', '4', host]
    result = subprocess.run(cmd, stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    append_to_widget(text_widget, result.stdout)


def whois_search(domain, text_widget):
    result = subprocess.run(f"wsl whois {domain}",
                            stdout=subprocess.PIPE,
                            text=True, shell=True)
    append_to_widget(text_widget, result.stdout)


def get_nmap(ip):
    ip_range = f"{ip}/24"
    result = subprocess.run(['nmap', '-T4', '-F', ip_range],
                            stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    return result.stdout


def open_nmap_scan(text_widget, entry_widget):
    ip = get_active_ip(entry_widget)
    results = get_nmap(ip)
    display_nmap_results(text_widget, results, entry_widget)


def display_nmap_results(text_widget, results, entry_widget):
    ip_range = get_active_ip(entry_widget)
    nmap_text = get_nmap(ip_range)
    text_widget.clear()
    colors = ['blue', 'green', 'purple', 'red', 'orange']
    for idx, line in enumerate(nmap_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def get_netstat_ano():
    result = subprocess.run(['netstat', '-ano'], stdout=subprocess.PIPE,
                            text=True, encoding='utf-8')
    return result.stdout


def update_text_with_netstat(text_widget):
    ano_text = get_netstat_ano()
    text_widget.clear()
    colors = ['blue', 'green', 'purple', 'red']
    for idx, line in enumerate(ano_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def get_ipconfig():
    if os.name == 'nt':
        result = subprocess.run(['ipconfig', '/all'],
                                stdout=subprocess.PIPE,
                                text=True, encoding='utf-8')
    else:
        result = subprocess.run(['ifconfig', '-a'],
                                stdout=subprocess.PIPE,
                                text=True, encoding='utf-8')
    return result.stdout


def display_ipconfig(text_widget):
    text_widget.clear()
    ipconfig_text = get_ipconfig()
    colors = ['blue', 'green', 'purple', 'red']
    for idx, line in enumerate(ipconfig_text.splitlines()):
        color = colors[idx % len(colors)]
        text_widget.append(f'<span style="color:{color}">{line}</span>')


def run_command(command, text_widget):
    cmd = ' '.join(command)
    full_cmd = f'{sys.executable} -c "import subprocess; subprocess.run([\'{cmd}\'], shell=True)"'
    full_command = f'runas /user:Administrator "{full_cmd}"'
    result = subprocess.run(full_command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, shell=True)
    append_to_widget(text_widget, result.stdout + result.stderr)


def flush_dns(text_widget):
    result = os.popen('ipconfig /flushdns').read()
    text_widget.append(result)


def ipconfig_release(text_widget):
    result = subprocess.run(['ipconfig', '/release'],
                            stdout=subprocess.PIPE, text=True, encoding='utf-8')
    append_to_widget(text_widget, result.stdout)


def ipconfig_renew(text_widget):
    result = subprocess.run(['ipconfig', '/renew'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8')
    output = result.stdout + result.stderr
    if not output.strip():
        output = "Renewal successful!"
    append_to_widget(text_widget, output)


def display_netstat(right_text_widget):
    result = subprocess.run(['netstat', '-b'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, shell=True)
    lines = result.stdout.split('\n') + result.stderr.split('\n')
    for line in lines:
        if '.exe' in line:
            right_text_widget.append(
                f'<span style="color:blue">{line}</span>')
        else:
            right_text_widget.append(line)


def get_mac_vendor(mac):
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url)
    return response.text if response.status_code == 200 else "Unknown"


def get_active_ip(entry_widget):
    return entry_widget.text()


def get_active_connections():
    conns = psutil.net_connections(kind='inet')
    port_services = {20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
                     25: 'SMTP', 53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client',
                     69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
                     119: 'NNTP', 123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS',
                     138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
                     162: 'SNMP Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
                     465: 'SMTPS', 514: 'Syslog', 587: 'SMTP (Submission)',
                     636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server',
                     1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP',
                     5061: 'SIPS', 5432: 'PostgreSQL', 5500: 'VNC', 5900: 'VNC',
                     8080: 'HTTP (Alternate)', 8443: 'HTTPS (Alternate)'}

    conns = sorted(conns, key=lambda c: c.laddr.port)
    summary = "Active Network Connections:\n---------------------------\n"
    for c in conns:
        local_port = c.laddr.port
        svc = port_services.get(local_port, 'Unknown')
        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
        summary += (f"Local: {c.laddr.ip}:{local_port} ({svc}) --> "
                    f"Remote: {remote}  Status: {c.status}\n")
    return summary


def display_connections(text_widget):
    text_widget.clear()
    for line in get_active_connections().splitlines():
        is_external = ("Remote: " in line and "N/A" not in line
                       and not line.startswith("Active"))
        is_listen = "Status: LISTEN" in line
        if is_listen:
            text_widget.append(f'<span style="color:red">{line}</span>')
        elif is_external:
            text_widget.append(f'<span style="color:blue">{line} (External Connection)</span>')
        else:
            text_widget.append(line)


def get_ip_and_subnet_mask(interface_name=None):
    for iface, addrs in psutil.net_if_addrs().items():
        if interface_name and iface != interface_name:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address, addr.netmask
    return None, None


def scan_network_results(text_widget, iface):
    text_widget.clear()
    text_widget.append("Scanning network, please wait…")
    threading.Thread(target=perform_scan, args=(
        text_widget, iface), daemon=True).start()


def perform_scan(text_widget, iface):
    ip, mask = get_ip_and_subnet_mask(iface)
    if not ip or not mask:
        text_widget.append(f"No valid interface found for {iface}.")
        return
    text_widget.append(f"Scanning {ip} /24 …")
    ip_range = ip.rsplit('.', 1)[0] + '.1/24'
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") /
                      ARP(pdst=ip_range), timeout=2, verbose=False,
                      iface=iface)
    text_widget.append("Devices found:")
    for _, rcv in answered:
        text_widget.append(f"IP: {rcv.psrc}  MAC: {rcv.hwsrc}")
    text_widget.append("Scan completed.")


# --------------------------- STORAGE UTILS --------------------------- #

def save_credentials():
    if LoginWindow.save_creds_var.isChecked():
        with open('credentials.txt', 'w') as file:
            file.write(f"{LoginWindow.username_entry.text()}\n"
                       f"{LoginWindow.password_entry.text()}")


def save_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}
    users[username] = {'password': hashed.decode('utf-8')}
    with open('users.json', 'w') as f:
        json.dump(users, f)


def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# --------------------------- QT HELPERS --------------------------- #

def append_to_widget(widget: QTextEdit, text: str):
    widget.clear()
    widget.append(text)
    widget.verticalScrollBar().setValue(
        widget.verticalScrollBar().maximum())


# --------------------------- REGISTER DIALOG --------------------------- #

class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register")
        self.setStyleSheet("background:black;color:green;")
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
        user = self.username.text()
        pw = self.password.text()
        cpw = self.confirm.text()
        if pw != cpw:
            self.status.setText("Passwords do not match")
            return
        save_user(user, pw)
        self.status.setText("Registration successful!")
        LoginWindow.username_entry.setText(user)
        self.accept()


# --------------------------- MAIN APPLICATION WINDOWS --------------------------- #

class LoginWindow(QWidget):
    username_entry: QLineEdit = None
    password_entry: QLineEdit = None
    save_creds_var: QCheckBox = None

    def __init__(self):
        super().__init__()
        self.setWindowTitle("FVS Networking Tools – Login")
        self.setStyleSheet("background:black;color:green;")
        self.resize(800, 400)

        v = QVBoxLayout(self)

        welcome = QLabel("Welcome To FVS Networking Tools", self)
        welcome.setAlignment(Qt.AlignCenter)
        welcome.setStyleSheet("font-size:24px;")
        v.addWidget(welcome)

        self.status = QLabel("SCAN NETWORK", self)
        self.status.setAlignment(Qt.AlignCenter)
        self.status.setStyleSheet("font-size:18px;")
        v.addWidget(self.status)

        LoginWindow.username_entry = QLineEdit(self)
        LoginWindow.username_entry.setPlaceholderText("Username")
        v.addWidget(LoginWindow.username_entry)

        LoginWindow.password_entry = QLineEdit(self)
        LoginWindow.password_entry.setEchoMode(QLineEdit.Password)
        LoginWindow.password_entry.setPlaceholderText("Password")
        v.addWidget(LoginWindow.password_entry)

        LoginWindow.save_creds_var = QCheckBox("Save Username", self)
        v.addWidget(LoginWindow.save_creds_var)

        btn_login = QPushButton("Login", self)
        btn_reg = QPushButton("Register", self)
        v.addWidget(btn_login)
        v.addWidget(btn_reg)

        btn_login.clicked.connect(self.login)
        btn_reg.clicked.connect(self.open_register)

        # preload creds
        u, p = load_credentials()
        if u and p:
            LoginWindow.username_entry.setText(u)
            LoginWindow.password_entry.setText(p)

        # status animation
        self.messages = ["SCAN NETWORK", "ACTIVE CONNECTIONS", "IP CONFIGURATION", "IP RELEASE",
                         "IP RENEW", "NETSTAT -b", "NETSTAT -anon", "OPEN Nmap", "PING",
                         "WHOIS", "NET TOOLS", "PROCESS ID CHECK", "PASS GENERATOR",
                         "PACKET SNIFFER", "NETSH", "PASS GENERATING WIFI BRUTE FORCER",
                         "PASS-LIST WIFI BRUTE FORCER", "SHOW WIFI PROFILE(WITH LOCAL PASSWORD)",
                         "SHOW BSSID"]
        self.msg_idx = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate_status)
        self.timer.start(1000)

    def animate_status(self):
        self.msg_idx = (self.msg_idx + 1) % len(self.messages)
        self.status.setText(self.messages[self.msg_idx])

    def login(self):
        user = LoginWindow.username_entry.text()
        pw = LoginWindow.password_entry.text().encode('utf-8')
        users = load_users()
        if user in users and bcrypt.checkpw(pw, users[user]['password'].encode('utf-8')):
            if LoginWindow.save_creds_var.isChecked():
                save_credentials()
            self.hide()
            self.main_win = MainWindow()
            self.main_win.showMaximized()
        else:
            self.status.setText("Login failed!")

    def open_register(self):
        dlg = RegisterDialog(self)
        dlg.exec_()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        logging.basicConfig(filename='app.log', level=logging.INFO)
        logging.info('Starting MainWindow')
        self.setWindowTitle("FVS Network Tools")
        self.setStyleSheet("background:black;color:green;")

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
        for iface in self.get_network_interfaces():
            self.iface_combo.addItem(iface)
        top_line.addWidget(self.iface_combo)

        # toolbar buttons
        btns = [
            ("Scan Network", self.scan_click),
            ("Active Connections", self.active_conn_click),
            ("Netstat -b", self.netstat_b_click),
            ("Netstat -ano", self.netstat_ano_click),
            ("Open Nmap Scan", self.nmap_click),
            ("Ping", self.ping_click),
            ("WHOIS", self.whois_click),
            ("Net Tools", wifi_tools),
            ("Process ID Check", self.taskmgr_click)
        ]
        for text, slot in btns:
            b = QPushButton(text, self)
            b.clicked.connect(slot)
            top_line.addWidget(b)

        # add IP action menu items now that widgets exist
        actions_menu.addAction("IP Configuration",
                               lambda: display_ipconfig(self.middle_top))
        actions_menu.addAction("Release IP",
                               lambda: ipconfig_release(self.middle_top))
        actions_menu.addAction("Renew IP",
                               lambda: ipconfig_renew(self.middle_top))
        actions_menu.addAction("Flush DNS",
                               lambda: flush_dns(self.middle_top))

        # ---------------- splitters for panes ---------------- #
        h_split = QSplitter(Qt.Horizontal, self)
        v_root.addWidget(h_split, 1)

        v_split = QSplitter(Qt.Vertical, h_split)

        self.middle_top = QTextEdit(self)
        self.middle_top.setReadOnly(False)
        self.middle_top.setStyleSheet("background:black;color:green;")
        v_split.addWidget(self.middle_top)

        self.middle_bottom = QTextEdit(self)
        self.middle_bottom.setReadOnly(False)
        self.middle_bottom.setStyleSheet("background:black;color:green;")
        v_split.addWidget(self.middle_bottom)

        self.right_text = QTextEdit(self)
        self.right_text.setReadOnly(False)
        self.right_text.setStyleSheet("background:black;color:green;")
        h_split.addWidget(v_split)
        h_split.addWidget(self.right_text)
        h_split.setStretchFactor(0, 3)
        h_split.setStretchFactor(1, 1)

        # input line
        self.input_entry = QLineEdit(self)
        self.input_entry.setPlaceholderText("Enter IP / domain / host …")
        v_root.addWidget(self.input_entry)

    # ------------ toolbar handlers ------------ #
    def scan_click(self):
        scan_network_results(self.middle_top, self.iface_combo.currentText())

    def active_conn_click(self):
        display_connections(self.middle_top)

    def netstat_b_click(self):
        display_netstat(self.right_text)

    def netstat_ano_click(self):
        update_text_with_netstat(self.right_text)

    def nmap_click(self):
        open_nmap_scan(self.middle_top, self.input_entry)

    def ping_click(self):
        ping_host(self.input_entry.text(), self.middle_bottom)

    def whois_click(self):
        whois_search(self.input_entry.text(), self.middle_bottom)

    def taskmgr_click(self):
        os.system("start taskmgr /7")

    # ------------ helpers ------------ #
    @staticmethod
    def get_network_interfaces():
        return [i for i, _ in psutil.net_if_addrs().items() if i != 'lo']


# --------------------------- MAIN ENTRY --------------------------- #

if __name__ == '__main__':
    qt_app = QApplication(sys.argv)
    login = LoginWindow()
    login.showMaximized()
    sys.exit(qt_app.exec_())
