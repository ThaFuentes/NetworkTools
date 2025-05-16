import sys
import time
import json
from pathlib import Path
from pywifi import const, PyWiFi, Profile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QTextEdit, QVBoxLayout, QHBoxLayout, QScrollArea, QFrame
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# File paths
def_file = Path(__file__).parent
saved_profiles_file = def_file / 'saved_profiles.txt'

class WifiLoginUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Wi-Fi Login')
        self.setStyleSheet('background-color:#0d0d0d; color:#00ff99;')  # Green on black theme
        self.resize(600, 500)
        self.should_enable_save = False
        self._setup_ui()
        self.display_saved_profiles()

    def _setup_ui(self):
        font_label = QFont('Helvetica', 12)

        # SSID
        lbl_ssid = QLabel('SSID:')
        lbl_ssid.setFont(font_label)
        self.entry_ssid = QLineEdit()
        self.entry_ssid.setStyleSheet('background:#1e1e1e; color:#00ff99;')  # Dark input fields with green text

        # Password
        lbl_pass = QLabel('Password:')
        lbl_pass.setFont(font_label)
        self.entry_pass = QLineEdit()
        self.entry_pass.setEchoMode(QLineEdit.Password)
        self.entry_pass.setStyleSheet('background:#1e1e1e; color:#00ff99;')  # Dark input fields with green text

        # Save Profile button (disabled until connect)
        self.btn_save = QPushButton('Save Profile')
        self.btn_save.setEnabled(False)
        self.btn_save.setStyleSheet('background:#00ff99; color:#0d0d0d;')  # Green button with dark text
        self.btn_save.clicked.connect(self.save_profile)

        # Login button
        self.btn_login = QPushButton('Login')
        self.btn_login.setStyleSheet('background:#00ff99; color:#0d0d0d;')  # Green button with dark text
        self.btn_login.clicked.connect(self.login)

        # Clear output
        self.btn_clear = QPushButton('Clear Output')
        self.btn_clear.setStyleSheet('background:#00ff99; color:#0d0d0d;')  # Green button with dark text
        self.btn_clear.clicked.connect(self.clear_output)

        # Exit button
        self.btn_exit = QPushButton('Exit')
        self.btn_exit.setStyleSheet('background:#ff3333; color:#0d0d0d;')  # Red button for exit
        self.btn_exit.clicked.connect(self.close)

        # Output field
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet('background:#0d0d0d; color:#00ff99;')  # Green on black output
        self.output.setFont(QFont('Consolas', 10))

        # Saved profiles container in scroll
        self.profile_container = QWidget()
        self.profile_layout = QVBoxLayout(self.profile_container)
        self.profile_layout.setAlignment(Qt.AlignTop)
        scroll = QScrollArea()
        scroll.setWidget(self.profile_container)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        # Layout assembly
        top_layout = QHBoxLayout()
        top_layout.addWidget(lbl_ssid)
        top_layout.addWidget(self.entry_ssid)
        top_layout.addWidget(lbl_pass)
        top_layout.addWidget(self.entry_pass)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_login)
        btn_layout.addWidget(self.btn_save)
        btn_layout.addWidget(self.btn_clear)
        btn_layout.addWidget(self.btn_exit)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addLayout(btn_layout)
        main_layout.addWidget(self.output, 1)
        main_layout.addWidget(QLabel('Saved Profiles:'), 0)
        main_layout.addWidget(scroll, 2)

        self.setLayout(main_layout)

    def clear_output(self):
        self.output.clear()

    def login(self):
        ssid = self.entry_ssid.text().strip()
        pwd = self.entry_pass.text()
        if connect_to_wifi(ssid, pwd):
            self.output.append(f'Connected to {ssid} successfully!')
            self.btn_save.setEnabled(True)
            self.display_success_banner()
        else:
            self.output.append(f'Failed to connect to {ssid}.')

    def save_profile(self):
        ssid = self.entry_ssid.text().strip()
        pwd = self.entry_pass.text()
        profiles = []
        if saved_profiles_file.exists():
            profiles = [line.strip() for line in saved_profiles_file.read_text().splitlines()]
        entry = f'{ssid}:{pwd}'
        if entry not in profiles:
            profiles.append(entry)
            saved_profiles_file.write_text('\n'.join(profiles))
            self.output.append(f'Saved profile for {ssid}.')
            self.btn_save.setEnabled(False)
            self.display_saved_profiles()
        else:
            self.output.append(f'Profile for {ssid} already exists.')

    def display_saved_profiles(self):
        # clear existing
        for i in reversed(range(self.profile_layout.count())):
            widget = self.profile_layout.takeAt(i).widget()
            if widget:
                widget.deleteLater()

        if not saved_profiles_file.exists():
            return
        for line in saved_profiles_file.read_text().splitlines():
            if ':' not in line: continue
            ssid, pwd = line.split(':', 1)
            row = QHBoxLayout()
            lbl = QLabel(f'{ssid} : {pwd}')
            lbl.setStyleSheet('color:#00ff99;')
            btn_connect = QPushButton('Connect')
            btn_connect.setStyleSheet('background:#00ff99; color:#0d0d0d;')
            btn_connect.clicked.connect(lambda _, s=ssid, p=pwd: self.connect_saved(s, p))
            btn_remove = QPushButton('Remove')
            btn_remove.setStyleSheet('color:red;')
            btn_remove.clicked.connect(lambda _, s=ssid: self.remove_saved(s))
            row.addWidget(btn_remove)
            row.addWidget(lbl)
            row.addWidget(btn_connect)
            container = QWidget()
            container.setLayout(row)
            self.profile_layout.addWidget(container)

    def connect_saved(self, ssid, pwd):
        self.entry_ssid.setText(ssid)
        self.entry_pass.setText(pwd)
        self.login()

    def remove_saved(self, ssid):
        if not saved_profiles_file.exists(): return
        lines = [l for l in saved_profiles_file.read_text().splitlines() if not l.startswith(ssid+':')]
        saved_profiles_file.write_text('\n'.join(lines))
        self.output.append(f'Removed profile for {ssid}.')
        self.display_saved_profiles()

    def display_success_banner(self):
        pass  # omitted banner for brevity


# Wi-Fi connection logic
def connect_to_wifi(ssid, password):
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.disconnect()
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password
    prof = iface.add_network_profile(profile)
    iface.connect(prof)
    for _ in range(5):
        time.sleep(1)
        if iface.status() == const.IFACE_CONNECTED:
            return True
    return False

# Run
app = QApplication(sys.argv)
window = WifiLoginUI()
window.show()
sys.exit(app.exec_())
