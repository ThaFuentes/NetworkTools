import sys
import ctypes
import os
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QTextEdit,
    QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QLineEdit, QFrame
)
from PyQt5.QtGui import QFont


# === Check for Admin Permissions ===
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)


# === Functions for launching scripts ===
def launch_wifi():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi.py')
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch wifi.py:", str(e))


def launch_wifi_pwlist():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi_crack_pwlists.py')
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch wifi_crack_pwlists.py:", str(e))


def show_wifi_profiles():
    command = 'netsh wlan show profiles'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output_text.append(output.decode("utf-8"))
    if error:
        output_text.append(error.decode("utf-8"))


def show_bssid_networks():
    command = 'netsh wlan show networks mode=bssid'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output_text.append(output.decode("utf-8"))
    if error:
        output_text.append(error.decode("utf-8"))


def execute_netsh_command():
    wifi_name = variable_input.text()
    if wifi_name:
        command = f'netsh wlan show profile "{wifi_name}" key=clear'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        output_text.append(output.decode("utf-8"))
        if error:
            output_text.append(error.decode("utf-8"))
    else:
        output_text.append("Please enter a Wi-Fi name.")


def launch_net_sniffer():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'net_monitor.py')
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print("Failed to launch net_sniffer.py:", str(e))


def launch_password():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'password.py')
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print("Failed to launch password.py:", str(e))


def launch_dns_monitor():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dns_monitor_gui.py')
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print("Failed to launch dns_monitor_gui.py:", str(e))


# === Main Window ===
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FVS Network Tools Menu")
        self.setStyleSheet("background-color:#0d0d0d;color:#00ff99;")
        self.resize(750, 700)  # Set initial window size (width, height)
        self._build_ui()

    def _build_ui(self):
        # Welcome Label
        welcome_label = QLabel("Welcome To FVS Network Tools", self)
        welcome_label.setFont(QFont("Helvetica", 16))
        welcome_label.setStyleSheet("color:#00ff99;")

        # Output Text Box
        global output_text
        output_text = QTextEdit(self)
        output_text.setReadOnly(True)
        output_text.setStyleSheet("background:#0d0d0d;color:#00ff99;")
        output_text.setFont(QFont("Consolas", 10))

        # Input Field for Wi-Fi Profile
        global variable_input
        variable_input = QLineEdit(self)
        variable_input.setStyleSheet("background:#1e1e1e;color:#00ff99;")

        # Button Layout for the top part (Brute Force and Profiles)
        top_layout = QVBoxLayout()
        top_layout.addWidget(welcome_label)

        # Group Wi-Fi Buttons
        wifi_button = QPushButton("Pass Gen Wi-Fi Brute Forcer", self)
        wifi_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        wifi_button.clicked.connect(launch_wifi)

        wifi_button_pwlist = QPushButton("Pass List Wi-Fi Brute Forcer", self)
        wifi_button_pwlist.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        wifi_button_pwlist.clicked.connect(launch_wifi_pwlist)

        wifi_group_layout = QHBoxLayout()
        wifi_group_layout.addWidget(wifi_button)
        wifi_group_layout.addWidget(wifi_button_pwlist)

        top_layout.addLayout(wifi_group_layout)

        # Group Show Profiles and BSSID
        show_profiles_button = QPushButton("Show Wi-Fi Profiles", self)
        show_profiles_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        show_profiles_button.clicked.connect(show_wifi_profiles)

        bssid_button = QPushButton("Show BSSID Networks", self)
        bssid_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        bssid_button.clicked.connect(show_bssid_networks)

        profile_bssid_group_layout = QHBoxLayout()
        profile_bssid_group_layout.addWidget(show_profiles_button)
        profile_bssid_group_layout.addWidget(bssid_button)

        top_layout.addLayout(profile_bssid_group_layout)

        # Netsh Command Section
        netsh_button = QPushButton("Run NETSH Command", self)
        netsh_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        netsh_button.clicked.connect(execute_netsh_command)
        top_layout.addWidget(variable_input)
        top_layout.addWidget(netsh_button)

        # Button Layout for the bottom part (Other tools)
        bottom_layout = QHBoxLayout()

        password_button = QPushButton("Password Tools", self)
        password_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        password_button.clicked.connect(launch_password)
        bottom_layout.addWidget(password_button)

        net_sniffer_button = QPushButton("Network Monitor", self)
        net_sniffer_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        net_sniffer_button.clicked.connect(launch_net_sniffer)
        bottom_layout.addWidget(net_sniffer_button)

        dns_monitor_button = QPushButton("DNS Monitor", self)
        dns_monitor_button.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        dns_monitor_button.clicked.connect(launch_dns_monitor)
        bottom_layout.addWidget(dns_monitor_button)

        exit_button = QPushButton("Exit", self)
        exit_button.setStyleSheet("background:#ff3333;color:#0d0d0d;")  # Red exit button for attention
        exit_button.clicked.connect(self.close)
        bottom_layout.addWidget(exit_button)

        # Layout
        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addWidget(output_text)
        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)


# === Run the Application ===
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
