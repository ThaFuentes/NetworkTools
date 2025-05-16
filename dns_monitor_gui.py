import random
import json
import string
import os
from pathlib import Path
import sys

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QFileDialog, QFrame, QVBoxLayout,
    QHBoxLayout
)
from PyQt5.QtGui import QTextCursor, QTextCharFormat, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
import pyshark
from urllib.parse import unquote, urlparse, parse_qs


# List of known adult site domains (example list, you should use a more comprehensive list)
known_adult_sites = [
    "exampleadultsite.com",
    "anotheradultsite.com"
]

# Global variable to control the thread
stop_thread = False


# Define a signal to communicate with the main thread
class Worker(QObject):
    update_signal = pyqtSignal(str)  # Signal to update GUI

    def __init__(self, ip, text_widget, tshark_path, interface):
        super().__init__()
        self.ip = ip
        self.text_widget = text_widget
        self.tshark_path = tshark_path
        self.interface = interface
        self.capture = None

    def monitor_traffic(self):
        global stop_thread
        self.text_widget.clear()

        # Start capturing traffic with pyshark
        self.capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter=f'ip.addr == {self.ip}',
            tshark_path=self.tshark_path
        )

        def process_packet(packet):
            global stop_thread
            if stop_thread:
                self.capture.close()
                return
            try:
                # Check for DNS query and process it
                if 'DNS' in packet:
                    dns_query = getattr(packet.dns, 'qry_name', None)
                    if dns_query:
                        # Emit the DNS query to the GUI
                        self.update_signal.emit(f"DNS Query: {dns_query}")
                    else:
                        self.update_signal.emit("DNS Query: (No DNS query found in packet)")

                # Check for HTTP traffic and extract search query if found
                if 'HTTP' in packet:
                    host = getattr(packet.http, 'host', '')
                    uri = getattr(packet.http, 'request_full_uri', '')
                    full_url = f"http://{host}{uri}" if uri else host
                    search_query = extract_search_query(full_url)
                    if search_query:
                        self.update_signal.emit(f'<span style="color:lightblue">Search Query: {search_query}</span>')
                    if is_adult_site(full_url):
                        self.update_signal.emit(f'<span style="color:lightgreen">Visited URL: {full_url}</span>')
                    else:
                        self.update_signal.emit(f"Visited URL: {full_url}")

                elif 'TLS' in packet:
                    server_name = getattr(packet.tls, 'handshake_extensions_server_name', None)
                    if server_name:
                        if is_adult_site(server_name):
                            self.update_signal.emit(
                                f'<span style="color:lightgreen">Visited URL (HTTPS): {server_name}</span>')
                        else:
                            self.update_signal.emit(f"Visited URL (HTTPS): {server_name}")

            except AttributeError as e:
                print(f"Error processing packet: {e}")

        # Apply packet capture filter and packet processing
        self.capture.apply_on_packets(process_packet, timeout=1000)


def is_adult_site(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    for adult_site in known_adult_sites:
        if adult_site in domain:
            return True
    return False


def extract_search_query(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    search_engines = {
        'google.com': 'q',
        'bing.com': 'q',
        'yahoo.com': 'p',
        'duckduckgo.com': 'q'
    }
    for engine, param in search_engines.items():
        if engine in parsed_url.netloc.lower() and param in query_params:
            return unquote(query_params[param][0])
    return None


def start_traffic_monitor():
    global stop_thread
    stop_thread = False
    ip = ip_entry.text().strip()
    tshark_path = tshark_entry.text().strip()
    interface = '\\Device\\NPF_{CCA43875-7988-4EC7-8526-188053EAEC12}'

    if ip and tshark_path:
        worker = Worker(ip, traffic_text_widget, tshark_path, interface)
        worker.update_signal.connect(update_traffic_text)

        # Start the monitoring in a separate thread
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.monitor_traffic)
        thread.finished.connect(thread.quit)  # Ensure thread exits cleanly

        thread.start()

        # Wait for thread to finish before cleaning up
        thread.finished.connect(lambda: thread.wait())


def update_traffic_text(text):
    # Safely update the GUI from the main thread
    traffic_text_widget.append(text)
    traffic_text_widget.verticalScrollBar().setValue(traffic_text_widget.verticalScrollBar().maximum())


def stop_traffic_monitor():
    global stop_thread
    stop_thread = True
    if worker.capture:
        worker.capture.close()


def save_to_file():
    file_path, _ = QFileDialog.getSaveFileName(window, "Save to File", "", "Text files (*.txt);;All files (*)")
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(traffic_text_widget.toPlainText())


def search_text():
    term = search_entry.text()
    # clear previous highlights
    traffic_text_widget.moveCursor(QTextCursor.Start)
    traffic_text_widget.setExtraSelections([])

    if not term:
        return

    selections = []
    color_fmt = QTextCharFormat()
    color_fmt.setForeground(QColor('red'))
    color_fmt.setBackground(QColor('yellow'))

    # find all occurrences
    while traffic_text_widget.find(term, QTextCursor.FindCaseSensitively):
        selection = QTextEdit.ExtraSelection()
        selection.cursor = traffic_text_widget.textCursor()
        selection.format = color_fmt
        selections.append(selection)

    traffic_text_widget.setExtraSelections(selections)


# --- GUI setup ---
app = QApplication(sys.argv)
window = QWidget()
window.setWindowTitle("HTTP/HTTPS Traffic Monitor")
window.setStyleSheet("""
    background-color: #0d0d0d;  /* Dark black background */
    color: #00ff99;  /* Neon green text */
    font-family: "Consolas", monospace;  /* Hacker font */
""")
window.resize(650, 500)  # Reduced width for a more compact layout

v_main = QVBoxLayout(window)

# Top frame
top_frame = QFrame(window)
h_top = QHBoxLayout(top_frame)

ip_label = QLabel("Enter IP to Monitor:", top_frame)
ip_label.setStyleSheet("color:lightgreen;")
ip_entry = QLineEdit(top_frame)
ip_entry.setStyleSheet("""
    background-color: #1e1e1e;  /* Dark gray input field */
    color: #00ff99;  /* Green text */
    border: 1px solid #00ff99;  /* Green border */
    border-radius: 5px;
    padding: 8px;
""")
ip_entry.setMinimumWidth(200)  # Reduced width

tshark_label = QLabel("Path to tshark executable:", top_frame)
tshark_label.setStyleSheet("color:lightgreen;")
tshark_entry = QLineEdit(top_frame)
tshark_entry.setStyleSheet("""
    background-color: #1e1e1e;  /* Dark gray input field */
    color: #00ff99;  /* Green text */
    border: 1px solid #00ff99;  /* Green border */
    border-radius: 5px;
    padding: 8px;
""")
tshark_entry.setText(r"C:\Program Files\Wireshark\tshark.exe")
tshark_entry.setMinimumWidth(400)  # Reduced width

btn_start = QPushButton("Start Traffic Monitor", top_frame)
btn_start.setStyleSheet("""
    background-color: #00ff99;
    color: #0d0d0d;
    border-radius: 5px;
    padding: 8px;
""")
btn_start.clicked.connect(start_traffic_monitor)
btn_stop = QPushButton("Stop Traffic Monitor", top_frame)
btn_stop.setStyleSheet("""
    background-color: #ff3333;  /* Red background for stop button */
    color: #0d0d0d;
    border-radius: 5px;
    padding: 8px;
""")
btn_stop.clicked.connect(stop_traffic_monitor)
btn_save = QPushButton("Save to File", top_frame)
btn_save.setStyleSheet("""
    background-color: #00ff99;
    color: #0d0d0d;
    border-radius: 5px;
    padding: 8px;
""")
btn_save.clicked.connect(save_to_file)

for w in (ip_label, ip_entry, tshark_label, tshark_entry, btn_start, btn_stop, btn_save):
    h_top.addWidget(w)

v_main.addWidget(top_frame)

# Mid frame
mid_frame = QFrame(window)
h_mid = QHBoxLayout(mid_frame)

search_label = QLabel("Search Term:", mid_frame)
search_label.setStyleSheet("color:lightgreen;")
search_entry = QLineEdit(mid_frame)
search_entry.setStyleSheet("""
    background-color: #1e1e1e;
    color: #00ff99;
    border: 1px solid #00ff99;
    border-radius: 5px;
    padding: 8px;
""")
btn_search = QPushButton("Search", mid_frame)
btn_search.setStyleSheet("""
    background-color: #00ff99;
    color: #0d0d0d;
    border-radius: 5px;
    padding: 8px;
""")
btn_search.clicked.connect(search_text)

for w in (search_label, search_entry, btn_search):
    h_mid.addWidget(w)

v_main.addWidget(mid_frame)

# Bottom frame
bottom_frame = QFrame(window)
v_bottom = QVBoxLayout(bottom_frame)

traffic_text_widget = QTextEdit(bottom_frame)
traffic_text_widget.setStyleSheet("""
    background-color: #1e1e1e;
    color: #00ff99;
    border: 1px solid #00ff99;
    border-radius: 5px;
    padding: 8px;
""")
traffic_text_widget.setLineWrapMode(QTextEdit.NoWrap)

v_bottom.addWidget(traffic_text_widget)
v_main.addWidget(bottom_frame, 1)

window.show()
sys.exit(app.exec_())
