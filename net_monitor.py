import sys
from datetime import datetime
from base64 import b64decode
import pytz
import psutil
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QTextEdit,
    QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog
)
from PyQt5.QtGui import QFont

# === Global Buffer ===
packet_info_buffer = []

# === Worker Thread ===
class SnifferThread(QThread):
    packet_signal = pyqtSignal(str)

    def __init__(self, iface, timezone_combo):
        super().__init__()
        self.iface = iface
        self.timezone_combo = timezone_combo
        self._running = True

    def run(self):
        sniff(
            iface=self.iface,
            prn=self.handle_packet,
            filter="ip",
            store=0,
            stop_filter=lambda pkt: not self._running
        )

    def handle_packet(self, packet):
        ts = packet.time
        tz_name = self.timezone_combo.currentText()
        local = datetime.fromtimestamp(ts, tz=pytz.timezone(tz_name)) \
            .strftime('%Y-%m-%d %H:%M:%S %Z')

        # Build HTML‐colored output
        html = []

        # Timestamp (green)
        html.append(f'<span style="color:green;">Packet Timestamp: {local}</span><br>')

        # Layer2 (green)
        html.append(f'<span style="color:green;">&nbsp;&nbsp;Ether type: {packet[Ether].type}</span><br>')
        html.append(f'<span style="color:green;">&nbsp;&nbsp;Src MAC: {packet[Ether].src}</span><br>')
        html.append(f'<span style="color:green;">&nbsp;&nbsp;Dst MAC: {packet[Ether].dst}</span><br>')

        # Layer3 (green)
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        flags = packet[IP].flags
        html.append(f'<span style="color:green;">&nbsp;&nbsp;version: {packet[IP].version}</span><br>')
        html.append(f'<span style="color:orange;">&nbsp;&nbsp;src: {src_ip}</span><br>')
        html.append(f'<span style="color:orange;">&nbsp;&nbsp;dst: {dst_ip}</span><br>')
        html.append(f'<span style="color:green;">&nbsp;&nbsp;ttl: {packet[IP].ttl}</span><br>')
        html.append(f'<span style="color:green;">&nbsp;&nbsp;flags: {flags}</span><br>')

        # ICMP (green)
        if ICMP in packet:
            html.append(f'<span style="color:green;">&nbsp;&nbsp;ICMP type: {packet[ICMP].type}</span><br>')
            html.append(f'<span style="color:green;">&nbsp;&nbsp;ICMP code: {packet[ICMP].code}</span><br>')

        # Layer4 (green + red ports)
        if TCP in packet or UDP in packet:
            proto = TCP if TCP in packet else UDP
            sport, dport = packet[proto].sport, packet[proto].dport
            html.append(f'<span style="color:red;">&nbsp;&nbsp;src port: {sport}</span><br>')
            html.append(f'<span style="color:red;">&nbsp;&nbsp;dst port: {dport}</span><br>')
            if proto is TCP:
                # flags in purple
                flag_names = []
                for bit, name in [(0x01, 'FIN'), (0x02, 'SYN'), (0x04, 'RST'),
                                  (0x08, 'PSH'), (0x10, 'ACK'), (0x20, 'URG')]:
                    if packet[TCP].flags & bit:
                        flag_names.append(name)
                html.append(f'<span style="color:purple;">&nbsp;&nbsp;flags: {", ".join(flag_names)}</span><br>')

        # Payload (blue)
        if Raw in packet:
            raw = packet[Raw].load
            s = raw.decode('utf-8', errors='ignore')
            if 'HTTP/' in s:
                for line in s.split('\r\n'):
                    # friendly name decode
                    if line.startswith('X-Friendly-Name: '):
                        b64 = line.split(': ')[1]
                        line = f'X-Friendly-Name: {b64decode(b64).decode(errors="ignore")}'
                    html.append(f'<span style="color:blue;">&nbsp;&nbsp;{line}</span><br>')
            else:
                html.append(f'<span style="color:blue;">&nbsp;&nbsp;Payload Data: {raw.hex()}</span><br>')

        html.append('<hr>')

        out = ''.join(html)
        packet_info_buffer.append(out)
        self.packet_signal.emit(out)

    def stop(self):
        self._running = False
        self.wait()


# === Main Window ===
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Packet Sniffer")
        self.setStyleSheet("background-color:#0d0d0d;color:#00ff99;")
        self.sniffer = None
        self._build_ui()

        # Set initial window size (width, height)
        self.resize(750, 700)  # Width x Height in pixels

    def _build_ui(self):
        # status
        self.status = QLabel("", self)
        self.status.setStyleSheet("color:#00ff99;")

        # welcome
        welcome = QLabel("Network Packet Sniffer", self)
        welcome.setFont(QFont("Helvetica", 16))
        welcome.setStyleSheet("color:#00ff99;")

        # timezone dropdown
        tz_label = QLabel("Timezone:", self)
        tz_label.setStyleSheet("color:#00ff99;")
        self.timezone_combo = QComboBox(self)
        self.timezone_combo.addItems(pytz.country_timezones['US'])

        # Set the default timezone to Chicago (US/Central)
        self.timezone_combo.setCurrentText('America/Chicago')

        self.timezone_combo.setStyleSheet("background:#1e1e1e;color:#00ff99;")

        # adapter dropdown
        ad_label = QLabel("Adapter:", self)
        ad_label.setStyleSheet("color:#00ff99;")
        self.adapter_combo = QComboBox(self)
        self.adapter_combo.addItems([str(i) for i in psutil.net_if_addrs()])
        self.adapter_combo.setStyleSheet("background:#1e1e1e;color:#00ff99;")

        # output
        self.output = QTextEdit(self)
        self.output.setReadOnly(True)
        self.output.setAcceptRichText(True)
        self.output.setStyleSheet("background:#0d0d0d;color:#00ff99;")
        self.output.setFont(QFont("Consolas", 10))

        # buttons
        start_btn = QPushButton("Start", self)
        start_btn.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        start_btn.clicked.connect(self.start_sniff)

        stop_btn = QPushButton("Stop", self)
        stop_btn.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        stop_btn.clicked.connect(self.stop_sniff)

        save_btn = QPushButton("Save", self)
        save_btn.setStyleSheet("background:#00ff99;color:#0d0d0d;")
        save_btn.clicked.connect(self.save_file)

        # layouts
        v = QVBoxLayout()
        v.addWidget(self.status)
        v.addWidget(welcome)

        h1 = QHBoxLayout()
        h1.addWidget(tz_label)
        h1.addWidget(self.timezone_combo)
        v.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(ad_label)
        h2.addWidget(self.adapter_combo)
        v.addLayout(h2)

        v.addWidget(self.output)

        h3 = QHBoxLayout()
        h3.addWidget(start_btn)
        h3.addWidget(stop_btn)
        h3.addWidget(save_btn)
        v.addLayout(h3)

        self.setLayout(v)

    def start_sniff(self):
        iface = self.adapter_combo.currentText()
        if self.sniffer and self.sniffer.isRunning():
            self.sniffer.stop()
        self.sniffer = SnifferThread(iface, self.timezone_combo)
        self.sniffer.packet_signal.connect(self.append_text)
        self.sniffer.start()
        self.status.setText(f"Sniffing on {iface}")

    def stop_sniff(self):
        if self.sniffer:
            self.sniffer.stop()
            self.status.setText("Stopped sniffing")

    def append_text(self, html):
        self.output.moveCursor(self.output.textCursor().End)
        self.output.insertHtml(html)

    def save_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save as", "", "Text files (*.txt)")
        if path:
            with open(path, 'w') as f:
                f.write("".join(packet_info_buffer))
            self.status.setText(f"Saved to {path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())
