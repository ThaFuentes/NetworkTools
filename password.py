import random
import json
import string
import os
from pathlib import Path
import sys

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QComboBox, QCheckBox,
    QPushButton, QHBoxLayout, QVBoxLayout, QFrame, QFormLayout
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Optional names for injection
common_names = [
    "John", "James", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles", "Daniel",
    "Sarah", "Jessica", "Emily", "Amanda", "Elizabeth", "Samantha", "Lauren", "Hannah", "Grace", "Sophia",
    "Benjamin", "Samuel", "Lucas", "Alexander", "Matthew", "Ethan", "Jacob", "Henry", "Jack", "Oliver",
    "Liam", "Noah", "Jameson", "Aiden", "Mason", "Sebastian", "Logan", "Joshua", "Nathan", "Adam",
    "Megan", "Ariana", "Chloe", "Isabella", "Charlotte", "Amelia", "Olivia", "Abigail", "Victoria",
    "Oliver", "Eli", "Carter", "Dylan", "Gabriel", "Zoe", "Ruby", "Lily", "Avery", "Ella", "Maya",
    "Evelyn", "Scarlett", "Brooklyn", "Madeline", "Natalie", "Mackenzie", "Sydney", "Chase", "Cameron",
    "Ian", "Grace", "Caleb", "David", "Michael", "Austin", "Matthew", "Landon", "Jackson", "Isaiah",
    "Levi", "Owen", "Wyatt", "Connor", "Jaxon", "Lila", "Hazel", "Lena", "Maya", "Adeline", "Clara",
    "Sadie", "Nora", "Vivian", "Charlotte", "Sarah", "Harrison", "Milo", "Brody", "Cole", "Miles",
    "Elliot", "Toby", "Jasper", "Lily", "Willow", "Amos", "Ezra", "Nathaniel", "Axel", "Cora", "Riley",
    "Anna", "Sophia", "Riley", "Madeline", "Leah", "Eva", "Paige", "Eva", "Leilani", "Sydney", "Ariana",
    "Aurora", "Lillian", "Sophie", "Zoey", "Ellie", "Hazel", "Mackenzie", "Alana", "Lindsey", "Eliana",
    "Gage", "Phoenix", "Xander", "Trey", "Zane", "Emmett", "Rhett", "Lennox", "Jude", "Grant",
    "Liam", "Maya", "Kai", "Zachary", "Kendall", "Mackenzie", "Jacob", "Aiden", "Grace", "Madeline",
    "Rafael", "Mateo", "Diego", "Lorenzo", "Nina", "Ximena", "Liana", "Chavez", "Zara", "Alisha",
    "Adrian", "Daniel", "Joshua", "Paxton", "Eli", "Tyson", "Max", "Caden", "Ben", "Santiago", "Emiliano",
    "Antonio", "Hugo", "Francesco", "Luis", "Eliot", "Oscar", "Oliver", "Sebastian", "Amos", "Miles",
    "Dante", "Titus", "Giovanni", "Antonio", "Mateo", "Ivan", "Brianna", "Ariana", "Carla", "Mia", "Gianna",
    "Tatiana", "Sabrina", "Beatrice", "Camila", "Jadyn", "Isabelle", "Valentina", "Olivia", "Victoria",
    "Riley", "Sienna", "Sage", "Talia", "Ember", "Aspen", "Kendall", "Addison", "Sloane", "Emery", "Tessa",
    "Brock", "Samson", "Jace", "Jordan", "Tyler", "Sam", "Christian", "Reed", "Milo", "Jax", "Charlie",
    "Finn", "Ronan", "Oliver", "Maximus", "Aiden", "Cooper", "Lucas", "Mason", "Asher", "Liam", "Jacob",
    "Daniel", "Blaise", "Toby", "Xander", "Maxwell", "Jake", "Graham", "Grant", "Levi", "Nico", "Reed",
    "Tate", "Archer", "Ryder", "Gage", "Paxton", "Luca", "Jett", "Isaiah", "Samson", "Cole", "Cameron",
    "Darius", "Boaz", "Xander", "Kellen", "Axel", "Carson", "Clark", "Sterling", "Zachary", "Duncan",
    "Theo", "Jared", "Harvey", "Tucker", "Chad", "Brandon", "Quinn", "Bryce", "Dalton", "Wilder", "Clayton",
    "Marcos", "Brennan", "Santos", "Jaxon", "Tanner", "Kiefer", "Dorian", "Santiago", "Stefan", "Cyrus",
    "Gunnar", "Ashton", "Javier", "Bryan", "Dax", "Griffin", "Knox", "Bennett", "Brycen", "Skyler", "Roman",
    "Theo", "Xander", "Quincy", "Isaac", "Oliver", "Titus", "Malachi", "Caden", "Brock", "Reed", "Joaquin",
    "Dante", "Harrison", "Jackson", "Maverick", "Winston", "Levi", "Jordan", "Caleb", "Hunter", "Paxton",
    "Landon", "Nash", "Ryan", "Leandro", "Avery", "Vince", "Vincent", "Luke", "Sebastian", "Gavin", "Keegan",
    "Damian", "Shane", "Travis", "Wade", "Aidan", "Beckett", "Everett", "Roman", "Nash", "Hendrix", "Dean",
    "Tristan", "Trey", "Zane", "Corbin", "Kayson", "Silas", "Jackson", "Wyatt", "Brady", "Dallas", "Finnley",
    "Marvin", "Hunter", "Lucas", "Casey", "Jaxson", "Reuben", "Jace", "Dillon", "Dawson", "Trey", "Wade",
    "Kane", "Jack", "Trey", "Levi", "Damian", "Samuel", "Blake", "Wyatt", "Wade", "Duncan", "Brody", "Wells",
    "Wyatt", "Dean", "Oscar", "Zane", "Ben", "Theo", "Griffin", "Miles", "Bridger", "Tucker", "Sebastian",
    "Clayton", "Gage", "Caleb", "Dean", "Zion", "Hunter", "Brody", "Levi", "Colby", "Wyatt", "Corbin", "Wyatt"
]


# Output folder + JSON path
output_folder = "lists"
Path(output_folder).mkdir(exist_ok=True)
output_json = os.path.join(output_folder, "passwords.json")


def remove_duplicates_from_file(path):
    """Load JSON list of {"password":...}, remove duplicate password values, save, return (before, after)."""
    if not os.path.exists(path):
        return 0, 0
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    seen = set()
    unique = []
    for entry in data:
        pwd = entry.get("password")
        if pwd and pwd not in seen:
            seen.add(pwd)
            unique.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(unique, f, ensure_ascii=False, indent=2)
    return len(data), len(unique)


class GeneratorThread(QThread):
    finished = pyqtSignal(int)     # total generated
    warning  = pyqtSignal(str)     # non‑fatal warning

    def __init__(self, length_range, include_name, mode, max_count,
                 sequential, prefix, suffix, insert_text):
        super().__init__()
        self.min_len, self.max_len = length_range
        self.include_name = include_name
        self.mode = mode
        self.max_count = max_count
        self.sequential = sequential
        self.prefix = prefix or ""
        self.suffix = suffix or ""
        self.insert_text = insert_text or ""

        # Determine the character set based on selected mode
        if mode == "Numbers Only":
            self.chars = string.digits
        elif mode == "Letters Only":
            self.chars = string.ascii_letters
        elif mode == "Mix":
            self.chars = string.ascii_letters + string.digits
        else:
            self.chars = (
                string.ascii_letters
                + string.digits
                + string.punctuation
            )

    def run(self):
        total_possible = 0
        for length in range(self.min_len, self.max_len + 1):
            core = length - len(self.prefix) - len(self.suffix)
            if core < 0:
                continue
            total_possible += (10 ** core) if self.sequential else (len(self.chars) ** core)

        to_generate = min(self.max_count, total_possible)
        if to_generate < self.max_count:
            self.warning.emit(
                f"Only {total_possible} unique passwords exist; generating {to_generate}."
            )

        count = 0
        first = True

        with open(output_json, "w", encoding="utf-8") as f:
            f.write("[\n")
            if self.sequential:
                for length in range(self.min_len, self.max_len + 1):
                    core = length - len(self.prefix) - len(self.suffix)
                    if core < 0:
                        continue
                    for i in range(10 ** core):
                        pwd = (
                            self.prefix
                            + str(i).zfill(core)
                            + self.suffix
                        )
                        # Insert additional text if provided
                        if self.insert_text:
                            p = random.randint(0, len(pwd))
                            pwd = pwd[:p] + self.insert_text + pwd[p:]
                        # Insert name if "Include Common Names" is checked
                        if self.include_name:
                            if len(pwd) < self.max_len:  # Ensure we don't exceed max length
                                name = random.choice(common_names)
                                name_pos = random.randint(0, len(pwd))
                                print(f"Inserting name: {name} at position {name_pos}")  # Debugging
                                pwd = pwd[:name_pos] + name + pwd[name_pos:]

                        entry = json.dumps({"password": pwd}, ensure_ascii=False)
                        if not first:
                            f.write(",\n")
                        f.write(entry)
                        first = False

                        count += 1
                        if count >= to_generate:
                            break
                    if count >= to_generate:
                        break
            else:
                seen = set()
                while count < to_generate:
                    for length in range(self.min_len, self.max_len + 1):
                        core = length - len(self.prefix) - len(self.suffix)
                        if core < 0:
                            continue
                        base = "".join(
                            random.choice(self.chars)
                            for _ in range(core)
                        )
                        pwd = self.prefix + base + self.suffix
                        # Insert additional text if provided
                        if self.insert_text:
                            p = random.randint(0, len(pwd))
                            pwd = pwd[:p] + self.insert_text + pwd[p:]
                        # Insert name if "Include Common Names" is checked
                        if self.include_name:
                            if len(pwd) < self.max_len:  # Ensure we don't exceed max length
                                name = random.choice(common_names)
                                name_pos = random.randint(0, len(pwd))
                                print(f"Inserting name: {name} at position {name_pos}")  # Debugging
                                pwd = pwd[:name_pos] + name + pwd[name_pos:]

                        if pwd in seen:
                            continue
                        seen.add(pwd)

                        entry = json.dumps({"password": pwd}, ensure_ascii=False)
                        if not first:
                            f.write(",\n")
                        f.write(entry)
                        first = False

                        count += 1
                        if count >= to_generate:
                            break
            f.write("\n]\n")

        self.finished.emit(count)


class PasswordGeneratorUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Generator")
        self.setStyleSheet("""
            background-color: #0d0d0d;  /* Main black background */
            color: #00ff99;  /* Green text color */
            font-family: "Consolas", monospace;  /* Hacker-like font */
        """)
        self.resize(650, 300)
        self._build_ui()

    def _build_ui(self):
        font_b = QFont("Helvetica", 16)
        font = QFont("Helvetica", 12)

        # Welcome text
        welcome = QLabel("Welcome to Password Generator\nExample: cats7777", self)
        welcome.setFont(font_b)
        welcome.setAlignment(Qt.AlignCenter)

        # Form layout for the input fields
        form = QFormLayout()
        self.lr_edit = QLineEdit("10-10")
        self.pref_edit = QLineEdit("432")
        self.insert_edit = QLineEdit()
        self.suff_edit = QLineEdit("0901")
        self.size_edit = QLineEdit("1")

        # Set style for the input fields
        for w in (self.lr_edit, self.pref_edit, self.insert_edit, self.suff_edit, self.size_edit):
            w.setStyleSheet("""
                background-color: #1e1e1e;  /* Dark gray background for input fields */
                color: #00ff99;  /* Green text color */
                border: 1px solid #00ff99;  /* Green border */
                border-radius: 5px;
                padding: 8px;
                font-size: 16px;
            """)

        # Add labels and inputs to the form
        for label_text, widget in [
            ("Length range (min-max):", self.lr_edit),
            ("Known Start:", self.pref_edit),
            ("Insert Text:", self.insert_edit),
            ("Known End:", self.suff_edit),
            ("Desired size (MB):", self.size_edit),
        ]:
            lbl = QLabel(label_text)
            lbl.setFont(font)
            form.addRow(lbl, widget)

        # Left panel with the form
        left = QFrame()
        left.setLayout(form)

        # Vertical box for the combo box and checkboxes
        vbox = QVBoxLayout()
        lbl = QLabel("Mode:"); lbl.setFont(font)
        self.mode_cb = QComboBox()
        self.mode_cb.addItems(['Numbers Only', 'Letters Only', 'Mix', 'Random'])
        self.mode_cb.setStyleSheet("""
            background-color: #1e1e1e;
            color: #00ff99;
            border: 1px solid #00ff99;
            border-radius: 5px;
        """)
        vbox.addWidget(lbl)
        vbox.addWidget(self.mode_cb)

        # Include name and sequential number checkboxes
        self.name_chk = QCheckBox("Include common name")
        self.seq_chk = QCheckBox("Sequential numbers")
        for chk in (self.name_chk, self.seq_chk):
            chk.setStyleSheet("""
                background-color: #1e1e1e;
                color: #00ff99;
                border: 1px solid #00ff99;
            """)
            vbox.addWidget(chk)

        # Buttons for generating passwords, removing duplicates, and showing count
        self.gen_btn = QPushButton("Generate")
        self.dup_btn = QPushButton("Remove Duplicates")
        self.count_btn = QPushButton("Show Count")

        # Style for buttons
        for btn in (self.gen_btn, self.dup_btn, self.count_btn):
            btn.setStyleSheet("""
                background-color: #00ff99;  /* Green background */
                color: #0d0d0d;  /* Dark text */
                border: none;
                border-radius: 5px;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
            """)
            btn.setCursor(Qt.PointingHandCursor)
            vbox.addWidget(btn)

        # Right panel with the vertical box layout
        right = QFrame()
        right.setLayout(vbox)

        # Status label for the UI
        self.status = QLabel("", self)
        self.status.setFont(font)

        # Horizontal layout for the form and options
        main_h = QHBoxLayout()
        main_h.addWidget(left)
        main_h.addWidget(right)

        # Vertical layout to add the welcome label and other elements
        main_v = QVBoxLayout()
        main_v.addWidget(welcome)
        main_v.addLayout(main_h)
        main_v.addWidget(self.status)

        self.setLayout(main_v)

        # Connecting signals to functions
        self.gen_btn.clicked.connect(self.start_generation)
        self.dup_btn.clicked.connect(self.remove_duplicates)
        self.count_btn.clicked.connect(self.show_count)

    def start_generation(self):
        try:
            p1, p2 = [int(x) for x in self.lr_edit.text().split('-')]
            lr = (p1, p2)
        except:
            return self._error("Invalid length range")

        prefix = self.pref_edit.text()
        insert = self.insert_edit.text()
        suffix = self.suff_edit.text()
        try:
            mb = float(self.size_edit.text())
            max_count = int(mb * 1024 * 1024 / 50)
        except:
            return self._error("Invalid size")

        self.gen_btn.setEnabled(False)
        self.status.setText("Generating passwords...")

        self.thread = GeneratorThread(
            lr,
            self.name_chk.isChecked(),
            self.mode_cb.currentText(),
            max_count,
            self.seq_chk.isChecked(),
            prefix,
            suffix,
            insert
        )
        self.thread.warning.connect(self._warn)
        self.thread.finished.connect(self._done)
        self.thread.start()

    def remove_duplicates(self):
        before, after = remove_duplicates_from_file(output_json)
        if before == 0:
            self.status.setText("No password file to process.")
        else:
            removed = before - after
            self.status.setText(f"Removed {removed} duplicates ({after} unique remain).")

    def show_count(self):
        if not os.path.exists(output_json):
            return self._error("No output file yet")
        try:
            with open(output_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.status.setText(f"{len(data)} passwords in {output_json}")
        except:
            self._error("Could not read JSON")

    def _warn(self, msg):
        self.status.setText(msg)

    def _done(self, total):
        self.status.setText(f"Done: {total} passwords written to {output_json}")
        self.gen_btn.setEnabled(True)

    def _error(self, text):
        self.status.setText(text)
        self.gen_btn.setEnabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = PasswordGeneratorUI()
    w.show()
    sys.exit(app.exec_())
