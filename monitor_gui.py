import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

import os
import hashlib
import json

from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

REPORT_FILE = "scan_report.csv"

import csv

def initialize_report():
    if not os.path.exists(REPORT_FILE):
        with open(REPORT_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp","Severity","Event","File"])

recent_events = {}
EVENT_COOLDOWN = 2

class MonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            alert = f"NEW FILE: {event.src_path}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)

    def on_deleted(self, event):
        if not event.is_directory:
            alert = f"DELETED: {event.src_path}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)

    def on_modified(self, event):
        if not event.is_directory:
            alert = f"MODIFIED: {event.src_path}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)

            observer = None

def start_monitoring():
    global observer

    folder = folder_path.get()

    if folder == "":
        log_output.insert(tk.END, "Select a folder first\n")
        return

    event_handler = MonitorHandler()

    observer = Observer()
    observer.schedule(event_handler, folder, recursive=True)
    observer.start()

    log_output.insert(tk.END, "Real-time monitoring started\n")


def stop_monitoring():
    global observer

    if observer:
        observer.stop()
        observer.join()

        log_output.insert(tk.END, "Monitoring stopped\n")

BASELINE_FILE = "baseline_hashes.json"

def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()

def create_baseline():
    folder = folder_path.get()

    if folder == "":
        log_output.insert(tk.END, "Please select a folder first\n")
        return

    hashes = {}

    for root_dir, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root_dir, file)

            try:
                file_hash = calculate_hash(file_path)
                hashes[file_path] = file_hash
            except:
                log_output.insert(tk.END, f"Could not read {file_path}\n")

    with open(BASELINE_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

    log_output.insert(tk.END, "Baseline created successfully\n")

# ---------------- MAIN WINDOW ----------------
root = tk.Tk()
root.title("File Integrity Monitoring Dashboard")
root.geometry("1100x750")
root.configure(bg="#f5f7fb")

# ---------------- HEADER ----------------
header = tk.Frame(root, bg="#2c3e50", height=60)
header.pack(fill="x")

title = tk.Label(
    header,
    text="File Integrity Monitoring Dashboard",
    fg="white",
    bg="#2c3e50",
    font=("Segoe UI", 16, "bold")
)
title.pack(pady=15)

# ---------------- CONTROL BAR ----------------
controls = tk.Frame(root, bg="#f5f7fb")
controls.pack(fill="x", padx=20, pady=10)

folder_path = tk.StringVar()

def select_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_path.set(folder)

folder_entry = tk.Entry(
    controls,
    textvariable=folder_path,
    width=60,
    font=("Segoe UI",10)
)
folder_entry.pack(side="left", padx=10)

browse_btn = tk.Button(
    controls,
    text="Select Folder",
    bg="#3498db",
    fg="white",
    font=("Segoe UI",10,"bold"),
    command=select_folder
)
browse_btn.pack(side="left", padx=5)

baseline_btn = tk.Button(
    controls,
    text="Create Baseline",
    bg="#2ecc71",
    fg="white",
    font=("Segoe UI",10,"bold"),
    command=create_baseline
)
baseline_btn.pack(side="left", padx=5)

from datetime import datetime
import time

from datetime import datetime
import csv

from datetime import datetime
import csv

def add_alert(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if message.startswith("DELETED"):
        severity = "CRITICAL"
    elif message.startswith("MODIFIED"):
        severity = "WARNING"
    else:
        severity = "INFO"

    full_message = f"[{timestamp}] [{severity}] {message}"

    alerts_box.insert(tk.END, full_message + "\n")
    alerts_box.see(tk.END)

    # Save to report
    event_type = message.split(":")[0]
    file_path = message.split(": ",1)[1]

    with open(REPORT_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, severity, event_type, file_path])

def update_chart(safe, modified, new):
    ax.clear()

    values = [safe, modified, new]
    labels = ["Safe", "Modified", "New"]
    colors = ["#2ecc71", "#e74c3c", "#f39c12"]

    ax.pie(values, labels=labels, colors=colors, autopct="%1.0f%%")
    ax.set_title("File Status Distribution")

    canvas.draw()

progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress.pack(pady=10)

monitor_btn = tk.Button(
    controls,
    text="Start Monitoring",
    bg="#9b59b6",
    fg="white",
    font=("Segoe UI",10,"bold"),
    command=start_monitoring
)
monitor_btn.pack(side="left", padx=5)

def start_scan():
    folder = folder_path.get()

    if folder == "":
        log_output.insert(tk.END, "Please select a folder first\n")
        return

    if not os.path.exists(BASELINE_FILE):
        log_output.insert(tk.END, "Baseline not found. Create baseline first.\n")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline_hashes = json.load(f)

    current_hashes = {}

    safe = 0
    modified = 0
    new_files = 0

    initialize_report()

    # count files for progress bar
    total_files = 0
    for root_dir, dirs, files in os.walk(folder):
        total_files += len(files)

    progress["maximum"] = total_files
    progress["value"] = 0

    for root_dir, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root_dir, file)

            try:
                file_hash = calculate_hash(file_path)
                current_hashes[file_path] = file_hash

                if file_path in baseline_hashes:
                    if baseline_hashes[file_path] == file_hash:
                        safe += 1
                    else:
                        modified += 1
                        alert = f"MODIFIED: {file_path}"
                        log_output.insert(tk.END, alert + "\n")
                        add_alert(alert)
                else:
                    new_files += 1
                    alert = f"NEW FILE: {file_path}"
                    log_output.insert(tk.END, alert + "\n")
                    add_alert(alert)

                progress["value"] += 1
                root.update_idletasks()

            except:
                log_output.insert(tk.END, f"Could not read {file_path}\n")

    deleted = 0
    reported = set()

    for file in baseline_hashes:
        if file not in current_hashes and file not in reported:
            deleted += 1
            reported.add(file)

            alert = f"DELETED: {file}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)
            deleted += 1
            alert = f"DELETED: {file}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)

    safe_card.config(text=str(safe))
    modified_card.config(text=str(modified))
    new_card.config(text=str(new_files))
    total_card.config(text=str(safe + modified + new_files))

    update_chart(safe, modified, new_files)

    log_output.insert(tk.END, "Scan completed\n")

    progress["value"] = 0

    deleted = 0
    for file in baseline_hashes:
        if file not in current_hashes:
            deleted += 1
            alert = f"DELETED: {file}"
            log_output.insert(tk.END, alert + "\n")
            add_alert(alert)

    safe_card.config(text=str(safe))
    modified_card.config(text=str(modified))
    new_card.config(text=str(new_files))
    total_card.config(text=str(safe + modified + new_files))

    update_chart(safe, modified, new_files)

    log_output.insert(tk.END, "Scan completed\n")

scan_btn = tk.Button(
    controls,
    text="Start Scan",
    bg="#e67e22",
    fg="white",
    font=("Segoe UI",10,"bold"),
    command=start_scan
)
scan_btn.pack(side="left", padx=5)

progress["value"] = 0

# ---------------- STATS CARDS ----------------
cards_frame = tk.Frame(root, bg="#f5f7fb")
cards_frame.pack(fill="x", padx=20, pady=10)

def create_card(parent, title, value, color):
    card = tk.Frame(
        parent,
        bg="white",
        width=200,
        height=80,
        highlightbackground=color,
        highlightthickness=3
    )
    card.pack(side="left", padx=10)

    label = tk.Label(card, text=title, bg="white", font=("Segoe UI",10))
    label.pack(pady=(10,0))

    number = tk.Label(
        card,
        text=value,
        bg="white",
        font=("Segoe UI",18,"bold"),
        fg=color
    )
    number.pack()

    return number

safe_card = create_card(cards_frame,"SAFE FILES","0","#2ecc71")
modified_card = create_card(cards_frame,"MODIFIED","0","#e74c3c")
new_card = create_card(cards_frame,"NEW FILES","0","#f39c12")
total_card = create_card(cards_frame,"TOTAL FILES","0","#3498db")

# ---------------- MIDDLE SECTION ----------------
middle_frame = tk.Frame(root, bg="#f5f7fb")
middle_frame.pack(fill="both", expand=True, padx=20)

# ----- PIE CHART PANEL -----
chart_frame = tk.Frame(middle_frame, bg="white", width=500, height=300)
chart_frame.pack(side="left", padx=10, pady=10)

fig = Figure(figsize=(4,3), dpi=100)
ax = fig.add_subplot(111)

data = [1,1,1]
labels = ["Safe","Modified","New"]

ax.pie(data, labels=labels, autopct="%1.0f%%")
ax.set_title("File Status Distribution")

canvas = FigureCanvasTkAgg(fig, chart_frame)
canvas.draw()
canvas.get_tk_widget().pack()

# ----- ALERT PANEL -----
alerts_frame = tk.Frame(middle_frame, bg="white", width=400)
alerts_frame.pack(side="right", padx=10, pady=10, fill="y")

alert_title = tk.Label(
    alerts_frame,
    text="Recent Alerts",
    bg="white",
    font=("Segoe UI",12,"bold")
)
alert_title.pack(pady=5)

alerts_box = scrolledtext.ScrolledText(alerts_frame, height=15)
alerts_box.pack(padx=10,pady=10)

# ---------------- LOG OUTPUT ----------------
log_frame = tk.Frame(root, bg="white")
log_frame.pack(fill="both", padx=20, pady=10)

log_title = tk.Label(
    log_frame,
    text="Scan Logs",
    bg="white",
    font=("Segoe UI",12,"bold")
)
log_title.pack(anchor="w",padx=10,pady=5)

log_output = scrolledtext.ScrolledText(log_frame,height=10)
log_output.pack(fill="both",padx=10,pady=5)

# ---------------- PROGRESS BAR ----------------
progress = ttk.Progressbar(
    root,
    orient="horizontal",
    length=900,
    mode="determinate"
)
progress.pack(pady=15)

def stop_monitoring():
    global observer

    if observer:
        observer.stop()
        observer.join()

        log_output.insert(tk.END, "Monitoring stopped\n")

root.mainloop()