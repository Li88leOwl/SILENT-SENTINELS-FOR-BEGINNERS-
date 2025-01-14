import os
import psutil
import winreg
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

# 1 Peter 4:10 - "Each of you should use whatever gift you have received to serve others, as faithful stewards of God’s grace in its various forms."

LOG_FILE = "keylogger_detection_log.txt"

class KeyloggerDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection Tool by Li88leowl")
        self.root.geometry("600x400")

        # Text area for displaying output
        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=20)
        self.output_area.pack(pady=10)

        # Buttons
        self.scan_process_button = tk.Button(root, text="Scan Processes", command=self.detect_keyloggers)
        self.scan_process_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.scan_startup_button = tk.Button(root, text="Scan Startup Entries", command=self.scan_startup_entries)
        self.scan_startup_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.scan_hidden_button = tk.Button(root, text="Scan Hidden Files", command=self.scan_hidden_files)
        self.scan_hidden_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.save_log_button = tk.Button(root, text="Save Log", command=self.save_log)
        self.save_log_button.pack(side=tk.LEFT, padx=10, pady=10)

    def log_to_gui(self, message):
        self.output_area.insert(tk.END, message + "\n")
        self.output_area.see(tk.END)  # Auto-scroll

    def log_to_file(self, message):
        with open(LOG_FILE, "a") as log:
            log.write(message + "\n")

    def detect_keyloggers(self):
        self.log_to_gui("\n[1] Scanning for suspicious processes...\n")
        self.log_to_file("\n[1] Scanning for suspicious processes...\n")
        suspicious_keywords = ['keylogger', 'keystroke', 'keyboard', 'logger']
        found_suspicious = False

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_name = proc.info['name']
                process_id = proc.info['pid']

                if any(keyword in process_name.lower() for keyword in suspicious_keywords):
                    found_suspicious = True
                    msg = f"Suspicious process detected: {process_name} (PID: {process_id})"
                    self.log_to_gui(msg)
                    self.log_to_file(msg)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if not found_suspicious:
            msg = "No suspicious processes found.\n"
            self.log_to_gui(msg)
            self.log_to_file(msg)

    def scan_startup_entries(self):
        self.log_to_gui("[2] Scanning startup entries...\n")
        self.log_to_file("\n[2] Scanning startup entries...\n")
        suspicious_keywords = ['keylogger', 'logger', 'keystroke', 'keyboard']
        startup_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        ]
        found_suspicious = False

        try:
            for path in startup_paths:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as reg_key:
                    for i in range(winreg.QueryInfoKey(reg_key)[1]):  # Query number of values
                        name, value, _ = winreg.EnumValue(reg_key, i)
                        if any(keyword in name.lower() or keyword in value.lower() for keyword in suspicious_keywords):
                            found_suspicious = True
                            msg = f"Suspicious startup entry: {name} -> {value}"
                            self.log_to_gui(msg)
                            self.log_to_file(msg)
        except Exception as e:
            msg = f"Could not access startup entries: {e}"
            self.log_to_gui(msg)
            self.log_to_file(msg)

        if not found_suspicious:
            msg = "No suspicious startup entries found.\n"
            self.log_to_gui(msg)
            self.log_to_file(msg)

    def scan_hidden_files(self):
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if not directory:
            return

        self.log_to_gui("[3] Scanning for hidden files...\n")
        self.log_to_file("\n[3] Scanning for hidden files...\n")
        hidden_files = []

        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.stat(file_path).st_file_attributes & 2:  # Check hidden attribute
                        hidden_files.append(file_path)
        except Exception as e:
            msg = f"Error while scanning hidden files: {e}"
            self.log_to_gui(msg)
            self.log_to_file(msg)

        if hidden_files:
            self.log_to_gui("Hidden files detected:")
            self.log_to_file("Hidden files detected:")
            for file in hidden_files:
                self.log_to_gui(f"   - {file}")
                self.log_to_file(f"   - {file}")
        else:
            msg = "No hidden files found in the directory.\n"
            self.log_to_gui(msg)
            self.log_to_file(msg)

    def save_log(self):
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if save_path:
            with open(LOG_FILE, "r") as log_file:
                content = log_file.read()
            with open(save_path, "w") as save_file:
                save_file.write(content)
            messagebox.showinfo("Success", f"Log saved to {save_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()
