import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import platform
import psutil

# File paths
LOG_FILE = "security_audit_log.txt"
REPORT_FILE = "security_audit_report.txt"

def log_message(message):
    """Logs messages to the log file and displays them in the GUI."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)
    log_output.insert(tk.END, log_entry)
    log_output.see(tk.END)

def audit_user_accounts():
    """Audit user accounts and check for security issues."""
    log_message("Auditing user accounts...")
    findings = []
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("net user", shell=True).decode()
            findings.append(output)
        else:
            with open("/etc/passwd") as f:
                accounts = f.read()
                findings.append(accounts)
    except Exception as e:
        log_message(f"Failed to audit user accounts: {e}")
    return findings

def audit_open_ports():
    """Check for open ports and log details."""
    log_message("Scanning for open ports...")
    findings = []
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netstat -ano", shell=True).decode()
        else:
            output = subprocess.check_output("netstat -tuln", shell=True).decode()
        findings.append(output)
    except Exception as e:
        log_message(f"Failed to scan open ports: {e}")
    return findings

def audit_network_traffic():
    """Analyze network traffic and log active connections."""
    log_message("Analyzing network traffic...")
    findings = []
    try:
        connections = psutil.net_connections()
        for conn in connections:
            findings.append(f"Local: {conn.laddr}, Remote: {conn.raddr}, Status: {conn.status}")
    except Exception as e:
        log_message(f"Failed to analyze network traffic: {e}")
    return findings

def check_weak_permissions():
    """Check for weak file permissions."""
    log_message("Checking for weak file permissions...")
    findings = []
    try:
        if platform.system() == "Windows":
            log_message("File permissions checks are not implemented for Windows.")
        else:
            for root, dirs, files in os.walk("/"):
                for name in files:
                    file_path = os.path.join(root, name)
                    if os.path.exists(file_path) and os.access(file_path, os.W_OK):
                        findings.append(f"Weak permissions: {file_path}")
    except Exception as e:
        log_message(f"Failed to check file permissions: {e}")
    return findings

def check_software_versions():
    """Check for outdated software versions."""
    log_message("Checking software versions...")
    findings = []
    try:
        if platform.system() == "Windows":
            log_message("Software version checks are not implemented for Windows.")
        else:
            output = subprocess.check_output("dpkg -l", shell=True).decode()
            findings.append(output)
    except Exception as e:
        log_message(f"Failed to check software versions: {e}")
    return findings

def generate_report(user_audit, open_ports, network_traffic, weak_permissions, software_versions):
    """Generate a security report."""
    log_message("Generating report...")
    with open(REPORT_FILE, "w") as report:
        report.write("### Security Audit Report\n")
        report.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        sections = {
            "User Accounts": user_audit,
            "Open Ports": open_ports,
            "Network Traffic": network_traffic,
            "Weak File Permissions": weak_permissions,
            "Software Versions": software_versions,
        }

        for section, content in sections.items():
            report.write(f"## {section}\n")
            if content:
                report.write("\n".join(content) + "\n\n")
            else:
                report.write("No issues found.\n\n")

    log_message(f"Report saved to {REPORT_FILE}")
    messagebox.showinfo("Report Generated", f"Report saved to {REPORT_FILE}")

def perform_audit():
    """Perform the entire security audit."""
    log_message("Starting security audit...")
    user_audit = audit_user_accounts()
    open_ports = audit_open_ports()
    network_traffic = audit_network_traffic()
    weak_permissions = check_weak_permissions()
    software_versions = check_software_versions()
    generate_report(user_audit, open_ports, network_traffic, weak_permissions, software_versions)
    log_message("Security audit completed.")

def view_report():
    """Open the generated report in a text editor."""
    if os.path.exists(REPORT_FILE):
        os.startfile(REPORT_FILE) if platform.system() == "Windows" else subprocess.call(["open", REPORT_FILE])
    else:
        messagebox.showerror("Error", "No report found. Please generate a report first.")

def clear_logs():
    """Clear the log output."""
    log_output.delete("1.0", tk.END)
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    log_message("Logs cleared.")

# GUI Setup
root = tk.Tk()
root.title("Security Audit Tool")
root.geometry("800x600")

frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)

# Title
title_label = ttk.Label(frame, text="Security Audit Tool by Li88leOwl", font=("Arial", 16))
title_label.pack(pady=10)

# Buttons
button_frame = ttk.Frame(frame)
button_frame.pack(pady=10)

audit_button = ttk.Button(button_frame, text="Run Audit", command=perform_audit)
audit_button.grid(row=0, column=0, padx=5)

view_report_button = ttk.Button(button_frame, text="View Report", command=view_report)
view_report_button.grid(row=0, column=1, padx=5)

clear_logs_button = ttk.Button(button_frame, text="Clear Logs", command=clear_logs)
clear_logs_button.grid(row=0, column=2, padx=5)

exit_button = ttk.Button(button_frame, text="Exit", command=root.quit)
exit_button.grid(row=0, column=3, padx=5)

# Log Output
log_frame = ttk.LabelFrame(frame, text="Log Output", padding="10")
log_frame.pack(fill=tk.BOTH, expand=True)

log_output = tk.Text(log_frame, wrap=tk.WORD, height=20)
log_output.pack(fill=tk.BOTH, expand=True)

scrollbar = ttk.Scrollbar(log_output, command=log_output.yview)
log_output.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Start GUI
root.mainloop()
