import os
import platform
import subprocess
import json
from datetime import datetime

# Log file path
LOG_FILE = "firewall_config_log.txt"

def log_action(action, status="SUCCESS", error=""):
    """Logs actions with timestamps and statuses."""
    with open(LOG_FILE, "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - ACTION: {action} - STATUS: {status}"
        if error:
            log_entry += f" - ERROR: {error}"
        log.write(log_entry + "\n")
        print(log_entry)

def detect_os():
    """Detect the operating system."""
    os_type = platform.system().lower()
    if os_type not in ["windows", "linux"]:
        log_action("OS Detection", status="FAILED", error="Unsupported OS")
        raise OSError("Unsupported OS")
    return os_type

def execute_command(command):
    """Executes a command and returns the result."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            log_action(command)
            return result.stdout.strip()
        else:
            log_action(command, status="FAILED", error=result.stderr.strip())
            print(f"Error Output: {result.stderr.strip()}")
            return None
    except Exception as e:
        log_action(command, status="FAILED", error=str(e))
        print(f"Exception: {str(e)}")
        return None

def apply_rule(rule):
    """Apply a firewall rule based on the rule dictionary."""
    try:
        os_type = detect_os()
        action = rule.get("action")
        ip = rule.get("ip", None)
        port = rule.get("port", None)
        protocol = rule.get("protocol", "tcp").lower()

        if action == "allow_ip":
            command = (f"netsh advfirewall firewall add rule name=\"Allow IP {ip}\" dir=in action=allow remoteip={ip}" 
                       if os_type == "windows" 
                       else f"iptables -A INPUT -s {ip} -j ACCEPT")
        elif action == "block_ip":
            command = (f"netsh advfirewall firewall add rule name=\"Block IP {ip}\" dir=in action=block remoteip={ip}" 
                       if os_type == "windows" 
                       else f"iptables -A INPUT -s {ip} -j DROP")
        elif action == "open_port":
            command = (f"netsh advfirewall firewall add rule name=\"Open Port {port}\" dir=in action=allow protocol={protocol} localport={port}" 
                       if os_type == "windows" 
                       else f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT")
        elif action == "close_port":
            command = (f"netsh advfirewall firewall delete rule name=\"Open Port {port}\" protocol={protocol} localport={port}" 
                       if os_type == "windows" 
                       else f"iptables -D INPUT -p {protocol} --dport {port} -j ACCEPT")
        else:
            log_action("Unknown Action", status="FAILED", error="Unsupported rule action.")
            return

        result = execute_command(command)
        if result:
            print(f"Rule applied: {action} for {ip or port}")
    except Exception as e:
        log_action("Apply Rule", status="FAILED", error=str(e))

def load_rules_from_file(file_path):
    """Load rules from a JSON configuration file."""
    try:
        with open(file_path, "r") as file:
            rules = json.load(file)
            for rule in rules:
                apply_rule(rule)
    except Exception as e:
        log_action(f"Load Rules from {file_path}", status="FAILED", error=str(e))

def list_rules():
    """List active firewall rules."""
    os_type = detect_os()
    command = ("netsh advfirewall firewall show rule name=all" 
               if os_type == "windows" 
               else "iptables -L -v -n")
    execute_command(command)

if __name__ == "__main__":
    print("Advanced Firewall Configuration Automation")
    print("1. Apply Rule\n2. Load Rules from File\n3. List Rules\n4. Exit")

    while True:
        try:
            choice = int(input("\nEnter your choice: "))
            if choice == 1:
                rule_action = input("Enter action (allow_ip/block_ip/open_port/close_port): ")
                if rule_action in ["allow_ip", "block_ip"]:
                    ip_address = input("Enter IP address: ")
                    apply_rule({"action": rule_action, "ip": ip_address})
                elif rule_action in ["open_port", "close_port"]:
                    port_number = int(input("Enter port number: "))
                    protocol = input("Enter protocol (tcp/udp, default tcp): ") or "tcp"
                    apply_rule({"action": rule_action, "port": port_number, "protocol": protocol})
                else:
                    print("Invalid action!")
            elif choice == 2:
                file_path = input("Enter the path to the JSON rules file: ")
                load_rules_from_file(file_path)
            elif choice == 3:
                list_rules()
            elif choice == 4:
                print("Exiting...")
                break
            else:
                print("Invalid choice! Try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
