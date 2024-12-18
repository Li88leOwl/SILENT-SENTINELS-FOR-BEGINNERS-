# ----------------------------------------------------------
# 1st Peter 4:10 - "Each of you should use whatever gift you 
# have received to serve others, as faithful stewards of God's 
# grace in its various forms."
# ----------------------------------------------------------

import platform
import subprocess
from ipaddress import ip_network

def ping_host(ip):
    """
    Pings a single IP address and returns True if the device is active.
    Works on both Windows and Unix-like systems.
    """
    try:
        # Ping command varies based on the operating system
        param = "-n" if platform.system().lower() == "windows" else "-c"
        # Send one ping with a short timeout
        cmd = ["ping", param, "1", "-w", "100", ip]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0  # Success if return code is 0
    except Exception as e:
        print(f"Couldn't ping {ip}. Error: {e}")
        return False

def network_scan(network_cidr):
    """
    Scans a given network range and checks for active devices using ping.
    """
    print(f"\n🔍 Scanning your network range: {network_cidr}")
    network = ip_network(network_cidr, strict=False)
    active_devices = []

    # Iterate through all valid IPs in the subnet
    for ip in network.hosts():
        print(f"Checking {ip}...", end=" ", flush=True)
        if ping_host(str(ip)):
            print("✅ Device is active!")
            active_devices.append(str(ip))
        else:
            print("❌ No response.")
    
    return active_devices

if __name__ == "__main__":
    print("\n👋 Welcome to the Network Scanner Tool!")
    print("This script will help you find devices on your local network.\n")

    # Ask the user to enter their network range
    cidr = input("👉 Enter your network range (e.g., 192.168.0.0/24): ")
    print("\nStarting the scan... Please wait.\n")

    # Run the network scan
    active_hosts = network_scan(cidr)

    # Display results
    print("\n🎯 Active Devices Found:")
    if active_hosts:
        for host in active_hosts:
            print(f" - {host}")
    else:
        print("No active devices found. 🕵️‍♂️")

    print("\n✅ Scan Complete. Thanks for using this tool!")
