import socket
import time

# 1 Peter 4:10 - "Each of you should use whatever gift you have received to serve others, as faithful stewards of God’s grace in its various forms."

def print_hacker_style():
    print("\nInitializing Port Scanner...\n")
    time.sleep(1)
    print("Connecting to target...\n")
    time.sleep(2)
    print("Scanning ports...\n")
    time.sleep(1)

def port_scanner(target, port_range):
    print_hacker_style() 
    print(f"Scanning target: {target}")
    print(f"Scanning ports: {port_range[0]} to {port_range[1]}")

    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Timeout to prevent long wait on closed ports
            result = s.connect_ex((target, port))
            if result == 0:  # Port is open
                print(f"Port {port}: OPEN  >>> [*]")
            else:
                print(f"Port {port}: CLOSED  >>> [ ]")


if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    port_scanner(target_ip, (start_port, end_port))
