# SILENT-SENTINELS-FOR-BEGINNERS![Silent Sentinels](https://github.com/user-attachments/assets/8c570881-1ec2-48f9-85ce-093f5b3766b1)


Welcome to Silent Sentinels, a collection of beginner-friendly cybersecurity projects designed to help you get hands-on experience with real-world security concepts and tools. This repository focuses on providing easy-to-understand scripts, explanations, and automations that make cybersecurity engaging and fun to learn!

## Projects Overview

This repository contains 8 foundational cybersecurity projects that will help you build essential skills, from simple password security checkers to more advanced breach detection systems. The projects are organized to allow you to build your skills progressively.

## Table of Contents

1. [Password Strength Checker](#1-password-strength-checker)
2. [Password Breach Checker](#2-password-breach-checker)
3. [Network Scanner](#3-network-scanner)
4. [Basic Port Scanner](#4-basic-port-scanner)
5. [Keylogger Detection Script](#5-keylogger-detection-script)
6. [Malware Detection Using File Hashing](#6-malware-detection-using-file-hashing)
7. [Firewall Configuration Automation](#7-firewall-configuration-automation)
8. [Security Audit Script](#8-security-audit-script)

---

## 1. Password Strength Checker

### Description:
A Python script that evaluates the strength of a password based on length, character variety (uppercase, lowercase, numbers, special characters), and common patterns. This tool provides feedback on whether a password is weak, moderate, strong, or very strong.

### Features:
- Checks password length and complexity
- Gives real-time feedback on password strength
- Provides suggestions to improve weak passwords

### Usage:
Run the script and enter a password to check its strength. The script will output the password score, strength rating, and a visual strength bar.

```bash
python password_strength_checker.py

```
## 2. Password Breach Checker

### Description:
This project enhances the password strength checker by adding a breach check feature. It uses the Have I Been Pwned (HIBP) API to check whether the password has been involved in any known data breaches.

### Features:
- Uses SHA-1 hashing to securely check passwords against the HIBP database
- Deduces points if the password has been breached and shows a warning
- Suggests alternative password improvements

### Usage:
After the password strength check, the script will inform you if your password has been exposed in any breaches, along with the number of times it has been found in compromised data sets.

```bash
python password_breach_checker.py

```
## 3. Network Scanner

### Description:
A simple Python script that scans your local network for active devices by sending ICMP requests to all IP addresses in the range. This can be useful for network administrators to map out connected devices.

### Features:
- Uses ICMP protocol to check for active hosts
- Displays IP addresses and hostnames of connected devices
- Helps identify unauthorized devices on your network

### Usage:
Run the script with the range of IP addresses you want to scan, and it will list active devices in your network.

```bash
python network_scanner.py
```
## 4. Basic Port Scanner

### Description:
A Python-based port scanner to check if specific ports on a target server or IP address are open, closed, or filtered. This is crucial for vulnerability assessments.

### Features:
- Scans a range of ports on a target server
- Provides feedback on whether each port is open, closed, or filtered
- Can be customized to scan specific ports or a range

### Usage:
Enter the target IP and the range of ports to scan. The script will check the specified ports and return the status for each one.

```bash
python port_scanner.py
```
## 5. Keylogger Detection Script

### Description:
This project helps you detect the presence of keyloggers or unauthorized keypress tracking programs on your system. Keyloggers are malicious software designed to record every key press made on your device, and they can be used to steal sensitive information such as passwords, credit card numbers, and personal messages. The Keylogger Detection Script scans the system for suspicious processes and compares them against known keylogger signatures. This is a vital tool for ensuring the security of your system and preventing unauthorized surveillance.

### Features:
- **Scans running processes**: The script inspects the list of processes currently running on your system.
- **Detects known keylogger signatures**: It uses a predefined set of signatures (or patterns) that are commonly associated with keylogging software.
- **Alerts on suspicious activity**: If any of the processes match known keylogger signatures, the script will notify you with an alert.
- **Cross-platform support**: The script is lightweight and can be run on both Windows and Linux environments.

### Usage:
To use the Keylogger Detection Script, simply execute it on your system. It will automatically scan all active processes, looking for any that exhibit the characteristics of known keylogging software. If any suspicious programs are found, it will raise an alert to notify you of potential security risks.

#### Running the Script:
```bash
python keylogger_detection.py
```
## 6. Malware Detection Using File Hashing

### Description:
This script detects potential malware by comparing file hashes against a list of known hashes of malicious software. Malware often disguises itself by using legitimate filenames, but the underlying file data (its hash) remains consistent. By calculating the hash of files and comparing them to a database of known malicious hashes, this tool helps identify compromised files on your system.

The script uses **SHA-256** hashing to securely generate unique fingerprints of files and compares these hashes against a predefined list of malicious file signatures. This method is reliable and effective because even small changes in a file will result in a completely different hash, allowing for precise detection of known threats.

### Features:
- **Hash Calculation**: The script calculates the **SHA-256 hash** of each file to generate a unique identifier.
- **Malware Hash Database**: It compares each file's hash with a list of known malware hashes.
- **Alerts on Matches**: If a file matches a known malicious hash, the script will alert you with a warning.
- **Customizable**: You can update the list of known malicious hashes by adding or removing entries in the database.

### Usage:
To use the script, simply provide it with a directory or set of files to scan. The script will calculate the hash for each file, compare it with a list of known malicious hashes, and provide an alert if any matches are found.

#### Running the Script:
```bash
python malware_detection.py /path/to/scan/directory
```
## 7. Firewall Configuration Automation

### Description:
This Python script automates the configuration of basic firewall rules on Linux systems using `iptables`. Firewalls are a critical line of defense for any system, controlling the incoming and outgoing traffic and blocking unauthorized access. This script helps administrators quickly set up secure firewall configurations by automatically applying essential rules such as blocking unwanted IPs, allowing specific ports, and securing the system against potential threats.

The script is particularly useful for system administrators who want to automate the configuration of firewall rules across multiple systems, ensuring consistency and security with minimal effort. It allows you to define your rules in a straightforward manner and then apply them to the system's firewall.

### Features:
- **Automated Firewall Setup**: The script applies predefined rules to the firewall, saving time and reducing the likelihood of manual configuration errors.
- **Common Security Rules**: Includes commonly used firewall rules for securing a system, such as blocking traffic from unwanted IP addresses, allowing specific ports for services (e.g., SSH, HTTP), and preventing unauthorized access.
- **Customizable Rules**: You can modify the script to include additional firewall rules specific to your needs.
- **Cross-Platform**: While it is primarily designed for Linux-based systems using `iptables`, you can adapt the script to work with other systems if necessary.

### Usage:
To use this script, simply run it with the desired firewall rules as parameters. The script will apply the rules to the system’s firewall (`iptables`), configuring it to block or allow traffic according to your specifications.

#### Running the Script:
```bash
python firewall_config_automation.py
```
## 8. Security Audit Script

### Description:
This Python-based security audit tool scans a system for common vulnerabilities, outdated software, open ports, weak file permissions, and other security issues. It helps administrators and security professionals perform a quick overview of the system's security posture, making it easier to identify areas that need attention or improvement. 

The script automates the process of auditing a system's security, providing an easy way to identify weak points that may be exploited by attackers. The audit checks for a wide range of security issues, from open ports that shouldn’t be exposed to outdated software versions that may have known vulnerabilities.

### Features:
- **Open Ports Detection**: Identifies open ports that may be exposed to the internet or local network.
- **Software Version Checks**: Scans for outdated software and warns if any applications need updating.
- **Weak File Permissions**: Detects files or directories with weak permissions that could allow unauthorized access.
- **Security Best Practices**: Performs a check against security best practices, such as ensuring critical system files are protected and user permissions are correctly configured.
- **Easy-to-Read Report**: After the audit, the script generates a security report that highlights any issues found and suggests actions to fix them.

### Usage:
To use the script, simply run it on the system you want to audit. The script will scan the system for common vulnerabilities and generate a security report that highlights any potential issues. The output will include details about any open ports, outdated software, weak file permissions, and any other vulnerabilities detected.

#### Running the Script:
```bash
python security_audit.py
```
## Requirements

To run these scripts, you'll need the following:

- **Python 3.x**: The scripts are written in Python 3, so you’ll need Python version 3.x or later installed on your system.
- **requests library**: Some scripts (especially those making API calls) use the `requests` library for HTTP requests. This library needs to be installed before running the scripts.
- **Administrative privileges**: Some scripts require administrative (root) privileges to access or modify system settings, scan the network, or modify firewall settings. Make sure to run these scripts with the necessary permissions (e.g., using `sudo` on Linux-based systems).

### Install the Required Libraries

Before running the scripts, install the required libraries using `pip`. If you don’t have `requests` installed, you can install it with the following command:

```bash
pip install requests
```

## License

This project is licensed under the **MIT License**.

The MIT License is a permissive free software license that allows you to freely use, modify, and distribute the code, provided that you include a copy of the license in any distribution of the software. It also includes a disclaimer that the software is provided "as-is," without warranties of any kind.

For full details, see the [LICENSE](LICENSE) file in this repository.

### Summary of the MIT License:

- **Permissions**: 
  - You can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.
  
- **Conditions**: 
  - You must include a copy of the license in all copies or substantial portions of the software.
  
- **Limitation**: 
  - The software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, or noninfringement.

For the full text of the MIT License, you can refer to the [LICENSE file](LICENSE).
