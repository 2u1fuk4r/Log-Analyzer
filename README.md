# 🛡️ SSH Log Analyzer

**SSH Log Analyzer** is a Python tool that analyzes recent SSH login activity on systemd-based Linux systems (like Kali Linux) using `journalctl`. It identifies failed login attempts, unusual accepted logins, and system/kernel warnings.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/Tested-Kali%20Linux-informational)

---

## 🚀 Features

- Reads SSH logs from `journalctl` for the past hour
- Tracks failed login attempts by IP address
- Detects accepted logins from multiple IPs for same user
- Displays system and kernel errors
- Supports `--reset` to permanently delete system logs (dangerous!)
- Beautiful output using the `rich` Python library

---

## 🧪 Usage

### 🔍 Run Log Analysis

Requirements
```bash
chmod +x install.sh
chmod +x log-analyzer.py
bash install.sh

=== run the tool===
python3 log-analyzer.py

Help Menu
python3 log-analyzer.py --help
usage: log-analyzer.py [-h] [-r] [--since SINCE] [--until UNTIL] [--export FILE] [--recommend]

SSH Log Analyzer Tool Analyze SSH logs from systemd journal, detect suspicious activity, and optionally reset logs or export reports.

options:
  -h, --help     show this help message and exit
  -r, --reset    Permanently delete all systemd journal logs (requires root)
  --since SINCE  Start time for logs (e.g., "2025-06-22 08:00:00" or "2 hours ago")
  --until UNTIL  End time for logs (e.g., "2025-06-22 10:00:00")
  --export FILE  Export the report to specified file (TXT or JSON based on extension)
  --recommend    Show iptables/fail2ban commands to block IPs with failed logins

