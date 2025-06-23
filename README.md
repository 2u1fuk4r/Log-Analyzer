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

=== For remove the all logs ===
Warning it is remove permanently!!!
python3 log-analyzer.py --reset
