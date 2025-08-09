# 🛡️ Log File Intrusion Detector (LFID) – Regex Enhanced

[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License: Apache 2.0 ](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

A Python-based intrusion detection tool that scans server log files for suspicious activities using **configurable regex patterns**.  
Supports detection of failed logins, SQL injection attempts, and access from blacklisted IPs.

---

## 📌 Overview

The **LFID** project is designed to help administrators quickly identify potential threats in server logs.  
It uses a **YAML/JSON config file** to define detection rules and outputs a detailed report.  
With **regex support**, detection patterns are now more flexible and powerful.

---

## ✨ Features

- **Configurable rules** (via YAML or JSON)
- **Regex pattern matching** for complex detection
- Detects:
  - ❌ Failed login attempts
  - 🚨 SQL injection patterns
  - ⛔ Blacklisted IP activity
- Generates a detailed `report.txt`
- Optional email alerts

---

## 📁 File Structure

```plaintext
.
├── lfid_regex.py                 # Main detection script (regex support)
├── lfidconfig_regex.yaml         # Config file with regex patterns
├── samplelog.txt                 # Example log file
├── report.txt                    # Generated report output
```

---

## ⚙️ Configuration

Example `lfidconfig_regex.yaml`:

```yaml
rules:
  failed_login:
    patterns:
      - 'failed\s+password'
      - 'authentication\s+failure'
  sql_injection:
    patterns:
      - 'select.+from'
      - 'union\s+select'
      - 'or\s+1\s*=\s*1'
      - 'drop\s+table'
      - '--'
  ip_blacklist:
    - '46.118.125.84'
    - '217.12.185.5'

email:
  enabled: false
  sender_email: 'you@example.com'
  sender_password: 'yourpassword'
  recipient_email: 'admin@example.com'
  smtp_server: 'smtp.example.com'
  smtp_port: 587
```

---

## 🚀 Usage

Run from the command line:

```bash
python lfid_regex.py --log samplelog.txt --config lfidconfig_regex.yaml
```

**This will:**
1. Parse the log file
2. Apply regex-based detection rules
3. Save findings in `report.txt`

---

## 📄 Example Report

```plaintext
 Suspicious Activity Report 

[Line 4335] [Blacklisted IP] 46.118.125.84 - - [18/May/2015:22:05:04 +0000] "GET /..."
[Line 7777] [Blacklisted IP] 217.12.185.5 - - [20/May/2015:02:05:56 +0000] "GET /..."
```

---

## 📧 Email Alerts (Optional)

1. Enable by setting `email.enabled: true` in the config
2. Fill in SMTP details and credentials
3. If suspicious entries are found, an email will be sent with the report attached

---

## 🛠️ Requirements

- Python 3.7+
- PyYAML

Install PyYAML:

```bash
pip install pyyaml
```

---

## 🧪 Testing

You can test detection using `samplelog.txt`, which contains:
- Normal requests
- Failed login attempts
- SQL injection-like patterns
- Requests from blacklisted IPs

---

## 📌 Improvements Roadmap

- Add severity levels for threats
- Support for real-time monitoring
- Option to store results in a database
- Integration with SIEM tools

---

## 📜 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Manisankaran K.**  
📧 For contributions or feedback, feel free to fork the repo and create a pull request.
