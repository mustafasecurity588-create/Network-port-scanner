# 🔍 NetScan Pro

> A modern Python GUI-based Network Port Scanner with TCP/UDP scanning, banner grabbing, service detection, OS fingerprinting, WHOIS lookup, GeoIP information, and PDF reporting.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

---

# 📖 Overview

NetScan Pro is an advanced yet lightweight network scanner developed entirely in Python. It provides a clean graphical interface for scanning TCP and UDP ports, detecting common services, grabbing banners, identifying possible operating systems, and exporting professional vulnerability reports.

The application was designed as an educational cybersecurity project demonstrating networking concepts, socket programming, multithreading, GUI development, and basic reconnaissance techniques.

---

# ✨ Features

## Network Scanning

- TCP Port Scanning
- UDP Port Scanning
- Multi-threaded scanning
- Custom port ranges
- Quick Scan mode
- Full Scan mode
- Stealth SYN Scan (Scapy)

---

## Service Detection

- Automatic service identification
- Common service database
- Version detection
- Banner grabbing
- HTTP header inspection

Example:

```
22   SSH
80   HTTP
443  HTTPS
3306 MySQL
3389 RDP
```

---

## OS Fingerprinting

Detects the probable operating system using:

- ICMP TTL values
- Service fingerprinting
- Banner analysis

Example output

```
Linux / Ubuntu
Windows
Cisco
Unknown
```

---

## WHOIS Lookup

Retrieve:

- Registrar
- Organization
- Name Servers
- Registration Date
- Expiration Date
- Country

---

## GeoIP Lookup

Displays

- Country
- City
- ISP
- Organization
- Latitude
- Longitude
- Timezone
- Hosting Provider
- VPN / Proxy Detection

---

## Risk Analysis

Each discovered port is classified automatically.

| Risk | Description |
|-------|-------------|
| 🔴 HIGH | Dangerous or commonly attacked services |
| 🟠 MEDIUM | Public services requiring attention |
| 🟢 LOW | Minimal risk |
| ⚪ INFO | Closed or informational |

---

## Export Options

Generate reports as

- PDF Report
- CSV Report

The PDF includes

- Scan Summary
- Open Ports
- Banner Information
- OS Fingerprint
- WHOIS
- GeoIP Information

---

## Modern GUI

Dark themed interface with

- Real-time progress
- Scan statistics
- Search & filtering
- Color-coded results
- Log viewer
- Summary tab
- WHOIS tab
- GeoIP tab

---

# 🖥 Screenshots

## Main Window

(Add Screenshot Here)

```
images/main.png
```

---

## Scan Results

(Add Screenshot Here)

```
images/results.png
```

---

## PDF Report

(Add Screenshot Here)

```
images/report.png
```

---

# ⚙ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/NetScanPro.git

cd NetScanPro
```

---

## Install Dependencies

```bash
pip install requests

pip install python-whois

pip install reportlab

pip install scapy
```

Or install everything

```bash
pip install requests python-whois reportlab scapy
```

---

# ▶ Run

```bash
python NetScanPro.py
```

---

# 📦 Project Structure

```
NetScanPro/

│
├── NetScanPro.py
├── README.md
├── LICENSE
├── requirements.txt
│
├── reports/
│
├── images/
│   ├── main.png
│   ├── results.png
│   └── report.png
│
└── exports/
```

---

# 🚀 Usage

## Step 1

Enter

```
Target Host

Example

scanme.nmap.org

or

192.168.1.1
```

---

## Step 2

Choose Scan Mode

- Quick
- Full
- Stealth SYN

---

## Step 3

Configure

- Timeout
- Retries
- Thread Count
- Banner Grabbing
- UDP Scan
- WHOIS Lookup
- GeoIP Lookup

---

## Step 4

Press

```
Start Scan
```

---

## Step 5

Review Results

- Open Ports
- Services
- Versions
- Risk Level
- Banner
- OS Guess

---

## Step 6

Export Results

- PDF
- CSV

---

# 📊 Supported Features

| Feature | Status |
|----------|--------|
| TCP Scan | ✅ |
| UDP Scan | ✅ |
| Multi-threading | ✅ |
| Banner Grabbing | ✅ |
| Service Detection | ✅ |
| Version Detection | ✅ |
| OS Fingerprinting | ✅ |
| WHOIS Lookup | ✅ |
| GeoIP Lookup | ✅ |
| PDF Export | ✅ |
| CSV Export | ✅ |
| GUI | ✅ |

---

# 🧠 Technologies Used

- Python
- Tkinter
- Socket Programming
- ThreadPoolExecutor
- Threading
- Queue
- ReportLab
- Requests
- Scapy
- Python-Whois

---

# 📚 Concepts Demonstrated

- Networking
- Socket Programming
- TCP/IP
- UDP
- Banner Grabbing
- Threading
- GUI Development
- Reconnaissance
- WHOIS
- GeoIP
- File Export
- PDF Generation

---

# ⚠ Disclaimer

This software is intended **only for educational purposes and authorized security testing**.

Never scan systems that you do not own or have explicit permission to test.

The author is not responsible for misuse of this software.

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

# 📝 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**Your Name**

Cybersecurity Student

Python Developer

Vulnerability Assessment Enthusiast

GitHub:
https://github.com/yourusername

LinkedIn:
https://linkedin.com/in/yourprofile

---

# ⭐ Support

If you found this project useful, please consider giving it a ⭐ on GitHub.

It helps others discover the project and motivates future improvements.

---

# 📈 Future Improvements

- Nmap XML Import
- CVE Database Integration
- NSE Script Support
- SSL Certificate Analysis
- Vulnerability Detection
- IPv6 Support
- Scheduled Scanning
- Scan History
- Database Storage
- Email Reports
- HTML Report Export
- Dark/Light Themes
- Plugin System

---

## Example Scan

```
Target:
scanme.nmap.org

Open Ports

22 SSH

80 HTTP

443 HTTPS

OS

Linux / Ubuntu

WHOIS

Registrar:
Namecheap

Country:
United States

ISP:
Linode

Risk

22 SSH        Medium

80 HTTP       Medium

443 HTTPS     Low

Export

Scan_Report.pdf
```

---

## ⭐ If you like this project

Give it a ⭐ on GitHub and share it with others.

Happy Scanning!
