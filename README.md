# Vuln_scanner
# Vulnerability Scanner

A **Python-based vulnerability scanner** that scans open ports, grabs banners, and checks for known vulnerabilities using the **NVD (National Vulnerability Database) API**.

## 🚀 Features
- **Port Scanning**: Scans all 65,535 ports using Nmap.
- **Service & Version Detection**: Identifies running services and their versions.
- **Banner Grabbing**: Extracts service banners to detect vulnerabilities.
- **CVE Lookup**: Fetches known vulnerabilities from the NVD API.

## 📌 Requirements
Ensure you have the following installed:

- Python 3.x
- nmap
- python-nmap
- requests

## 🔧 Installation

sh
# Clone the repository
git clone https://github.com/yourusername/vulnerability-scanner.git
cd vulnerability-scanner

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt



## 🛠️ Usage

sh
python scanner.py <target_ip_or_domain>


Example:

sh
python scanner.py 192.168.1.1



## ⚠️ Disclaimer
This tool is for **educational purposes only**. Do **not** scan systems without proper authorization.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💡 Contributions
Pull requests and improvements are welcome! Open an issue if you find a bug or want to suggest a feature.

---
🚀 Happy Hacking!