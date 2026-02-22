<h1 align="center">🤖 AutoDAST</h1>
<h3 align="center">AI-Powered Automated Vulnerability Assessment & Penetration Testing Tool</h3>

<p align="center">
  <a href="#"><img alt="PyQt6" src="https://img.shields.io/badge/Built%20with-PyQt6-41B883?logo=qt&logoColor=white"></a>
  <a href="#"><img alt="Orca Mini" src="https://img.shields.io/badge/AI%20Model-Orca%20Mini%203B-800080?logo=openai&logoColor=white"></a>
  <a href="https://www.zaproxy.org/"><img alt="ZAP Integration" src="https://img.shields.io/badge/Integrated%20with-OWASP%20ZAP-orange"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python" src="https://img.shields.io/badge/Python-3.8+-blue.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg"></a>
  <a href="#"><img alt="Platform" src="https://img.shields.io/badge/Platform-Cross--Platform-lightgrey?logo=windows&logoColor=blue"></a>
</p>

---

> ⚠️ **Security Notice:** This tool is intended for authorized security testing only. Do **NOT** use on systems without permission.

---

## 🚀 Features

### 🛡️ Vulnerability Assessment

- Automated scanning via [OWASP ZAP](https://www.zaproxy.org/)
- OWASP Top 10 mapping
- Severity classification
- JSON & **Native Python PDF reporting (no Pandoc/LaTeX required!)**

### ⚔️ Penetration Testing

- Subdomain enumeration (`subfinder`, `amass`)
- Port scanning (`nmap`, `masscan`)
- Dir brute-forcing (`gobuster`)
- JS & API recon (`LinkFinder`, `SecretFinder`)
- XSS, SQLi, SSRF, LFI, IDOR, Open Redirect checks
- **Automatic screenshots of findings included in reports**

### 🤖 AI-Powered Insights

- CVE/CVSS scoring
- Risk-level estimation
- Actionable hybrid mitigation
- Lightweight Orca Mini 3B model support

### 💬 Built-in Cyber Assistant

- Explains risks & fixes
- Offers best practices
- Gives responsive replies with loading indicator

---

## ⚙️ Requirements

- Python 3.8+
- [OWASP ZAP](https://www.zaproxy.org/)
- Tools: `subfinder`, `amass`, `nmap`, `masscan`, `gobuster`, `LinkFinder`, `SecretFinder`, `retire.js`, `nuclei`
- **No Pandoc or LaTeX required for PDF reports!**

---

## 📦 Installation

```bash
# Clone your repo
git clone https://github.com/Vaibhav-crux/ai_dast_security_tool.git
cd ai_dast_security_tool

python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

🔧 Update `.env` with:

- ZAP API Key
- Paths to tools
- AI model location

---

## 💻 Usage

```bash
python main.py
```

From the GUI:

- Enter target URL
- Choose assessment type
- Start scan
- View results
- Export reports (PDFs generated natively in Python)

---

## 📁 Output Files

| File                   | Description                                 |
| ---------------------- | ------------------------------------------- |
| `va_results.json`      | Vulnerability scan results                  |
| `pentest_results.json` | PT logs and tool outputs                    |
| `VAPT_Report_*.pdf`    | **Professional PDF report (native Python)** |

---

## 🧩 Configuration

Edit the `.env` file for:

- API keys
- Output paths
- Model parameters
- Tool binaries

---

## 📜 License

Licensed under the [MIT License](LICENSE).

---

## 🙌 Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/)
- [ProjectDiscovery](https://github.com/projectdiscovery)
- Open-source security community
- PyQt6, Orca Mini AI, ZAP API
