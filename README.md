#  Sanatan Labs – AI Cyber Shield

<p align="center">
  <img src="assets/logo.png" width="150"/>
</p>

<h3 align="center">AI-Powered Autonomous Security Vulnerability Detection & Remediation Platform</h3>

<p align="center">
Detect • Analyze • Remediate • Secure
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue"/>
  <img src="https://img.shields.io/badge/Flask-Backend-red"/>
  <img src="https://img.shields.io/badge/SocketIO-RealTime-green"/>
  <img src="https://img.shields.io/badge/TailwindCSS-Frontend-cyan"/>
  <img src="https://img.shields.io/badge/SQLite-Database-lightgrey"/>
  <img src="https://img.shields.io/badge/OpenRouter-LLM-orange"/>
</p>

---

##  Project Overview

AI Cyber Shield is an autonomous security intelligence platform that leverages Artificial Intelligence and Large Language Models to perform deep semantic code analysis, identify vulnerabilities, generate secure remediation code, and create interactive security reports.

Unlike traditional static analysis tools that rely on predefined rules and signatures, AI Cyber Shield understands the context of source code and can detect complex vulnerabilities that conventional scanners often miss.

---

#  Application Preview

## Landing Page
<img width="1918" height="946" alt="image" src="https://github.com/user-attachments/assets/52ecd3b4-e727-4106-95da-ed58a8cfeeb2" />

<img width="1909" height="965" alt="image" src="https://github.com/user-attachments/assets/508423df-03a9-43ce-98f0-a3d17cb6abb0" />

---

## Real-Time Scanning Dashboard
<img width="1909" height="971" alt="image" src="https://github.com/user-attachments/assets/15cc4f45-f808-4ef1-8af3-59af882a1ea3" />



## Vulnerability Report
<img width="1597" height="967" alt="image" src="https://github.com/user-attachments/assets/8d5e0665-712f-4bf0-ace6-310cbec2c16e" />


---

## Secure Code Generation
<img width="1632" height="641" alt="image" src="https://github.com/user-attachments/assets/91ba61eb-e1f6-45ec-9d5f-64bd7991a110" />
```text
Here ->
- represents that lines has been removed /modified from the original code.
+ represents the addition of the secure code.
```

---

## Git Diff & Remediation Comparison

<img width="1588" height="603" alt="image" src="https://github.com/user-attachments/assets/4941fbf3-2ac5-47c5-984d-b08375c9817f" />

---
## User Overall Dashboard and log

<img width="1918" height="969" alt="image" src="https://github.com/user-attachments/assets/a05c5f7e-a182-4847-8d7a-858b2c7bf97d" />
<img width="1910" height="891" alt="image" src="https://github.com/user-attachments/assets/caa2d172-57e9-4356-a1d5-6ff2c3e3b3e1" />


---
#  Features

 AI-based semantic vulnerability detection
 Automated secure code remediation
 Real-time WebSocket terminal logs
 GitHub repository scanning
 File upload and code snippet analysis
 Interactive vulnerability reports
 CVSS severity analysis
 Secure code generation and diff comparison
 OWASP Top-10 vulnerability detection

---

#  Vulnerabilities Detected

* SQL Injection
* Command Injection
* Authentication Bypass
* Access Control Issues
* Hardcoded Secrets
* Credential Exposure
* Insecure Deserialization
* Buffer Overflows
* Race Conditions
* Cross-Site Scripting (XSS)
* Code Injection Vulnerabilities

---

# 🏗️ System Architecture

```text
User Input
     │
     ▼
Code Parser & Context Segmenter
     │
     ▼
AI Vulnerability Scanner
     │
     ▼
Remediation Engine
     │
     ▼
Report Generator
     │
     ▼
Dashboard & Terminal Logs
```

---

#  Tech Stack

| Category                | Technologies             |
| ----------------------- | ------------------------ |
| Backend                 | Python, Flask            |
| Real-Time Communication | Flask-SocketIO, Eventlet |
| AI Engine               | OpenRouter API           |
| Database                | SQLite                   |
| Frontend                | HTML, CSS, TailwindCSS   |
| Repository Management   | GitPython                |
| Reporting               | HTML Reports             |

---

# 📂 Project Structure

```bash
Codebase Vul analysis/ (Root Directory)
├── .gitignore                                 # Git rules ignoring caches, credentials, and logs
├── project_overview.md                        # Project documentation for ChatGPT
└── industry_project/
    ├── .env                                   # API Credentials & Config Keys (git-ignored)
    ├── sample_code/                           # Sample source scripts for evaluation
    │   ├── paste_169aea.py
    │   └── up_120a55_Assignmnet 11.cpp
    └── cyber_vuln_system/
        ├── __init__.py
        ├── app.py                             # Main Web Server entrypoint (SocketIO server)
        ├── api_routes.py                      # RESTful controller routing endpoints (API v2)
        ├── main.py                            # Core startup controller orchestration
        ├── database.py                        # DB initialization configuration
        ├── realtime.py                        # Real-time WebSocket event triggers
        ├── requirements.txt                   # Platform dependencies (Flask-SocketIO, Eventlet, etc.)
        ├── cyber_vuln.db                      # Local SQLite database engine (git-ignored)
        │
        ├── modules/                           # Custom analysis engines and SAST microservices
        │   ├── __init__.py
        │   ├── static_scanner.py              # Rule-based AST syntax and regex SAST engine
        │   ├── scan_service.py                # Orchestrator of code scanner sequences
        │   ├── ai_analyzer.py                 # LLM Integration and prompt builder service
        │   ├── risk_classifier.py             # Severity scorer and vulnerability impact analyzer
        │   ├── auth.py                        # User authentication and token validator module
        │   ├── audit_logger.py                # User activity and event logger module
        │   └── chart_formatter.py             # Format scan graphs & chart visualizations
        │
        ├── profile/                           # Core output formatting plugins
        │   ├── __init__.py
        │   ├── report_generator.py            # Generates compliance HTML audit reports
        │   └── code_generator.py              # Writes secure remediated file templates
        │
        ├── static/
        │   └── logo.png                       # Sanatan Labs premium logo asset
        │
        ├── templates/
        │   └── index.html                     # Full UI Frontend Dashboard with Canvas background
        │
        ├── sample_code/                       # Scoped sandbox for code uploads & git clones (git-ignored)
        └── reports/                           # Output directory for HTML audits & secure files (git-ignored)

```

---

# ⚙️ Installation & Setup

## Clone Repository

```bash
git clone https://github.com/ojas-k070/Sanatan-Cybershield.git
cd Sanatan-Cybershield
cd industry_project

```

## Create Virtual Environment

```bash
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configure Environment Variables

Create a `.env` file:

```env
OPENROUTER_API_KEY=your_openrouter_api_key
```

---

## Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

#  Workflow

1. User uploads source code or GitHub repository.
2. Repository is cloned and parsed.
3. Context segmenter extracts functions and variables.
4. AI engine scans for vulnerabilities.
5. Real-time logs are streamed to the dashboard.
6. Secure remediation code is generated.
7. Interactive HTML reports are created.
8. User downloads reports and fixed code.

---

#  Project Highlights

* Autonomous AI Security Auditor
* Real-Time Vulnerability Detection
* Automated Secure Code Generation
* Enterprise Security Reporting
* Developer-Friendly Interactive Dashboard
* Significantly Reduces Mean Time To Resolution (MTTR)

---

# 🚀 Future Enhancements


* Docker deployment
* Kubernetes integration
* CI/CD pipeline integration
* Email alert system
* Team collaboration dashboard
* Historical vulnerability analytics
* OWASP compliance scoring

---

#  Author

**Ojas Anand Kulkarni**

B.Tech Artificial Intelligence Student
VISHWAKARMA INSTITUTE OF TECHNOLOGY, PUNE-37, INDIA
GitHub: https://github.com/ojas-k070

---

# ⭐ Support

If you found this project useful:

⭐ Star this repository

🍴 Fork this repository

---


