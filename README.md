# 🛡️ Sanatan Labs: AI Cyber Shield

> **Autonomous security intelligence platform executing deep-neural vulnerability detection and real-time code remediation with military-grade precision.**

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.x-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![WebSockets](https://img.shields.io/badge/WebSockets-Socket.IO-010101?style=for-the-badge&logo=socket.io&logoColor=white)](https://socket.io/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)

---

## 📸 Platform Interface

Below is the interface showcase of the **Sanatan Labs: AI Cyber Shield** terminal and dashboard:

<div align="center">
  <img src="https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=1000" width="100%" alt="Sanatan Labs Interface Hero" style="border-radius: 12px; border: 1px solid rgba(0, 240, 255, 0.2);" />
  
  *Replace the placeholder image link above with your repository screenshot link once pushed to GitHub*
</div>

---

## 🚀 Key Architectural Features

* **🧠 Deep-Neural Code Auditing**: Replaces traditional static pattern-matching with context-segmented neural vulnerability analysis, discovering complex logical flaws and zero-day security gaps.
* **⚡ Automated Code Remediation**: Generates instant, production-ready code patches and secure code diffs to neutralize active security threats immediately.
* **📡 Real-Time Telemetry Terminal**: Powered by event-driven **Flask-SocketIO** WebSockets, streaming code compilation logs, telemetry data, and audit outputs back to the client at 60fps.
* **💎 Premium Interactive UX**: Implements a glassmorphic sci-fi dark-theme interface with custom HTML5 Canvas particle physics, fluid micro-interactions, and fully responsive layouts optimized for all device sizes.
* **📁 Repository Scanning**: Orchestrates direct cloning and parsing of local and remote GitHub repositories to audit full source directories on the fly.

---

## 🛠️ Technology Stack & Dependencies

* **Backend Engine**: Python 3.9+, Flask, Flask-CORS, Flask-SocketIO (WebSocket Server)
* **Asynchronous Networking**: Eventlet WSGI, Gunicorn
* **Static Analysis & OS Wrappers**: GitPython, AST Parsers, context segmenters
* **Database & Storage**: SQLite3 (Transactional local state preservation)
* **Frontend Layer**: HTML5 Canvas, Tailwind CSS, FontAwesome Icons, JavaScript (Vanilla ES6)

---

## ⚡ Quick Start & Deployment Guide

### 1. Local Development Installation
```bash
# Clone the repository
git clone https://github.com/ojas-k070/Sanatan-Cybershield.git
cd Sanatan-Cybershield/industry_project/cyber_vuln_system

# Install required system dependencies
pip install -r requirements.txt

# Run the local Flask server
python app.py
```
Open `http://127.0.0.1:5000` on your browser to load the platform.

### 2. Cloud Server Deployment (Render, Railway, Koyeb)
The app is configured for instant cloud deployment using dynamic port bindings. 

* **Startup Command**:
  ```bash
  gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:$PORT industry_project.cyber_vuln_system.app:app
  ```
* **Environment Variables**:
  Ensure you set the following variables in your hosting provider's dashboard:
  - `PORT`: Automatically assigned by hosting provider.
  - `OPENROUTER_API_KEY`: Your private LLM inference engine key.

---

## 🌟 Recruiter & Resume Highlights

If you are featuring this project on your resume, highlight these engineering challenges solved:
* **Event-Driven Telemetry**: Designed and implemented a low-latency WebSocket connection handling real-time console streaming and progressive scan telemetry updates.
* **Secure Environment Configuration**: Applied standard `.gitignore` filter definitions and untracked Git Index resets to enforce Push Protection compliance on sensitive API credentials and binary databases.
* **Responsive Fluid Design**: Engineered custom layout break-points and view-port limits using CSS grid systems alongside responsive Canvas animation handlers supporting touchscreen mobile gestures.
