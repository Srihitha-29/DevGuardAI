# 🛡️ DevGuard AI — Hybrid Static Code Security Auditor

DevGuard AI is a hybrid AI-powered security auditing platform that combines rule-based static analysis with Gemini AI contextual code review to identify security vulnerabilities in source code projects.

The application scans Java, Python, JavaScript, and C++ files (including ZIP projects), detects vulnerabilities, explains security risks in plain English, recommends secure fixes, and generates downloadable PDF security reports.

## ✨ Features

* 🔍 Rule-based static vulnerability scanner.
* 🤖 Gemini AI contextual security auditing.
* 🛠 AI-generated explanations and secure fixes.
* 📊 Security score calculation.
* 📄 Downloadable PDF security report.
* 📦 ZIP project scanning with recursive file extraction.
* 🎨 Modern interactive dashboard with loading stages and vulnerability visualization.

## 🧠 Hybrid Security Architecture

1. Upload source code or ZIP project.
2. Static scanner checks predefined vulnerability patterns.
3. Gemini AI audits risky code for contextual security issues.
4. Findings are merged into a single security dashboard.
5. PDF report is generated with recommendations.

## 🔐 Vulnerabilities Detected

### Static Scanner

* SQL Injection
* Hardcoded Secrets
* Weak Passwords
* Insecure HTTP Usage
* Command Injection
* Dangerous `eval()` / `exec()`

### AI Security Audit

* Missing Input Validation
* Sensitive Logging
* Debug Logging
* Contextual Security Risks
* Additional secure coding recommendations

## 🛠 Tech Stack

**Frontend**

* HTML5
* CSS3
* JavaScript

**Backend**

* Python
* FastAPI
* Google Gemini API
* ReportLab

## 📁 Project Structure

DevGuardAI/
├── frontend/
├── backend/
│ ├── ai/
│ ├── scanner/
│ ├── test_files/
│ ├── main.py
│ ├── report_generator.py
│ └── requirements.txt
├── .gitignore
└── README.md

## 🚀 How to Run Locally

### Backend

```bash
cd backend

python -m venv venv

source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

pip install -r requirements.txt

uvicorn main:app --reload
```

### Frontend

Open `frontend/index.html` using VS Code Live Server.

## 📊 Sample Workflow

* Upload `.java`, `.py`, `.js`, `.cpp`, or `.zip`
* Static scan executes.
* AI security audit runs.
* Dashboard displays vulnerabilities.
* Download PDF security report.

## 👩‍💻 Developer

**Savarapu Lakshmi Srihitha**

Final Year Computer Science Engineering Student

Ravindra College of Engineering for Women

## 📌 Future Enhancements

* Multi-language support.
* OWASP Top 10 coverage.
* Authentication and scan history.
* CI/CD GitHub integration.
* Team security dashboard.
