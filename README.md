# Simplified Predictive Risk Reporting Tool

## Overview
The Simplified Predictive Risk Reporting Tool is a cybersecurity-focused web application designed to assist with cyber threat monitoring and risk reporting. The system combines Natural Language Processing (NLP), threat intelligence APIs, and secure authentication to help users analyse threat information and generate structured risk reports.

This project was developed as a final-year cybersecurity project and demonstrates practical skills in secure development, threat analysis, and web-based security tooling.

---

## Key Features

### NLP-Based Threat Classification
- Custom-trained spaCy Named Entity Recognition (NER) model
- Detects cybersecurity entities such as vulnerabilities, attack types, and threat actors
- Converts unstructured text into structured threat information

### Threat Intelligence Integration
- VirusTotal API integration for malicious file/hash analysis
- Shodan API integration for infrastructure exposure insights
- Live enrichment of analysed data

### Secure Authentication & Access Control
- User registration and login system
- Password hashing for secure credential storage
- Email-based Two-Factor Authentication (2FA)
- Session protection and route access control

### 📊 Dashboard & Reporting
- Interactive dashboard for viewing analysis results
- Automated risk report generation
- Export reports to TXT and PDF formats
- Report history tracking

### UI/UX Enhancements
- Clean card-based dashboard layout
- Dark mode toggle
- Responsive design
- Loading spinner during analysis

---

## Technologies Used

**Backend**
- Python
- Flask
- spaCy (NLP / NER)
- SQLite

**Frontend**
- HTML
- CSS
- Bootstrap
- JavaScript

**Security & APIs**
- VirusTotal API
- Shodan API
- Mailtrap (2FA testing)
- Password hashing & session management

**Tools**
- Git & GitHub
- Trello (Agile sprint planning)
- Figma (UI wireframing)
- Render (deployment)

---

## Security Focus
This project demonstrates practical cybersecurity implementation including:

- Secure authentication workflows
- Two-Factor Authentication (2FA)
- API-based threat intelligence enrichment
- Risk scoring and reporting logic
- Secure session handling
- Environment variable usage for sensitive data

---

## Live Deployment
Live Application:

https://simplified-predictive-risk-reporting.onrender.com

---

## 📸 Screenshots
()

Example:

![Dashboard](screenshots/dashboard.png)

---

## Running Locally

Clone the repository:

```bash
git clone https://github.com/Aishamako/simplified-predictive-risk-reporting-tool.git
