# 🛡️ CyberAlert
### A Web-Based Cybersecurity Threat Detection and Alert Reporting System

CyberAlert is a web-based cybersecurity monitoring platform designed to detect suspicious activities on a host system and network. It integrates Host-Based Intrusion Detection (HIDS), Network-Based Intrusion Detection (NIDS), and basic malware detection into a centralized security dashboard.

The system monitors selected host activities and network traffic, analyzes them using predefined rules and signatures, and generates security alerts whenever potentially suspicious behavior is detected.

The main goal of CyberAlert is to make security monitoring easier by providing a centralized platform for detecting, viewing, and reporting potential security threats.

---

## 📌 Project Overview

CyberAlert focuses on three major areas of cybersecurity:

- **Host-Based Intrusion Detection (HIDS):** Monitors system activities, file changes, and selected suspicious processes.
- **Network-Based Intrusion Detection (NIDS):** Monitors network traffic and identifies potentially suspicious network behavior.
- **Malware Detection:** Performs basic static file analysis and signature-based detection to identify potentially malicious files.

All generated security alerts are collected and displayed through a centralized web dashboard.

---

## ✨ Features

### 1. Malware Detection
- Identify suspicious executable files using file hashes.
- Perform basic static file analysis.
- Detect known suspicious patterns using YARA rules.
- Generate alerts for potentially malicious files.

### 2. Host-Based Intrusion Detection (HIDS)
- Monitor selected files and directories.
- Detect unexpected file modifications and deletions.
- Monitor repeated failed login attempts.
- Identify selected suspicious process activities.
- Generate alerts when configured detection rules are triggered.

### 3. Network-Based Intrusion Detection (NIDS)
- Monitor network traffic in real time.
- Analyze TCP, UDP, ICMP, and DNS traffic.
- Detect possible port scanning activities.
- Identify repeated connection attempts.
- Detect selected suspicious network patterns.
- Generate alerts for potential network intrusions.

### 4. Security Dashboard
- Display generated security alerts.
- Categorize alerts by severity:
  - Low
  - Medium
  - High
  - Critical
- Display alert timestamps and relevant source information.
- Filter alerts based on category and severity.
- Maintain alert history.

### 5. Security Reporting
- Display total detected security events.
- Show HIDS and NIDS alert statistics.
- Visualize alert severity and attack categories.
- Generate downloadable security reports in PDF and CSV formats.

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | React.js |
| Backend | Node.js |
| Backend Framework | Express.js |
| Database | MongoDB |
| Detection Engine | Python |
| Network Monitoring | Scapy |
| Signature Detection | YARA |
| File Monitoring | Python |
| Data Visualization | Chart.js |

---

## 📂 Project Structure

```text
CyberAlert/
│
├── backend/             # Node.js and Express backend
│
├── frontend/            # React.js frontend
│
├── engine/              # Python-based detection engine
│   ├── main.py          # Detection engine entry point
│   ├── venv/            # Python virtual environment (local)
│   └── ...
│
├── .gitignore
└── README.md
```

---

## ⚙️ Installation and Setup

Follow these steps to run CyberAlert locally.

### Prerequisites

Make sure you have installed:

- Node.js and npm
- Python 3
- MongoDB
- Git
- pip (Python package manager)

Some detection features may require additional system permissions and dependencies.

### 1. Clone the Repository

```bash
git clone https://github.com/kshitiz8704/cyberalert.git

cd cyberalert
```

### 2. Backend Setup

Open a terminal and navigate to the backend directory.

```bash
cd backend

npm install
```

Configure your environment variables in the `.env` file according to your backend configuration.

Start the backend using the script defined in `package.json`.

For example:

```bash
npm run dev
```

### 3. Frontend Setup

Open another terminal.

```bash
cd frontend

npm install
```

Start the React development server:

```bash
npm run dev
```

### 4. Detection Engine Setup

Open another terminal and navigate to the engine directory.

```bash
cd engine
```

Create a Python virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment:

**macOS / Linux:**

```bash
source venv/bin/activate
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

Run the detection engine:

```bash
sudo ./venv/bin/python main.py
```

**Note:** Network packet sniffing may require administrator/root privileges. Run the detection engine only on systems and networks you own or are authorized to monitor.

---

## 🔍 How CyberAlert Works

The overall working process of CyberAlert is:

1. The detection engine starts monitoring selected host activities and network traffic.
2. HIDS and NIDS modules collect relevant system and network information.
3. The collected information is analyzed using predefined detection rules, signatures, and thresholds.
4. When suspicious activity is identified, a security alert is generated.
5. The backend handles the alert data and stores relevant information in MongoDB.
6. The React dashboard displays the generated alerts and security statistics.
7. Administrators can review alert details and generate security reports.

---

## 🎯 Project Objectives

- Develop a centralized cybersecurity monitoring platform.
- Integrate host-based and network-based intrusion detection.
- Identify selected suspicious activities and malware signatures.
- Generate alerts automatically when detection rules are triggered.
- Provide a user-friendly dashboard for security monitoring.
- Maintain security alert history and generate reports.

---

## 🔒 Project Scope

CyberAlert focuses exclusively on:

- Security monitoring
- Threat detection
- Security alert generation
- Alert management
- Security reporting

**The system does not perform automatic threat prevention or remediation.**

It does not automatically block network connections, delete files, quarantine malware, or modify system configurations in response to detected threats.

The primary detection approach is based on predefined rules, signatures, and thresholds rather than machine learning.

---

## 🚀 Future Improvements

Some possible future improvements include:

- Integration of additional malware signatures.
- Support for more advanced detection rules.
- Improved alert filtering and searching.
- Enhanced security analytics and visualizations.
- Support for additional network protocols.
- More detailed security reports.

---

## 👨‍💻 Developer

**Kshitizdeep**

GitHub: [@kshitiz8704](https://github.com/kshitiz8704)

Project Repository: [CyberAlert](https://github.com/kshitiz8704/cyberalert)

---

## 📄 License

This project is developed for educational and academic purposes.
