# 🛡️ AI Powered Brute Force Detector

A Python-based Security Operations Centre (SOC) dashboard that identifies suspicious authentication activity using rule-based detection and supports AI-assisted alert investigation with Google Gemini.

## 📌 Project Overview

The AI-Powered Brute Force Detector is a cybersecurity learning project designed to analyse authentication logs, identify potentially suspicious login activity, classify alerts by severity, and present findings through an interactive Streamlit dashboard.

The project combines rule-based detection with AI-assisted investigations, alert status tracking, audit history, and reporting features to demonstrate a SOC-style workflow.

## 🎯 Objectives

- Identify failed authentication records that meet configured detection rules.
- Classify detected alerts by severity.
- Display security metrics and authentication activity through a dashboard.
- Use Google Gemini AI to assist with alert investigations.
- Record investigation results and analyst notes.
- Track investigation statuses and record status changes.
- Export alerts and investigation reports.
- Test detection logic and supporting functions using Pytest.

## ✨ Features

### 1. Security Overview

Displays key metrics, including total alerts and the number of LOW, MEDIUM, and HIGH severity alerts.

### 2. Rule-Based Alert Detection

Loads authentication records from `data/authentication_logs.csv` and selects failed login records that meet the configured threshold.

The default threshold is five failed attempts.

### 3. Severity Classification

The current project rules classify alerts as follows:

| Failed attempts | Severity |
| --- | --- |
| 0–5 | LOW |
| 6 | MEDIUM |
| 7 or more | HIGH |

These are project-defined rules for demonstration and learning, not universal security standards.

### 4. Security Dashboard and Visualisations

The dashboard includes:

- Failed login activity charts.
- Failed-attempt distribution.
- Risk level distribution.
- Highest cumulative failed-attempts table.
- Threat intelligence summary.
- SOC Analyst Observation.
- Severity summary.

Chart display settings can be adjusted through the dashboard sidebar.

### 5. Advanced Alert Management

Supports alert review through search, severity and status filters, alert metrics, and status updates.

### 6. AI-Powered Alert Investigation

Google Gemini AI assists with analysing selected alerts and generating investigation findings.

The investigation workflow is designed to support threat assessment, possible attack identification, evidence review, and recommended analyst actions.

AI-generated findings must be checked against the available evidence. They do not independently confirm that an attack occurred.

### 7. Investigation History and Analyst Notes

Records investigation details such as alert ID, severity, timestamp, investigation result, and analyst notes.

The application maintains an investigation history in Streamlit session state and supports exporting investigation history as JSON.

**Important:** Session-based investigation history is not the same as permanent database storage.

### 8. Persistent Investigation Statuses

Uses SQLite to store alert investigation statuses.

Supported statuses include:

- New
- In Progress
- Escalated
- Closed

Status changes are saved through the dashboard and can be retrieved from the database.

### 9. Audit History and Investigation Timeline

Maintains records of investigation status changes, including previous and new statuses and update timestamps.

The dashboard includes an investigation timeline and audit activity view to support review of recorded changes.

### 10. Report Export

The application supports:

- CSV export of alert information.
- ZIP export containing alert, investigation history, and audit history files.
- PDF incident reports for selected alerts.

## 🧰 Technologies Used

- **Python** — application logic and data processing.
- **Pandas** — authentication log analysis.
- **Streamlit** — interactive dashboard.
- **Plotly** — data visualisation.
- **Google Gemini AI** — AI-assisted investigation.
- **SQLite** — persistent investigation statuses and audit records.
- **Pytest** — automated testing.
- **ReportLab** — PDF report generation.
- **CSV, JSON and ZIP** — data export and reporting.
- **Git and GitHub** — version control and project hosting.

## 📂 Project Structure

```text
AI-Powered-Brute-Force-Detector/
├── app.py
├── ai_analyzer.py
├── ai_investigation.py
├── alert_detection.py
├── database.py
├── detector.py
├── investigation_history.py
├── severity.py
├── data/
│   └── authentication_logs.csv
├── tests/
│   ├── test_ai_investigation.py
│   ├── test_ai_workflow.py
│   ├── test_alert_detection.py
│   ├── test_database.py
│   └── test_severity.py
├── requirements.txt
├── README.md
└── NOTES.md
```

The actual repository may contain additional files, including `.gitignore`, `.env.example`, and screenshot assets. Keep the documentation aligned with the files actually committed to GitHub.

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Phiandi/AI-Powered-Brute-Force-Detector.git
cd AI-Powered-Brute-Force-Detector
```

### 2. Create a virtual environment

On Windows:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure the Gemini API key

If the application requires a Gemini API key, create a local `.env` file in the project root and add your own key:

```env
GEMINI_API_KEY=your_api_key_here
```

Use the environment-variable name expected by the current application code. Never commit your real API key to GitHub.

### 5. Run the dashboard

```powershell
python -m streamlit run app.py
```

Open the local URL displayed in the terminal.

## 🔍 How It Works

1. The application loads the authentication dataset.
2. The detection module validates the required fields.
3. Failed login records are filtered.
4. Records meeting the configured threshold are selected as alerts.
5. The severity function classifies each alert.
6. The dashboard displays metrics, charts, and alert information.
7. An analyst can review a selected alert and request AI-assisted investigation.
8. Investigation findings and analyst notes can be reviewed and exported.
9. Alert status changes are stored in SQLite and recorded in the audit history.

## 🧪 Automated Testing

The project uses Pytest to test detection logic, severity classification, AI investigation handling, and database operations.

Run the full test suite:

```powershell
python -m pytest -v
```

Run the alert detection tests:

```powershell
python -m pytest tests/test_alert_detection.py -v
```

### Latest verified test results

The latest recorded full test run reported:

```text
30 passed in 7.30s
```

The dedicated alert detection test run reported:

```text
12 passed in 3.19s
```

These results reflect the recorded test runs and may change as the project develops. Run the tests again after making changes.

## ⚠️ Limitations

- Detection depends on the quality and structure of the authentication dataset.
- The default detection rule uses failed-attempt counts and does not independently establish malicious intent.
- AI-generated analysis can be incomplete or incorrect.
- Session-based investigation history may not survive an application restart.
- The current severity thresholds are simplified project rules.
- The project is intended for learning and demonstration, not as a replacement for a production security monitoring platform.

## 🚀 Future Improvements

Potential improvements include:

- Password-spraying detection across multiple accounts.
- Time-window-based detection and correlation.
- Detection of successful logins following suspicious failures.
- Support for additional authentication log formats.
- More comprehensive investigation persistence.
- Improved detection testing and false-positive analysis.
- Additional dashboard filtering and reporting.
- Screenshots and a demonstration walkthrough.

## 📸 Screenshots

Screenshots of the running dashboard can be added to an `Assets/screenshots/` folder.

For example, after adding the image file:

```markdown
![SOC Dashboard](Assets/screenshots/01_soc_dashboard.png)
```

## 📚 Learning Outcomes

This project demonstrates practical work with authentication log analysis, rule-based detection, severity classification, SOC dashboard development, AI API integration, alert investigation, database persistence, audit records, reporting, and automated testing.

## 👤 Author

### Mohau Klas Phiandi

- GitHub: [@Phiandi](https://github.com/Phiandi)

This project is part of my ongoing cybersecurity learning and portfolio development.
