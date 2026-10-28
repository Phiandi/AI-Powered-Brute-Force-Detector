# AI Powered Brute Force Detector — Project Notes

**Project type:** Cybersecurity / Security Operations Centre (SOC)
**Status:** Active development
**Main technologies:** Python, Streamlit, Pandas, SQLite, Gemini AI, Pytest

---

## 1. Project Overview

The AI Powered Brute Force Detector is a cybersecurity monitoring project designed to analyse authentication logs, identify suspicious login activity, classify alerts by severity, and help an analyst investigate potential security incidents.

A brute force attack occurs when an attacker repeatedly attempts different passwords to gain unauthorised access to an account or system.

The project uses authentication log data to identify failed login attempts that meet a configurable threshold. It then assigns severity levels and presents the alerts through a Security Operations Centre (SOC) dashboard.

The dashboard also supports AI assisted alert investigations, investigation history, analyst notes, status tracking, audit records, and report exports.

**Important:** The project is intended for defensive monitoring and learning. An alert indicates suspicious activity requiring investigation; it does not automatically prove that an attack occurred.

## 2. Project Objectives

The main objectives are to:

1. Read and analyse authentication log data.
2. Identify failed login activity that meets the alert threshold.
3. Assign LOW, MEDIUM, and HIGH severity levels.
4. Display security metrics and charts through a dashboard.
5. Support the investigation of individual security alerts.
6. Use Gemini AI to assist with investigation summaries.
7. Record investigation history and analyst notes.
8. Track alert statuses and maintain an audit trail.
9. Export alert information and investigation reports.
10. Test the detection logic and supporting functions.
11. Develop practical skills relevant to SOC Analyst and cybersecurity roles.

## 3. Technologies Used

| Technology | Purpose |
| --- | --- |
| Python | Main programming language |
| Pandas | Loading, filtering, and analysing authentication log data |
| Streamlit | Interactive SOC dashboard |
| SQLite | Persistent storage for investigation statuses and audit records |
| Gemini AI | AI-assisted alert investigation |
| Pytest | Automated testing |
| ReportLab | Generating PDF incident reports |
| CSV | Storing and exporting tabular data |
| JSON | Exporting investigation history |
| ZIP | Packaging multiple investigation reports |
| Git and GitHub | Version control and project sharing |

Additional dashboard and visualisation libraries are used in the application. Check `requirements.txt` for the exact installed packages.

## 4. Project Structure

The following is the known project structure. Some supporting folders may contain additional files.

```text
AI-Powered-Brute-Force-Detector/
│
├── app.py
├── ai_analyzer.py
├── ai_investigation.py
├── alert_detection.py
├── database.py
├── detector.py
├── investigation_history.py
├── severity.py
│
├── data/
│   ├── authentication_logs.csv
│   └── investigation_statuses.db
│
├── tests/
│   ├── test_ai_investigation.py
│   ├── test_ai_workflow.py
│   ├── test_alert_detection.py
│   ├── test_database.py
│   └── test_severity.py
│
├── requirements.txt
├── README.md
├── NOTES.md
└── .gitignore
```

## 5. What Each Python File Does

### 5.1 `app.py` — Main Dashboard

This is the main Streamlit application. It brings the project's components together and displays the SOC dashboard.

The application has included the following features:

- Security overview metrics.
- Threat intelligence summary.
- Failed login activity charts.
- Failed attempt distribution.
- Risk level distribution.
- Highest cumulative failed-attempts table.
- SOC Analyst Observation.
- Advanced alert management.
- Alert search and filtering.
- Alert status management.
- AI powered alert investigations.
- Investigation history and analyst notes.
- Investigation timeline.
- Audit activity dashboard.
- Alert CSV export.
- Full investigation report ZIP export.
- PDF incident reports for selected alerts.
- Severity summary.

The dashboard loads authentication logs from `data/authentication_logs.csv` and uses the extracted alert detection and severity functions.

**Important:** `app.py` is the dashboard entry point. Run it to open the main application.

### 5.2 `alert_detection.py` — Alert Detection Logic

This file contains the reusable function:

```python
detect_alerts(logs, threshold=5)
```

Its responsibilities include:

1. Checking whether the threshold is a positive integer.
2. Checking that the required columns exist.
3. Rejecting missing login statuses.
4. Rejecting missing failed-attempt values.
5. Rejecting non numeric failed attempt data.
6. Rejecting negative failed attempt counts.
7. Filtering records where `login_status` equals `"Failed"`.
8. Selecting failed login records that meet the threshold.
9. Assigning severity to the resulting alerts.
10. Returning the resulting alerts as a DataFrame.

The default threshold is five failed attempts.

For example, with the default threshold:

| Login status | Failed attempts | Alert? |
| --- | ---: | --- |
| Failed | 2 | No |
| Failed | 4 | No |
| Failed | 5 | Yes |
| Failed | 6 | Yes |
| Failed | 7 | Yes |
| Success | 10 | No |

A successful login is not classified as an alert by this function, even if the failed attempt count is high.

### 5.3 `severity.py` — Severity Classification

This module contains the `assign_severity(attempts)` function.

The current rules are:

| Failed attempts | Severity |
| ---: | --- |
| 0–5 | LOW |
| 6 | MEDIUM |
| 7 or more | HIGH |

The function returns the corresponding severity label.

These are the project's current rule based thresholds. They are not universal industry standards, and real SOC environments may use additional factors such as account importance, source IP reputation, login frequency, and successful logins after repeated failures.

### 5.4 `ai_analyzer.py` — AI Analysis Component

This is one of the project's AI related modules.

It belongs to the AI analysis part of the application. Refer to the current source code to confirm its exact functions, how it communicates with Gemini, and whether any responsibilities overlap with `ai_investigation.py`.

Do not assume every AI function is located in this file.

### 5.5 `ai_investigation.py` — AI Investigation Workflow

This module includes the function:

```python
is_successful_analysis(ai_result)
```

The function checks whether an AI result is a non empty string and whether it begins with one of the recognised failure messages:

- `AI analysis unavailable:`
- `AI service temporarily unavailable:`
- `AI analysis failed:`

It returns `False` for recognised failures, empty results, and non string values. Otherwise, it returns `True`.

The application uses this check to avoid saving recognised AI failure messages as successful investigation results.

**Security note:** An AI generated investigation is supporting information, not proof that an alert is malicious. Findings should be checked against the underlying logs and other available evidence.

### 5.6 `investigation_history.py` — Investigation Records

This module contains:

```python
add_investigation_history(...)
```

It creates an investigation record containing:

- Alert ID.
- Severity.
- Investigation ID.
- Timestamp.
- AI investigation result.
- Analyst notes.

The function appends the record to the supplied history list and returns the newly created record.

The application also maintains investigation history in Streamlit session state.

### 5.7 `database.py` — SQLite Persistence and Audit Trail

This module handles persistent alert status information and audit records.

The database file is:

```text
data/investigation_statuses.db
```

The known database functionality includes:

- Initialising the database tables.
- Retrieving saved alert statuses with `get_all_statuses()`.
- Saving alert statuses with `save_status()`.
- Retrieving an alert's status history with `get_status_history()`.
- Retrieving audit records with `get_audit_history()`.

The known tables are:

- `investigation_statuses`
- `investigation_status_history`

The supported status values are:

- New
- In Progress
- Escalated
- Closed

The audit history records status changes, including the old status, new status, alert ID, and update timestamp.

The database allows status information to persist beyond a temporary dashboard session.

### 5.8 `detector.py` — Earlier Detection Script

This file is an older standalone detection script that loads a CSV file and prints detection results or charts.

The current dashboard detection flow uses `alert_detection.py`. `app.py` does not need to import `detector.py` for that workflow.

Keep these files separate unless you intentionally decide to refactor the project. Avoid maintaining conflicting detection rules in multiple places.

## 6. How Alert Detection Works

The basic detection workflow is:

1. Load the authentication log CSV file.
2. Check that the required fields are present.
3. Validate the login status and failed attempt data.
4. Filter the records to failed logins.
5. Apply the configured threshold.
6. Assign a severity level to each alert.
7. Return the alerts to the dashboard.
8. Display the results in tables, metrics, and charts.
9. Allow the analyst to review and investigate alerts.

Simplified flow:

```text
Authentication Logs
        |
        v
Data Validation
        |
        v
Filter Failed Logins
        |
        v
Apply Attempt Threshold
        |
        v
Assign Severity
        |
        v
Display Alerts in SOC Dashboard
        |
        v
Analyst Investigation
        |
        v
Record Findings and Status
        |
        v
Export Reports
```

### Detection versus investigation

Detection identifies records that meet the configured rules.

Investigation examines an alert to understand its context and determine what may have happened.

These are different activities. A detected alert should not automatically be treated as a confirmed security incident.

## 7. Current Dataset and Verified Dashboard Counts

The previously verified dashboard run reported the following counts:

| Metric | Reported result |
| --- | ---: |
| Total authentication records | 200,000 |
| Failed login records | 28,571 |
| Detected alerts | 10,715 |
| Failed records below the threshold | 17,856 |
| LOW severity alerts | 3,572 |
| MEDIUM severity alerts | 3,572 |
| HIGH severity alerts | 3,571 |

These figures are from the reported dashboard run. They should be rechecked if the dataset or detection rules change.

The counts are consistent with the following calculation:

28,571 failed logins − 17,856 below threshold records = 10,715 alerts.

The alert severity totals also add up to 10,715.

## 8. AI Powered Investigation Workflow

The AI investigation workflow assists an analyst in reviewing a selected alert.

The general workflow is:

1. Select an alert in the dashboard.
2. Request an AI assisted investigation.
3. Review the returned analysis.
4. Check whether the result represents a successful analysis.
5. Save successful investigation results to the investigation history.
6. Add analyst notes where needed.
7. Track the alert's investigation status.
8. Export the relevant information when required.

Gemini is used as a cloud AI service, rather than requiring a large language model to run locally.

AI output can be incorrect, incomplete, or unavailable. The analyst remains responsible for reviewing the evidence and deciding what action to take.

## 9. Alert Management and Audit History

The alert management features support the investigation lifecycle.

An alert can be assigned a status such as New, In Progress, Escalated, or Closed.

The database records status changes so the analyst can review how an alert's state changed over time.

The audit dashboard and investigation timeline help make these activities more traceable.

An audit record is useful for answering questions such as:

- Which alert was updated?
- What was its previous status?
- What is its new status?
- When was the status changed?

Audit history is different from AI investigation history. Audit records track recorded activities such as status changes, while investigation history stores investigation results and analyst notes.

## 10. Export and Reporting Features

The project has included several export options.

### Alert CSV

Exports alert information in a tabular format for further analysis.

### Full investigation report ZIP

Packages multiple report files, including:

- `alerts.csv`
- AI investigation history CSV
- Audit history CSV

### PDF incident report

Generates a PDF report for a selected alert using ReportLab.

Before sharing a report, check it for sensitive information, including usernames, IP addresses, authentication details, API keys, and other potentially confidential data.

## 11. Automated Testing

The project uses Pytest to test important components independently.

The known test files are:

| Test file | Main area |
| --- | --- |
| `test_ai_investigation.py` | AI result validation |
| `test_ai_workflow.py` | Saving successful and failed AI results |
| `test_alert_detection.py` | Alert detection and input validation |
| `test_database.py` | Status persistence and audit history |
| `test_severity.py` | Severity classification |

### How to run all tests

Open PowerShell in the project folder and ensure the project's virtual environment is active.

Run:

```powershell
python -m pytest -v
```

### How to test alert detection only

```powershell
python -m pytest tests/test_alert_detection.py -v
```

### How to test severity only

```powershell
python -m pytest tests/test_severity.py -v
```

### How to test database functionality only

```powershell
python -m pytest tests/test_database.py -v
```

### Latest verified test result

On the most recent full test run documented in this notebook:

```text
collected 30 items

30 passed in 7.30s
```

The alert detection test file also passed all 12 of its tests in a separate run.

These results establish that the tested cases passed at that time. Run the tests again after making code changes.

## 12. Running the Streamlit Dashboard

From PowerShell, change to the project folder:

```powershell
cd "C:\Users\mkphi\Downloads\AI-Powered-Brute-Force-Detector"
```

Activate the virtual environment if it is not already active:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell reports an execution policy error, do not change system settings blindly. Resolve the environment issue using an appropriate method for your machine.

Install the project dependencies if needed:

```powershell
python -m pip install -r requirements.txt
```

Start the dashboard:

```powershell
python -m streamlit run app.py
```

Streamlit should provide a local URL in the terminal. Open that URL in your browser.

Stop the running application with `Ctrl + C` in the terminal.

## 13. Common Troubleshooting Notes

### A. Tests cannot find a module

Check that the terminal is in the project root and that the virtual environment is active.

### B. The CSV file cannot be found

Check that the file exists at:

```text
data/authentication_logs.csv
```

The current application uses a relative CSV path, so the working directory matters.

### C. The AI investigation is unavailable

Check the Gemini configuration, API key, network connection, service availability, and any API limits. Do not assume an unavailable response means the detection system itself has failed.

### D. The database does not show expected changes

Check that the application is using the expected database file and that the database functions are saving and retrieving records correctly.

### E. A test fails after an update

Read the first failure carefully. Identify whether the problem is in the test, the input data, or the application logic before changing any code.

Run the focused test first, then run the full test suite.

## 14. Git and GitHub Workflow

The GitHub repository is:

<https://github.com/Phiandi/AI-Powered-Brute-Force-Detector>

Before committing changes, inspect the working tree:

```powershell
git status
```

Review the changed files and ensure that API keys, virtual-environment files, database secrets, and other sensitive material are not being committed.

Review the diff:

```powershell
git diff
```

After reviewing the changes, stage only the intended files:

```powershell
git add app.py alert_detection.py severity.py database.py investigation_history.py ai_investigation.py tests NOTES.md
```

This example stages the named files and the `tests` directory if they exist. Add other modified files intentionally if needed.

Commit the reviewed changes:

```powershell
git commit -m "Improve alert detection validation and tests"
```

Push to GitHub only after checking the branch and repository configuration:

```powershell
git push
```

These commands describe the workflow; they do not mean that a commit or push has already occurred.

## 15. Cybersecurity Concepts Demonstrated

This project provides practical experience with:

- Authentication log analysis.
- Failed login detection.
- Rule based alerting.
- Severity classification.
- Security monitoring dashboards.
- Alert triage and investigation.
- AI ssisted security analysis.
- Database persistence.
- Audit trails.
- Incident reporting.
- CSV and JSON data handling.
- Input validation.
- Automated testing.
- Git and GitHub version control.

These concepts are relevant to entry level SOC Analyst and cybersecurity monitoring work.

## 16. Known Limitations and Future Improvements

The current threshold based detector is a starting point, not a complete enterprise detection system.

Potential future improvements include:

1. Add detection for password spraying across multiple accounts.
2. Correlate failed attempts by source IP, username, and time window.
3. Add timestamps and time based detection rules.
4. Identify successful logins following suspicious failures.
5. Add configurable severity rules.
6. Improve handling of malformed authentication logs.
7. Add tests for more edge cases and larger datasets.
8. Improve error handling for unavailable AI services.
9. Add stronger validation of AI output.
10. Add role based access control if the application is deployed for multiple users.
11. Improve report formatting and evidence traceability.
12. Document the detection logic and known false positive scenarios.
13. Add screenshots of the working dashboard to the README.
14. Verify that secrets and sensitive records are excluded from Git.

These are possible improvements, not claims that the features are already implemented.

## 17. Project Development Record

### Completed and verified

- [x] Extracted alert detection into `alert_detection.py`.
- [x] Added validation for missing required columns.
- [x] Added validation for missing login statuses.
- [x] Added validation for missing and non-numeric failed attempt values.
- [x] Added validation for negative failed attempt counts.
- [x] Added threshold validation.
- [x] Tested severity assignment.
- [x] Tested AI result validation and workflow.
- [x] Tested database status persistence and audit history.
- [x] Ran the complete test suite successfully: 30 passed.
- [x] Ran alert detection tests successfully: 12 passed.

### Features already present in the project

- [x] Streamlit SOC dashboard.
- [x] Alert search and filtering.
- [x] Severity summary and charts.
- [x] AI assisted alert investigation.
- [x] Investigation history and analyst notes.
- [x] SQLite status persistence and audit records.
- [x] CSV, ZIP, and PDF report exports.

### Still to verify or improve

- [ ] Review the full project directory and confirm this notebook matches the current code.
- [ ] Re run all tests after future code changes.
- [ ] Check the dashboard manually after the latest detection changes.
- [ ] Review and update the README with accurate setup instructions and screenshots.
- [ ] Review Git status and commit the intended changes.
- [ ] Add future detection improvements only after implementing and testing them.

## 18. Important Commands Reference

| Task | Command |
| --- | --- |
| Run dashboard | `python -m streamlit run app.py` |
| Run all tests | `python -m pytest -v` |
| Run alert detection tests | `python -m pytest tests/test_alert_detection.py -v` |
| Run severity tests | `python -m pytest tests/test_severity.py -v` |
| Run database tests | `python -m pytest tests/test_database.py -v` |
| Check Git changes | `git status` |
| Review code changes | `git diff` |
| Install dependencies | `python -m pip install -r requirements.txt` |

---

## 19. Final Project Summary

The AI Powered Brute Force Detector is a defensive cybersecurity project that combines authentication log analysis, rule based alert detection, severity classification, a Streamlit SOC dashboard, AI assisted investigations, SQLite persistence, audit records, and report exports.

The latest recorded full test run passed all 30 tests, while the dedicated alert detection suite passed all 12 tests.

The next priorities are to keep this notebook aligned with the actual source code, verify the dashboard manually, maintain the automated tests, and document future changes as they are completed.

**Documentation rule:** After every development step, record what changed, which files were affected, which command was run, the actual result, and any remaining issues. Never mark a feature as complete until it has been implemented and verified.
