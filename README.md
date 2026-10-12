# AI Powered Brute Force Detector

A Python based cybersecurity project that analyses authentication logs, identifies suspicious login activity using rule based detection, and presents security alerts through a Streamlit Security Operations Centre (SOC) dashboard.

The project also integrates Google's Gemini AI to help analyse selected authentication alerts, explain potential risks, and recommend investigation steps based on the available evidence.

## Project Status

Under development.

## Key Features

- **Authentication Log Analysis:** Reads authentication data from a CSV dataset using Python and Pandas.
- **Rule Based Detection:** Identifies suspicious authentication activity using a configurable failed attempt threshold.
- **Risk Classification:** Assigns LOW, MEDIUM, and HIGH severity levels to detected alerts.
- **SOC Dashboard:** Displays authentication statistics, failed login activity, risk distribution, and security alerts using Streamlit and Plotly.
- **AI Powered Alert Analysis:** Integrates Google's Gemini API to analyse selected alerts and suggest investigation steps.
- **Evidence Based AI Responses:** Instructs the AI to distinguish available evidence from unconfirmed attack hypotheses.
- **Investigation Recommendations:** Highlights additional authentication logs and contextual information that a SOC analyst may need to investigate.

## Technologies Used

- **Python** — Core programming language.
- **Pandas** — Authentication dataset processing and analysis.
- **Streamlit** — Interactive SOC dashboard.
- **Plotly** — Data visualisation and security charts.
- **Google Gemini API (`google-genai`)** — AI powered security alert analysis.
- **python dotenv** — Loading API credentials from environment variables.
- **CSV** — Authentication log data format.
- **Git and GitHub** — Version control and project hosting.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/Phiandi/AI-Powered-Brute-Force-Detector.git
cd AI-Powered-Brute-Force-Detector
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

On Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure the Gemini API key

Create a `.env` file in the project root and add:

```text
GEMINI_API_KEY=your_api_key_here
```

Replace the placeholder with your own Gemini API key. Keep `.env` private and never commit it to GitHub.

### 6. Run the SOC dashboard

```bash
streamlit run app.py
```

Streamlit will provide a local URL to open the dashboard in your browser.

## Dataset

The project uses a CSV authentication dataset containing login outcomes, authentication methods, user identifiers, session and token identifiers, failed attempt counts, and timestamps.

The dataset is processed with Pandas to summarise authentication activity and identify records that meet the project's rule based alert criteria.

**Note:** The detected alerts are indicators for investigation, not proof of malicious activity. The results depend on the quality and limitations of the supplied dataset.

## Screenshots

Project screenshots are stored in the `Assets/screenshots/` directory.

They document the development process and demonstrate the SOC dashboard, authentication analysis, risk distribution, and AI-powered alert investigation.

Additional screenshots will be added as the project develops.

## Responsible Use and Limitations

This project is intended for educational purposes and cybersecurity portfolio development.

- Alerts identify suspicious patterns based on configured detection rules; they do not independently prove that an attack occurred.
- AI generated analysis may be inaccurate and must be validated against authentication logs and other available evidence.
- Risk levels are assigned by the project's detection logic and should not be treated as definitive measures of real world risk.
- Recommended investigation or containment actions should be reviewed by a qualified analyst before implementation.
- API credentials and other secrets must be kept private and excluded from version control.

## Disclaimer

This project is a learning tool and is not intended to replace a production Security Information and Event Management (SIEM) platform or professional security investigation.
