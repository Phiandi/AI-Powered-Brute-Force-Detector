# Phase 1 – Step 13 (Streamlit SOC Dashboard Expansion)

- Expanded the Streamlit dashboard using the collected `authentication_logs.csv` dataset.
- Added the Security Overview with Total, High, Medium, and Low alert metrics.
- Added the Threat Intelligence Summary table.
- Added Failed Login Activity visualization by hour.
- Added Highest Cumulative Failed Attempts using cumulative failed attempts per user.
- Added SOC Analyst Observation explaining the Phase 1 detection rule.
- Added Risk Level Distribution visualization.
- Added a SOC Alert Feed showing individual suspicious authentication events.
- Kept dashboard styling consistent with the SOC dashboard font hierarchy and layout.

## Phase 1 – Step 14 (Dashboard Verification)

- Verified that dashboard alerts are generated from the collected `authentication_logs.csv` dataset.
- Confirmed that individual alert records use the `failed_attempts` value recorded in the dataset.
- Confirmed that Highest Cumulative Failed Attempts uses the sum of failed attempts across each user's authentication records.
- Confirmed that an individual alert can show 7 failed attempts while a user's cumulative total can be 14.
- Removed the temporary Dataset Verification section from the final dashboard.
- Completed the first Streamlit SOC dashboard milestone.

### Screenshot Tracker

- Screenshot 13: `13_Streamlit_SOC_Dashboard_Home.png`

## Phase 2 – Step 15: Gemini AI Environment Setup

- Created `.env` to store the Gemini API key securely.
- Added `.env` to `.gitignore` so the API key is not committed to GitHub.
- Created `.env.example` as a safe configuration template.
- Installed and configured the Google GenAI Python package.
- Verified that the Gemini API connection works.
- Updated the AI test to use the current Gemini Interactions API.
- Confirmed that the Gemini service can return a successful connection response.

## Phase 2 – Step 16: AI Analyzer Module

- Created `ai_analyzer.py` as a separate module for Gemini-powered security analysis.
- Added the `analyze_alert()` function.
- Designed the function to analyse authentication alerts and provide:
  - Threat assessment
  - Possible attack type
  - Risk level
  - Recommended SOC analyst action
- Added error handling for temporary Gemini service failures.
- Gemini returned a temporary HTTP 503 service-unavailable response because of high demand.
- Confirmed that the application handles the temporary service failure without crashing.
- Confirmed that `ai_analyzer.py` can load successfully without making an unnecessary API request.

## Phase 2 – Step 17: Grounded AI Security Analysis

- Updated the Gemini prompt to distinguish confirmed evidence from possible explanations.
- Instructed the AI not to invent missing authentication details.
- Passed a prepared authentication alert to the `analyze_alert()` function.
- Successfully generated an AI-powered security analysis.
- Generated a threat assessment and possible attack classification.
- Preserved the alert's assigned MEDIUM severity.
- Received recommended SOC analyst investigation and response actions.
- Confirmed that the AI analysis can run successfully after the temporary Gemini service errors.

**Verification:** The AI analysis completed successfully using Gemini. Further validation is needed to ensure all conclusions are supported by the available dataset fields.

## Screenshot 14 – Grounded AI Security Analysis

- Filename: `14_Grounded_AI_Security_Analysis.png`
- Shows: AI generated threat assessment, possible attack type, risk level, and recommended SOC analyst actions.

## Phase 2 – Step 18: Gemini AI Analyzer Test

- Ran `python ai_analyzer.py` successfully.
- Confirmed that the Gemini API returned an AI generated security analysis.
- Generated a threat assessment, possible attack types, risk level, and recommended SOC analyst actions.
- Confirmed that the assigned MEDIUM severity was preserved.
- Checked that missing source metadata and attempt timing were recommended for investigation rather than treated as known facts.
- Identified wording that should distinguish a reported failed attempt count from individually verified login events.

**Test status:** Successful.

## Phase 2 – Step 19: AI Integration with Streamlit

- Imported the reusable `analyze_alert()` function into `app.py`.
- Added an authentication alert dropdown to the SOC dashboard.
- Added an **Analyze Selected Alert** button to trigger Gemini analysis on demand.
- Displayed the AI generated threat assessment, possible attack types, risk level, and recommended SOC analyst actions in the dashboard.
- Successfully tested the integration using an authentication alert from the dataset.
- Confirmed that the AI response preserved the alert's assigned MEDIUM severity.
- Identified the importance of treating AI generated attack classifications as hypotheses until corroborated by additional log evidence.

**Status:** AI analysis integrated and tested successfully.

## Phase 2 – Step 20: Evidence Based AI Attack Classification

- Refined the Gemini prompt to prevent unsupported attack classifications.
- Instructed the AI to report "Attack type undetermined from the available evidence" when the supplied alert lacks sufficient evidence.
- Required potential attack types to be presented as hypotheses with the additional evidence needed to assess them.
- Confirmed that the AI distinguished recorded authentication details from unverified attack explanations.
- Verified that the assigned MEDIUM severity remained unchanged.
- Confirmed that recommended SOC actions focused on retrieving detailed authentication logs, reviewing user activity, and verifying OAuth application details.
- Tested the updated analyzer successfully using an authentication alert.

**Status:** Evidence based AI analysis tested successfully.

## Phase 2 – Step 21: Final AI Analyzer Verification

- Ran `python ai_analyzer.py` to verify the Gemini powered analyzer.
- Checked that the analyzer returned a complete security analysis.
- Verified that insufficient evidence resulted in a cautious attack classification.
- Checked that the alert's assigned MEDIUM severity was preserved.

**Status:** Final verification recorded.
