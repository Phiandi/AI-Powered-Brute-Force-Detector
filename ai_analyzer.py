import os
import time
import importlib
from click import prompt

try:
    load_dotenv = importlib.import_module("dotenv").load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

from google import genai


load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key) if api_key else None



def analyze_alert(alert_data):
    if client is None:
        return "AI analysis unavailable: GEMINI_API_KEY is not configured."


    prompt = f"""
You are a SOC analyst assistant.

Analyze the authentication security alert provided below.

IMPORTANT RULES:
- Use only the information contained in the alert as factual evidence.
- Do not invent or assume information that is not provided.
- Do not assume the user's location, source IP, geolocation, ISP, user-agent,
  working hours, academic hours, or whether the event occurred on a holiday.
- If additional information would be useful, clearly describe it as something
  the SOC analyst should investigate, not as an existing fact.
- Distinguish between confirmed evidence and possible explanations.
- Do not infer that attempts occurred in a short period or in sequence
  unless the supplied alert explicitly provides that timing evidence.
  
Authentication security alert:
{alert_data}

Provide:

1. Threat Assessment
   Explain what the available evidence indicates.

2. Possible Attack Type
   - Do not automatically label an alert as brute force, credential stuffing,
     password spraying, or OAuth token abuse based only on a failed attempt count.
   - If the evidence is insufficient to distinguish an attack from legitimate
     errors or application misconfiguration, state:
     "Attack type undetermined from the available evidence."
   - List potential attack types only as hypotheses, with the evidence needed
     to assess each one.
   - Never describe a hypothesis as a confirmed attack.
   - Do not assume the failed attempt count represents separately verified
     authentication events unless the supplied data confirms this.
   - Do not infer token replay, token modification, credential stuffing,
     or a specific attack target from the authentication method or token ID alone.
   - If the alert only provides a failed attempt count, authentication method,
     token ID, and session ID, do not identify a specific attack type.
     State: "Attack type undetermined from the available evidence."
     Explain that further logs are required before classifying the activity.
3. Risk Level
   Use the severity already assigned to the alert unless the available
   evidence clearly indicates otherwise.

4. Recommended SOC Analyst Actions
   Give practical investigation or containment steps based on the available
   evidence.

Keep the response concise, professional, and suitable for a SOC analyst.
"""
    try:
        for attempt in range(3):
            try:
                interaction = client.interactions.create(
                    model="gemini-3.8-flash",
                    input=prompt
                )

                return interaction.output_text

            except Exception as error:
                if attempt < 2:
                    time.sleep(3)
                else:
                    return f"AI service temporarily unavailable: {error}"

    except Exception as error:
        return f"AI analysis failed: {error}"
if __name__ == "__main__":
    test_alert = {
        "auth_event_id": "AUTH000000006",
        "user_id": "STU000006",
        "login_status": "Failed",
        "failed_attempts": 6,
        "timestamp": "2026-01-01 08:12:00",
        "severity": "MEDIUM"
    }

    result = analyze_alert(test_alert)
    print("\nAI SECURITY ANALYSIS")
    print("--------------------")
    print(result)