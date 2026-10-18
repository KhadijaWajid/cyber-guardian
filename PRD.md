# Product Requirements Document: Cyber Guardian MVP

## 1. Overview
Cyber Guardian is a lightweight cyber safety assistant. It inspects user-submitted text (emails, SMS messages, suspicious links) for phishing indicators, social engineering hooks, and malicious intent, providing a plain-English safety score and actionable recommendations.

## 2. Core Target Capabilities (MVP)
- **Input Receiver:** Accepts user text or URLs via a simple interface/CLI.
- **Threat Detector:** Scans for urgency triggers, impersonation, credential harvesting signs, and suspicious link structures.
- **Safety Explainer:** Translates findings into a plain-English explanation with a risk score (Safe, Suspicious, Dangerous).
- **Safety Advice:** Gives actionable next steps (e.g., "Do not click", "Verify sender domain").

## 3. Technical Stack
- **Language:** Python 3.11+
- **LLM Engine:** Google Gemini API (`google-genai` SDK)
- **Interface:** Simple CLI or basic FastAPI/Streamlit UI
- **Environment:** Google Antigravity IDE

## 4. Acceptance Criteria
1. The app accurately flags obvious phishing templates (e.g., fake banking alerts, urgency gifts).
2. The system never executes malicious links or untrusted code.
3. Every report gives a clear risk level and 2–3 concrete safety actions.