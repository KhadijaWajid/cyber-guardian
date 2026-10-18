# Agent Architecture & Operational Guidelines

## System Roles
This project uses two lightweight, focused agent tasks rather than a complex graph:

### 1. Security Analyzer Agent
- **Role:** Extracts technical markers and behavioral red flags from user text.
- **Checks:**
  - Urgency and panic drivers (e.g., "Account suspended within 2 hours").
  - Mismatched URLs or obfuscated domains.
  - Sensitive information requests (passwords, OTPs, credit cards).
- **Output:** Structured JSON containing extracted threat signals.

### 2. Safety Advisor Agent
- **Role:** Takes the structured threat signals and translates them for everyday users.
- **Output:**
  - Threat Level: `LOW`, `MEDIUM`, or `HIGH`.
  - Plain-English breakdown of why it was flagged.
  - Safe mitigation advice (what to do and what NOT to do).

## Agent Communication Guidelines
- Avoid external shell execution of user inputs.
- Keep output formats strictly schema-bound using Pydantic or structured JSON.