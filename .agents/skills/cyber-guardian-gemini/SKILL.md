---
name: cyber-guardian-gemini
description: Guidelines and patterns for calling Google Gemini API cleanly within the Cyber Guardian system.
---

# Gemini Integration Skill

## Usage Rules
- Use the official Google GenAI SDK:
  ```python
  from google import genai
  from google.genai import types

  client = genai.Client()