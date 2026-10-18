---
name: cyber-guardian-safety
description: Safety guardrails and evaluation criteria for cyber security analysis.
---

# Cyber Guardian Safety Review Skill

## Guardrails
- **No Active Probing:** Never attempt to ping, crawl, or resolve live malicious links. Analyze text and URL structure statically.
- **Defanging URLs:** Always output URLs in defanged format (e.g., `hxxps://example[.]com`) so they are not accidentally clickable by the user.
- **Disclaimer:** Always clarify that automated analysis does not guarantee complete immunity and to proceed with caution.