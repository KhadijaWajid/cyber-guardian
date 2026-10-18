import uuid
import datetime
import html
from typing import List, Dict, Any, Optional
from src.schemas import ThreatReport
from src.utils import defang_url


def _get_iso_utc_timestamp() -> str:
    """Returns formatted ISO 8601 UTC timestamp compliant with STIX 2.1."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_heuristic(h: Any) -> Dict[str, Any]:
    """Safely converts HeuristicResult or dict to dictionary representation."""
    if hasattr(h, "model_dump"):
        return h.model_dump()
    elif isinstance(h, dict):
        return h
    return {
        "original_url": getattr(h, "original_url", ""),
        "defanged_url": getattr(h, "defanged_url", ""),
        "is_ip_address": getattr(h, "is_ip_address", False),
        "is_high_risk_tld": getattr(h, "is_high_risk_tld", False),
        "typosquat_target": getattr(h, "typosquat_target", None),
        "severity": getattr(h, "severity", "LOW"),
        "findings": getattr(h, "findings", []),
    }


def generate_stix_threat_bundle(
    report: ThreatReport,
    heuristics_results: Optional[List[Any]] = None,
    raw_text: str = "",
) -> Dict[str, Any]:
    """
    Builds an official STIX 2.1 JSON bundle structure (type="bundle") containing:
      - identity SDO
      - indicator SDOs (for URLs, IPs, and threat markers)
      - course-of-action SDOs (from recommended actions)
      - malware-analysis SDO (threat assessment & engine details)
    """
    if heuristics_results is None:
        heuristics_raw = report.threat_signals.heuristics_results or []
    else:
        heuristics_raw = heuristics_results

    heuristics_results_norm = [_normalize_heuristic(h) for h in heuristics_raw]

    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = _get_iso_utc_timestamp()
    objects: List[Dict[str, Any]] = []

    # 1. Identity SDO (Cyber Guardian SOC Platform)
    identity_id = f"identity--{uuid.uuid4()}"
    identity_sdo = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Cyber Guardian Security Operations",
        "identity_class": "system",
        "description": "Automated Cyber Guardian Two-Agent Security & Forensic Intelligence Platform",
        "contact_information": "security-operations@cyber-guardian.local",
    }
    objects.append(identity_sdo)

    # 2. Indicator SDOs
    # A. Process suspicious URLs from report and heuristics
    processed_urls = set()
    indicators_created = 0

    all_urls = []
    for u in report.threat_signals.suspicious_urls:
        all_urls.append({
            "url": u.original_url,
            "defanged": u.defanged_url,
            "reason": u.risk_reason,
            "is_ip": False,
        })

    for h in heuristics_results_norm:
        orig = h.get("original_url", "")
        if orig and orig not in [x["url"] for x in all_urls]:
            all_urls.append({
                "url": orig,
                "defanged": h.get("defanged_url", defang_url(orig)),
                "reason": "; ".join(h.get("findings", ["Static heuristic red flag"])),
                "is_ip": h.get("is_ip_address", False),
            })

    for item in all_urls:
        raw_url = item["url"]
        if raw_url in processed_urls or not raw_url:
            continue
        processed_urls.add(raw_url)

        # Build STIX 2.1 pattern
        if item.get("is_ip") or (raw_url.replace(".", "").isdigit()):
            ip_val = raw_url.split("://")[-1].split("/")[0].split(":")[0]
            stix_pattern = f"[ipv4-addr:value = '{ip_val}']"
        else:
            safe_val = raw_url.replace("'", "%27")
            stix_pattern = f"[url:value = '{safe_val}']"

        ind_id = f"indicator--{uuid.uuid4()}"
        ind_sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Phishing / Malicious Indicator: {item['defanged']}",
            "description": f"Extracted threat indicator flagged for: {item['reason']}",
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern": stix_pattern,
            "pattern_type": "stix",
            "valid_from": now_iso,
            "created_by_ref": identity_id,
        }
        objects.append(ind_sdo)
        indicators_created += 1

    # Fallback indicator if zero URLs were present
    if indicators_created == 0:
        target = report.threat_signals.impersonation_target
        ind_id = f"indicator--{uuid.uuid4()}"
        pattern_str = (
            f"[email-message:body_multipart[*].body_raw LIKE '%{target}%']"
            if target and target.lower() != "none"
            else "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
        )
        ind_sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Social Engineering / Phishing Threat Marker ({report.overall_risk})",
            "description": f"Behavioral indicators extracted: {'; '.join(report.threat_signals.key_findings) or 'General red flags'}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern_str,
            "pattern_type": "stix",
            "valid_from": now_iso,
            "created_by_ref": identity_id,
        }
        objects.append(ind_sdo)

    # 3. Course of Action SDOs
    for action in report.recommended_actions:
        coa_id = f"course-of-action--{uuid.uuid4()}"
        coa_sdo = {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": now_iso,
            "modified": now_iso,
            "name": action[:100],
            "description": action,
            "created_by_ref": identity_id,
        }
        objects.append(coa_sdo)

    # 4. Malware-Analysis SDO
    result_mapping = {
        "HIGH": "malicious",
        "MEDIUM": "suspicious",
        "LOW": "benign",
    }
    analysis_id = f"malware-analysis--{uuid.uuid4()}"
    analysis_sdo = {
        "type": "malware-analysis",
        "spec_version": "2.1",
        "id": analysis_id,
        "created": now_iso,
        "modified": now_iso,
        "product": "Cyber Guardian Static & LLM Security Engine",
        "version": "1.0.0",
        "result_name": f"{report.overall_risk}-Risk Phishing & Social Engineering Analysis",
        "result": result_mapping.get(report.overall_risk, "suspicious"),
        "analysis_engine_version": "1.0.0",
        "submitted": now_iso,
        "analysis_started": now_iso,
        "analysis_ended": now_iso,
        "summary": report.summary,
        "created_by_ref": identity_id,
    }
    objects.append(analysis_sdo)

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def generate_executive_html_report(
    report: ThreatReport,
    heuristics_results: Optional[List[Any]] = None,
    raw_text: str = "",
) -> str:
    """
    Generates a beautifully styled, standalone executive forensic HTML report.
    Includes high-contrast print/PDF CSS (@media print) and an instant
    'Print / Save to PDF' trigger button.
    """
    if heuristics_results is None:
        heuristics_raw = report.threat_signals.heuristics_results or []
    else:
        heuristics_raw = heuristics_results

    heuristics_results_norm = [_normalize_heuristic(h) for h in heuristics_raw]

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_ref = f"CG-INC-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # Calculate threat score
    if report.overall_risk == "HIGH":
        threat_score = 95
        risk_class = "risk-high"
        risk_title = "HIGH THREAT LEVEL (CRITICAL RISK)"
    elif report.overall_risk == "MEDIUM":
        threat_score = 55
        risk_class = "risk-medium"
        risk_title = "MEDIUM THREAT LEVEL (SUSPICIOUS)"
    else:
        threat_score = 10
        risk_class = "risk-low"
        risk_title = "LOW THREAT LEVEL (BENIGN / MINIMAL RISK)"

    signals = report.threat_signals
    impersonation_val = signals.impersonation_target or "None Detected"
    urgency_val = (
        f"YES - {signals.urgency_explanation}"
        if signals.urgency_detected
        else "No artificial pressure detected"
    )
    creds_val = (
        ", ".join(signals.sensitive_info_details)
        if signals.sensitive_info_requested
        else "None detected"
    )

    # Static Heuristics Rows
    heuristics_rows_html = ""
    if heuristics_results_norm:
        for idx, h in enumerate(heuristics_results_norm, start=1):
            sev = h.get("severity", "LOW")
            sev_class = "sev-high" if sev == "HIGH" else ("sev-med" if sev == "MEDIUM" else "sev-low")
            findings_str = "<br>• ".join(h.get("findings", ["No flags"]))
            raw_ip_str = "YES" if h.get("is_ip_address") else "No"
            tld_str = "YES" if h.get("is_high_risk_tld") else "Standard"
            typosquat_str = h.get("typosquat_target") or "None"

            heuristics_rows_html += f"""
            <tr>
                <td style="font-family: monospace; font-size: 0.85rem;">{html.escape(h.get('defanged_url', ''))}</td>
                <td style="text-align: center;"><span class="badge {sev_class}">{sev}</span></td>
                <td style="text-align: center;">{raw_ip_str}</td>
                <td style="text-align: center;">{tld_str}</td>
                <td style="font-weight: 600;">{html.escape(typosquat_str)}</td>
                <td style="font-size: 0.85rem;">• {findings_str}</td>
            </tr>
            """
    else:
        heuristics_rows_html = """
        <tr>
            <td colspan="6" style="text-align: center; color: #64748b; font-style: italic; padding: 1rem;">
                No external URLs or domains were found in the scanned message.
            </td>
        </tr>
        """

    # Actions list
    actions_html = ""
    for act in report.recommended_actions:
        is_dont = act.upper().startswith("DO NOT") or act.upper().startswith("DON'T") or "NEVER" in act.upper()
        icon = "❌" if is_dont else "✅"
        act_class = "action-dont" if is_dont else "action-do"
        actions_html += f'<div class="action-card {act_class}">{icon} <b>{html.escape(act)}</b></div>'

    # Findings bullets
    findings_html = "".join([f"<li>{html.escape(k)}</li>" for k in signals.key_findings])

    # Raw message preview
    escaped_raw = html.escape(raw_text.strip() if raw_text else "[No raw text recorded]").replace("\n", "<br>")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Threat Forensic Report - {incident_ref}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface-color: #111827;
            --border-color: #1f2937;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --high-risk: #ef4444;
            --med-risk: #f59e0b;
            --low-risk: #10b981;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2.5rem 1.5rem;
        }}
        .report-container {{
            max-width: 960px;
            margin: 0 auto;
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2.5rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 1.75rem;
        }}
        .header-title h1 {{
            font-size: 1.85rem;
            color: #ffffff;
            font-weight: 800;
            letter-spacing: -0.5px;
        }}
        .header-subtitle {{
            color: var(--primary);
            font-size: 0.95rem;
            font-weight: 600;
            margin-top: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .meta-box {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .meta-box strong {{
            color: var(--text-color);
        }}
        .tlp-badge {{
            display: inline-block;
            background: #f59e0b;
            color: #000000;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-bottom: 0.4rem;
        }}
        /* Print Action Button */
        .action-bar {{
            display: flex;
            justify-content: flex-end;
            margin-bottom: 1.5rem;
        }}
        .print-button {{
            background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
            color: #ffffff;
            border: none;
            padding: 0.65rem 1.25rem;
            font-size: 0.95rem;
            font-weight: 700;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.4);
            transition: all 0.2s ease;
        }}
        .print-button:hover {{
            background: linear-gradient(135deg, #0369a1 0%, #075985 100%);
            transform: translateY(-1px);
        }}
        /* Overall Threat Banner */
        .risk-banner {{
            padding: 1.25rem;
            border-radius: 8px;
            text-align: center;
            font-weight: 800;
            font-size: 1.4rem;
            letter-spacing: 0.5px;
            margin-bottom: 1.75rem;
        }}
        .risk-high {{
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
            border: 2px solid var(--high-risk);
            color: #ffffff;
        }}
        .risk-medium {{
            background: linear-gradient(135deg, #78350f 0%, #92400e 100%);
            border: 2px solid var(--med-risk);
            color: #ffffff;
        }}
        .risk-low {{
            background: linear-gradient(135deg, #064e3b 0%, #166534 100%);
            border: 2px solid var(--low-risk);
            color: #ffffff;
        }}
        /* Section Cards */
        .section-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: #ffffff;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.4rem;
            margin-top: 1.5rem;
            margin-bottom: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .summary-box {{
            background-color: #0b0f19;
            border: 1px solid var(--border-color);
            border-left: 5px solid var(--primary);
            border-radius: 6px;
            padding: 1.25rem;
            font-size: 1.05rem;
            line-height: 1.7;
            margin-bottom: 1.25rem;
        }}
        /* Metrics Table */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .metric-card {{
            background-color: #0b0f19;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.9rem;
            text-align: center;
        }}
        .metric-label {{
            font-size: 0.78rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .metric-value {{
            font-size: 1.3rem;
            font-weight: 800;
            color: #ffffff;
            margin-top: 0.35rem;
        }}
        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.25rem;
            background-color: #0b0f19;
            border-radius: 6px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        th, td {{
            padding: 0.75rem 0.9rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #1e293b;
            color: var(--primary);
            font-size: 0.82rem;
            text-transform: uppercase;
            font-weight: 700;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .sev-high {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }}
        .sev-med {{ background: #78350f; color: #fde047; border: 1px solid #f59e0b; }}
        .sev-low {{ background: #064e3b; color: #86efac; border: 1px solid #10b981; }}

        /* Action items */
        .action-card {{
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
        }}
        .action-do {{
            background-color: #052e16;
            border: 1px solid #166534;
            color: #dcfce7;
        }}
        .action-dont {{
            background-color: #450a0a;
            border: 1px solid #991b1b;
            color: #fee2e2;
        }}
        /* Raw Evidence Box */
        .raw-box {{
            background-color: #030712;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            font-family: Consolas, Monaco, monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            color: #cbd5e1;
            word-break: break-all;
            margin-bottom: 1.25rem;
        }}
        .footer {{
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
            padding-top: 1rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            text-align: center;
        }}

        /* HIGH-CONTRAST PRINT STYLES FOR PDF EXPORT */
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
                padding: 0 !important;
            }}
            .print-button, .action-bar {{
                display: none !important;
            }}
            .report-container {{
                box-shadow: none !important;
                border: none !important;
                padding: 0 !important;
                max-width: 100% !important;
                background-color: #ffffff !important;
            }}
            .header-title h1 {{
                color: #000000 !important;
            }}
            .header-subtitle {{
                color: #0f172a !important;
            }}
            .risk-banner {{
                background: #f1f5f9 !important;
                color: #000000 !important;
                border: 2px solid #000000 !important;
            }}
            .summary-box {{
                background-color: #f8fafc !important;
                color: #000000 !important;
                border: 1px solid #cbd5e1 !important;
                border-left: 5px solid #0284c7 !important;
            }}
            .metric-card {{
                background-color: #f8fafc !important;
                border: 1px solid #94a3b8 !important;
            }}
            .metric-value {{
                color: #000000 !important;
            }}
            table {{
                background-color: #ffffff !important;
                border: 1px solid #000000 !important;
            }}
            th {{
                background-color: #e2e8f0 !important;
                color: #000000 !important;
                border-bottom: 2px solid #000000 !important;
            }}
            td {{
                border-bottom: 1px solid #cbd5e1 !important;
                color: #000000 !important;
            }}
            .badge {{
                border: 1px solid #000000 !important;
                color: #000000 !important;
                background-color: #f1f5f9 !important;
            }}
            .action-do {{
                background-color: #f0fdf4 !important;
                border: 1px solid #16a34a !important;
                color: #000000 !important;
            }}
            .action-dont {{
                background-color: #fef2f2 !important;
                border: 1px solid #dc2626 !important;
                color: #000000 !important;
            }}
            .raw-box {{
                background-color: #f8fafc !important;
                color: #000000 !important;
                border: 1px solid #94a3b8 !important;
            }}
            .footer {{
                color: #475569 !important;
                border-top: 1px solid #cbd5e1 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Print / PDF Action Trigger -->
        <div class="action-bar">
            <button class="print-button" onclick="window.print()">🖨️ Print / Save to PDF</button>
        </div>

        <!-- Report Header -->
        <div class="header">
            <div class="header-title">
                <h1>Cyber Guardian Executive Incident Report</h1>
                <div class="header-subtitle">Automated Security Forensics &amp; Threat Intelligence</div>
            </div>
            <div class="meta-box">
                <span class="tlp-badge">TLP:AMBER+STRICT</span><br>
                <strong>Incident ID:</strong> {incident_ref}<br>
                <strong>Timestamp:</strong> {timestamp}<br>
                <strong>Classification:</strong> RESTRICTED
            </div>
        </div>

        <!-- Overall Risk Assessment Banner -->
        <div class="risk-banner {risk_class}">
            {risk_title} — SCORE {threat_score}/100
        </div>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Threat Score</div>
                <div class="metric-value">{threat_score}/100</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Urgency Detected</div>
                <div class="metric-value">{'YES' if signals.urgency_detected else 'NONE'}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Target Brand</div>
                <div class="metric-value">{html.escape(impersonation_val)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Credentials At Risk</div>
                <div class="metric-value">{'YES' if signals.sensitive_info_requested else 'NO'}</div>
            </div>
        </div>

        <!-- Executive Plain-English Summary -->
        <div class="section-title">💡 Executive Summary (Plain English)</div>
        <div class="summary-box">
            {html.escape(report.summary)}
        </div>

        <!-- Pre-LLM Static Heuristics Findings -->
        <div class="section-title">🔬 Pre-LLM Static URL Heuristics Analysis</div>
        <table>
            <thead>
                <tr>
                    <th>Defanged URL</th>
                    <th style="text-align: center;">Severity</th>
                    <th style="text-align: center;">Raw IP</th>
                    <th style="text-align: center;">High-Risk TLD</th>
                    <th>Typosquat Target</th>
                    <th>Deterministic Findings</th>
                </tr>
            </thead>
            <tbody>
                {heuristics_rows_html}
            </tbody>
        </table>

        <!-- Behavioral Red Flags & Markers -->
        <div class="section-title">🚩 Extracted Behavioral Indicators</div>
        <table>
            <tbody>
                <tr>
                    <td style="width: 30%; font-weight: 700; color: var(--primary);">Impersonation Target:</td>
                    <td>{html.escape(impersonation_val)}</td>
                </tr>
                <tr>
                    <td style="font-weight: 700; color: var(--primary);">Urgency &amp; Pressure Tactics:</td>
                    <td>{html.escape(urgency_val)}</td>
                </tr>
                <tr>
                    <td style="font-weight: 700; color: var(--primary);">Credentials Solicited:</td>
                    <td>{html.escape(creds_val)}</td>
                </tr>
            </tbody>
        </table>

        <!-- Key Findings -->
        {f'<div class="section-title">📌 Key Technical Findings</div><ul style="margin-left: 1.5rem; margin-bottom: 1.25rem;">{findings_html}</ul>' if signals.key_findings else ''}

        <!-- Recommended Mitigation Actions -->
        <div class="section-title">📋 Recommended Mitigation Checklist</div>
        <div style="margin-bottom: 1.25rem;">
            {actions_html}
        </div>

        <!-- Raw Evidence Box -->
        <div class="section-title">📄 Scanned Evidence (Defanged / Escaped)</div>
        <div class="raw-box">
            {escaped_raw}
        </div>

        <!-- Footer / Disclaimer -->
        <div class="footer">
            Cyber Guardian Automated Incident Export Package &bull; {report.disclaimer}<br>
            Confidential &bull; Generated by Two-Agent Security Architecture (Security Analyzer &amp; Safety Advisor)
        </div>
    </div>
</body>
</html>
"""
    return html_content
