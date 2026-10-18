import os
import sys
from pathlib import Path

# Ensure project root is in sys.path regardless of how Streamlit is launched
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st

# 1. Try loading from .env
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# 2. Bridge Streamlit secrets into os.environ
try:
    if hasattr(st, "secrets"):
        if "GEMINI_API_KEY" in st.secrets and not os.environ.get(
            "GEMINI_API_KEY"
        ):
            os.environ["GEMINI_API_KEY"] = str(st.secrets["GEMINI_API_KEY"])
        if "GEMINI_API_KEY_BACKUP" in st.secrets and not os.environ.get(
            "GEMINI_API_KEY_BACKUP"
        ):
            os.environ["GEMINI_API_KEY_BACKUP"] = str(
                st.secrets["GEMINI_API_KEY_BACKUP"]
            )
except Exception:
    pass


# 3. Helper function for modules to retrieve the key
def get_api_key() -> str | None:
    if os.environ.get("GEMINI_API_KEY"):
        return os.environ.get("GEMINI_API_KEY")
    try:
        if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
            return str(st.secrets["GEMINI_API_KEY"])
    except Exception:
        pass
    return None

import re
import json
import datetime
import urllib.parse

from src.analyzer import analyze_text
from src.advisor import generate_advice
from src.schemas import ThreatReport
from src.utils import parse_eml_bytes, highlight_evidence
from src.exporter import generate_stix_threat_bundle, generate_executive_html_report
from src.db import log_threat, check_repeat_offender, get_all_records, create_user, verify_user
from src.honeypot import generate_counter_probe, simulate_scammer_reply
from src.heuristics import analyze_ecommerce_discount


# Page configuration
st.set_page_config(
    page_title="Cyber Guardian - Threat Intelligence & Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Modern Production SaaS Theme & Visual Architecture (Linear / Vercel style)
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Canvas & Typography */
    .stApp {
        background-color: #090a0f !important;
        background-image: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.04) 0%, transparent 60%) !important;
        color: #f0f3f6 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, system-ui, sans-serif !important;
        -webkit-font-smoothing: antialiased;
    }

    [data-testid="stSidebar"] {
        background-color: #0d0f15 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
        box-shadow: none !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, system-ui, sans-serif !important;
    }

    [data-testid="stSidebar"] hr {
        border-color: rgba(255, 255, 255, 0.08) !important;
    }

    /* Crisp Typography Hierarchy */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        color: #f0f3f6 !important;
        font-weight: 600 !important;
        letter-spacing: -0.025em !important;
    }

    h1 {
        font-size: 1.75rem !important;
        line-height: 1.25 !important;
    }

    h2 {
        font-size: 1.25rem !important;
        line-height: 1.35 !important;
    }

    h3 {
        font-size: 1.05rem !important;
        line-height: 1.4 !important;
    }

    /* Top Navigation Bar */
    .saas-topbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 0.5rem;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .saas-brand {
        display: flex;
        align-items: center;
        gap: 0.65rem;
    }

    .brand-icon {
        font-size: 1.35rem;
    }

    .brand-name {
        font-size: 1.15rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #ffffff;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        padding: 2px 9px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: rgba(255, 255, 255, 0.04);
        color: #94a3b8;
    }

    .status-live {
        border-color: rgba(16, 185, 129, 0.35);
        background: rgba(16, 185, 129, 0.1);
        color: #34d399;
    }

    .status-env {
        border-color: rgba(59, 130, 246, 0.35);
        background: rgba(59, 130, 246, 0.1);
        color: #60a5fa;
    }

    @keyframes pulse {
        0% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); opacity: 1; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); opacity: 0.8; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .pulsing-dot {
        width: 7px;
        height: 7px;
        background-color: #10b981;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
        animation: pulse 2.2s infinite;
    }

    /* Polished Hero Section */
    .saas-hero {
        text-align: center;
        margin: 0.5rem auto 1.75rem auto;
        max-width: 720px;
    }

    .hero-title {
        font-size: 2rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.03em !important;
        color: #ffffff !important;
        margin-bottom: 0.5rem !important;
    }

    .hero-subtitle {
        color: #94a3b8 !important;
        font-size: 0.98rem !important;
        line-height: 1.55 !important;
        margin: 0 auto !important;
    }

    /* Glassmorphic Layered Surfaces */
    /* Glassmorphic Layered Surfaces */
    .glass-surface, .summary-card, .indicators-card, .heuristics-box, .probe-card {
        background: linear-gradient(180deg, rgba(26, 29, 36, 0.7) 0%, rgba(18, 20, 26, 0.9) 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.5) !important;
        backdrop-filter: blur(12px) !important;
        padding: 1.35rem 1.5rem;
        margin-bottom: 1.25rem;
    }

    .auth-header {
        text-align: center;
        margin-bottom: 1.5rem;
    }

    .auth-title {
        font-size: 1.35rem;
        font-weight: 600;
        letter-spacing: -0.02em;
        color: #ffffff;
        margin-bottom: 0.35rem;
    }

    .auth-subtitle {
        font-size: 0.88rem;
        color: #94a3b8;
        line-height: 1.5;
    }

    /* Single-line Input Fields */
    input, [data-baseweb="input"], [data-baseweb="base-input"] {
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        background-color: #0e1117 !important;
        color: #f0f3f6 !important;
        box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.4) !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-size: 0.92rem !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    input:focus, [data-baseweb="input"]:focus-within, [data-baseweb="base-input"]:focus-within {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25), inset 0 1px 2px rgba(0, 0, 0, 0.4) !important;
        background-color: #0e1117 !important;
    }

    /* Raw Message Textarea: Modern Crisp Monospace Font & Alignment */
    textarea, [data-testid="stTextArea"] textarea, [data-baseweb="textarea"] textarea {
        font-family: 'JetBrains Mono', -apple-system, monospace !important;
        font-size: 14px !important;
        line-height: 1.55 !important;
        letter-spacing: -0.01em !important;
        padding: 0.75rem 0.85rem !important;
        background-color: #0a0c10 !important;
        color: #f0f3f6 !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 8px !important;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.5) !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    textarea:focus, [data-testid="stTextArea"] textarea:focus, [data-baseweb="textarea"] textarea:focus {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25), inset 0 1px 3px rgba(0, 0, 0, 0.5) !important;
        background-color: #0d1017 !important;
    }

    /* Vertical dividing line between scanner and honeypot */
    .scammer-sandbox-container {
        border-left: 1px solid rgba(255, 255, 255, 0.12) !important;
        padding-left: 1.5rem !important;
    }

    [data-testid="stHorizontalBlock"]:has(.scammer-sandbox-container) > [data-testid="column"]:nth-child(2) {
        border-left: 1px solid rgba(255, 255, 255, 0.12) !important;
        padding-left: 1.5rem !important;
    }

    /* Buttons: Secondary / Standard */
    .stButton > button {
        border-radius: 8px !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        background-color: rgba(255, 255, 255, 0.04) !important;
        color: #e2e8f0 !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-weight: 500 !important;
        font-size: 0.88rem !important;
        letter-spacing: normal !important;
        text-transform: none !important;
        box-shadow: none !important;
        transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
        padding: 0.55rem 1rem !important;
    }

    .stButton > button p,
    .stButton > button span {
        color: #e2e8f0 !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-weight: 500 !important;
        transition: color 0.18s ease !important;
    }

    .stButton > button:hover {
        background-color: rgba(255, 255, 255, 0.09) !important;
        border-color: rgba(255, 255, 255, 0.25) !important;
        color: #ffffff !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25) !important;
    }

    .stButton > button:hover p,
    .stButton > button:hover span {
        color: #ffffff !important;
    }

    /* Primary Action Buttons with Smooth Hover Lift */
    button[kind="primary"] {
        background: linear-gradient(180deg, #3b82f6 0%, #2563eb 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        color: #ffffff !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 8px rgba(37, 99, 235, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.2) !important;
        transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
        padding: 0.6rem 1.25rem !important;
    }

    button[kind="primary"] p, button[kind="primary"] span {
        color: #ffffff !important;
        font-weight: 600 !important;
    }

    button[kind="primary"]:hover {
        background: linear-gradient(180deg, #60a5fa 0%, #3b82f6 100%) !important;
        border-color: rgba(255, 255, 255, 0.25) !important;
        color: #ffffff !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
    }

    /* Secondary Ghost Export Buttons */
    .stDownloadButton > button {
        background: rgba(255, 255, 255, 0.03) !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        color: #e2e8f0 !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-weight: 500 !important;
        border-radius: 8px !important;
        padding: 0.55rem 1rem !important;
        box-shadow: none !important;
        transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .stDownloadButton > button p, .stDownloadButton > button span {
        color: #e2e8f0 !important;
        font-weight: 500 !important;
    }

    .stDownloadButton > button:hover {
        background: rgba(255, 255, 255, 0.08) !important;
        border-color: rgba(255, 255, 255, 0.25) !important;
        color: #ffffff !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3) !important;
    }

    /* Clean Tabs with Underline / Indicator */
    [data-baseweb="tab-list"] {
        gap: 6px !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
        background-color: transparent !important;
        margin-bottom: 1.5rem !important;
        padding-bottom: 2px !important;
    }

    [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0 !important;
        color: #94a3b8 !important;
        background-color: transparent !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
        font-weight: 500 !important;
        font-size: 0.92rem !important;
        letter-spacing: -0.01em !important;
        padding: 0.65rem 1.15rem !important;
        transition: all 0.15s ease-in-out !important;
    }

    [data-baseweb="tab"] p, [data-baseweb="tab"] span {
        color: #94a3b8 !important;
        font-weight: 500 !important;
        transition: color 0.15s ease !important;
    }

    [data-baseweb="tab"]:hover {
        color: #f0f3f6 !important;
        background-color: rgba(255, 255, 255, 0.04) !important;
    }

    [data-baseweb="tab"]:hover p, [data-baseweb="tab"]:hover span {
        color: #f0f3f6 !important;
    }

    [data-baseweb="tab"][aria-selected="true"] {
        color: #ffffff !important;
        background-color: rgba(255, 255, 255, 0.03) !important;
        border-bottom: 2px solid #3b82f6 !important;
        font-weight: 600 !important;
    }

    [data-baseweb="tab"][aria-selected="true"] p, [data-baseweb="tab"][aria-selected="true"] span {
        color: #ffffff !important;
        font-weight: 600 !important;
    }

    [data-baseweb="tab-highlight"] {
        background-color: #3b82f6 !important;
        height: 2px !important;
    }

    /* KPI Quick Stats Grid */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 0.85rem;
        margin-bottom: 1.5rem;
    }

    @media (max-width: 900px) {
        .kpi-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }

    .kpi-card {
        background: linear-gradient(180deg, rgba(26, 29, 36, 0.7) 0%, rgba(18, 20, 26, 0.9) 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.5) !important;
        backdrop-filter: blur(12px) !important;
        padding: 1.1rem 1.15rem;
    }

    .kpi-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.4rem;
    }

    .kpi-label {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #94a3b8;
    }

    .kpi-value {
        font-size: 1.45rem;
        font-weight: 700;
        color: #f0f3f6;
        letter-spacing: -0.02em;
        line-height: 1.2;
    }

    .kpi-subval {
        font-size: 0.9rem;
        color: #64748b;
        font-weight: 500;
    }

    .kpi-delta {
        font-size: 0.78rem;
        font-weight: 500;
        margin-top: 0.35rem;
    }

    .dot-red {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #ef4444;
        box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
        display: inline-block;
    }

    .dot-amber {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #f59e0b;
        box-shadow: 0 0 8px rgba(245, 158, 11, 0.6);
        display: inline-block;
    }

    .dot-green {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
        display: inline-block;
    }

    .dot-blue {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #3b82f6;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.6);
        display: inline-block;
    }

    /* Defanged IOCs & Snippet Boxes */
    .ioc-snippet-box {
        background: #0a0c10 !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
        padding: 0.85rem 1rem !important;
        margin-bottom: 0.75rem !important;
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important;
    }

    .ioc-snippet-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.35rem;
    }

    .ioc-tag {
        font-size: 0.7rem;
        font-weight: 600;
        color: #94a3b8;
        letter-spacing: 0.05em;
    }

    .ioc-code {
        font-size: 0.9rem;
        color: #60a5fa;
        user-select: all;
        word-break: break-all;
    }

    .ioc-reason {
        font-size: 0.82rem;
        color: #94a3b8;
        margin-top: 0.35rem;
        font-family: 'Inter', -apple-system, sans-serif !important;
    }

    /* Status Badges & Alerts */
    .risk-banner-card {
        border-radius: 10px !important;
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        padding: 1rem 1.25rem !important;
        margin: 1.25rem 0 !important;
        text-align: center !important;
        letter-spacing: 0.02em !important;
    }

    .risk-high {
        background: rgba(239, 68, 68, 0.12) !important;
        border: 1px solid rgba(239, 68, 68, 0.4) !important;
        color: #f87171 !important;
    }

    .risk-medium {
        background: rgba(245, 158, 11, 0.12) !important;
        border: 1px solid rgba(245, 158, 11, 0.4) !important;
        color: #fbbf24 !important;
    }

    .risk-low {
        background: rgba(16, 185, 129, 0.12) !important;
        border: 1px solid rgba(16, 185, 129, 0.4) !important;
        color: #34d399 !important;
    }

    .alert-banner {
        border-radius: 10px !important;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
        font-size: 0.92rem;
        line-height: 1.5;
    }

    .alert-banner-danger {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.4) !important;
        color: #fca5a5 !important;
    }

    .alert-banner-warning {
        background: rgba(245, 158, 11, 0.1) !important;
        border: 1px solid rgba(245, 158, 11, 0.4) !important;
        color: #fde68a !important;
    }

    /* Action Checklist */
    .action-item-do {
        background: rgba(16, 185, 129, 0.06) !important;
        color: #f0f3f6 !important;
        border: 1px solid rgba(16, 185, 129, 0.25) !important;
        border-left: 3px solid #10b981 !important;
        border-radius: 8px !important;
        padding: 0.85rem 1.15rem;
        margin-bottom: 0.65rem;
        font-size: 0.92rem;
        line-height: 1.5;
    }

    .action-item-dont {
        background: rgba(239, 68, 68, 0.06) !important;
        color: #f0f3f6 !important;
        border: 1px solid rgba(239, 68, 68, 0.25) !important;
        border-left: 3px solid #ef4444 !important;
        border-radius: 8px !important;
        padding: 0.85rem 1.15rem;
        margin-bottom: 0.65rem;
        font-size: 0.92rem;
        line-height: 1.5;
    }

    /* Forensic Highlighter Box & Legend */
    .forensic-box {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 8px !important;
        background-color: #0a0c10 !important;
        color: #f0f3f6 !important;
        font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important;
        font-size: 0.9rem;
        line-height: 1.6;
        padding: 1.25rem;
        overflow-x: auto;
        margin-bottom: 1.25rem;
    }

    .legend-bar {
        display: flex;
        gap: 1.25rem;
        margin-bottom: 0.75rem;
        font-size: 0.82rem;
        flex-wrap: wrap;
        color: #94a3b8;
    }

    .chip-urgency {
        background: rgba(239, 68, 68, 0.15) !important;
        border: 1px solid rgba(239, 68, 68, 0.5) !important;
        color: #fca5a5 !important;
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 500;
    }

    .chip-sensitive {
        background: rgba(245, 158, 11, 0.15) !important;
        border: 1px solid rgba(245, 158, 11, 0.5) !important;
        color: #fde68a !important;
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 500;
    }

    .chip-url {
        background: rgba(59, 130, 246, 0.15) !important;
        border: 1px solid rgba(59, 130, 246, 0.5) !important;
        color: #93c5fd !important;
        padding: 2px 6px;
        border-radius: 4px;
        font-weight: 500;
    }

    .defanged-pill {
        background-color: #0a0c10 !important;
        color: #60a5fa !important;
        font-family: 'JetBrains Mono', ui-monospace, monospace !important;
        padding: 3px 8px;
        border-radius: 4px;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        font-size: 0.85rem;
    }

    .badge-heur-high {
        background-color: rgba(239, 68, 68, 0.15) !important;
        color: #f87171 !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .badge-heur-med {
        background-color: rgba(245, 158, 11, 0.15) !important;
        color: #fbbf24 !important;
        border: 1px solid rgba(245, 158, 11, 0.3) !important;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .badge-heur-clean {
        background-color: rgba(16, 185, 129, 0.15) !important;
        color: #34d399 !important;
        border: 1px solid rgba(16, 185, 129, 0.3) !important;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    /* Scammer Chatbox Styling */
    .chat-panel-container {
        background: linear-gradient(180deg, rgba(26, 29, 36, 0.7) 0%, rgba(18, 20, 26, 0.95) 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 12px !important;
        box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.5) !important;
        backdrop-filter: blur(12px) !important;
        padding: 1.15rem 1.25rem;
        margin-bottom: 1.25rem;
    }

    [data-testid="stChatMessage"] {
        background: rgba(26, 29, 36, 0.45) !important;
        border: 1px solid rgba(255, 255, 255, 0.06) !important;
        border-radius: 8px !important;
        padding: 0.75rem 1rem !important;
        margin-bottom: 0.65rem !important;
    }

    [data-testid="stChatInput"] {
        border-radius: 8px !important;
    }

    [data-testid="stChatInput"] textarea {
        background-color: #0e1117 !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 8px !important;
        color: #f0f3f6 !important;
    }

    /* File Uploader Section */
    [data-testid="stFileUploaderDropzone"] {
        border: 1px dashed rgba(255, 255, 255, 0.15) !important;
        border-radius: 8px !important;
        background-color: rgba(22, 27, 34, 0.4) !important;
    }

    /* Expanders & Alerts */
    [data-testid="stExpander"] {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 10px !important;
        background: linear-gradient(180deg, rgba(26, 29, 36, 0.6) 0%, rgba(18, 20, 26, 0.8) 100%) !important;
        color: #f0f3f6 !important;
    }

    div[data-testid="stAlert"] {
        border-radius: 8px !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        background-color: #12141a !important;
        color: #f0f3f6 !important;
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: #090a0f;
    }
    ::-webkit-scrollbar-thumb {
        background: #262a36;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #3b4254;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if "is_guest" not in st.session_state:
    st.session_state["is_guest"] = False

if "username" not in st.session_state:
    st.session_state["username"] = None

if "auth_mode" not in st.session_state:
    st.session_state["auth_mode"] = "signin"

if "input_text" not in st.session_state:
    st.session_state["input_text"] = ""

if "current_report" not in st.session_state:
    st.session_state["current_report"] = None

if "current_input" not in st.session_state:
    st.session_state["current_input"] = ""

if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

if "honeypot_messages" not in st.session_state:
    st.session_state["honeypot_messages"] = []

if "honeypot_persona" not in st.session_state:
    st.session_state["honeypot_persona"] = "Auto-Derive from Current Analyzed Threat"

# Preset samples for rapid testing
SAMPLE_PHISHING = (
    "URGENT: Your Wells Fargo account has been locked due to suspicious activity. "
    "You must verify your identity within 2 hours or your funds will be frozen. "
    "Click here immediately: https://wellsfargo-security-alert.verify-account88.com/login "
    "and enter your username, password, and 6-digit OTP."
)

SAMPLE_FAMILY_EMERGENCY = (
    "Hi Mom, it's me! My phone fell into the water and broke so I'm using this temporary number. "
    "I'm stuck at the station in an emergency and need $450 urgently to pay for the ride home. "
    "Please send it via Zelle or buy an Apple gift card and text me the code right away! Don't call my regular phone it's dead."
)

SAMPLE_DISCOUNT = (
    "FLASH SALE: Genuine Apple iPhone 15 Pro Max was $1199 now only $89! 92% OFF clearance discount! "
    "Hurry, only 2 items left in stock, flash sale ends in 5 minutes! "
    "Claim your deal now before timer expires: https://apple-direct-outlet.xyz/checkout"
)

SAMPLE_BENIGN = "Hi team, don't forget our weekly project retrospective tomorrow at 10:00 AM on Google Meet."


# Callbacks for button and file upload actions
def set_sample_phishing():
    st.session_state["input_text"] = SAMPLE_PHISHING


def set_sample_family():
    st.session_state["input_text"] = SAMPLE_FAMILY_EMERGENCY


def set_sample_discount():
    st.session_state["input_text"] = SAMPLE_DISCOUNT


def set_sample_benign():
    st.session_state["input_text"] = SAMPLE_BENIGN


def clear_input_and_results():
    st.session_state["input_text"] = ""
    st.session_state["current_report"] = None
    st.session_state["current_input"] = ""


def handle_file_upload():
    uploaded_file = st.session_state.get("threat_file_uploader")
    if uploaded_file is not None:
        filename = uploaded_file.name.lower()
        raw_bytes = uploaded_file.getvalue()
        if filename.endswith(".eml"):
            parsed_text = parse_eml_bytes(raw_bytes)
            st.session_state["input_text"] = parsed_text
        elif filename.endswith(".txt"):
            try:
                st.session_state["input_text"] = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                st.session_state["input_text"] = str(raw_bytes)


def clear_scan_history():
    st.session_state["scan_history"] = []


def reload_scan(entry):
    st.session_state["current_report"] = entry["report"]
    st.session_state["input_text"] = entry["full_text"]
    st.session_state["current_input"] = entry["full_text"]


# ==============================================================================
# AUTHENTICATION PORTAL: Polished Centered Modal Card
# ==============================================================================
if not (st.session_state.get("authenticated", False) or st.session_state.get("is_guest", False)):
    st.markdown(
        """
        <div class="saas-topbar">
            <div class="saas-brand">
                <span class="brand-icon">🛡️</span>
                <span class="brand-name">Cyber Guardian</span>
                <span class="status-pill status-live"><span class="pulsing-dot"></span> LIVE SHIELD</span>
                <span class="status-pill status-env">ENTERPRISE</span>
            </div>
            <div class="status-pill">
                PORTAL ACCESS
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    auth_col1, auth_col2, auth_col3 = st.columns([1, 1.8, 1])
    with auth_col2:
        # Centered product banner directly above authentication buttons
        st.markdown(
            """
            <div style="text-align: center; margin: 1.5rem auto 1.75rem auto;">
                <div style="display: inline-flex; align-items: center; justify-content: center; width: 56px; height: 56px; border-radius: 12px; background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.25); font-size: 26px; margin-bottom: 0.85rem; box-shadow: 0 4px 16px rgba(59, 130, 246, 0.2);">🛡️</div>
                <h1 style="font-size: 1.85rem; font-weight: 700; color: #ffffff; margin: 0 0 0.35rem 0; letter-spacing: -0.025em;">Cyber Guardian</h1>
                <p style="font-size: 0.92rem; color: #94a3b8; margin: 0; line-height: 1.5;">Enterprise Threat Intelligence &amp; Behavioral Counter-Interrogation</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Three clearly separated action tabs / buttons
        btn_c1, btn_c2, btn_c3 = st.columns(3)
        with btn_c1:
            if st.button("↳ Sign In", key="btn_signin_nav", use_container_width=True,
                         type="primary" if st.session_state.get("auth_mode") == "signin" else "secondary"):
                st.session_state["auth_mode"] = "signin"
                st.rerun()
        with btn_c2:
            if st.button("+ Register", key="btn_create_nav", use_container_width=True,
                         type="primary" if st.session_state.get("auth_mode") == "register" else "secondary"):
                st.session_state["auth_mode"] = "register"
                st.rerun()
        with btn_c3:
            if st.button("⊘ Guest Access", key="btn_guest_nav", use_container_width=True):
                st.session_state["authenticated"] = False
                st.session_state["is_guest"] = True
                st.session_state["username"] = None
                st.rerun()

        st.markdown('<div style="height: 1rem;"></div>', unsafe_allow_html=True)

        if st.session_state.get("auth_mode") == "signin":
            st.markdown(
                """
                <div class="auth-header">
                    <div class="auth-title">Welcome Back</div>
                    <div class="auth-subtitle">Enter your operator credentials to access your persistent threat intelligence memory.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.form("login_form", clear_on_submit=False):
                login_user = st.text_input("Username / Handle", placeholder="e.g. analyst_01")
                login_pass = st.text_input("Password", type="password", placeholder="Enter password")
                login_submit = st.form_submit_button("Sign In", use_container_width=True, type="primary")

                if login_submit:
                    if not login_user.strip() or not login_pass.strip():
                        st.error("Username and password cannot be empty.")
                    elif verify_user(login_user.strip(), login_pass.strip()):
                        st.session_state["authenticated"] = True
                        st.session_state["is_guest"] = False
                        st.session_state["username"] = login_user.strip().lower()
                        st.success(f"Access granted: Welcome, {st.session_state['username']}")
                        st.rerun()
                    else:
                        st.error("Access denied: Invalid username or password.")

        elif st.session_state.get("auth_mode") == "register":
            st.markdown(
                """
                <div class="auth-header">
                    <div class="auth-title">Create Account</div>
                    <div class="auth-subtitle">Register a new security analyst profile to persist and track threat indicators across sessions.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.form("register_form", clear_on_submit=False):
                reg_user = st.text_input("Username / Handle", placeholder="e.g. sentry_lead")
                reg_pass = st.text_input("Password", type="password", placeholder="At least 4 characters")
                reg_pass_conf = st.text_input("Confirm Password", type="password", placeholder="Re-type password")
                reg_submit = st.form_submit_button("Create Account", use_container_width=True, type="primary")

                if reg_submit:
                    if not reg_user.strip() or not reg_pass.strip():
                        st.error("Username and password cannot be empty.")
                    elif reg_pass != reg_pass_conf:
                        st.error("Passwords do not match.")
                    elif len(reg_pass) < 4:
                        st.error("Password must be at least 4 characters.")
                    else:
                        created = create_user(reg_user.strip(), reg_pass.strip())
                        if created:
                            st.session_state["authenticated"] = True
                            st.session_state["is_guest"] = False
                            st.session_state["username"] = reg_user.strip().lower()
                            st.success(f"Account initialized: Welcome, {st.session_state['username']}")
                            st.rerun()
                        else:
                            st.error("Username is already registered. Please choose another.")

    # Block rendering of protected console until access is authenticated
    st.stop()


# ==============================================================================
# SIDEBAR: Operator Badge & Session Controls
# ==============================================================================
if st.session_state.get("authenticated", False):
    st.sidebar.markdown(
        f"""
        <div style="background: linear-gradient(180deg, rgba(26, 29, 36, 0.7) 0%, rgba(18, 20, 26, 0.9) 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-top: 1px solid rgba(255, 255, 255, 0.15); border-radius: 10px; padding: 1rem 1.15rem; margin-bottom: 1.25rem;">
            <div style="font-size: 0.72rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.06em; font-weight: 600;">
                ACTIVE OPERATOR
            </div>
            <div style="font-size: 1.05rem; font-weight: 600; color: #f0f3f6; margin-top: 0.25rem;">
                {st.session_state.get('username', 'Unknown')}
            </div>
            <div style="font-size: 0.8rem; color: #60a5fa; margin-top: 0.25rem;">
                ● Persistent Memory Active
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
elif st.session_state.get("is_guest", False):
    st.sidebar.markdown(
        """
        <div style="background: linear-gradient(180deg, rgba(26, 29, 36, 0.7) 0%, rgba(18, 20, 26, 0.9) 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-top: 1px solid rgba(255, 255, 255, 0.15); border-radius: 10px; padding: 1rem 1.15rem; margin-bottom: 1.25rem;">
            <div style="font-size: 0.72rem; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.06em; font-weight: 600;">
                SESSION MODE
            </div>
            <div style="font-size: 1.05rem; font-weight: 600; color: #f0f3f6; margin-top: 0.25rem;">
                Guest (Incognito)
            </div>
            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem;">
                Transient Mode • Zero DB Logging
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def handle_logout():
    st.session_state["authenticated"] = False
    st.session_state["is_guest"] = False
    st.session_state["username"] = None
    st.session_state["auth_mode"] = "signin"
    st.session_state["scan_history"] = []
    st.session_state["current_report"] = None
    st.session_state["input_text"] = ""
    st.session_state["current_input"] = ""
    st.session_state["honeypot_messages"] = []


st.sidebar.button("Sign Out", on_click=handle_logout, use_container_width=True)
st.sidebar.write("---")

st.sidebar.markdown("### Scan History")

history_list = st.session_state["scan_history"]

if not history_list:
    st.sidebar.caption("No scans performed yet in this session.")
else:
    st.sidebar.button("Clear History", on_click=clear_scan_history, use_container_width=True)
    st.sidebar.write("")

    # Display in reverse chronological order (newest first)
    for idx, item in enumerate(reversed(history_list)):
        risk = item["risk"]
        expander_title = f"[{risk}] {item['timestamp']} - {item['preview']}"
        with st.sidebar.expander(expander_title):
            st.markdown(f"**Threat Level:** `{risk}`")
            st.markdown(f"**Timestamp:** `{item['timestamp']}`")
            st.markdown(f"**Input Snippet:**\n*{item['preview']}*")
            st.button(
                "Load Scan",
                key=f"reload_btn_{len(history_list) - 1 - idx}",
                on_click=reload_scan,
                args=(item,),
                use_container_width=True,
            )

# SQLite Recidivism Database Viewer
st.sidebar.write("---")
st.sidebar.markdown("### Threat Recidivism DB")
if st.session_state.get("is_guest", False):
    st.sidebar.caption("Database persistence is disabled in Incognito Guest Mode.")
else:
    current_user = st.session_state.get("username")
    db_records = get_all_records(limit=10, username=current_user)
    if not db_records:
        st.sidebar.caption(f"No repeat threats logged yet for Operator {current_user}.")
    else:
        st.sidebar.caption(f"Tracking {len(db_records)} historical threat indicators for {current_user}.")
        with st.sidebar.expander("Recent Tracked Indicators"):
            for rec in db_records:
                st.markdown(f"• **`{rec['sender_handle']}`**")
                st.caption(f"Target: {rec['impersonated_target']} | Score: `{rec['risk_score']}` | {rec['threat_type']}")


# ==============================================================================
# MAIN PAGE: Navigation Header & Hero
# ==============================================================================
operator_display = (
    f"Operator: {st.session_state.get('username')}"
    if st.session_state.get("authenticated")
    else "Guest: Incognito"
)

st.markdown(
    f"""
    <div class="saas-topbar">
        <div class="saas-brand">
            <span class="brand-icon">🛡️</span>
            <span class="brand-name">Cyber Guardian</span>
            <span class="status-pill status-live"><span class="pulsing-dot"></span> LIVE SHIELD</span>
            <span class="status-pill status-env">ENTERPRISE</span>
        </div>
        <div class="status-pill" style="color: #f0f3f6;">
            {operator_display}
        </div>
    </div>
    <div class="saas-hero">
        <h1 class="hero-title">Intelligent Threat Detection &amp; Forensics</h1>
        <p class="hero-subtitle">Analyze suspicious emails, URLs, and social engineering payloads in real-time with multi-vector heuristics.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


def build_markdown_report(report: ThreatReport, scanned_text: str) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    signals = report.threat_signals

    url_lines = ""
    if signals.suspicious_urls:
        url_lines = "\n### Defanged Suspicious Links\n"
        for u in signals.suspicious_urls:
            url_lines += f"- **Defanged:** `{u.defanged_url}`\n  *Flag Reason:* {u.risk_reason}\n"

    actions_lines = "\n".join([f"- [ ] {act}" for act in report.recommended_actions])

    md = f"""# Cyber Guardian Threat Report
**Generated:** {timestamp}
**Overall Threat Level:** {report.overall_risk}

---

## 1. Plain-English Summary
{report.summary}

---

## 2. Threat Indicators
- **Impersonation Target:** {signals.impersonation_target or 'None'}
- **Urgency / Pressure Tactics:** {'Yes - ' + signals.urgency_explanation if signals.urgency_detected else 'No'}
- **Sensitive Credentials Requested:** {', '.join(signals.sensitive_info_details) if signals.sensitive_info_requested else 'None'}
{url_lines}

### Key Technical Findings:
{chr(10).join(['- ' + k for k in signals.key_findings])}

---

## 3. Recommended Actions
{actions_lines}

---

*Notice: {report.disclaimer}*
"""
    return md


def build_incident_email(report: ThreatReport, scanned_text: str) -> str:
    """Generates a professional pre-filled Incident Response Email for IT or Fraud desks."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    signals = report.threat_signals
    target = (
        signals.impersonation_target
        if signals.impersonation_target and signals.impersonation_target.lower() != "none"
        else "Unknown"
    )

    url_block = "\n".join([
        f"  - Link: {u.defanged_url}\n    Flagged For: {u.risk_reason}"
        for u in signals.suspicious_urls
    ]) or "  - None identified."

    credentials_block = ", ".join(signals.sensitive_info_details) if signals.sensitive_info_requested else "None detected"

    subject = f"[SECURITY INCIDENT] {report.overall_risk}-Risk Suspicious Message / Phishing - {target}"
    email_text = f"""Subject: {subject}
To: security-operations@company.com, abuse@{target.lower().replace(' ', '')}.com
Date: {timestamp}

Security Operations Team / Fraud Department,

I am escalating a suspicious communication for inspection and defensive action. This item was analyzed by Cyber Guardian and flagged with an overall risk level of {report.overall_risk}.

=== INCIDENT OVERVIEW ===
• Overall Threat Level: {report.overall_risk}
• Impersonation Target: {target}
• Urgency / Panic Drivers: {'YES - ' + signals.urgency_explanation if signals.urgency_detected else 'None'}
• Sensitive Data Requested: {credentials_block}

=== SECURITY SUMMARY ===
{report.summary}

=== SUSPICIOUS INDICATORS (DEFANGED) ===
{url_block}

=== RAW MESSAGE CONTENT (FOR AUDIT) ===
{scanned_text}

=== RECOMMENDED MITIGATION ACTIONS TAKEN ===
{chr(10).join(['• ' + act for act in report.recommended_actions])}

Please confirm receipt and advise if endpoint isolation, password reset, or domain blocklisting is required.

Regards,
Security Reporter
"""
    return email_text


# ==============================================================================
# SPLIT-SCREEN LAYOUT: [1.6 Analysis Console : 1.0 Scammer Honeypot Sandbox]
# ==============================================================================
col_analysis, col_chat = st.columns([1.6, 1.0], gap="medium")


# ------------------------------------------------------------------------------
# LEFT COLUMN: Primary Analysis & Forensics Console
# ------------------------------------------------------------------------------
with col_analysis:
    # Preset sample buttons
    col_a, col_b, col_c, col_d, col_e = st.columns([1, 1, 1, 1, 1])
    with col_a:
        st.button("Phishing Sample", on_click=set_sample_phishing, use_container_width=True)
    with col_b:
        st.button("Family Emergency", on_click=set_sample_family, use_container_width=True)
    with col_c:
        st.button("Fake Discount", on_click=set_sample_discount, use_container_width=True)
    with col_d:
        st.button("Benign Sample", on_click=set_sample_benign, use_container_width=True)
    with col_e:
        st.button("Clear Input", on_click=clear_input_and_results, use_container_width=True)

    # File Uploader (.txt, .eml)
    uploaded_file = st.file_uploader(
        "Upload Threat Sample",
        type=["txt", "eml"],
        label_visibility="collapsed",
        key="threat_file_uploader",
        on_change=handle_file_upload,
    )

    # Input text area directly bound to key="input_text"
    user_input = st.text_area(
        "Suspicious Message, Email, or Link:",
        height=130,
        placeholder="Paste suspicious email text, SMS message, or link here to inspect...",
        key="input_text",
    )

    scan_clicked = st.button("Run Analysis", type="primary", use_container_width=True)

    # Scan execution
    if scan_clicked:
        if not user_input.strip():
            st.warning("Please paste or type a message before running analysis.")
        else:
            with st.spinner("Analyzing payload with multi-vector heuristics and intelligence agents..."):
                try:
                    signals = analyze_text(user_input.strip())
                    report = generate_advice(signals)

                    # Set current active report
                    st.session_state["current_report"] = report
                    st.session_state["current_input"] = user_input.strip()

                    # Log threat into SQLite recidivism database
                    try:
                        sender_m = re.search(r"(?:From|Reply-To):\s*(?:[^\r\n<]*<)?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>?", user_input.strip(), re.IGNORECASE)
                        detected_sender = sender_m.group(1) if sender_m else ""
                        if not detected_sender:
                            email_m = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", user_input.strip())
                            if email_m:
                                detected_sender = email_m.group(0)

                        detected_links = [u.original_url for u in signals.suspicious_urls]
                        if not detected_sender and detected_links:
                            try:
                                detected_sender = urllib.parse.urlsplit(detected_links[0] if "://" in detected_links[0] else f"http://{detected_links[0]}").netloc
                            except Exception:
                                pass

                        rec_type = "family_emergency" if getattr(signals, "family_emergency_flag", False) else ("phishing" if report.overall_risk != "LOW" else "benign")
                        calc_score = 95 if report.overall_risk == "HIGH" else (55 if report.overall_risk == "MEDIUM" else 10)

                        if not st.session_state.get("is_guest", False):
                            log_threat(
                                sender_handle=detected_sender or "unknown",
                                threat_type=rec_type,
                                risk_score=calc_score,
                                impersonated_target=signals.impersonation_target or "None",
                                extracted_links=detected_links,
                                notes=report.summary[:250],
                                username=st.session_state.get("username"),
                            )
                    except Exception:
                        pass

                    # Add to scan history
                    snippet = user_input.strip()[:40] + ("..." if len(user_input.strip()) > 40 else "")
                    history_entry = {
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "preview": snippet,
                        "risk": report.overall_risk,
                        "report": report,
                        "full_text": user_input.strip(),
                    }
                    st.session_state["scan_history"].append(history_entry)

                except Exception as e:
                    err_str = str(e)
                    if "503" in err_str or "unavailable" in err_str.lower() or "high demand" in err_str.lower():
                        st.warning(
                            "⚠️ **AI Service High Demand (503 UNAVAILABLE)**\n\n"
                            "Google Gemini servers are currently experiencing peak global traffic. "
                            "Our automatic retries and fallback models were attempted, but servers are temporarily saturated.\n\n"
                            "👉 **Recommendation:** Please wait 5–10 seconds and click **Run Analysis** again."
                        )
                    elif "429" in err_str or "quota" in err_str.lower() or "resource_exhausted" in err_str.lower():
                        st.warning(
                            "⚠️ **Rate Limit Exceeded (429)**\n\n"
                            "API request quota is temporarily exhausted. Please wait a moment before trying again."
                        )
                    elif "api_key" in err_str.lower():
                        st.warning(
                            "⚠️ **API Key Configuration Error**\n\n"
                            "Please verify that your `GEMINI_API_KEY` is properly configured in your `.env` file or Streamlit secrets."
                        )
                    else:
                        st.warning(
                            f"⚠️ **Security Scan Service Notice**\n\n"
                            f"{err_str}\n\n"
                            "Please try scanning again in a few moments."
                        )

    # --------------------------------------------------------------------------
    # RESULTS DASHBOARD: Quick Stats KPI Bar & 4 Operational Tabs
    # --------------------------------------------------------------------------
    if st.session_state.get("current_report") is not None:
        report: ThreatReport = st.session_state["current_report"]
        signals = report.threat_signals
        raw_text = st.session_state.get("current_input", "")

        # Calculate numerical threat score & status indicator dot
        if report.overall_risk == "HIGH":
            threat_score = 95
            score_dot = "dot-red"
            score_delta_html = '<span style="color: #ef4444;">▲ Critical Threat</span>'
            level_dot = "dot-red"
            level_text = "HIGH RISK"
            level_sub = "Dangerous Payload"
        elif report.overall_risk == "MEDIUM":
            threat_score = 55
            score_dot = "dot-amber"
            score_delta_html = '<span style="color: #f59e0b;">▲ Elevated Suspicion</span>'
            level_dot = "dot-amber"
            level_text = "MEDIUM RISK"
            level_sub = "Anomalies Flagged"
        else:
            threat_score = 10
            score_dot = "dot-green"
            score_delta_html = '<span style="color: #10b981;">▼ Clean Analysis</span>'
            level_dot = "dot-green"
            level_text = "LOW RISK"
            level_sub = "Benign Payload"

        # Repeat Offender Recidivism Check & E-Commerce Discount Heuristic
        sender_m = re.search(r"(?:From|Reply-To):\s*(?:[^\r\n<]*<)?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)>?", raw_text, re.IGNORECASE)
        detected_sender = sender_m.group(1) if sender_m else ""
        if not detected_sender:
            email_m = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", raw_text)
            if email_m:
                detected_sender = email_m.group(0)

        links = [u.original_url for u in signals.suspicious_urls]
        if not detected_sender and links:
            try:
                detected_sender = urllib.parse.urlsplit(links[0] if "://" in links[0] else f"http://{links[0]}").netloc
            except Exception:
                pass

        if not st.session_state.get("is_guest", False):
            repeat_data = check_repeat_offender(
                sender_handle=detected_sender,
                links=links,
                username=st.session_state.get("username"),
            )
            if repeat_data["is_repeat_offender"]:
                matched_str = ", ".join(repeat_data["matched_identifiers"]) if repeat_data["matched_identifiers"] else "Previous URL / Sender"
                st.markdown(
                    f"""
                    <div class="alert-banner alert-banner-warning">
                        <div style="font-weight: 700; margin-bottom: 0.35rem;">
                            Repeat Offender / Known Adversary Match
                        </div>
                        <div>
                            This sender handle or infrastructure was logged in <b>{repeat_data['repeat_count']}</b> prior scan(s).
                            <br><span style="color: #94a3b8;">Matched Tracked Markers:</span> <code>{matched_str}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        discount_data = analyze_ecommerce_discount(raw_text, " ".join(links))

        # Threat Classification
        if getattr(signals, "family_emergency_flag", False):
            classification = "Account Hijack / Distress"
            class_dot = "dot-red"
        elif discount_data.get("is_fake_discount_likely", False):
            classification = "Predatory Storefront"
            class_dot = "dot-amber"
        elif report.overall_risk != "LOW":
            classification = "Credential Phishing"
            class_dot = "dot-red"
        else:
            classification = "Benign Payload"
            class_dot = "dot-green"

        target_name = (
            signals.impersonation_target
            if signals.impersonation_target and signals.impersonation_target.lower() != "none"
            else "None"
        )

        st.markdown('<div style="height: 0.5rem;"></div>', unsafe_allow_html=True)

        # 1. Elevated Quick Stats Bar (4 KPI Cards)
        kpi_html = f"""
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-label">Heuristic Score</span>
                    <span class="{score_dot}"></span>
                </div>
                <div class="kpi-value">{threat_score}<span class="kpi-subval">/100</span></div>
                <div class="kpi-delta">{score_delta_html}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-label">Risk Level</span>
                    <span class="{level_dot}"></span>
                </div>
                <div class="kpi-value">{level_text}</div>
                <div class="kpi-delta" style="color: #94a3b8;">{level_sub}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-label">Classification</span>
                    <span class="{class_dot}"></span>
                </div>
                <div class="kpi-value" style="font-size: 1.05rem; line-height: 1.3;">{classification}</div>
                <div class="kpi-delta" style="color: #94a3b8;">Target: {target_name}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-label">Processing Pipeline</span>
                    <span class="dot-blue"></span>
                </div>
                <div class="kpi-value">Active<span class="kpi-subval"> (4/4)</span></div>
                <div class="kpi-delta" style="color: #38bdf8;">Multi-Vector Active</div>
            </div>
        </div>
        """
        st.markdown(kpi_html, unsafe_allow_html=True)

        # 2. Interactive Message Forensic Highlighter
        st.markdown("### Message Forensic Highlighter")
        highlighted_html = highlight_evidence(raw_text, signals)
        st.markdown(
            f"""
            <div class="legend-bar">
                <span><span class="chip-urgency">■</span> <b>Urgency &amp; Pressure Tactics</b></span>
                <span><span class="chip-sensitive">■</span> <b>Sensitive Credentials / Data</b></span>
                <span><span class="chip-url">■</span> <b>Suspicious / Defanged Links</b></span>
            </div>
            <div class="forensic-box">
                <div style="font-weight: 600; color: #94a3b8; margin-bottom: 0.65rem; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em;">
                    Extracted Message Evidence
                </div>
                {highlighted_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.write("")

        # 3. Four Operational Tabs
        tab_advice, tab_technical, tab_incident, tab_probes = st.tabs([
            "Plain-English Advice",
            "Technical Breakdown",
            "Incident Response Email",
            "Export Packages & Probes",
        ])

        # ----------------------------------------------------------------------
        # TAB 1: Plain-English Advice
        # ----------------------------------------------------------------------
        with tab_advice:
            risk = report.overall_risk
            if risk == "HIGH":
                badge_html = '<div class="risk-banner-card risk-high">OVERALL THREAT LEVEL: HIGH (CRITICAL RISK)</div>'
            elif risk == "MEDIUM":
                badge_html = '<div class="risk-banner-card risk-medium">OVERALL THREAT LEVEL: MEDIUM (SUSPICIOUS)</div>'
            else:
                badge_html = '<div class="risk-banner-card risk-low">OVERALL THREAT LEVEL: LOW (BENIGN)</div>'

            st.markdown(badge_html, unsafe_allow_html=True)

            if getattr(signals, "family_emergency_flag", False):
                st.markdown(
                    f"""
                    <div class="alert-banner alert-banner-danger">
                        <div style="font-size: 1rem; font-weight: 700; margin-bottom: 0.35rem;">
                            Account Takeover / Family Impersonation Warning
                        </div>
                        <div>
                            The sender is masquerading as a relative in an emergency ({signals.family_emergency_details or 'broken phone, stranded'}).
                            <br><b>Do not send funds, wire transfers, or gift cards.</b>
                            <br><b>Mandatory Protocol:</b> Call the contact directly on their known, verified voice number.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            if discount_data.get("is_fake_discount_likely", False):
                st.markdown(
                    f"""
                    <div class="alert-banner alert-banner-warning">
                        <div style="font-size: 1rem; font-weight: 700; margin-bottom: 0.35rem;">
                            Predatory Discount / Scam Storefront Detected
                        </div>
                        <div>
                            {discount_data['risk_summary']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.subheader("Summary")
            st.markdown(f'<div class="summary-card">{report.summary}</div>', unsafe_allow_html=True)

            st.subheader("Recommended Action Checklist")
            for act in report.recommended_actions:
                is_dont = act.upper().startswith("DO NOT") or act.upper().startswith("DON'T") or "NEVER" in act.upper()
                if is_dont:
                    st.markdown(f'<div class="action-item-dont"><b>[AVOID]</b> {act}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="action-item-do"><b>[ACTION]</b> {act}</div>', unsafe_allow_html=True)

            st.write("")
            markdown_data = build_markdown_report(report, raw_text)
            st.download_button(
                label="Download Safety Report (.md)",
                data=markdown_data,
                file_name="cyber_guardian_report.md",
                mime="text/markdown",
                use_container_width=True,
            )

        # ----------------------------------------------------------------------
        # TAB 2: Technical Breakdown
        # ----------------------------------------------------------------------
        with tab_technical:
            st.subheader("Static Heuristics Engine")
            st.caption("Deterministic structural inspection executed locally prior to AI reasoning (zero network probing).")

            heuristics_raw = signals.heuristics_results or []
            heuristics = [
                h.model_dump() if hasattr(h, "model_dump") else h
                for h in heuristics_raw
            ]
            if heuristics:
                has_raw_ip = any(h.get("is_ip_address") for h in heuristics)
                has_high_risk_tld = any(h.get("is_high_risk_tld") for h in heuristics)
                typosquat_targets = list(dict.fromkeys([h.get("typosquat_target") for h in heuristics if h.get("typosquat_target")]))

                badge_ip = (
                    '<span class="badge-heur-high">RAW IP DETECTED</span>'
                    if has_raw_ip
                    else '<span class="badge-heur-clean">NO RAW IP</span>'
                )
                badge_tld = (
                    '<span class="badge-heur-med">HIGH-RISK TLD DETECTED</span>'
                    if has_high_risk_tld
                    else '<span class="badge-heur-clean">STANDARD TLD</span>'
                )
                badge_typo = (
                    f'<span class="badge-heur-high">TYPOSQUAT TARGET: {", ".join(typosquat_targets)}</span>'
                    if typosquat_targets
                    else '<span class="badge-heur-clean">NO TYPOSQUATTING</span>'
                )

                st.markdown(
                    f'<div style="display: flex; gap: 0.65rem; flex-wrap: wrap; margin-bottom: 1rem;">'
                    f'{badge_ip}{badge_tld}{badge_typo}</div>',
                    unsafe_allow_html=True,
                )

                for h in heuristics:
                    sev = h.get("severity", "LOW")
                    sev_badge = (
                        '<span class="badge-heur-high">HIGH SEVERITY</span>'
                        if sev == "HIGH"
                        else ('<span class="badge-heur-med">MEDIUM SEVERITY</span>' if sev == "MEDIUM" else '<span class="badge-heur-clean">LOW SEVERITY</span>')
                    )
                    findings_items = "".join([f"<li>{f}</li>" for f in h.get("findings", [])])
                    st.markdown(
                        f"""
                        <div class="ioc-snippet-box">
                            <div class="ioc-snippet-header">
                                <span class="ioc-code"><code>{h.get("defanged_url", "")}</code></span>
                                {sev_badge}
                            </div>
                            <ul style="margin-left: 1.25rem; margin-top: 0.35rem; font-size: 0.88rem; color: #94a3b8; margin-bottom: 0;">{findings_items}</ul>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No external links or IP addresses were detected for static heuristic inspection.")

            st.write("")
            st.subheader("Threat Indicators & Findings")

            indicators_html = ['<div class="indicators-card">']

            if signals.impersonation_target and signals.impersonation_target.lower() != "none":
                indicators_html.append(
                    f'<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color: #94a3b8; font-weight: 600;">Impersonation Target:</span> '
                    f'<b>{signals.impersonation_target}</b></div>'
                )

            if signals.urgency_detected:
                urgency_txt = f" - {signals.urgency_explanation}" if signals.urgency_explanation else ""
                indicators_html.append(
                    f'<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color: #94a3b8; font-weight: 600;">Urgency &amp; Pressure Tactics:</span> '
                    f'Artificial deadline detected{urgency_txt}</div>'
                )

            if signals.sensitive_info_requested:
                cred_list = ", ".join(signals.sensitive_info_details) if signals.sensitive_info_details else "Credentials"
                indicators_html.append(
                    f'<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color: #94a3b8; font-weight: 600;">Sensitive Credentials Solicited:</span> '
                    f'<b>{cred_list}</b></div>'
                )

            if getattr(signals, "family_emergency_flag", False):
                indicators_html.append(
                    f'<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color: #94a3b8; font-weight: 600;">Family Emergency Impersonation:</span> '
                    f'<b style="color: #ef4444;">DETECTED</b> ({signals.family_emergency_details or "Distress driver"})</div>'
                )

            if getattr(signals, "is_account_takeover_likely", False):
                indicators_html.append(
                    '<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    '<span style="color: #94a3b8; font-weight: 600;">Account Takeover / Contact Hijack:</span> '
                    '<b style="color: #ef4444;">HIGH PROBABILITY</b></div>'
                )

            if discount_data.get("is_fake_discount_likely", False):
                rate_str = f"{discount_data['discount_rate']:.0f}%" if discount_data.get("discount_rate") else "Steep"
                target_brand = discount_data.get("luxury_brand_detected", "Luxury item").capitalize()
                indicators_html.append(
                    f'<div style="padding: 0.65rem 0; border-bottom: 1px solid rgba(255,255,255,0.06);">'
                    f'<span style="color: #94a3b8; font-weight: 600;">Predatory Storefront Flag:</span> '
                    f'<b style="color: #fbbf24;">{rate_str} off {target_brand}</b> - {discount_data["risk_summary"]}</div>'
                )

            if signals.suspicious_urls:
                indicators_html.append(
                    '<div style="padding-top: 0.65rem; color: #f0f3f6; font-weight: 600;">Extracted Defanged IOCs:</div>'
                )
                for link in signals.suspicious_urls:
                    indicators_html.append(
                        f'<div class="ioc-snippet-box" style="margin-top: 0.5rem;">'
                        f'<div class="ioc-snippet-header">'
                        f'<span class="ioc-tag">DEFANGED URL</span>'
                        f'<span class="badge-heur-high">SUSPICIOUS</span>'
                        f'</div>'
                        f'<div class="ioc-code"><code>{link.defanged_url}</code></div>'
                        f'<div class="ioc-reason">{link.risk_reason}</div>'
                        f'</div>'
                    )

            if not signals.urgency_detected and not signals.sensitive_info_requested and not signals.suspicious_urls:
                indicators_html.append(
                    '<div style="padding: 0.5rem 0; color: #94a3b8;">No artificial urgency, sensitive data harvesting, or suspicious links were detected.</div>'
                )

            indicators_html.append('</div>')
            st.markdown("".join(indicators_html), unsafe_allow_html=True)

            if signals.key_findings:
                st.markdown("#### Key Technical Findings:")
                for k in signals.key_findings:
                    st.markdown(f"- {k}")

            with st.expander("View Raw Threat Signals (JSON)"):
                st.json(signals.model_dump())

        # ----------------------------------------------------------------------
        # TAB 3: Incident Response Email
        # ----------------------------------------------------------------------
        with tab_incident:
            st.subheader("Incident Response Escalation Draft")
            st.caption(
                "Copy and forward this prepared escalation notice directly to your internal Security Operations Center (SOC) "
                "or the anti-abuse desk of the affected provider."
            )

            incident_email = build_incident_email(report, raw_text)

            st.text_area(
                "Draft Email (Ready to Copy):",
                value=incident_email,
                height=260,
                key="incident_email_text",
            )

            st.download_button(
                label="Download Draft Email (.txt)",
                data=incident_email,
                file_name="incident_escalation_email.txt",
                mime="text/plain",
                use_container_width=True,
            )

        # ----------------------------------------------------------------------
        # TAB 4: Export Packages & Tactical Probes
        # ----------------------------------------------------------------------
        with tab_probes:
            st.subheader("Tactical Counter-Probes & Threat Intel Packages")
            st.caption("Structured probe strategies to safely extract attacker infrastructure without tipping them off.")

            # Generate static tactical probes
            probes_data = generate_counter_probe(
                attacker_last_message=raw_text,
                client=st.session_state.get("gemini_client"),
            )

            p1 = probes_data.get("infrastructure_probe", {})
            st.markdown(
                f"""
                <div class="ioc-snippet-box">
                    <div class="ioc-snippet-header">
                        <span class="ioc-tag">1. {p1.get('name', 'Infrastructure Probe')}</span>
                        <span class="badge-heur-clean">SAFE PROBE</span>
                    </div>
                    <div class="ioc-reason" style="margin-bottom: 0.4rem;"><b>Objective:</b> {p1.get('strategy', '')}</div>
                    <div class="ioc-code" style="color: #f0f3f6; background: rgba(255,255,255,0.03); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06);">{p1.get('copy_text', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            p2 = probes_data.get("consistency_check", {})
            st.markdown(
                f"""
                <div class="ioc-snippet-box">
                    <div class="ioc-snippet-header">
                        <span class="ioc-tag">2. {p2.get('name', 'Stalling / Consistency Check')}</span>
                        <span class="badge-heur-med">STALL TACTIC</span>
                    </div>
                    <div class="ioc-reason" style="margin-bottom: 0.4rem;"><b>Objective:</b> {p2.get('strategy', '')}</div>
                    <div class="ioc-code" style="color: #f0f3f6; background: rgba(255,255,255,0.03); padding: 0.65rem 0.85rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06);">{p2.get('copy_text', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_exp1, col_exp2 = st.columns(2)
            with col_exp1:
                stix_bundle = generate_stix_threat_bundle(report, signals.heuristics_results, raw_text)
                stix_json_str = json.dumps(stix_bundle, indent=2)
                st.download_button(
                    label="Download STIX 2.1 Intel (.json)",
                    data=stix_json_str,
                    file_name="cyber_guardian_stix21_bundle.json",
                    mime="application/json",
                    use_container_width=True,
                )
            with col_exp2:
                html_report = generate_executive_html_report(report, signals.heuristics_results, raw_text)
                st.download_button(
                    label="Download Forensic Report (.html)",
                    data=html_report,
                    file_name="cyber_guardian_executive_report.html",
                    mime="text/html",
                    use_container_width=True,
                )

        # Disclaimer footer
        st.markdown(
            f'<div style="color: #64748b; font-size: 0.82rem; margin-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 0.75rem;">Notice: {report.disclaimer}</div>',
            unsafe_allow_html=True,
        )


# ------------------------------------------------------------------------------
# RIGHT COLUMN: Dedicated Scammer Reverse-Interrogation & Behavioral Sandbox
# ------------------------------------------------------------------------------
with col_chat:
    st.markdown(
        """
        <div class="scammer-sandbox-container">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; padding-bottom: 0.65rem; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
                <div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: #ffffff; letter-spacing: -0.015em;">🎭 Scammer Sandbox</div>
                    <div style="font-size: 0.8rem; color: #94a3b8;">Reverse-Interrogation &amp; Behavioral Analysis</div>
                </div>
                <span class="status-pill status-live"><span class="pulsing-dot"></span> LIVE SIM</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Persona Selector & Controls
    c_p1, c_p2 = st.columns([1.8, 1.0])
    with c_p1:
        persona_choice = st.selectbox(
            "Adversary Persona:",
            options=[
                "Auto-Derive from Current Analyzed Threat",
                "Bank Fraud Department",
                "Tech Support Impersonator",
                "Crypto Investment Con",
                "Urgent Family Distress",
            ],
            key="persona_select",
            label_visibility="collapsed",
        )
    with c_p2:
        if st.button("Reset Chat", key="btn_reset_chat", use_container_width=True):
            st.session_state["honeypot_messages"] = []
            st.rerun()

    # Active Persona Resolution
    resolved_persona = persona_choice
    if persona_choice == "Auto-Derive from Current Analyzed Threat":
        curr_rep = st.session_state.get("current_report")
        if curr_rep and getattr(curr_rep.threat_signals, "family_emergency_flag", False):
            resolved_persona = "Urgent Family Distress"
        elif curr_rep and curr_rep.threat_signals.impersonation_target and curr_rep.threat_signals.impersonation_target.lower() != "none":
            resolved_persona = f"{curr_rep.threat_signals.impersonation_target} Fraud Department"
        else:
            resolved_persona = "Bank Fraud Department"

    st.caption(f"🎯 Target Persona: **{resolved_persona}**")

    # If messages are empty, offer seed option if threat input exists, or show starter guide
    if not st.session_state.get("honeypot_messages"):
        curr_inp = st.session_state.get("current_input") or st.session_state.get("input_text", "")
        if curr_inp.strip():
            if st.button("⚡ Seed Chat from Current Threat", use_container_width=True):
                st.session_state["honeypot_messages"].append({
                    "role": "scammer",
                    "content": curr_inp.strip(),
                    "tactic": "⚡ Tactic: Initial Inbound Social Engineering Lure | 🎯 Objective: Hook Target",
                })
                st.rerun()

        st.markdown(
            """
            <div style="background: rgba(26, 29, 36, 0.45); border: 1px dashed rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 1.25rem 1rem; text-align: center; color: #94a3b8; font-size: 0.85rem; margin: 0.85rem 0;">
                <div style="font-size: 1.15rem; margin-bottom: 0.35rem;">🛡️ Honeypot Ready</div>
                Probe the scammer with questions, challenge their badge number, or feign compliance to observe how their manipulation tactics adapt.
                <br><br>
                <span style="font-size: 0.78rem; color: #64748b;">All replies include real-time behavioral analysis tags and enforce strict safety boundaries.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Render multi-turn chat history
    for msg in st.session_state.get("honeypot_messages", []):
        if msg.get("role") in ["user", "analyst"]:
            with st.chat_message("user"):
                st.markdown(msg.get("content", ""))
        else:
            with st.chat_message("assistant", avatar="🎭"):
                if msg.get("tactic"):
                    st.markdown(
                        f"""
                        <div style="font-size: 0.74rem; font-weight: 600; color: #fbbf24; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 4px; padding: 2px 7px; margin-bottom: 0.35rem; display: inline-block;">
                            {msg['tactic']}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                st.markdown(msg.get("content", ""))

    # Interactive chat input
    chat_prompt = st.chat_input("Probe the scammer or counter-interrogate...", key="honeypot_chat_input")
    if chat_prompt:
        st.session_state["honeypot_messages"].append({
            "role": "user",
            "content": chat_prompt.strip(),
            "tactic": None,
        })
        with st.spinner("Analyzing scammer behavioral counter-reaction..."):
            threat_ctx = st.session_state.get("current_input") or st.session_state.get("input_text", "")
            scammer_res = simulate_scammer_reply(
                messages=st.session_state["honeypot_messages"],
                persona=resolved_persona,
                current_threat_context=threat_ctx,
                client=st.session_state.get("gemini_client"),
            )
            st.session_state["honeypot_messages"].append({
                "role": "scammer",
                "content": scammer_res.get("content", ""),
                "tactic": scammer_res.get("tactic", "⚡ Tactic: Adversary Pressure | 🎯 Objective: Compliance"),
            })
            st.rerun()
