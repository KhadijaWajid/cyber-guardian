import re
import json
import datetime
import urllib.parse
import streamlit as st

from src.analyzer import analyze_text
from src.advisor import generate_advice
from src.schemas import ThreatReport
from src.utils import parse_eml_bytes, highlight_evidence
from src.exporter import generate_stix_threat_bundle, generate_executive_html_report
from src.db import log_threat, check_repeat_offender, get_all_records, create_user, verify_user
from src.honeypot import generate_counter_probe
from src.heuristics import analyze_ecommerce_discount


# Page configuration
st.set_page_config(
    page_title="Cyber Guardian - SOC Threat Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Cybersecurity SOC Theme & Styling: Deep Void Purple Pixel HUD
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Share+Tech+Mono&display=swap');

    /* Global Tactical HUD Abyssal Background & Pixel Grid */
    .stApp {
        background-color: #08040f !important;
        background-image: 
            linear-gradient(rgba(157, 78, 221, 0.04) 1px, transparent 1px), 
            linear-gradient(90deg, rgba(157, 78, 221, 0.04) 1px, transparent 1px) !important;
        background-size: 32px 32px !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
    }

    [data-testid="stSidebar"] {
        background-color: #12091f !important;
        border-right: 2px solid #9d4edd !important;
        box-shadow: 3px 0 0 0 #5a189a, 0 0 16px rgba(157, 78, 221, 0.3) !important;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* Pixelated Typography & Glowing Void Purple Headers */
    h1, h2, h3, .main-title {
        font-family: 'Press Start 2P', monospace !important;
        color: #9d4edd !important;
        text-shadow: 0 0 12px rgba(157, 78, 221, 0.7) !important;
        letter-spacing: 1px !important;
    }

    h1, .main-title {
        font-size: 1.55rem !important;
        line-height: 1.6 !important;
    }

    h2 {
        font-size: 1.15rem !important;
        line-height: 1.5 !important;
    }

    h3 {
        font-size: 0.95rem !important;
        line-height: 1.5 !important;
    }

    h4 {
        font-family: 'Press Start 2P', monospace !important;
        font-size: 0.8rem !important;
        color: #9d4edd !important;
        text-shadow: 0 0 8px rgba(157, 78, 221, 0.5) !important;
        letter-spacing: 0.5px !important;
    }

    .main-header {
        text-align: center;
        margin-bottom: 2rem;
        padding: 1.25rem 0.5rem;
        border-bottom: 2px solid #5a189a;
    }

    .main-subtitle {
        color: #d8b4fe !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1.05rem !important;
        letter-spacing: 2px !important;
        opacity: 0.95;
        margin-top: 0.65rem;
        text-transform: uppercase;
        text-shadow: 0 0 8px rgba(157, 78, 221, 0.4);
    }

    /* Pixelated Stepped Border Form Elements & Containers */
    textarea, input, [data-baseweb="textarea"], [data-baseweb="input"], [data-baseweb="base-input"] {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.98rem !important;
    }

    textarea:focus, input:focus, [data-baseweb="textarea"]:focus-within, [data-baseweb="input"]:focus-within, [data-baseweb="base-input"]:focus-within {
        border-color: #b5179e !important;
        box-shadow: 
            3px 0 0 0 #7209b7, 
            -3px 0 0 0 #7209b7, 
            0 3px 0 0 #7209b7, 
            0 -3px 0 0 #7209b7, 
            0 0 18px rgba(181, 23, 158, 0.5) !important;
    }

    /* Tactical HUD Metric Cards */
    [data-testid="stMetric"] {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        padding: 0.95rem 1.15rem !important;
    }

    [data-testid="stMetricLabel"] {
        color: #d8b4fe !important;
        font-family: 'Press Start 2P', monospace !important;
        font-size: 0.64rem !important;
        letter-spacing: 0.5px !important;
        text-transform: uppercase !important;
    }

    [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        text-shadow: 0 0 10px #9d4edd !important;
    }

    [data-testid="stMetricDelta"] {
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 0.85rem !important;
    }

    /* Pixelated Sharp Streamlit Buttons */
    .stButton > button, 
    .stDownloadButton > button, 
    button[kind="primary"], 
    button[kind="secondary"] {
        border-radius: 0px !important;
        border: 2px solid #9d4edd !important;
        background-color: #1e0e33 !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 10px rgba(157, 78, 221, 0.35) !important;
        transition: all 0.12s ease-in-out !important;
        padding: 0.65rem 1.15rem !important;
    }

    .stButton > button p, 
    .stDownloadButton > button p,
    button[kind="primary"] p,
    button[kind="secondary"] p,
    .stButton > button span,
    .stDownloadButton > button span {
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-weight: 700 !important;
        transition: color 0.12s ease-in-out !important;
    }

    .stButton > button:hover, 
    .stDownloadButton > button:hover, 
    button[kind="primary"]:hover, 
    button[kind="secondary"]:hover {
        background-color: #9d4edd !important;
        color: #08040f !important;
        border: 2px solid #b5179e !important;
        box-shadow: 0 0 18px #9d4edd, 0 0 25px rgba(181, 23, 158, 0.5) !important;
        transform: translate(-1px, -1px) !important;
    }

    .stButton > button:hover p, 
    .stDownloadButton > button:hover p,
    button[kind="primary"]:hover p,
    button[kind="secondary"]:hover p,
    .stButton > button:hover span,
    .stDownloadButton > button:hover span {
        color: #08040f !important;
    }

    .stButton > button:active, 
    .stDownloadButton > button:active, 
    button[kind="primary"]:active, 
    button[kind="secondary"]:active {
        transform: translate(2px, 2px) !important;
        box-shadow: none !important;
    }

    /* Sharp Block Tabs (stTabs) */
    [data-baseweb="tab-list"] {
        gap: 8px !important;
        border-bottom: 2px solid #5a189a !important;
        background-color: transparent !important;
        margin-bottom: 1.5rem !important;
    }

    [data-baseweb="tab"] {
        border-radius: 0px !important;
        color: #a370f7 !important;
        background-color: #12091f !important;
        border: 1px solid #5a189a !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
        letter-spacing: 0.5px !important;
        padding: 0.75rem 1.25rem !important;
        transition: all 0.15s ease-in-out !important;
    }

    [data-baseweb="tab"] p, 
    [data-baseweb="tab"] div, 
    [data-baseweb="tab"] span {
        color: #a370f7 !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-weight: 700 !important;
        transition: color 0.15s ease-in-out !important;
    }

    [data-baseweb="tab"]:hover {
        color: #e9d5ff !important;
        background-color: #1e0e33 !important;
        border-color: #9d4edd !important;
    }

    [data-baseweb="tab"]:hover p, 
    [data-baseweb="tab"]:hover div, 
    [data-baseweb="tab"]:hover span {
        color: #e9d5ff !important;
    }

    [data-baseweb="tab"][aria-selected="true"] {
        color: #e9d5ff !important;
        background-color: #1e0e33 !important;
        border: 1px solid #9d4edd !important;
        border-bottom: 3px solid #9d4edd !important;
        box-shadow: 0 0 15px rgba(157, 78, 221, 0.4), inset 0 0 10px rgba(157, 78, 221, 0.2) !important;
        text-shadow: 0 0 8px #9d4edd !important;
    }

    [data-baseweb="tab"][aria-selected="true"] p, 
    [data-baseweb="tab"][aria-selected="true"] div, 
    [data-baseweb="tab"][aria-selected="true"] span {
        color: #e9d5ff !important;
        text-shadow: 0 0 8px #9d4edd !important;
    }

    [data-baseweb="tab-highlight"] {
        background-color: #9d4edd !important;
        height: 3px !important;
    }

    [data-baseweb="tab-border"] {
        background-color: #5a189a !important;
    }

    /* Glowing Retro Threat Badges */
    .risk-card {
        border-radius: 0px !important;
        font-family: 'Press Start 2P', monospace !important;
        font-size: 0.95rem !important;
        padding: 1.35rem 1rem !important;
        margin: 1.4rem 0 !important;
        text-align: center !important;
        letter-spacing: 1px !important;
    }

    .risk-high {
        background-color: #20050d !important;
        border: 2px solid #ff2a6d !important;
        color: #ff2a6d !important;
        box-shadow: 
            3px 0 0 0 #800020, 
            -3px 0 0 0 #800020, 
            0 3px 0 0 #800020, 
            0 -3px 0 0 #800020, 
            0 0 20px rgba(255, 42, 109, 0.5) !important;
        text-shadow: 0 0 10px #ff2a6d !important;
    }

    .risk-medium {
        background-color: #211500 !important;
        border: 2px solid #ffb800 !important;
        color: #ffb800 !important;
        box-shadow: 
            3px 0 0 0 #664400, 
            -3px 0 0 0 #664400, 
            0 3px 0 0 #664400, 
            0 -3px 0 0 #664400, 
            0 0 20px rgba(255, 184, 0, 0.5) !important;
        text-shadow: 0 0 10px #ffb800 !important;
    }

    .risk-low {
        background-color: #140824 !important;
        border: 2px solid #9d4edd !important;
        color: #d8b4fe !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 20px rgba(157, 78, 221, 0.45) !important;
        text-shadow: 0 0 10px #9d4edd !important;
    }

    /* Plain-English Summary & Indicators Card */
    .summary-card {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1.05rem;
        line-height: 1.7;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.5rem;
    }

    .indicators-card {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.5rem;
    }

    .indicator-row {
        padding: 0.75rem 0;
        border-bottom: 1px solid #3c096c;
        color: #e9d5ff !important;
        font-size: 1rem;
    }

    .indicator-row:last-child {
        border-bottom: none;
    }

    .indicator-label {
        font-weight: 700;
        color: #d8b4fe !important;
        text-shadow: 0 0 6px rgba(157, 78, 221, 0.4);
    }

    .defanged-pill {
        background-color: #08040f !important;
        color: #d8b4fe !important;
        font-family: 'Share Tech Mono', monospace;
        padding: 4px 8px;
        border-radius: 0px;
        border: 1px solid #9d4edd !important;
        font-size: 0.95rem;
        box-shadow: 1px 1px 0px #5a189a;
    }

    .defanged-reason {
        color: #a370f7 !important;
        font-size: 0.9rem;
        margin-top: 0.35rem;
        margin-left: 1rem;
    }

    /* Action Checklist */
    .action-item-do {
        background-color: #1a0b2e !important;
        color: #e9d5ff !important;
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 2px 2px 0px #5a189a, 0 0 8px rgba(157, 78, 221, 0.3) !important;
        padding: 0.9rem 1.15rem;
        margin-bottom: 0.75rem;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1rem;
        line-height: 1.5;
    }

    .action-item-do b {
        color: #d8b4fe !important;
    }

    .action-item-dont {
        background-color: #20050d !important;
        color: #e9d5ff !important;
        border: 2px solid #ff2a6d !important;
        border-radius: 0px !important;
        box-shadow: 2px 2px 0px #800020, 0 0 8px rgba(255, 42, 109, 0.25) !important;
        padding: 0.9rem 1.15rem;
        margin-bottom: 0.75rem;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1rem;
        line-height: 1.5;
    }

    .action-item-dont b {
        color: #ff2a6d !important;
    }

    /* Forensic Keyword Highlighter & Monospace Box */
    .forensic-box {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        font-size: 1rem;
        line-height: 1.7;
        padding: 1.25rem;
        overflow-x: auto;
        margin-bottom: 1.5rem;
    }

    .legend-bar {
        display: flex;
        gap: 1.25rem;
        margin-bottom: 0.75rem;
        font-size: 0.85rem;
        flex-wrap: wrap;
        color: #e9d5ff;
        font-family: 'Share Tech Mono', monospace;
    }

    .chip-urgency {
        background: #20050d !important;
        border: 1px solid #ff2a6d !important;
        color: #ff2a6d !important;
        padding: 2px 6px;
        border-radius: 0px;
        font-family: 'Share Tech Mono', monospace;
        font-weight: 700;
        text-shadow: 0 0 6px #ff2a6d;
    }

    .chip-sensitive {
        background: #211500 !important;
        border: 1px solid #ffb800 !important;
        color: #ffb800 !important;
        padding: 2px 6px;
        border-radius: 0px;
        font-family: 'Share Tech Mono', monospace;
        font-weight: 700;
        text-shadow: 0 0 6px #ffb800;
    }

    .chip-url {
        background: #1a0b2e !important;
        border: 1px solid #9d4edd !important;
        color: #d8b4fe !important;
        padding: 2px 6px;
        border-radius: 0px;
        font-family: 'Share Tech Mono', monospace;
        font-weight: 700;
        text-shadow: 0 0 6px #9d4edd;
    }

    .disclaimer-card {
        color: #a370f7 !important;
        font-family: 'Share Tech Mono', monospace;
        font-size: 0.85rem;
        margin-top: 1.5rem;
        border-top: 1px solid #5a189a;
        padding-top: 0.75rem;
    }

    /* Static Heuristics Engine Cards & Badges */
    .heuristics-box {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.5rem;
    }

    .heur-badges-container {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-bottom: 1.1rem;
    }

    .badge-heur-high {
        background-color: #20050d !important;
        color: #ff2a6d !important;
        border: 1px solid #ff2a6d !important;
        padding: 4px 10px;
        border-radius: 0px;
        font-family: 'Press Start 2P', monospace;
        font-size: 0.65rem;
        letter-spacing: 0.5px;
        box-shadow: 2px 2px 0px #800020;
    }

    .badge-heur-med {
        background-color: #211500 !important;
        color: #ffb800 !important;
        border: 1px solid #ffb800 !important;
        padding: 4px 10px;
        border-radius: 0px;
        font-family: 'Press Start 2P', monospace;
        font-size: 0.65rem;
        letter-spacing: 0.5px;
        box-shadow: 2px 2px 0px #664400;
    }

    .badge-heur-clean {
        background-color: #1a0b2e !important;
        color: #d8b4fe !important;
        border: 1px solid #9d4edd !important;
        padding: 4px 10px;
        border-radius: 0px;
        font-family: 'Press Start 2P', monospace;
        font-size: 0.65rem;
        letter-spacing: 0.5px;
        box-shadow: 2px 2px 0px #5a189a;
    }

    .heur-url-card {
        background-color: #08040f;
        border: 1px solid #7209b7;
        border-radius: 0px;
        padding: 0.85rem 1rem;
        margin-bottom: 0.75rem;
        box-shadow: 2px 2px 0px #5a189a;
    }

    /* Repeat Offender Recidivism Alert Banner */
    .repeat-banner {
        background-color: #1c1300 !important;
        border: 2px solid #ffb800 !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #664400, 
            -3px 0 0 0 #664400, 
            0 3px 0 0 #664400, 
            0 -3px 0 0 #664400, 
            0 0 16px rgba(255, 184, 0, 0.4) !important;
        color: #ffe680 !important;
        padding: 1.15rem 1.35rem;
        margin-bottom: 1.4rem;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* Family Emergency & Account Takeover Alert */
    .alert-box-family {
        background-color: #20050d !important;
        border: 2px solid #ff2a6d !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #800020, 
            -3px 0 0 0 #800020, 
            0 3px 0 0 #800020, 
            0 -3px 0 0 #800020, 
            0 0 16px rgba(255, 42, 109, 0.4) !important;
        color: #ffb3c6 !important;
        padding: 1.15rem 1.35rem;
        margin-bottom: 1.25rem;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* E-Commerce Predatory Discount Alert */
    .alert-box-discount {
        background-color: #1c1300 !important;
        border: 2px solid #ffb800 !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #664400, 
            -3px 0 0 0 #664400, 
            0 3px 0 0 #664400, 
            0 -3px 0 0 #664400, 
            0 0 16px rgba(255, 184, 0, 0.4) !important;
        color: #ffe680 !important;
        padding: 1.15rem 1.35rem;
        margin-bottom: 1.25rem;
        font-family: 'Share Tech Mono', monospace !important;
    }

    /* Honeypot & Counter-Probe Cards */
    .probe-card {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 14px rgba(157, 78, 221, 0.3) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.25rem;
    }

    .probe-title {
        font-family: 'Press Start 2P', monospace !important;
        font-size: 0.8rem !important;
        color: #d8b4fe !important;
        margin-bottom: 0.5rem;
        text-shadow: 0 0 8px rgba(157, 78, 221, 0.5);
    }

    .probe-strategy {
        color: #c77dff;
        font-size: 0.92rem;
        margin-bottom: 0.75rem;
    }

    .probe-copy-box {
        background-color: #08040f;
        border: 1px solid #7209b7;
        border-radius: 0px;
        padding: 0.85rem 1rem;
        font-family: 'Share Tech Mono', monospace;
        color: #d8b4fe;
        font-size: 0.98rem;
        line-height: 1.6;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.5);
    }

    /* File Uploader Section */
    [data-testid="stFileUploader"] section {
        border: 2px dashed #9d4edd !important;
        border-radius: 0px !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 12px rgba(157, 78, 221, 0.2) !important;
    }

    [data-testid="stFileUploader"] section:hover {
        border-color: #b5179e !important;
        box-shadow: 0 0 16px rgba(181, 23, 158, 0.35) !important;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        border: 2px solid #5a189a !important;
        border-radius: 0px !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        box-shadow: 2px 2px 0px #3c096c !important;
    }

    [data-testid="stExpander"] summary {
        font-family: 'Share Tech Mono', monospace !important;
        color: #d8b4fe !important;
    }

    /* Alerts and Warnings */
    div[data-testid="stAlert"] {
        border-radius: 0px !important;
        border: 2px solid #9d4edd !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 12px rgba(157, 78, 221, 0.25) !important;
    }

    /* Auth Terminal Box */
    .auth-terminal-card {
        border: 2px solid #9d4edd !important;
        border-radius: 0px !important;
        box-shadow: 
            3px 0 0 0 #5a189a, 
            -3px 0 0 0 #5a189a, 
            0 3px 0 0 #5a189a, 
            0 -3px 0 0 #5a189a, 
            0 0 20px rgba(157, 78, 221, 0.4) !important;
        background-color: #12091f !important;
        color: #e9d5ff !important;
        font-family: 'Share Tech Mono', monospace !important;
        padding: 1.75rem 2rem;
        margin: 1.5rem auto;
        max-width: 680px;
    }

    /* Tactical HUD Scrollbars */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #08040f;
    }
    ::-webkit-scrollbar-thumb {
        background: #5a189a;
        border: 1px solid #9d4edd;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #9d4edd;
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

if "input_text" not in st.session_state:
    st.session_state["input_text"] = ""

if "current_report" not in st.session_state:
    st.session_state["current_report"] = None

if "current_input" not in st.session_state:
    st.session_state["current_input"] = ""

if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

if "uploader_key" not in st.session_state:
    st.session_state["uploader_key"] = 0

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
    st.session_state["uploader_key"] = st.session_state.get("uploader_key", 0) + 1


def handle_file_upload():
    current_key = f"file_uploader_{st.session_state.get('uploader_key', 0)}"
    uploaded_file = st.session_state.get(current_key)
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
# AUTHENTICATION GATEWAY: Retro Pixel Auth Terminal
# ==============================================================================
if not (st.session_state.get("authenticated", False) or st.session_state.get("is_guest", False)):
    st.markdown(
        """
        <div class="main-header" style="max-width: 680px; margin: 2rem auto 1.5rem auto;">
            <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #b5179e; margin-bottom: 0.65rem; letter-spacing: 2px;">
                [ RESTRICTED ACCESS // SOC PROTOCOL GATEWAY ]
            </div>
            <div class="main-title">🛡️ CYBER GUARDIAN</div>
            <div class="main-subtitle">⚡ Operator Authentication &amp; Incognito Terminal</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    auth_col1, auth_col2, auth_col3 = st.columns([1, 6, 1])
    with auth_col2:
        tab_login, tab_register, tab_guest = st.tabs([
            "🔑 Log In",
            "📝 Create Account",
            "👻 Use as Guest (Incognito)",
        ])

        with tab_login:
            st.markdown(
                """
                <div style="margin-bottom: 1rem; color: #d8b4fe; font-size: 0.95rem;">
                    Enter your Operator credentials to access your persistent threat intelligence memory.
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.form("login_form", clear_on_submit=False):
                login_user = st.text_input("Operator Handle / Username:", placeholder="e.g. analyst_01")
                login_pass = st.text_input("Access Cipher / Password:", type="password", placeholder="Enter cipher")
                login_submit = st.form_submit_button("Authenticate Operator", use_container_width=True)

                if login_submit:
                    if not login_user.strip() or not login_pass.strip():
                        st.error("Operator handle and cipher cannot be empty.")
                    elif verify_user(login_user.strip(), login_pass.strip()):
                        st.session_state["authenticated"] = True
                        st.session_state["is_guest"] = False
                        st.session_state["username"] = login_user.strip().lower()
                        st.success(f"ACCESS GRANTED: Welcome, Operator {st.session_state['username']}")
                        st.rerun()
                    else:
                        st.error("ACCESS DENIED: Invalid Operator Handle or Password.")

        with tab_register:
            st.markdown(
                """
                <div style="margin-bottom: 1rem; color: #d8b4fe; font-size: 0.95rem;">
                    Register a new SOC analyst identity to persist and track threat indicators across sessions.
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.form("register_form", clear_on_submit=False):
                reg_user = st.text_input("Choose Operator Handle:", placeholder="e.g. sentry_lead")
                reg_pass = st.text_input("Create Access Cipher:", type="password", placeholder="At least 4 characters")
                reg_pass_conf = st.text_input("Confirm Access Cipher:", type="password", placeholder="Re-type cipher")
                reg_submit = st.form_submit_button("Create Operator Account", use_container_width=True)

                if reg_submit:
                    if not reg_user.strip() or not reg_pass.strip():
                        st.error("Operator handle and cipher cannot be empty.")
                    elif reg_pass != reg_pass_conf:
                        st.error("Access ciphers do not match.")
                    elif len(reg_pass) < 4:
                        st.error("Access cipher must be at least 4 characters.")
                    else:
                        created = create_user(reg_user.strip(), reg_pass.strip())
                        if created:
                            st.session_state["authenticated"] = True
                            st.session_state["is_guest"] = False
                            st.session_state["username"] = reg_user.strip().lower()
                            st.success(f"ACCOUNT INITIALIZED: Welcome, Operator {st.session_state['username']}")
                            st.rerun()
                        else:
                            st.error("Handle is already registered in SQLite memory. Please choose another.")

        with tab_guest:
            st.markdown(
                """
                <div class="summary-card" style="margin-top: 0.5rem; margin-bottom: 1.25rem;">
                    <div style="font-family: 'Press Start 2P', monospace; font-size: 0.72rem; color: #d8b4fe; margin-bottom: 0.5rem;">
                        👻 INCOGNITO GUEST MODE
                    </div>
                    <div style="font-size: 0.95rem; line-height: 1.6; color: #e9d5ff;">
                        Operate Cyber Guardian in transient memory.
                        <br><br>
                        • <b>Zero DB Persistence:</b> No scans, extracted links, or sender indicators are logged to SQLite.
                        <br>
                        • <b>Recidivism Disabled:</b> Repeat offender detection and historical alerts are silenced.
                        <br>
                        • <b>Full Real-time Analysis:</b> All heuristic and LLM multi-agent scans function without restriction.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("Enter as Guest (Incognito)", use_container_width=True):
                st.session_state["authenticated"] = False
                st.session_state["is_guest"] = True
                st.session_state["username"] = None
                st.rerun()

    # Block rendering of protected console until access is authenticated
    st.stop()


# ==============================================================================
# SIDEBAR: Operator Badge & Session Controls
# ==============================================================================
if st.session_state.get("authenticated", False):
    st.sidebar.markdown(
        f"""
        <div style="background-color: #1e0e33; border: 2px solid #9d4edd; box-shadow: 2px 2px 0 #5a189a; padding: 0.85rem; margin-bottom: 1.2rem;">
            <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #d8b4fe; letter-spacing: 0.5px;">
                👾 OPERATOR: {st.session_state.get('username', 'UNKNOWN')}
            </div>
            <div style="font-size: 0.85rem; color: #c77dff; margin-top: 0.4rem;">
                SOC Analyst Session • Persistent Memory
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
elif st.session_state.get("is_guest", False):
    st.sidebar.markdown(
        """
        <div style="background-color: #1e0e33; border: 2px solid #b5179e; box-shadow: 2px 2px 0 #5a189a; padding: 0.85rem; margin-bottom: 1.2rem;">
            <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #ff99c8; letter-spacing: 0.5px;">
                👻 GUEST MODE (Incognito - History &amp; Recidivism Disabled)
            </div>
            <div style="font-size: 0.85rem; color: #d8b4fe; margin-top: 0.4rem;">
                Transient Mode • Zero SQLite Logging
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def handle_logout():
    st.session_state["authenticated"] = False
    st.session_state["is_guest"] = False
    st.session_state["username"] = None
    st.session_state["scan_history"] = []
    st.session_state["current_report"] = None
    st.session_state["input_text"] = ""
    st.session_state["current_input"] = ""


st.sidebar.button("🚪 Logout / Exit Session", on_click=handle_logout, use_container_width=True)
st.sidebar.write("---")

st.sidebar.title("📜 Scan History")

history_list = st.session_state["scan_history"]

if not history_list:
    st.sidebar.caption("No scans performed yet in this session.")
else:
    st.sidebar.button("🗑️ Clear History", on_click=clear_scan_history, use_container_width=True)
    st.sidebar.write("")

    # Display in reverse chronological order (newest first)
    for idx, item in enumerate(reversed(history_list)):
        risk = item["risk"]
        if risk == "HIGH":
            risk_icon = "🚨 HIGH"
        elif risk == "MEDIUM":
            risk_icon = "⚠️ MEDIUM"
        else:
            risk_icon = "✅ LOW"

        expander_title = f"{risk_icon} [{item['timestamp']}] {item['preview']}"
        with st.sidebar.expander(expander_title):
            st.markdown(f"**Threat Level:** `{risk}`")
            st.markdown(f"**Timestamp:** `{item['timestamp']}`")
            st.markdown(f"**Input Snippet:**\n*{item['preview']}*")
            st.button(
                "🔄 Reload into View",
                key=f"reload_btn_{len(history_list) - 1 - idx}",
                on_click=reload_scan,
                args=(item,),
                use_container_width=True,
            )

# SQLite Recidivism Database Viewer
st.sidebar.write("---")
st.sidebar.title("🗄️ Threat Recidivism DB")
if st.session_state.get("is_guest", False):
    st.sidebar.caption("🔒 Database persistence is disabled in Incognito Guest Mode.")
else:
    current_user = st.session_state.get("username")
    db_records = get_all_records(limit=10, username=current_user)
    if not db_records:
        st.sidebar.caption(f"No repeat threats logged yet for Operator {current_user}.")
    else:
        st.sidebar.caption(f"Tracking {len(db_records)} historical threat indicators for {current_user}.")
        with st.sidebar.expander("🔍 Recent Tracked Offenders"):
            for rec in db_records:
                st.markdown(f"• **`{rec['sender_handle']}`**")
                st.caption(f"Target: {rec['impersonated_target']} | Score: `{rec['risk_score']}` | {rec['threat_type']}")


# ==============================================================================
# MAIN PAGE: Scanner Interface
# ==============================================================================
st.markdown(
    """
    <div class="main-header">
        <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #b5179e; margin-bottom: 0.65rem; letter-spacing: 2px;">
            [ TACTICAL HUD // SOC THREAT DEFENSE CONSOLE ]
        </div>
        <div class="main-title">🛡️ CYBER GUARDIAN</div>
        <div class="main-subtitle">⚡ Two-Agent Threat Detection &amp; Security Response Console</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Preset buttons
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
uploader_key = f"file_uploader_{st.session_state.get('uploader_key', 0)}"
st.file_uploader(
    "📁 Upload Suspicious Email or Message File (.txt, .eml):",
    type=["txt", "eml"],
    key=uploader_key,
    on_change=handle_file_upload,
    help="Upload an .eml email file (headers and body will be safely extracted) or a .txt message export to analyze.",
)

# Input text area directly bound to key="input_text"
user_input = st.text_area(
    "Suspicious Message, Email, or Link:",
    height=140,
    placeholder="Paste suspicious email text, SMS message, or link here to inspect...",
    key="input_text",
)

scan_clicked = st.button("🔍 Scan for Threats", type="primary", use_container_width=True)


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


# Scan execution
if scan_clicked:
    if not user_input.strip():
        st.warning("Please paste or type a message before scanning.")
    else:
        with st.spinner("Analyzing message with Security Analyzer & Safety Advisor..."):
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
                        "👉 **Recommendation:** Please wait 5–10 seconds and click **Scan for Threats** again."
                    )
                elif "429" in err_str or "quota" in err_str.lower() or "resource_exhausted" in err_str.lower():
                    st.warning(
                        "⚠️ **Rate Limit Exceeded (429)**\n\n"
                        "API request quota is temporarily exhausted. Please wait a moment before trying again."
                    )
                elif "api_key" in err_str.lower():
                    st.warning(
                        "⚠️ **API Key Configuration Error**\n\n"
                        "Please verify that your `GEMINI_API_KEY` is properly configured in your `.env` file."
                    )
                else:
                    st.warning(
                        f"⚠️ **Security Scan Service Notice**\n\n"
                        f"{err_str}\n\n"
                        "Please try scanning again in a few moments."
                    )


# ==============================================================================
# ANALYST DASHBOARD: Results Rendering (Header Metrics + 3 Tabs)
# ==============================================================================
if st.session_state.get("current_report") is not None:
    report: ThreatReport = st.session_state["current_report"]
    signals = report.threat_signals
    raw_text = st.session_state.get("current_input", "")

    # Calculate numerical threat score (0-100)
    if report.overall_risk == "HIGH":
        threat_score = 95
        score_delta = "High Risk"
        delta_color = "inverse"
    elif report.overall_risk == "MEDIUM":
        threat_score = 55
        score_delta = "Medium Risk"
        delta_color = "inverse"
    else:
        threat_score = 10
        score_delta = "Low Risk"
        delta_color = "normal"

    st.write("---")

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
                <div class="repeat-banner">
                    <div style="font-size: 1.15rem; font-weight: 800; margin-bottom: 0.35rem;">
                        {repeat_data['warning_badge']}
                    </div>
                    <div style="font-size: 0.95rem; line-height: 1.5;">
                        This sender handle or domain infrastructure was previously logged in <b>{repeat_data['repeat_count']}</b> prior scan(s) in your persistent threat memory.
                        <br><b>Matched Tracked Markers:</b> <code>{matched_str}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    discount_data = analyze_ecommerce_discount(raw_text, " ".join(links))

    # 1. Header Metrics (4 Columns)
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(
            label="Threat Score",
            value=f"{threat_score}/100",
            delta=score_delta,
            delta_color=delta_color,
        )
    with m2:
        urgency_val = "DETECTED" if signals.urgency_detected else "NONE"
        st.metric(
            label="Urgency Pressure",
            value=urgency_val,
            delta="Artificial Deadline" if signals.urgency_detected else "Standard",
            delta_color="inverse" if signals.urgency_detected else "off",
        )
    with m3:
        target_name = (
            signals.impersonation_target
            if signals.impersonation_target and signals.impersonation_target.lower() != "none"
            else "NONE"
        )
        st.metric(
            label="Impersonation",
            value=target_name,
            delta="Target Identified" if target_name != "NONE" else "No Spoofing",
            delta_color="inverse" if target_name != "NONE" else "off",
        )
    with m4:
        creds_val = "YES" if signals.sensitive_info_requested else "NO"
        st.metric(
            label="Credentials Requested",
            value=creds_val,
            delta=f"{len(signals.sensitive_info_details)} targets" if signals.sensitive_info_requested else "Secure",
            delta_color="inverse" if signals.sensitive_info_requested else "normal",
        )

    st.write("")

    # 2. Interactive Message Forensic Highlighter
    st.markdown("### 🔍 Message Forensic Highlighter")
    highlighted_html = highlight_evidence(raw_text, signals)
    st.markdown(
        f"""
        <div class="legend-bar">
            <span><span class="chip-urgency">■</span> <b>Urgency &amp; Panic Driver</b></span>
            <span><span class="chip-sensitive">■</span> <b>Sensitive Data / Credentials</b></span>
            <span><span class="chip-url">■</span> <b>Suspicious / Defanged Link</b></span>
        </div>
        <div class="forensic-box">
            <div style="font-weight: 700; color: #94a3b8; margin-bottom: 0.65rem; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.75px;">
                [Analyzed Raw Evidence]
            </div>
            {highlighted_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")

    # 3. Four Analyst Tabs
    tab_advice, tab_technical, tab_incident, tab_honeypot = st.tabs([
        "🛡️ Plain-English Advice",
        "🔬 Technical Breakdown",
        "✉️ Incident Response Email",
        "🕵️ Honeypot & Reverse-Interrogation",
    ])

    # --------------------------------------------------------------------------
    # TAB 1: Plain-English Advice
    # --------------------------------------------------------------------------
    with tab_advice:
        risk = report.overall_risk
        if risk == "HIGH":
            badge_html = '<div class="risk-card risk-high">🚨 OVERALL THREAT LEVEL: HIGH (DANGEROUS)</div>'
        elif risk == "MEDIUM":
            badge_html = '<div class="risk-card risk-medium">⚠️ OVERALL THREAT LEVEL: MEDIUM (SUSPICIOUS)</div>'
        else:
            badge_html = '<div class="risk-card risk-low">✅ OVERALL THREAT LEVEL: LOW (NO THREATS DETECTED)</div>'

        st.markdown(badge_html, unsafe_allow_html=True)

        # Family Emergency Alert Banner
        if getattr(signals, "family_emergency_flag", False):
            st.markdown(
                f"""
                <div class="alert-box-family">
                    <div style="font-size: 1.15rem; font-weight: 800; margin-bottom: 0.35rem;">
                        🚨 CRITICAL WARNING: Hacked Contact / Family Emergency Impersonation
                    </div>
                    <div style="line-height: 1.6;">
                        The sender is masquerading as a child, parent, or close friend in an emergency ({signals.family_emergency_details or 'broken phone, stranded, or medical crisis'}).
                        <br><b>DO NOT send money, wire transfers, or gift cards.</b>
                        Scammers often compromise real accounts or claim their phone broke to prevent voice calls.
                        <br>👉 <b>Mandatory Action:</b> Call your relative directly on their known, saved voice number or ask a shared family secret question only they know before responding.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Predatory E-Commerce Discount Alert Banner
        if discount_data.get("is_fake_discount_likely", False):
            st.markdown(
                f"""
                <div class="alert-box-discount">
                    <div style="font-size: 1.15rem; font-weight: 800; margin-bottom: 0.35rem;">
                        🛍️ PREDATORY DISCOUNT / SCAM STOREFRONT DETECTED
                    </div>
                    <div style="line-height: 1.6;">
                        {discount_data['risk_summary']}
                        <br><b>Heuristic Notice:</b> Extreme discounts (> 70%) on brand electronics or luxury items combined with artificial checkout countdowns are designed to harvest credit cards.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.subheader("💡 What This Means (Plain English)")
        st.markdown(f'<div class="summary-card">{report.summary}</div>', unsafe_allow_html=True)

        st.subheader("📋 Recommended Action Checklist")
        for act in report.recommended_actions:
            is_dont = act.upper().startswith("DO NOT") or act.upper().startswith("DON'T") or "NEVER" in act.upper()
            if is_dont:
                st.markdown(f'<div class="action-item-dont">❌ <b>{act}</b></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="action-item-do">✅ <b>{act}</b></div>', unsafe_allow_html=True)

        st.write("")
        markdown_data = build_markdown_report(report, raw_text)
        st.download_button(
            label="📥 Download Safety Report (.md)",
            data=markdown_data,
            file_name="cyber_guardian_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    # --------------------------------------------------------------------------
    # --------------------------------------------------------------------------
    # TAB 2: Technical Breakdown
    # --------------------------------------------------------------------------
    with tab_technical:
        st.subheader("⚡ Pre-LLM Static Heuristics Engine")
        st.caption("Deterministic structural inspection executed locally prior to AI reasoning (zero external network probing).")

        heuristics_raw = signals.heuristics_results or []
        heuristics = [
            h.model_dump() if hasattr(h, "model_dump") else h
            for h in heuristics_raw
        ]
        if heuristics:
            has_raw_ip = any(h.get("is_ip_address") for h in heuristics)
            has_high_risk_tld = any(h.get("is_high_risk_tld") for h in heuristics)
            typosquat_targets = list(dict.fromkeys([h.get("typosquat_target") for h in heuristics if h.get("typosquat_target")]))

            # Status Badges
            badge_ip = (
                '<span class="badge-heur-high">🔴 RAW IP DETECTED</span>'
                if has_raw_ip
                else '<span class="badge-heur-clean">🟢 NO RAW IP</span>'
            )
            badge_tld = (
                '<span class="badge-heur-med">🟠 HIGH-RISK TLD DETECTED</span>'
                if has_high_risk_tld
                else '<span class="badge-heur-clean">🟢 STANDARD TLD</span>'
            )
            badge_typo = (
                f'<span class="badge-heur-high">🚨 TYPOSQUAT TARGET: {", ".join(typosquat_targets)}</span>'
                if typosquat_targets
                else '<span class="badge-heur-clean">🟢 NO TYPOSQUATTING LOOKALIKES</span>'
            )

            heur_html = [
                '<div class="heuristics-box">',
                f'<div class="heur-badges-container">{badge_ip}{badge_tld}{badge_typo}</div>',
            ]

            for h in heuristics:
                sev = h.get("severity", "LOW")
                sev_badge = (
                    '<span class="badge-heur-high">HIGH SEVERITY</span>'
                    if sev == "HIGH"
                    else ('<span class="badge-heur-med">MEDIUM SEVERITY</span>' if sev == "MEDIUM" else '<span class="badge-heur-clean">LOW SEVERITY</span>')
                )
                findings_items = "".join([f"<li>{f}</li>" for f in h.get("findings", [])])
                heur_html.append(
                    f'<div class="heur-url-card">'
                    f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">'
                    f'<span class="defanged-pill">{h.get("defanged_url", "")}</span>'
                    f'{sev_badge}'
                    f'</div>'
                    f'<ul style="margin-left: 1.25rem; margin-top: 0.35rem; font-size: 0.9rem; color: #cbd5e1;">{findings_items}</ul>'
                    f'</div>'
                )

            heur_html.append('</div>')
            st.markdown("".join(heur_html), unsafe_allow_html=True)
        else:
            st.info("ℹ️ No external links or IP addresses were detected for static heuristic inspection.")

        st.write("")
        st.subheader("🔬 AI Security Analyzer Indicators & Red Flags")

        indicators_html = ['<div class="indicators-card">']

        if signals.impersonation_target and signals.impersonation_target.lower() != "none":
            indicators_html.append(
                f'<div class="indicator-row"><span class="indicator-label">Impersonation Target:</span> '
                f'<b>{signals.impersonation_target}</b></div>'
            )

        if signals.urgency_detected:
            urgency_txt = f" - {signals.urgency_explanation}" if signals.urgency_explanation else ""
            indicators_html.append(
                f'<div class="indicator-row"><span class="indicator-label">Urgency & Panic Driver:</span> '
                f'Artificial pressure detected{urgency_txt}</div>'
            )

        if signals.sensitive_info_requested:
            cred_list = ", ".join(signals.sensitive_info_details) if signals.sensitive_info_details else "Credentials"
            indicators_html.append(
                f'<div class="indicator-row"><span class="indicator-label">Sensitive Credentials Solicited:</span> '
                f'<b>{cred_list}</b></div>'
            )

        if getattr(signals, "family_emergency_flag", False):
            indicators_html.append(
                f'<div class="indicator-row"><span class="indicator-label">Family Emergency Impersonation:</span> '
                f'<b style="color: #f87171;">DETECTED</b> ({signals.family_emergency_details or "Relative distress driver"})</div>'
            )

        if getattr(signals, "is_account_takeover_likely", False):
            indicators_html.append(
                '<div class="indicator-row"><span class="indicator-label">Account Takeover / Contact Hijack:</span> '
                '<b style="color: #f87171;">HIGH PROBABILITY</b></div>'
            )

        if discount_data.get("is_fake_discount_likely", False):
            rate_str = f"{discount_data['discount_rate']:.0f}%" if discount_data.get("discount_rate") else "Steep"
            target_brand = discount_data.get("luxury_brand_detected", "Luxury item").capitalize()
            indicators_html.append(
                f'<div class="indicator-row"><span class="indicator-label">E-Commerce Scam Storefront:</span> '
                f'<b style="color: #fde047;">FLAGGED ({rate_str} off {target_brand})</b> - {discount_data["risk_summary"]}</div>'
            )

        if signals.suspicious_urls:
            indicators_html.append(
                '<div class="indicator-row"><span class="indicator-label">Suspicious Links (Defanged for Safety):</span></div>'
            )
            for link in signals.suspicious_urls:
                indicators_html.append(
                    f'<div style="margin-left: 1rem; margin-top: 0.35rem; margin-bottom: 0.5rem;">'
                    f'<span class="defanged-pill">{link.defanged_url}</span>'
                    f'<div class="defanged-reason">Reason: {link.risk_reason}</div>'
                    f'</div>'
                )

        if not signals.urgency_detected and not signals.sensitive_info_requested and not signals.suspicious_urls:
            indicators_html.append(
                '<div class="indicator-row">No artificial urgency, sensitive data harvesting, or suspicious links were detected.</div>'
            )

        indicators_html.append('</div>')
        st.markdown("".join(indicators_html), unsafe_allow_html=True)

        if signals.key_findings:
            st.markdown("#### Key Technical Findings:")
            for k in signals.key_findings:
                st.markdown(f"- {k}")

        with st.expander("📄 View Raw Pydantic Threat Signals (JSON)"):
            st.json(signals.model_dump())

    # --------------------------------------------------------------------------
    # TAB 3: Incident Response Email
    # --------------------------------------------------------------------------
    with tab_incident:
        st.subheader("✉️ Pre-filled Incident Response Escalation Draft")
        st.caption(
            "Copy and forward this prepared escalation email directly to your internal IT Security department "
            "or the anti-abuse team of the affected provider."
        )

        incident_email = build_incident_email(report, raw_text)

        st.text_area(
            "Draft Email (Ready to Copy):",
            value=incident_email,
            height=300,
            key="incident_email_text",
        )

        col_dl1, col_dl2, col_dl3 = st.columns(3)
        with col_dl1:
            st.download_button(
                label="📥 Download Draft Email (.txt)",
                data=incident_email,
                file_name="incident_escalation_email.txt",
                mime="text/plain",
                use_container_width=True,
            )
        with col_dl2:
            stix_bundle = generate_stix_threat_bundle(report, signals.heuristics_results, raw_text)
            stix_json_str = json.dumps(stix_bundle, indent=2)
            st.download_button(
                label="📥 Download STIX 2.1 Threat Intel (.json)",
                data=stix_json_str,
                file_name="cyber_guardian_stix21_bundle.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_dl3:
            html_report = generate_executive_html_report(report, signals.heuristics_results, raw_text)
            st.download_button(
                label="📥 Download Executive Forensic Report (.html)",
                data=html_report,
                file_name="cyber_guardian_executive_report.html",
                mime="text/html",
                use_container_width=True,
            )

    # --------------------------------------------------------------------------
    # TAB 4: Honeypot & Reverse-Interrogation
    # --------------------------------------------------------------------------
    with tab_honeypot:
        st.markdown("### 🕵️ Reverse-Interrogation & Controlled Honeypot Probing")
        st.write(
            "Safely interact with an active attacker to extract forensic markers (real IPs, banking rails, "
            "corporate registry) without tipping them off or compromising sensitive assets."
        )

        honeypot_input = st.text_area(
            "Ongoing Conversation / Latest Scammer Message:",
            value=raw_text,
            height=120,
            help="Paste the ongoing dialogue or latest message from the suspected scammer.",
            key="honeypot_dialogue_input",
        )

        col_hp_btn, col_hp_info = st.columns([1, 2])
        with col_hp_btn:
            generate_probes_btn = st.button("🎯 Generate Tactical Counter-Probes", use_container_width=True)

        if generate_probes_btn or "honeypot_data" in st.session_state:
            if generate_probes_btn or "honeypot_data" not in st.session_state:
                with st.spinner("Analyzing scammer psychological playbook & crafting counter-probes..."):
                    probe_results = generate_counter_probe(
                        attacker_last_message=honeypot_input,
                        client=st.session_state.get("gemini_client"),
                    )
                    st.session_state["honeypot_data"] = probe_results
            else:
                probe_results = st.session_state["honeypot_data"]

            st.write("")
            hp_col1, hp_col2 = st.columns(2)
            with hp_col1:
                st.markdown(
                    f"""
                    <div style="background-color: #12091f; border: 2px solid #9d4edd; box-shadow: 3px 0 0 0 #5a189a, -3px 0 0 0 #5a189a, 0 3px 0 0 #5a189a, 0 -3px 0 0 #5a189a, 0 0 10px rgba(157, 78, 221, 0.25); padding: 1rem 1.2rem; margin-bottom: 1rem;">
                        <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #d8b4fe; text-transform: uppercase; letter-spacing: 0.5px;">🎯 Scammer's Immediate Objective</div>
                        <div style="font-family: 'Share Tech Mono', monospace; font-size: 1.05rem; color: #ffffff; margin-top: 0.5rem;">{probe_results.get('attacker_objective', 'Harvest credentials / initiate urgent transfer')}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with hp_col2:
                st.markdown(
                    f"""
                    <div style="background-color: #12091f; border: 2px solid #b5179e; box-shadow: 3px 0 0 0 #5a189a, -3px 0 0 0 #5a189a, 0 3px 0 0 #5a189a, 0 -3px 0 0 #5a189a, 0 0 10px rgba(181, 23, 158, 0.25); padding: 1rem 1.2rem; margin-bottom: 1rem;">
                        <div style="font-family: 'Press Start 2P', monospace; font-size: 0.65rem; color: #e9d5ff; text-transform: uppercase; letter-spacing: 0.5px;">🧠 Psychological Playbook</div>
                        <div style="font-family: 'Share Tech Mono', monospace; font-size: 1.05rem; color: #d8b4fe; margin-top: 0.5rem;">{probe_results.get('playbook_analysis', 'Urgency & emotional coercion')}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("#### 🛡️ Copy-Ready Tactical Counter-Replies")
            st.caption("Select one of the safe probes below to copy and paste to the scammer:")

            # Probe 1: Infrastructure Probe
            p1 = probe_results.get("infrastructure_probe", {})
            st.markdown(
                f"""
                <div class="probe-card" style="border: 2px solid #9d4edd !important; box-shadow: 3px 0 0 0 #5a189a, -3px 0 0 0 #5a189a, 0 3px 0 0 #5a189a, 0 -3px 0 0 #5a189a, 0 0 12px rgba(157, 78, 221, 0.25) !important;">
                    <div class="probe-title">🌐 1. {p1.get('name', 'Infrastructure Probe')}</div>
                    <div class="probe-strategy"><b>Forensic Objective:</b> {p1.get('strategy', '')}</div>
                    <div class="probe-copy-box">{p1.get('copy_text', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Probe 2: Stalling / Consistency Check
            p2 = probe_results.get("consistency_check", {})
            st.markdown(
                f"""
                <div class="probe-card" style="border: 2px solid #ffb800 !important; box-shadow: 3px 0 0 0 #664400, -3px 0 0 0 #664400, 0 3px 0 0 #664400, 0 -3px 0 0 #664400, 0 0 12px rgba(255, 184, 0, 0.25) !important;">
                    <div class="probe-title" style="color: #ffb800 !important; text-shadow: 0 0 8px rgba(255, 184, 0, 0.5) !important;">⏳ 2. {p2.get('name', 'Stalling / Consistency Check')}</div>
                    <div class="probe-strategy"><b>Forensic Objective:</b> {p2.get('strategy', '')}</div>
                    <div class="probe-copy-box" style="color: #ffe680 !important; border-color: #ffb800 !important;">{p2.get('copy_text', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Probe 3: Fake Compliance
            p3 = probe_results.get("fake_compliance", {})
            st.markdown(
                f"""
                <div class="probe-card" style="border: 2px solid #ff2a6d !important; box-shadow: 3px 0 0 0 #800020, -3px 0 0 0 #800020, 0 3px 0 0 #800020, 0 -3px 0 0 #800020, 0 0 12px rgba(255, 42, 109, 0.25) !important;">
                    <div class="probe-title" style="color: #ff2a6d !important; text-shadow: 0 0 8px rgba(255, 42, 109, 0.5) !important;">🎭 3. {p3.get('name', 'Fake Compliance / Trap')}</div>
                    <div class="probe-strategy"><b>Forensic Objective:</b> {p3.get('strategy', '')}</div>
                    <div class="probe-copy-box" style="color: #ffb3c6 !important; border-color: #ff2a6d !important;">{p3.get('copy_text', '')}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # Disclaimer footer
    st.markdown(
        f'<div class="disclaimer-card">🛡️ Notice: {report.disclaimer}</div>',
        unsafe_allow_html=True,
    )
