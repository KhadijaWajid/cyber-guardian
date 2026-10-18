import os
import re
import html
import time
import logging
import email
from email import policy
from typing import List, Optional, Any
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
logger = logging.getLogger("cyber_guardian")

# Fallback chain prioritizing active stable Gemini models
DEFAULT_MODEL_CHAIN: List[str] = [
    "gemini-2.5-flash",
    "gemini-3.8-flash",
]

__all__ = [
    "defang_url",
    "parse_eml_bytes",
    "generate_with_fallback",
    "highlight_evidence",
    "is_rate_limit_error",
    "is_retryable_error",
    "is_not_found_error",
    "get_gemini_client",
    "DEFAULT_MODEL_CHAIN",
]


def defang_url(url: str) -> str:
    """
    Defangs a URL or domain so it cannot be accidentally clicked or resolved.
    Replaces http/https with hxxp/hxxps and dots with [.].
    Performs purely static text manipulation with zero network probing.
    """
    if not url:
        return ""
    
    # Replace protocols
    defanged = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)
    
    # Replace dots in host/domain
    # Avoid double defanging if already defanged
    if "[.]" not in defanged:
        defanged = defanged.replace(".", "[.]")
        
    return defanged


def parse_eml_bytes(raw_bytes: bytes) -> str:
    """Parses raw .eml bytes into structured headers and clean text body."""
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        headers = []
        for header_name in ["Subject", "From", "To", "Date", "Reply-To"]:
            val = msg.get(header_name)
            if val:
                headers.append(f"{header_name}: {val}")
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    break
            if not body:
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            body = part.get_content()
                        except Exception:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                        break
        else:
            try:
                body = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                else:
                    body = str(msg.get_payload() or "")
            
        header_block = "\n".join(headers)
        return f"{header_block}\n\n--- Body ---\n{body}".strip()
    except Exception as e:
        return f"[Error parsing .eml file: {e}]\n\nRaw contents:\n" + raw_bytes.decode("utf-8", errors="replace")




def is_rate_limit_error(exc: Exception) -> bool:
    """Detects 429 Rate Limit / Quota Exceeded errors."""
    err_str = str(exc).lower()
    return any(
        term in err_str
        for term in [
            "429",
            "rate limit",
            "resource_exhausted",
            "quota",
        ]
    )


def is_retryable_error(exc: Exception) -> bool:
    """Detects 503 UNAVAILABLE, 429 Rate Limits, or transient server saturation errors."""
    err_str = str(exc).lower()
    return is_rate_limit_error(exc) or any(
        term in err_str
        for term in [
            "503",
            "unavailable",
            "high demand",
            "overloaded",
            "timeout",
            "connection reset",
        ]
    )


def is_not_found_error(exc: Exception) -> bool:
    """Detects 404 NOT_FOUND, model deprecated, retired, or unavailable errors."""
    err_str = str(exc).lower()
    return any(
        term in err_str
        for term in [
            "404",
            "not_found",
            "not found",
            "no longer available",
            "deprecated",
            "unsupported",
            "retired",
        ]
    )


def generate_with_fallback(
    client: genai.Client,
    contents: Any,
    config: types.GenerateContentConfig,
    model_chain: Optional[List[str]] = None,
    backoff_delays: Optional[List[float]] = None,
) -> Any:
    """
    Executes generate_content across a model fallback chain with exponential
    backoff retries on transient errors (503 UNAVAILABLE, 429).
    Automatically swaps GEMINI_API_KEY for GEMINI_API_KEY_BACKUP upon encountering 429 rate limits.
    Cleanly falls forward to the next candidate model upon encountering 404 NOT_FOUND / deprecated models.
    """
    if backoff_delays is None:
        backoff_delays = [2.0, 4.0]

    if not model_chain:
        env_chain = os.getenv("GEMINI_MODEL_CHAIN")
        if env_chain:
            model_chain = [m.strip() for m in env_chain.split(",") if m.strip()]
        else:
            model_chain = list(DEFAULT_MODEL_CHAIN)

    active_client = client
    swapped_to_backup = False
    last_exception = None

    for model in model_chain:
        for attempt in range(len(backoff_delays) + 1):
            try:
                response = active_client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=config,
                )
                return response
            except Exception as e:
                last_exception = e

                # 404 NOT_FOUND / Deprecated model: immediately fall forward to next candidate
                if is_not_found_error(e):
                    logger.warning(
                        "Model '%s' is not found or deprecated (%s). Cleanly falling forward to next model...",
                        model,
                        e,
                    )
                    break

                # Automatic key rotation on 429 Rate Limit
                if is_rate_limit_error(e) and not swapped_to_backup:
                    backup_key = os.getenv("GEMINI_API_KEY_BACKUP")
                    if backup_key:
                        logger.warning(
                            "429 Rate Limit encountered. Automatically swapping GEMINI_API_KEY "
                            "for GEMINI_API_KEY_BACKUP from .env before retrying..."
                        )
                        os.environ["GEMINI_API_KEY"] = backup_key
                        # If client is not a test mock, instantiate new client with backup key
                        if not (hasattr(client, "_is_mock") or type(client).__name__ == "MagicMock"):
                            active_client = genai.Client(api_key=backup_key)
                        swapped_to_backup = True
                        time.sleep(1.0)
                        continue

                # If error is transient (e.g. 503 high demand or 429 rate limit) and retries remain
                if is_retryable_error(e) and attempt < len(backoff_delays):
                    delay = backoff_delays[attempt]
                    logger.warning(
                        "Model '%s' returned transient error: %s. Retrying in %ss (attempt %d/%d)...",
                        model,
                        e,
                        delay,
                        attempt + 1,
                        len(backoff_delays),
                    )
                    time.sleep(delay)
                    continue
                else:
                    # Non-retryable error (e.g., 404 retired model) or retries exhausted for this model
                    logger.warning(
                        "Model '%s' failed (%s). Attempting next model in fallback chain...",
                        model,
                        e,
                    )
                    break

    raise RuntimeError(
        f"All models in fallback chain ({model_chain}) failed. Last error: {last_exception}"
    ) from last_exception


def highlight_evidence(text: str, signals: Any) -> str:
    """
    Safely annotates suspicious tokens in text using non-nested HTML color chips:
    - Urgency phrases: Red/pink pill highlight
    - Sensitive data phrases: Amber pill highlight
    - URLs/links: Cyan pill highlight
    Returns safely escaped HTML suitable for monospace forensic display.
    """
    import html

    if not text:
        return ""

    # Gather URLs to highlight
    urls = set()
    if hasattr(signals, "suspicious_urls"):
        for u in signals.suspicious_urls:
            if getattr(u, "original_url", None):
                urls.add(u.original_url.strip())
            if getattr(u, "defanged_url", None):
                urls.add(u.defanged_url.strip())

    # Detect any additional raw or defanged URLs in text
    for match in re.findall(r"https?://[^\s<>\"']+|hxxps?://[^\s<>\"']+", text):
        urls.add(match.strip())

    # Gather sensitive data keywords
    sensitive_keywords = {
        "password",
        "passwords",
        "username",
        "usernames",
        "otp",
        "6-digit otp",
        "pin",
        "ssn",
        "social security",
        "credit card",
        "cvv",
        "credentials",
        "bank account",
        "routing number",
        "login",
    }
    if hasattr(signals, "sensitive_info_details"):
        for item in signals.sensitive_info_details:
            clean = item.strip().lower()
            if clean and len(clean) > 2:
                sensitive_keywords.add(clean)

    # Gather urgency keywords
    urgency_keywords = {
        "urgent",
        "urgently",
        "immediately",
        "immediate action",
        "within 2 hours",
        "within 24 hours",
        "within 48 hours",
        "locked",
        "frozen",
        "suspended",
        "funds will be frozen",
        "account has been locked",
        "permanently closed",
        "verify your identity",
        "unauthorized activity",
        "suspicious activity",
        "security alert",
        "registrations close",
    }

    parts = []
    if urls:
        url_regex = "|".join(re.escape(u) for u in sorted(urls, key=len, reverse=True))
        parts.append(f"(?P<URL>{url_regex})")

    if sensitive_keywords:
        sens_regex = "|".join(r"\b" + re.escape(w) + r"\b" for w in sorted(sensitive_keywords, key=len, reverse=True))
        parts.append(f"(?P<SENSITIVE>{sens_regex})")

    if urgency_keywords:
        urg_regex = "|".join(r"\b" + re.escape(w) + r"\b" for w in sorted(urgency_keywords, key=len, reverse=True))
        parts.append(f"(?P<URGENCY>{urg_regex})")

    if not parts:
        return html.escape(text).replace("\n", "<br>")

    master_pattern = re.compile("|".join(parts), re.IGNORECASE)

    def replacer(m):
        try:
            group_dict = m.groupdict()
            if group_dict.get("URL"):
                val = html.escape(group_dict["URL"])
                return f'<span class="chip-url" title="Suspicious Link">{val}</span>'
            elif group_dict.get("SENSITIVE"):
                val = html.escape(group_dict["SENSITIVE"])
                return f'<span class="chip-sensitive" title="Sensitive Data Solicitation">{val}</span>'
            elif group_dict.get("URGENCY"):
                val = html.escape(group_dict["URGENCY"])
                return f'<span class="chip-urgency" title="Urgency / Panic Driver">{val}</span>'
        except (IndexError, KeyError, Exception):
            pass
        return html.escape(m.group(0))

    last_idx = 0
    pieces = []
    for m in master_pattern.finditer(text):
        start, end = m.span()
        pieces.append(html.escape(text[last_idx:start]))
        pieces.append(replacer(m))
        last_idx = end
    pieces.append(html.escape(text[last_idx:]))

    return "".join(pieces).replace("\n", "<br>")

