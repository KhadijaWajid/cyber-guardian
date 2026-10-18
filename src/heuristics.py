import re
import ipaddress
import urllib.parse
from typing import Optional, List, Dict, Any, Tuple
from src.utils import defang_url


TOP_TARGETED_BRANDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "wells fargo": "wellsfargo.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
}

HIGH_RISK_TLDS: set[str] = {
    ".top",
    ".xyz",
    ".tk",
    ".click",
    ".buzz",
    ".fit",
    ".work",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".country",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Levenshtein distance between two strings using standard matrix DP.
    Pure Python, zero external dependencies.
    """
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(
                    dp[i - 1][j],      # deletion
                    dp[i][j - 1],      # insertion
                    dp[i - 1][j - 1],  # substitution
                )
    return dp[m][n]


def extract_host_and_port(raw_url: str) -> Tuple[str, Optional[int]]:
    """
    Safely extracts domain/host and port from URL or naked domain using urllib.parse.
    Handles URLs with or without scheme, and safely ignores path/query parameters.
    """
    if not raw_url:
        return "", None

    url_to_parse = raw_url.strip()
    # Normalize scheme for parsing if absent
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_to_parse):
        url_to_parse = f"http://{url_to_parse}"

    try:
        parsed = urllib.parse.urlsplit(url_to_parse)
        host = parsed.hostname or ""
        port = parsed.port
        return host.lower().strip(), port
    except Exception:
        # Fallback manual string extraction if urlsplit fails
        raw = raw_url.split("://")[-1].split("/")[0].split("?")[0].split("#")[0]
        if ":" in raw and not raw.startswith("["):
            parts = raw.split(":")
            return parts[0].lower().strip(), int(parts[1]) if parts[1].isdigit() else None
        return raw.lower().strip(), None


def is_ip_host(host: str) -> bool:
    """
    Determines if a host is a raw IPv4, IPv6, or integer decimal IP address.
    """
    if not host:
        return False

    clean_host = host.strip("[]").strip()

    # Dotted-decimal IPv4 or colon IPv6
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Pure integer decimal IP representation (e.g., 2130706433 for 127.0.0.1)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                ipaddress.ip_address(val)
                return True
        except ValueError:
            pass

    return False


def is_high_risk_tld(host: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if the domain ends with one of the HIGH_RISK_TLDS.
    """
    if not host or is_ip_host(host):
        return False, None

    for tld in HIGH_RISK_TLDS:
        normalized_tld = tld if tld.startswith(".") else f".{tld}"
        if host.endswith(normalized_tld):
            return True, normalized_tld
    return False, None


def check_typosquatting(host: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Checks if a host attempts to impersonate or typosquat TOP_TARGETED_BRANDS.
    Returns (brand_name, reason) if flagged, or (None, None) if clean.
    """
    if not host or is_ip_host(host):
        return None, None

    labels = host.split(".")
    # If host has fewer than 2 parts (e.g. localhost), ignore
    if len(labels) < 2:
        return None, None

    # Separate domain labels
    # e.g., for 'wellsfargo.com', sld is 'wellsfargo', tld is 'com'
    # e.g., for 'paypal.verify-account.com', labels = ['paypal', 'verify-account', 'com']
    for brand_name, legitimate_domain in TOP_TARGETED_BRANDS.items():
        leg_domain = legitimate_domain.lower()
        leg_labels = leg_domain.split(".")
        leg_sld = leg_labels[0]  # e.g., 'wellsfargo', 'paypal'
        brand_slug = brand_name.replace(" ", "").replace("-", "").lower()

        # Check if this host IS the legitimate domain or legitimate subdomain
        # e.g., 'paypal.com' or 'www.paypal.com' or 'login.paypal.com'
        if host == leg_domain or host.endswith(f".{leg_domain}"):
            # Truly legitimate brand domain
            continue

        # Check 1: Brand appears as a subdomain label or embedded label
        # e.g. 'paypal.verify-account.com' or 'wellsfargo-security.verify-account88.com'
        # or 'bankofamerica.update-billing.click'
        subdomain_labels = labels[:-2]  # labels preceding the apex domain
        for sub in subdomain_labels:
            if sub == brand_slug or sub == leg_sld:
                return brand_name, f"Brand '{brand_name}' appears as an untrusted subdomain in '{host}'."
            if brand_slug in sub or leg_sld in sub:
                return brand_name, f"Brand identifier '{brand_name}' embedded in subdomain label '{sub}'."

        # Check 2: Brand appears inside the registered domain name (e.g. 'paypal-security.com' or 'wellsfargo-update.com')
        apex_sld = labels[-2]  # e.g. 'verify-account' in 'verify-account.com'
        if brand_slug in apex_sld or leg_sld in apex_sld:
            return brand_name, f"Brand identifier '{brand_name}' embedded in unregistered domain '{apex_sld}'."

        # Check 3: Levenshtein distance typosquatting on the apex SLD
        # e.g. 'paypa1' vs 'paypal' (dist 1), 'wellsfarg0' vs 'wellsfargo' (dist 1), 'arnazon' vs 'amazon' (dist 1)
        dist_slug = levenshtein_distance(apex_sld, brand_slug)
        dist_sld = levenshtein_distance(apex_sld, leg_sld)
        min_dist = min(dist_slug, dist_sld)

        # Flag if distance is 1 or 2, and length is sufficiently close (>= 4 chars)
        if 1 <= min_dist <= 2 and len(apex_sld) >= 4 and abs(len(apex_sld) - len(brand_slug)) <= 2:
            return brand_name, f"Typosquatting lookalike '{apex_sld}' closely matches '{brand_name}' (edit distance: {min_dist})."

    return None, None


def analyze_url_heuristics(url: str) -> Dict[str, Any]:
    """
    Performs deterministic static URL heuristic inspection with zero external API calls.
    Returns:
      - original_url: str
      - defanged_url: str
      - is_ip_address: bool
      - is_high_risk_tld: bool
      - typosquat_target: Optional[str]
      - severity: "HIGH" | "MEDIUM" | "LOW"
      - findings: list[str]
    """
    clean_url = (url or "").strip()
    defanged = defang_url(clean_url)

    if not clean_url:
        return {
            "original_url": "",
            "defanged_url": "",
            "is_ip_address": False,
            "is_high_risk_tld": False,
            "typosquat_target": None,
            "severity": "LOW",
            "findings": ["Empty URL provided."],
        }

    host, _ = extract_host_and_port(clean_url)
    is_ip = is_ip_host(host)
    is_tld, matched_tld = is_high_risk_tld(host)
    typosquat_target, typosquat_reason = check_typosquatting(host)

    findings: List[str] = []

    if is_ip:
        findings.append(f"Host uses raw numeric IP address format '{host}' instead of a registered domain.")

    if is_tld:
        findings.append(f"Domain uses high-abuse/high-risk TLD '{matched_tld}'.")

    if typosquat_target:
        findings.append(typosquat_reason or f"Typosquatting or brand spoofing detected targeting '{typosquat_target}'.")

    # Severity determination
    if is_ip or typosquat_target:
        severity = "HIGH"
    elif is_tld:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        findings.append("No static heuristic red flags detected for this URL.")

    return {
        "original_url": clean_url,
        "defanged_url": defanged,
        "is_ip_address": is_ip,
        "is_high_risk_tld": is_tld,
        "typosquat_target": typosquat_target,
        "severity": severity,
        "findings": findings,
    }


def extract_urls(text: str) -> List[str]:
    """
    Discovers URLs, IP links, and naked domains in text without active network calls.
    """
    if not text:
        return []

    found = []
    # Match standard URLs with schemes
    url_pattern = re.compile(r"https?://[^\s<>\"'()]+|hxxps?://[^\s<>\"'()]+", re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        if url and url not in found:
            found.append(url)

    # Match raw IP links without scheme (e.g., 192.168.1.1/login or 10.0.0.1:8080)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>\"']*)?\b")
    for match in ip_pattern.finditer(text):
        ip_url = match.group(0).rstrip(".,;:!?)")
        if ip_url and ip_url not in found:
            found.append(ip_url)

    return found


def analyze_all_heuristics(urls_or_text: Any) -> List[Dict[str, Any]]:
    """
    Inspects multiple URLs or extracts and inspects all URLs found in input text.
    """
    if isinstance(urls_or_text, str):
        urls = extract_urls(urls_or_text)
        if not urls and ("." in urls_or_text or "://" in urls_or_text):
            urls = [urls_or_text.strip()]
    elif isinstance(urls_or_text, (list, tuple, set)):
        urls = list(urls_or_text)
    else:
        urls = []

    return [analyze_url_heuristics(u) for u in urls if u]


LUXURY_AND_ELECTRONICS_BRANDS: List[str] = [
    "iphone",
    "apple",
    "rolex",
    "dyson",
    "ps5",
    "playstation",
    "macbook",
    "gucci",
    "louis vuitton",
    "prada",
    "ray-ban",
    "rayban",
    "balenciaga",
    "nike",
    "samsung",
    "ipad",
]


def analyze_ecommerce_discount(text: str, url: str = "") -> Dict[str, Any]:
    """
    Analyzes an e-commerce advertisement or product page for counterfeit/fake discount scams.
    Extracts discount rates, compares against high-value luxury/tech brands,
    and detects predatory artificial checkout timers.
    """
    clean_text = (text or "").lower()
    clean_url = (url or "").lower()
    combined_content = f"{clean_text} {clean_url}"

    # 1. Detect Luxury or Electronics Brand
    detected_brand = None
    for brand in LUXURY_AND_ELECTRONICS_BRANDS:
        # Check boundary or whole word in combined content
        if re.search(r"\b" + re.escape(brand) + r"\b", combined_content):
            detected_brand = brand
            break

    # 2. Extract Discount Rate (%)
    discount_rate = None

    # Pattern A: Direct percentage (e.g., '90% off', '85% discount')
    pct_match = re.search(r"(\d{1,2})\s*%\s*(?:off|discount|sale)", combined_content)
    if not pct_match:
        pct_match = re.search(r"(?:save|discount of|off)\s*(\d{1,2})\s*%", combined_content)
    if pct_match:
        discount_rate = float(pct_match.group(1))

    # Pattern B: Was $X Now $Y comparison
    price_match = re.search(
        r"(?:was|regular(?:ly)?|original(?:ly)?)\s*[:\$]?\s*(\d+(?:[.,]\d+)?)\s*(?:now|sale|only|for)?\s*[:\$]?\s*(\d+(?:[.,]\d+)?)",
        combined_content,
    )
    if price_match:
        try:
            was_price = float(price_match.group(1).replace(",", ""))
            now_price = float(price_match.group(2).replace(",", ""))
            if was_price > 0 and was_price > now_price:
                computed_rate = ((was_price - now_price) / was_price) * 100.0
                if discount_rate is None or computed_rate > discount_rate:
                    discount_rate = round(computed_rate, 1)
        except (ValueError, ZeroDivisionError):
            pass

    # 3. Detect Checkout Urgency & Scarcity Markers
    urgency_patterns = [
        (r"only\s+\d+\s+items?\s+left", "Severe artificial inventory scarcity"),
        (r"flash\s+sale\s+ends\s+in", "Fast-expiry countdown pressure"),
        (r"ends\s+in\s+\d+\s+(?:minutes|hours)", "Artificial deadline timer"),
        (r"limited\s+stock", "Limited stock pressure"),
        (r"hurry", "High-pressure urgency keyword"),
        (r"claim\s+before\s+timer\s+expires", "Timer expiration driver"),
        (r"9\d%\s*sold", "Manufactured FOMO social proof"),
    ]

    urgency_markers_found = []
    for pattern, desc in urgency_patterns:
        if re.search(pattern, combined_content):
            urgency_markers_found.append(desc)

    # 4. Fraud / Predatory Assessment
    is_fake_discount = False
    reasons = []

    if discount_rate is not None and discount_rate >= 70.0:
        is_fake_discount = True
        reasons.append(f"Unrealistically steep discount ({discount_rate:.0f}%) exceeding normal retail margin limits.")

    if detected_brand and discount_rate is not None and discount_rate >= 50.0:
        is_fake_discount = True
        reasons.append(
            f"Steep discount ({discount_rate:.0f}%) on price-controlled brand '{detected_brand.capitalize()}', typical of counterfeit or clone storefronts."
        )

    if detected_brand and not discount_rate and urgency_markers_found:
        reasons.append(f"High-value brand '{detected_brand.capitalize()}' paired with aggressive scarcity timers.")

    if urgency_markers_found:
        reasons.append(f"Aggressive conversion tactics: {', '.join(urgency_markers_found)}.")

    if not reasons:
        risk_summary = "Pricing and discount patterns appear within conventional commercial parameters."
    else:
        risk_summary = " ".join(reasons)

    return {
        "is_fake_discount_likely": is_fake_discount,
        "discount_rate": discount_rate,
        "luxury_brand_detected": detected_brand,
        "urgency_markers_found": urgency_markers_found,
        "risk_summary": risk_summary,
    }

