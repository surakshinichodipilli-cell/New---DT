import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_KEYWORDS = (
    "login", "verify", "account", "confirm", "secure", "update",
    "bank", "signin", "password", "payment", "free", "claim", "winner",
)

SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "tiny.cc", "buff.ly",
}

DISCLAIMER = (
    "Automated analysis is an estimate based on URL text patterns. It does not "
    "visit the URL and cannot guarantee that a website or device is malicious or safe."
)


def normalize_url(raw_url):
    if not isinstance(raw_url, str):
        raise ValueError("Please enter a website URL.")
    value = raw_url.strip()
    if not value:
        raise ValueError("Please enter a website URL.")
    if len(value) > 2048 or any(ord(char) < 32 or char.isspace() for char in value):
        raise ValueError("Please enter a URL no longer than 2,048 characters without spaces or control characters.")
    if not re.match(r"^https?://", value, flags=re.IGNORECASE):
        value = "https://" + value
    return value


def analyze_url(raw_url):
    url = normalize_url(raw_url)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Please enter a valid HTTP/HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded usernames or passwords are not supported.")
    try:
        parsed.port
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Please enter a valid website hostname and port.") from exc

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip and any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in hostname.split(".")
    ):
        raise ValueError("Please enter a valid website hostname.")

    if len(hostname) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in hostname.split(".")
    ):
        raise ValueError("Please enter a valid website hostname.")

    indicators = []
    score = 0
    lower_url = url.lower()
    if len(url) > 90:
        indicators.append("Suspicious URL length")
        score += 20

    registered_domain = hostname.split(".")[-2] if hostname.count(".") else hostname
    if len(registered_domain) > 20:
        indicators.append("Long domain name")
        score += 10

    if hostname.count(".") > 4:
        indicators.append("Excessive dotted structure")
        score += 12

    if url.count("-") > 2:
        indicators.append("Multiple hyphen separators")
        score += 8

    if len(re.findall(r"[^a-zA-Z0-9:/._?#=&%-]", url)) > 3:
        indicators.append("Excessive special characters")
        score += 12

    if sum(char.isdigit() for char in hostname) > 7:
        indicators.append("Numerical pattern in hostname")
        score += 8

    if parsed.scheme == "http":
        indicators.append("HTTP connection instead of HTTPS")
        score += 15

    if is_ip:
        indicators.append("IP address used as hostname")
        score += 18

    matched_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_url]
    if matched_keywords:
        indicators.append("Possible phishing keywords detected")
        score += 15 + len(matched_keywords) * 5

    subdomain_count = max(0, len(hostname.split(".")) - 2)
    if subdomain_count > 2:
        indicators.append("Multiple subdomains detected")
        score += 10

    if any(hostname == domain or hostname.endswith(f".{domain}") for domain in SHORTENING_DOMAINS):
        indicators.append("URL shortener detected")
        score += 20

    if any(marker in lower_url for marker in ("%2f", "%00", "%3d", "?token=")):
        indicators.append("Encoded suspicious request pattern")
        score += 10

    score = min(100, score)
    if score >= 71:
        risk_level = "HIGH RISK"
        recommendation = "Do not open this link unless you can independently verify its source and destination."
    elif score >= 31:
        risk_level = "SUSPICIOUS"
        recommendation = "Verify the domain through a trusted channel before entering information."
    else:
        risk_level = "SAFE"
        recommendation = "No major text-based indicators were detected; continue to use normal caution."

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "detected_indicators": indicators,
        "recommendation": recommendation,
        "analysis_mode": "transparent rule-based baseline",
        "disclaimer": DISCLAIMER,
    }
