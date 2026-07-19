import re
from urllib.parse import urlparse


def analyze_url(url: str) -> dict:
    """
    Analyze a URL using offline heuristic rules.

    Important:
    This function estimates structural risk.
    It does not guarantee that a website is malicious or safe.
    """

    url = url.strip()

    if not url:
        return {
            "domain": "",
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "evidence": ["No URL was provided."]
        }

    # urlparse needs a scheme to correctly identify the domain.
    normalized_url = url
    if not normalized_url.lower().startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    domain = parsed.netloc.lower()
    domain_without_port = domain.split(":")[0]
    full_url = normalized_url.lower()

    evidence = []
    score = 0.0

    # 1. Missing HTTPS
    if not url.lower().startswith("https://"):
        evidence.append("No HTTPS protection")
        score += 0.15

    # 2. IP address used instead of a normal domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.fullmatch(ip_pattern, domain_without_port):
        evidence.append("IP address used as domain")
        score += 0.30

    # 3. Common URL-shortening services
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    }

    if domain_without_port in shorteners:
        evidence.append("Shortened URL hides destination")
        score += 0.25

    # 4. Punycode can be used for lookalike domains
    if "xn--" in domain_without_port:
        evidence.append("Punycode domain detected")
        score += 0.25

    # 5. @ can mislead users about the actual destination
    if "@" in full_url:
        evidence.append("@ symbol found in URL")
        score += 0.20

    # 6. Suspicious words
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "otp",
        "payment",
        "wallet",
        "bank",
        "cnic",
        "easypaisa",
        "jazzcash",
        "job-offer",
        "selected",
        "claim",
        "reward",
        "prize",
        "free-gift"
    ]

    found_words = [
        word for word in suspicious_words
        if word in full_url
    ]

    if found_words:
        evidence.append(
            "Suspicious words: " + ", ".join(found_words)
        )
        score += min(0.10 * len(found_words), 0.30)

    # 7. Very long URL
    if len(full_url) > 100:
        evidence.append("Unusually long URL")
        score += 0.15

    # 8. Too many subdomain levels
    domain_parts = domain_without_port.split(".")

    if len(domain_parts) > 4:
        evidence.append("Too many subdomains")
        score += 0.15

    # 9. Excessive hyphens
    if domain_without_port.count("-") >= 3:
        evidence.append("Excessive hyphens in domain")
        score += 0.15

    # 10. Multiple indicators together increase risk
    if len(evidence) >= 4:
        evidence.append("Multiple URL risk indicators detected")
        score += 0.10

    score = min(round(score, 2), 1.0)

    if score >= 0.65:
        risk_level = "HIGH"
    elif score >= 0.30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not evidence:
        evidence.append("No obvious structural risk detected")

    return {
        "domain": domain_without_port,
        "risk_score": score,
        "risk_level": risk_level,
        "evidence": evidence
    }
