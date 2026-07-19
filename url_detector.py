import re
from urllib.parse import urlparse


TRUSTED_SOCIAL_DOMAINS = {
    "Instagram": {
        "instagram.com",
        "www.instagram.com"
    },
    "Facebook": {
        "facebook.com",
        "www.facebook.com",
        "m.facebook.com",
        "fb.com",
        "www.fb.com"
    },
    "LinkedIn": {
        "linkedin.com",
        "www.linkedin.com"
    },
    "WhatsApp": {
        "whatsapp.com",
        "www.whatsapp.com",
        "wa.me"
    },
    "Telegram": {
        "telegram.org",
        "www.telegram.org",
        "t.me"
    }
}


SOCIAL_MEDIA_NAMES = {
    "instagram": "Instagram",
    "facebook": "Facebook",
    "linkedin": "LinkedIn",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram"
}


def detect_social_platform(domain: str, full_url: str):
    """
    Detect whether a URL belongs to a known social-media platform
    or uses a suspicious lookalike domain.
    """

    for platform, trusted_domains in TRUSTED_SOCIAL_DOMAINS.items():
        if domain in trusted_domains:
            return platform, "OFFICIAL"

    for keyword, platform in SOCIAL_MEDIA_NAMES.items():
        if keyword in domain or keyword in full_url:
            return platform, "LOOKALIKE"

    return None, "NOT_SOCIAL"


def analyze_url(url: str) -> dict:
    """
    Estimate URL risk using offline structural rules.

    Important:
    This function cannot guarantee that a website, profile,
    page or account is genuine.
    """

    url = url.strip()

    if not url:
        return {
            "domain": "",
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "platform": None,
            "domain_status": "UNKNOWN",
            "evidence": ["No URL was provided."]
        }

    normalized_url = url

    if not normalized_url.lower().startswith(
        ("http://", "https://")
    ):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    domain = parsed.netloc.lower()

    # Remove username/password information if present.
    if "@" in domain:
        domain = domain.split("@")[-1]

    domain_without_port = domain.split(":")[0]
    full_url = normalized_url.lower()

    evidence = []
    score = 0.0

    platform, domain_status = detect_social_platform(
        domain_without_port,
        full_url
    )

    # 1. Social-media domain verification
    if domain_status == "OFFICIAL":
        evidence.append(
            f"Official {platform} domain detected"
        )

    elif domain_status == "LOOKALIKE":
        evidence.append(
            f"Possible fake or lookalike {platform} domain"
        )
        score += 0.50

    # 2. Missing HTTPS
    if not url.lower().startswith("https://"):
        evidence.append("No HTTPS protection")
        score += 0.15

    # 3. IP address used as a domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.fullmatch(ip_pattern, domain_without_port):
        evidence.append("IP address used as domain")
        score += 0.30

    # 4. URL shortener
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
        evidence.append(
            "Shortened URL hides the final destination"
        )
        score += 0.25

    # 5. Punycode domain
    if "xn--" in domain_without_port:
        evidence.append(
            "Punycode domain may imitate another website"
        )
        score += 0.30

    # 6. @ symbol
    if "@" in full_url:
        evidence.append(
            "@ symbol may hide the real destination"
        )
        score += 0.25

    # 7. Suspicious words
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
        "free-gift",
        "security-check",
        "account-recovery"
    ]

    found_words = [
        word
        for word in suspicious_words
        if word in full_url
    ]

    if found_words:
        evidence.append(
            "Suspicious words: " + ", ".join(found_words)
        )

        score += min(
            0.10 * len(found_words),
            0.30
        )

    # 8. Very long URL
    if len(full_url) > 100:
        evidence.append("Unusually long URL")
        score += 0.15

    # 9. Excessive subdomains
    domain_parts = domain_without_port.split(".")

    if len(domain_parts) > 4:
        evidence.append("Too many subdomains")
        score += 0.15

    # 10. Excessive hyphens
    if domain_without_port.count("-") >= 3:
        evidence.append(
            "Excessive hyphens in domain"
        )
        score += 0.15

    # 11. Invalid or missing domain
    if not domain_without_port:
        evidence.append("Valid domain could not be detected")
        score += 0.40

    # 12. Multiple indicators
    risky_evidence = [
        item for item in evidence
        if not item.startswith("Official")
    ]

    if len(risky_evidence) >= 4:
        evidence.append(
            "Multiple URL risk indicators detected"
        )
        score += 0.10

    score = min(round(score, 2), 1.0)

    if score >= 0.65:
        risk_level = "HIGH"

    elif score >= 0.30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    if not evidence:
        evidence.append(
            "No obvious structural risk detected"
        )

    return {
        "domain": domain_without_port,
        "risk_score": score,
        "risk_level": risk_level,
        "platform": platform,
        "domain_status": domain_status,
        "evidence": evidence
    }
