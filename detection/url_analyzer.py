from urllib.parse import urlparse
import re


def analyze_url(url):
    """
    Analyze a URL for basic phishing indicators.
    Returns a risk score, risk level, and reasons.
    """

    score = 0
    reasons = []

    # Make sure the URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Check HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS")

    # 2. Check URL length
    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long")

    # 3. Check for IP address
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):
        score += 20
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # 4. Suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "bank",
        "payment",
        "wallet",
        "otp"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            found_keywords.append(keyword)

    if found_keywords:
        score += 10
        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # 5. Check for @ symbol
    if "@" in url:
        score += 15
        reasons.append("URL contains @ symbol")

    # 6. Check excessive hyphens
    if domain.count("-") >= 3:
        score += 10
        reasons.append("Domain contains many hyphens")

    # 7. Check too many subdomains
    domain_parts = domain.split(".")

    if len(domain_parts) >= 4:
        score += 10
        reasons.append("Domain contains many subdomains")

    # Don't allow score above 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


if __name__ == "__main__":

    print("===================================")
    print("       TRAPDOOR URL ANALYZER")
    print("===================================")

    url = input("\nEnter a URL to scan: ")

    result = analyze_url(url)

    print("\n========== RESULT ==========")

    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Risk Level: {result['risk_level']}")

    print("\nReasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f" - {reason}")
    else:
        print(" - No obvious suspicious indicators detected.")

    print("============================")