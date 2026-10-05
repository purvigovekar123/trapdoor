import re


def analyze_message(message):
    """
    Analyze a message for common scam/phishing indicators.
    Returns a risk score, risk level, and reasons.
    """

    score = 0
    reasons = []

    message_lower = message.lower()

    # 1. Urgency indicators
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "limited time",
        "expires today",
        "within 24 hours"
    ]

    found_urgency = []

    for word in urgency_words:
        if word in message_lower:
            found_urgency.append(word)

    if found_urgency:
        score += 15
        reasons.append(
            "Urgency or pressure tactics detected: "
            + ", ".join(found_urgency)
        )

    # 2. Sensitive information requests
    sensitive_words = [
        "password",
        "otp",
        "pin",
        "cvv",
        "credit card",
        "debit card",
        "bank account"
    ]

    found_sensitive = []

    for word in sensitive_words:
        if word in message_lower:
            found_sensitive.append(word)

    if found_sensitive:
        score += 25
        reasons.append(
            "Request for sensitive information detected: "
            + ", ".join(found_sensitive)
        )

    # 3. Suspicious financial terms
    financial_words = [
        "prize",
        "winner",
        "lottery",
        "refund",
        "cashback",
        "reward",
        "payment"
    ]

    found_financial = []

    for word in financial_words:
        if word in message_lower:
            found_financial.append(word)

    if found_financial:
        score += 15
        reasons.append(
            "Financial or reward-related language detected: "
            + ", ".join(found_financial)
        )

    # 4. Links inside the message
    urls = re.findall(
        r"https?://\S+|www\.\S+",
        message
    )

    if urls:
        score += 15
        reasons.append(
            f"Message contains {len(urls)} link(s)"
        )

    # 5. Excessive exclamation marks
    if message.count("!") >= 3:
        score += 10
        reasons.append(
            "Message uses excessive exclamation marks"
        )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "message": message,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


if __name__ == "__main__":

    print("===================================")
    print("      TRAPDOOR MESSAGE ANALYZER")
    print("===================================")

    message = input("\nEnter a message to scan: ")

    result = analyze_message(message)

    print("\n========== RESULT ==========")

    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Risk Level: {result['risk_level']}")

    print("\nReasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f" - {reason}")
    else:
        print(" - No obvious suspicious indicators detected.")

    print("============================")