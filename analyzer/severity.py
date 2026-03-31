def assign_severity(threats):
    results = []

    for item in threats:
        if item["threat"] == "BRUTE_FORCE_ATTEMPT":
            severity = "HIGH"
        elif item["threat"] == "RATE_LIMIT_EXCEEDED":
            severity = "HIGH"
        elif item["threat"] == "SUSPICIOUS_LOGIN_PATTERN":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        enriched = item.copy()
        enriched["severity"] = severity
        results.append(enriched)

    return results