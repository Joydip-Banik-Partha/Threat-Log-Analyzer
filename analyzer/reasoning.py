MIN_CONFIDENCE_TO_ALERT = 0.6


def build_evidence(threat, details):
    evidence = []
    confidence = 0.0

    if threat == "BRUTE_FORCE_ATTEMPT":
        evidence.append(f"{details['failed_attempts']} FAILED attempts")
        evidence.append(f"Same IP: {details['ip']}")
        confidence = 0.7

    elif threat == "SUSPICIOUS_LOGIN_PATTERN":
        evidence.append("Multiple failures followed by success")
        evidence.append(f"USER: {details['user']}")
        evidence.append(f"IP: {details['ip']}")
        confidence = 0.9

    elif threat == "RATE_LIMIT_EXCEEDED":
        evidence.append(
            f"{details['attempts']} attempts within {details['window_seconds']} seconds"
        )
        evidence.append(f"Same IP: {details['ip']}")
        confidence = 0.95

    return {
        "evidence": evidence,
        "confidence": round(confidence, 2)
    }


def should_suppress(threat, confidence, minimum=MIN_CONFIDENCE_TO_ALERT):
    return confidence < minimum


def build_timeline(events):
    timeline = []
    step = 1

    for event in events:
        timeline.append(f"STEP {step}: {event}")
        step += 1

    return timeline


def classify_threat(threat):
    if threat == "BRUTE_FORCE_ATTEMPT":
        return {
            "classification": "AUTHENTICATION_ABUSE",
            "impact": "ACCOUNT_COMPROMISE_RISK"
        }

    if threat == "SUSPICIOUS_LOGIN_PATTERN":
        return {
            "classification": "CREDENTIAL_MISUSE",
            "impact": "SESSION_TAKEOVER_RISK"
        }

    if threat == "RATE_LIMIT_EXCEEDED":
        return {
            "classification": "AUTOMATED_ATTACK",
            "impact": "SERVICE_ABUSE_RISK"
        }

    return {
        "classification": "UNKNOWN",
        "impact": "LOW"
    }


def explain_no_alert(event_summary, reason):
    return {
        "observed": event_summary,
        "not_alerted_reason": reason
    }