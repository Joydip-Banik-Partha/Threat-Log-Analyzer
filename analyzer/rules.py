from datetime import datetime


def detect_bruteforce_attempts(auth_events, threshold=3):
    results = []
    failed_counts = {}

    for event in auth_events:
        if event["result"] == "FAILED":
            ip = event["ip"]
            failed_counts[ip] = failed_counts.get(ip, 0) + 1

    for ip, count in failed_counts.items():
        if count >= threshold:
            results.append({
                "threat": "BRUTE_FORCE_ATTEMPT",
                "ip": ip,
                "failed_attempts": count
            })

    return results


def detect_success_after_failure(auth_events):
    results = []
    failure_tracker = {}

    for event in auth_events:
        key = (event["user"], event["ip"])

        if event["result"] == "FAILED":
            failure_tracker[key] = True

        if event["result"] == "SUCCESS" and key in failure_tracker:
            results.append({
                "threat": "SUSPICIOUS_LOGIN_PATTERN",
                "user": event["user"],
                "ip": event["ip"]
            })

    return results


def detect_rate_limited_failures(auth_events, max_attempts=3, window_seconds=60):
    results = {}
    timestamps_by_ip = {}

    for event in auth_events:
        if event["result"] != "FAILED":
            continue

        ip = event["ip"]
        ts = datetime.fromisoformat(event["timestamp"])

        timestamps_by_ip.setdefault(ip, []).append(ts)

    findings = []

    for ip, times in timestamps_by_ip.items():
        times.sort()

        start = 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > window_seconds:
                start += 1

            attempts = end - start + 1
            if attempts >= max_attempts:
                findings.append({
                    "threat": "RATE_LIMIT_EXCEEDED",
                    "ip": ip,
                    "attempts": attempts,
                    "window_seconds": window_seconds
                })
                break

    return findings