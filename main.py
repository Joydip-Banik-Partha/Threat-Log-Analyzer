import os
import sys
import importlib.util

ROOT = os.path.dirname(os.path.abspath(__file__))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---- Load modules ----
parser = load("parser", os.path.join(ROOT, "analyzer", "parser.py"))
rules = load("rules", os.path.join(ROOT, "analyzer", "rules.py"))
severity = load("severity", os.path.join(ROOT, "analyzer", "severity.py"))
report = load("report", os.path.join(ROOT, "analyzer", "report.py"))
reasoning = load("reasoning", os.path.join(ROOT, "analyzer", "reasoning.py"))


# ---- CLI arguments ----
access_log = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "logs", "access.log")
auth_log = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "logs", "auth.log")
output_file = sys.argv[3] if len(sys.argv) > 3 else os.path.join(ROOT, "threat_report.txt")
json_flag = "--json" in sys.argv


# ---- Parse logs ----
access_events = parser.parse_access_log(access_log)
auth_events = parser.parse_auth_log(auth_log)


# ---- Detect threats ----
detections = []
detections += rules.detect_bruteforce_attempts(auth_events)
detections += rules.detect_success_after_failure(auth_events)
detections += rules.detect_rate_limited_failures(auth_events)


# ---- Assign severity ----
final = severity.assign_severity(detections)


# ---- Build reasoning report ----
final_report = []

for item in final:
    threat = item["threat"]

    evidence_block = reasoning.build_evidence(threat, item)
    suppressed = reasoning.should_suppress(
        threat,
        evidence_block["confidence"],
        reasoning.MIN_CONFIDENCE_TO_ALERT
    )

    classification = reasoning.classify_threat(threat)
    timeline = reasoning.build_timeline(evidence_block["evidence"])

    if suppressed:
        final_report.append({
            "THREAT": threat,
            "STATUS": "SUPPRESSED",
            "CONFIDENCE": evidence_block["confidence"]
        })
        continue

    final_report.append({
        "THREAT": threat,
        "SEVERITY": item["severity"],
        "CLASSIFICATION": classification["classification"],
        "IMPACT": classification["impact"],
        "EVIDENCE": evidence_block["evidence"],
        "CONFIDENCE": evidence_block["confidence"],
        "TIMELINE": timeline
    })


# ---- Output ----
print("\nSECURITY REASONING REPORT:\n")

for entry in final_report:
    for key, value in entry.items():
        print(f"{key}: {value}")
    print("-" * 40)