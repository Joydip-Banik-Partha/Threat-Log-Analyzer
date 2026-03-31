import os
import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

parser = load("parser", os.path.join(ROOT, "analyzer", "parser.py"))
rules = load("rules", os.path.join(ROOT, "analyzer", "rules.py"))
severity = load("severity", os.path.join(ROOT, "analyzer", "severity.py"))

def run_tests():
    auth_log = os.path.join(ROOT, "logs", "auth.log")
    auth_events = parser.parse_auth_log(auth_log)

    detections = []
    detections += rules.detect_bruteforce_attempts(auth_events)
    detections += rules.detect_success_after_failure(auth_events)
    detections += rules.detect_rate_limited_failures(auth_events, max_attempts=3, window_seconds=60)

    final = severity.assign_severity(detections)

    assert any(d["threat"] == "BRUTE_FORCE_ATTEMPT" for d in final)
    assert any(d["threat"] == "SUSPICIOUS_LOGIN_PATTERN" for d in final)

    print("ALL TESTS PASSED")

if __name__ == "__main__":
    run_tests()