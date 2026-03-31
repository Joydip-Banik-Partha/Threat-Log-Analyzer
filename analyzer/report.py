def generate_report(items):
    lines = []

    for item in items:
        line = f"[{item['severity']}] {item['threat']}"

        if "ip" in item:
            line += f" | IP: {item['ip']}"

        if "user" in item:
            line += f" | USER: {item['user']}"

        if "failed_attempts" in item:
            line += f" | FAILS: {item['failed_attempts']}"

        lines.append(line)

    return lines


def save_report(lines, file_path):
    with open(file_path, "w") as file:
        for line in lines:
            file.write(line + "\n")

import json

def generate_json(items):
    return json.dumps(items, indent=2)