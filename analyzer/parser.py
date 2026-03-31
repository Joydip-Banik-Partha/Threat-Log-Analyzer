def parse_access_log(file_path):
    """
    Parses access.log and returns structured access events.
    """
    events = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) != 4:
                continue

            ip, method, path, status = parts

            events.append({
                "type": "access",
                "ip": ip,
                "method": method,
                "path": path,
                "status": int(status)
            })

    return events


def parse_auth_log(file_path):
    """
    Parses auth.log and returns structured auth events.
    """
    events = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) != 4:
                continue

            timestamp, user, result, ip = parts

            events.append({
                "type": "auth",
                "timestamp": timestamp,
                "user": user,
                "result": result,
                "ip": ip
            })

    return events