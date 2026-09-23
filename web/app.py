import sys
import os
import re
import json
import random


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request

from engine.decision_engine import evaluate_url
from logging_module.logger import LOG_FILE
from collections import defaultdict
from datetime import datetime
from datetime import datetime, timedelta
from capture.sniffer import start_capture_thread, get_captured_events
from capture.sniffer import start_capture_thread, get_captured_events, get_protocol_breakdown
from capture.network_scan import scan_devices

app = Flask(__name__)

SETTINGS_PATH = "data/settings.json"


def get_recent_logs(limit=50):
    """Reads and parses log lines into structured dictionaries."""
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    parsed = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue

        match = re.match(r"(\S+ \S+) \| (\w+) \| (.+)", line)
        if not match:
            continue

        timestamp, level, details = match.groups()

        verdict_match = re.search(r"VERDICT=(\w+)", details)
        reason_match = re.search(r"REASON=(.+?)(?:\s*\|\s*$|$)", details)
        target_match = re.search(r"(?:FILE|URL)=(\S+)", details)

        parsed.append({
            "timestamp": timestamp,
            "level": level,
            "target": target_match.group(1) if target_match else "unknown",
            "verdict": verdict_match.group(1) if verdict_match else "unknown",
            "reason": reason_match.group(1) if reason_match else ""
        })

    return parsed[::-1]


def get_verdict_counts(log_entries):
    """Counts how many log entries fall into each verdict category."""
    counts = {"ALLOW": 0, "BLOCK": 0, "SUSPICIOUS": 0}
    for entry in log_entries:
        verdict = entry["verdict"]
        if verdict in counts:
            counts[verdict] += 1
    return counts


def get_incidents(log_entries):
    """Groups BLOCK/SUSPICIOUS log entries by target, showing repeat occurrences."""
    threats = [e for e in log_entries if e["verdict"] in ("BLOCK", "SUSPICIOUS")]

    grouped = {}
    for entry in threats:
        target = entry["target"]
        if target not in grouped:
            grouped[target] = {
                "target": target,
                "count": 0,
                "first_seen": entry["timestamp"],
                "last_seen": entry["timestamp"],
                "worst_verdict": entry["verdict"],
                "latest_reason": entry["reason"]
            }
        grouped[target]["count"] += 1
        grouped[target]["last_seen"] = entry["timestamp"]
        if entry["verdict"] == "BLOCK":
            grouped[target]["worst_verdict"] = "BLOCK"

    return sorted(grouped.values(), key=lambda x: x["count"], reverse=True)



def get_report_data(log_entries):
    """Aggregates log entries into daily verdict counts and top targets."""
    daily_counts = defaultdict(lambda: {"ALLOW": 0, "BLOCK": 0, "SUSPICIOUS": 0})
    target_counts = defaultdict(int)

    for entry in log_entries:
        date = entry["timestamp"].split(" ")[0]
        verdict = entry["verdict"]
        if verdict in ("ALLOW", "BLOCK", "SUSPICIOUS"):
            daily_counts[date][verdict] += 1
        if verdict in ("BLOCK", "SUSPICIOUS"):
            target_counts[entry["target"]] += 1

    sorted_dates = sorted(daily_counts.keys())
    top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    total_checks = len(log_entries)
    total_blocked = sum(1 for e in log_entries if e["verdict"] == "BLOCK")
    total_suspicious = sum(1 for e in log_entries if e["verdict"] == "SUSPICIOUS")

    return {
        "dates": sorted_dates,
        "daily_counts": daily_counts,
        "top_targets": top_targets,
        "total_checks": total_checks,
        "total_blocked": total_blocked,
        "total_suspicious": total_suspicious
    }

def generate_live_events(count=15):
    """Generates simulated live network events for demo purposes."""
    protocols = ["HTTP", "HTTPS", "DNS", "FTP", "SSH"]
    statuses = ["Allowed", "Blocked", "Flagged"]
    sample_ips = [f"192.168.1.{i}" for i in range(2, 40)]

    events = []
    now = datetime.now()
    for i in range(count):
        event_time = now - timedelta(seconds=i * random.randint(5, 45))
        events.append({
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": random.choice(sample_ips),
            "dest_ip": f"{random.randint(20,220)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "protocol": random.choice(protocols),
            "status": random.choices(statuses, weights=[80, 10, 10])[0]
        })
    return events


def generate_network_stats():
    """Generates simulated network traffic stats for demo purposes."""
    hours = [f"{h:02d}:00" for h in range(24)]
    traffic = [random.randint(50, 500) for _ in hours]
    protocol_breakdown = {
        "HTTPS": random.randint(50, 70),
        "HTTP": random.randint(10, 25),
        "DNS": random.randint(5, 15),
        "Other": random.randint(2, 10)
    }
    return {"hours": hours, "traffic": traffic, "protocol_breakdown": protocol_breakdown}


def generate_devices():
    """Generates simulated device/host inventory for demo purposes."""
    device_types = ["Laptop", "Desktop", "Mobile", "Server", "IoT Device"]
    os_list = ["Windows 11", "Windows 10", "Ubuntu 22.04", "macOS", "Android"]
    devices = []
    for i in range(8):
        devices.append({
            "hostname": f"HOST-{1000 + i}",
            "ip": f"192.168.1.{10 + i}",
            "type": random.choice(device_types),
            "os": random.choice(os_list),
            "status": random.choices(["Online", "Offline"], weights=[75, 25])[0],
            "last_seen": (datetime.now() - timedelta(minutes=random.randint(0, 300))).strftime("%Y-%m-%d %H:%M:%S")
        })
    return devices

def load_settings():
    with open(SETTINGS_PATH, "r") as f:
        return json.load(f)


def save_settings(settings):
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


@app.route("/")
def home():
    log_entries = get_recent_logs()
    verdict_counts = get_verdict_counts(log_entries)
    return render_template("dashboard.html", result=None, log_entries=log_entries, verdict_counts=verdict_counts, active_page="dashboard")


@app.route("/check-url", methods=["POST"])
def check_url():
    url = request.form["url"]
    result = evaluate_url(url)
    log_entries = get_recent_logs()
    verdict_counts = get_verdict_counts(log_entries)
    return render_template("dashboard.html", result=result, log_entries=log_entries, verdict_counts=verdict_counts, active_page="dashboard")


@app.route("/alerts")
def alerts():
    log_entries = get_recent_logs(limit=100)
    alert_entries = [entry for entry in log_entries if entry["verdict"] in ("BLOCK", "SUSPICIOUS")]
    return render_template("alerts.html", alert_entries=alert_entries, active_page="alerts")


@app.route("/incidents")
def incidents():
    log_entries = get_recent_logs(limit=200)
    incident_list = get_incidents(log_entries)
    return render_template("incidents.html", incidents=incident_list, active_page="incidents")


@app.route("/logs")
def logs():
    log_entries = get_recent_logs(limit=200)
    return render_template("logs.html", log_entries=log_entries, active_page="logs")


@app.route("/detection-engine")
def detection_engine():
    metrics = None
    if os.path.exists("data/model_metrics.json"):
        with open("data/model_metrics.json", "r") as f:
            metrics = json.load(f)
    return render_template("detection_engine.html", metrics=metrics, active_page="engine")

@app.route("/reports")
def reports():
    log_entries = get_recent_logs(limit=500)
    report_data = get_report_data(log_entries)
    return render_template("reports.html", report=report_data, active_page="reports")

@app.route("/live-monitoring")
def live_monitoring():
    events = get_captured_events()
    return render_template("live_monitoring.html", events=events, active_page="live")

@app.route("/network")
def network():
    stats = generate_network_stats()
    stats["protocol_breakdown"] = get_protocol_breakdown()
    return render_template("network.html", stats=stats, active_page="network")

@app.route("/devices")
def devices():
    device_list = scan_devices()
    return render_template("devices.html", devices=device_list, active_page="devices")

@app.route("/settings", methods=["GET"])
def settings_page():
    settings = load_settings()
    return render_template("settings.html", settings=settings, saved=False, active_page="settings")


@app.route("/settings", methods=["POST"])
def update_settings():
    settings = {
        "fail_policy": request.form["fail_policy"],
        "sandbox_entropy_threshold": float(request.form["sandbox_entropy_threshold"]),
        "log_retention_limit": int(request.form["log_retention_limit"])
    }
    save_settings(settings)
    return render_template("settings.html", settings=settings, saved=True, active_page="settings")


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        start_capture_thread()
    app.run(debug=True)