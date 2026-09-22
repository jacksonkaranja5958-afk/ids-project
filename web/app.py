import sys
import os
import re
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request

from engine.decision_engine import evaluate_url
from logging_module.logger import LOG_FILE

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
    app.run(debug=True)