import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template, request

from engine.decision_engine import evaluate_url
from logging_module.logger import LOG_FILE

app = Flask(__name__)


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


@app.route("/")
def home():
    log_entries = get_recent_logs()
    verdict_counts = get_verdict_counts(log_entries)
    return render_template("dashboard.html", result=None, log_entries=log_entries, verdict_counts=verdict_counts)


@app.route("/check-url", methods=["POST"])
def check_url():
    url = request.form["url"]
    result = evaluate_url(url)
    log_entries = get_recent_logs()
    verdict_counts = get_verdict_counts(log_entries)
    return render_template("dashboard.html", result=result, log_entries=log_entries, verdict_counts=verdict_counts)


if __name__ == "__main__":
    app.run(debug=True)