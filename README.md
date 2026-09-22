# IDS — Phishing & Malware Detection System

A Python-based Intrusion Detection System that inspects files and URLs before they're trusted, combining hash matching, heuristic analysis, machine learning classification, and simulated sandbox detonation — with a full web dashboard for monitoring and configuration.

Built as a first full-stack security project, covering the complete SDLC from requirements through a working, tested, deployed system.

## Features

- **Hash Matching** — SHA-256 fingerprinting against known-malicious hash lists
- **Heuristic Analysis** — detects disguised file extensions (e.g. `invoice.pdf.exe`) using generic pattern matching
- **ML Phishing Classifier** — a Random Forest model trained on 30,000 real URLs (PhiUSIIL dataset), using 17 lexical/structural features including URL entropy, achieving 99.75% test accuracy
- **Simulated Sandbox** — Shannon entropy analysis on file bytes as a static stand-in for dynamic detonation (clearly documented as simulated, not a real isolated execution environment)
- **Decision Engine** — combines all module outputs with escalation logic (e.g. disguised extensions get escalated to sandbox analysis before a final verdict)
- **Logging** — every decision is timestamped and persisted
- **Web Dashboard** (Flask) — six live pages:
  - Dashboard — verdict summary chart, URL checker, recent activity
  - Alerts — filtered feed of BLOCK/SUSPICIOUS events
  - Logs — full searchable/filterable activity history
  - Detection Engine — live module status and real ML performance metrics
  - Threats/Incidents — repeat-offender grouping by target
  - Settings — configurable fail-open/fail-closed policy, sandbox threshold, log retention

## Tech Stack

- **Backend**: Python, Flask
- **ML**: scikit-learn (Random Forest), pandas
- **Frontend**: HTML, CSS, JavaScript, Chart.js
- **Testing**: pytest (18 passing tests across all modules)

## Architecture