import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.hash_matcher import compute_file_hash, check_hash
from detection.heuristic_analyzer import check_double_extension
from detection.ml_classifier import load_model, check_phishing_url
from detection.sandbox import simulate_detonation
from logging_module.logger import log_verdict

phishing_model = load_model()


phishing_model = load_model()


def evaluate_file(file_path):
    """Runs available checks on a file and returns a verdict."""
    filename = os.path.basename(file_path)

    file_hash = compute_file_hash(file_path)
    is_known_malicious = check_hash(file_hash)

    if is_known_malicious:
        return {
            "file": filename,
            "hash": file_hash,
            "verdict": "BLOCK",
            "reason": "Matched known-malicious hash"
        }

    has_suspicious_extension = check_double_extension(filename)

    if has_suspicious_extension:
        sandbox_result = simulate_detonation(file_path)

        if sandbox_result["verdict"] == "SUSPICIOUS":
            verdict = "BLOCK"
            reason = f"Disguised extension + sandbox flagged high entropy ({sandbox_result['entropy']}/8.0)"
        else:
            verdict = "ALLOW"
            reason = f"Disguised extension, but sandbox found normal entropy ({sandbox_result['entropy']}/8.0)"

        return {
            "file": filename,
            "hash": file_hash,
            "verdict": verdict,
            "reason": reason
        }

    return {
        "file": filename,
        "hash": file_hash,
        "verdict": "ALLOW",
        "reason": "No threats detected"
    }


def evaluate_url(url):
    """Runs phishing detection on a URL and returns a verdict."""
    is_phishing = check_phishing_url(url, phishing_model)

    if is_phishing:
        verdict = "BLOCK"
        reason = "Classified as phishing by ML model"
    else:
        verdict = "ALLOW"
        reason = "No phishing indicators detected"

    result = {
        "url": url,
        "verdict": verdict,
        "reason": reason
    }

    log_message = f"URL={url} | VERDICT={verdict} | REASON={reason}"
    if verdict == "BLOCK":
        from logging_module.logger import ids_logger
        ids_logger.warning(log_message)
    else:
        from logging_module.logger import ids_logger
        ids_logger.info(log_message)

    return result


if __name__ == "__main__":
    file_result = evaluate_file("data/sample.txt")
    print(file_result)
    log_verdict(file_result)

    url_result = evaluate_url("http://paypa1-account-verify.tk/login")
    print(url_result)