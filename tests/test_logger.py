import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from logging_module.logger import log_verdict, LOG_FILE


def test_log_verdict_writes_to_file():
    fake_result = {
        "file": "test_file.txt",
        "hash": "abc123",
        "verdict": "ALLOW",
        "reason": "Test entry"
    }

    log_verdict(fake_result)

    with open(LOG_FILE, "r") as f:
        contents = f.read()

    assert "test_file.txt" in contents
    assert "ALLOW" in contents