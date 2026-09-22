import logging
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "ids_activity.log")

os.makedirs(LOG_DIR, exist_ok=True)

ids_logger = logging.getLogger("ids_logger")
ids_logger.setLevel(logging.INFO)

if not ids_logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    ids_logger.addHandler(file_handler)


def log_verdict(result):
    """Writes a decision engine result to the log file."""
    message = f"FILE={result['file']} | HASH={result['hash']} | VERDICT={result['verdict']} | REASON={result['reason']}"

    if result["verdict"] == "BLOCK":
        ids_logger.warning(message)
    else:
        ids_logger.info(message)