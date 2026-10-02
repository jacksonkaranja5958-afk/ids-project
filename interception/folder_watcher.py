import sys
import os

_log_dir = os.path.dirname(os.path.abspath(__file__))
_error_log_path = os.path.join(_log_dir, "watcher_errors.log")
sys.stdout = open(_error_log_path, "a")
sys.stderr = sys.stdout

import time
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine.decision_engine import evaluate_file
from logging_module.logger import log_verdict

# ... (rest of the file stays exactly the same as before)


from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine.decision_engine import evaluate_file
from logging_module.logger import log_verdict

DOWNLOADS_PATH = os.path.expanduser("~\\Downloads")

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "watcher.log"),
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        filename = os.path.basename(file_path)

        if filename.endswith((".crdownload", ".tmp", ".part")):
            return

        logging.info(f"NEW FILE DETECTED: {filename}")
        time.sleep(1)

        try:
            result = evaluate_file(file_path)
            log_verdict(result)
            logging.info(f"Verdict: {result['verdict']} - {result['reason']}")

            if result["verdict"] == "BLOCK":
                logging.warning(f"THREAT BLOCKED: {filename}")

        except Exception as e:
            logging.error(f"Error scanning {filename}: {e}")


def start_watching():
    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, DOWNLOADS_PATH, recursive=False)
    observer.start()

    logging.info(f"SentinelX watcher started - monitoring {DOWNLOADS_PATH}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_watching()