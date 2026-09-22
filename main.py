import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from engine.decision_engine import evaluate_file, evaluate_url
from logging_module.logger import log_verdict


def print_result(result):
    print("-" * 50)
    for key, value in result.items():
        print(f"{key}: {value}")
    print("-" * 50)


def run_file_check(file_path):
    if not os.path.exists(file_path):
        print(f"Error: file not found at '{file_path}'")
        return

    result = evaluate_file(file_path)
    log_verdict(result)
    print_result(result)


def run_url_check(url):
    result = evaluate_url(url)
    print_result(result)


def main():
    print("IDS — Phishing & Malware Detection System")
    print("=" * 50)
    print("1. Check a file")
    print("2. Check a URL")
    print("3. Exit")

    choice = input("Choose an option (1-3): ").strip()

    if choice == "1":
        file_path = input("Enter file path (e.g. data/sample.txt): ").strip()
        run_file_check(file_path)
    elif choice == "2":
        url = input("Enter URL: ").strip()
        run_url_check(url)
    elif choice == "3":
        print("Goodbye.")
        sys.exit()
    else:
        print("Invalid option.")

    main()  # loop back to the menu after each check


if __name__ == "__main__":
    main()