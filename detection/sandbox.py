import math
import os
import time
from collections import Counter


def calculate_entropy(file_path):
    """Calculates Shannon entropy of a file's byte content (0 = predictable, 8 = random)."""
    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) == 0:
        return 0.0

    byte_counts = Counter(data)
    file_size = len(data)

    entropy = 0.0
    for count in byte_counts.values():
        probability = count / file_size
        entropy -= probability * math.log2(probability)

    return entropy

ENTROPY_THRESHOLD = 6.5


def simulate_detonation(file_path):
    """
    Simulates sandbox detonation using static entropy analysis.
    NOTE: This is a simplified stand-in for real sandbox detonation, which
    would execute the file in an isolated VM and monitor actual behavior
    (process creation, registry/file writes, network calls). This function
    only estimates risk from file structure, and does not execute anything.
    """
    time.sleep(1)  # simulates the real time cost of a detonation, for realism

    entropy = calculate_entropy(file_path)
    file_size = os.path.getsize(file_path)

    likely_packed_or_encrypted = entropy >= ENTROPY_THRESHOLD

    if likely_packed_or_encrypted:
        verdict = "SUSPICIOUS"
        reason = f"High entropy ({entropy:.2f}/8.0) suggests packed or encrypted content"
    else:
        verdict = "CLEAN"
        reason = f"Low entropy ({entropy:.2f}/8.0), consistent with normal, unpacked content"

    return {
        "file": os.path.basename(file_path),
        "entropy": round(entropy, 2),
        "file_size_bytes": file_size,
        "verdict": verdict,
        "reason": reason,
        "note": "Simulated analysis — not a real sandbox detonation"
    }    

if __name__ == "__main__":
    result = simulate_detonation("data/sample.txt")
    print(result)   