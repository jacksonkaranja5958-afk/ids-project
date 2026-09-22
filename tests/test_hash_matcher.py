import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.hash_matcher import compute_file_hash, check_hash


def test_compute_file_hash():
    test_file = "data/sample.txt"
    result = compute_file_hash(test_file)
    assert isinstance(result, str)
    assert len(result) == 64  # SHA-256 is always 64 hex characters


def test_check_hash_true_case():
    fake_hash = "known_bad_hash_example"
    result = check_hash(fake_hash)
    assert result is False  # this hash isn't in our blocklist, so should be False


def test_check_hash_with_real_entry():
    from detection.hash_matcher import KNOWN_MALICIOUS_HASHES
    sample_hash = next(iter(KNOWN_MALICIOUS_HASHES))
    result = check_hash(sample_hash)
    assert result is True  # this one IS in the blocklist