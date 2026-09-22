import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.sandbox import calculate_entropy, simulate_detonation


def test_entropy_of_empty_file(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")
    entropy = calculate_entropy(str(empty_file))
    assert entropy == 0.0


def test_entropy_of_repetitive_data(tmp_path):
    repetitive_file = tmp_path / "repetitive.txt"
    repetitive_file.write_bytes(b"a" * 1000)
    entropy = calculate_entropy(str(repetitive_file))
    assert entropy < 1.0  # all identical bytes = near-zero entropy


def test_entropy_of_random_data(tmp_path):
    random_file = tmp_path / "random.bin"
    random_file.write_bytes(os.urandom(5000))
    entropy = calculate_entropy(str(random_file))
    assert entropy > 7.0  # random bytes = near-maximum entropy


def test_simulate_detonation_flags_high_entropy(tmp_path):
    random_file = tmp_path / "random.bin"
    random_file.write_bytes(os.urandom(5000))
    result = simulate_detonation(str(random_file))
    assert result["verdict"] == "SUSPICIOUS"


def test_simulate_detonation_clears_low_entropy(tmp_path):
    text_file = tmp_path / "text.txt"
    text_file.write_bytes(b"Hello world, this is normal text." * 10)
    result = simulate_detonation(str(text_file))
    assert result["verdict"] == "CLEAN"