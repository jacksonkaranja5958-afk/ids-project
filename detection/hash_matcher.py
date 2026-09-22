import hashlib

def compute_file_hash(file_path):
    """Reads a file and returns its SHA-256 hash as a hex string."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
}

def check_hash(file_hash):
    """Returns True if the hash matches a known-malicious hash."""
    return file_hash in KNOWN_MALICIOUS_HASHES


if __name__ == "__main__":
    test_file = "data/sample.txt"
    file_hash = compute_file_hash(test_file)
    print(f"SHA-256 hash: {file_hash}")

    is_malicious = check_hash(file_hash)
    print(f"Malicious: {is_malicious}")