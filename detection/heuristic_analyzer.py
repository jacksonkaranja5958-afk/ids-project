import os

SAFE_LOOKING_EXTENSIONS = [".pdf", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".txt", ".xlsx", ".mp3", ".mp4"]
DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1"]

def check_double_extension(filename):
    """Returns True if the filename disguises a dangerous extension behind a safe-looking one."""
    filename_lower = filename.lower()
    name_parts = filename_lower.split(".")

    if len(name_parts) < 3:
        return False  # needs at least name.safe.dangerous to be suspicious

    last_ext = "." + name_parts[-1]
    second_last_ext = "." + name_parts[-2]

    return second_last_ext in SAFE_LOOKING_EXTENSIONS and last_ext in DANGEROUS_EXTENSIONS


if __name__ == "__main__":
    test_names = ["invoice.pdf.exe", "report.docx", "photo.jpg.exe", "notes.txt"]

    for name in test_names:
        result = check_double_extension(name)
        print(f"{name} -> Suspicious: {result}")