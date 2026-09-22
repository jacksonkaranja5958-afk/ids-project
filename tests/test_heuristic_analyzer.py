import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.heuristic_analyzer import check_double_extension


def test_detects_disguised_executable():
    assert check_double_extension("invoice.pdf.exe") is True


def test_detects_disguised_screensaver():
    assert check_double_extension("photo.jpg.scr") is True


def test_allows_normal_document():
    assert check_double_extension("report.docx") is False


def test_case_insensitive_detection():
    assert check_double_extension("INVOICE.PDF.EXE") is True