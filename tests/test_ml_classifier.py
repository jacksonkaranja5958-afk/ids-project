import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.ml_classifier import extract_features, train_model, check_phishing_url


def test_extract_features_returns_expected_keys():
    features = extract_features("https://www.google.com")
    expected_keys = {"url_length", "valid_url", "at_symbol", "sensitive_words_count",
                      "path_length", "isHttps", "nb_dots", "nb_hyphens", "nb_and",
                      "nb_or", "nb_www", "nb_com", "nb_underscore", "num_subdirs",
                      "digits_count", "special_char_count", "url_entropy"}
    assert set(features.keys()) == expected_keys


def test_https_detected_correctly():
    features = extract_features("https://www.google.com")
    assert features["isHttps"] == 1


def test_http_not_flagged_as_https():
    features = extract_features("http://example.com")
    assert features["isHttps"] == 0


def test_entropy_is_higher_for_random_looking_url():
    normal = extract_features("https://www.google.com")
    random_like = extract_features("http://xk39fj2-slkq93jd-verify.tk/a1b2c3")
    assert random_like["url_entropy"] >= normal["url_entropy"]


def test_model_flags_known_phishing_pattern():
    model = train_model("data/combined_training_data.csv")
    result = check_phishing_url("http://192.168.5.5/paypal-verify-login", model)
    assert result == True