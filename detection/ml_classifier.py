import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

def extract_features(url):
    """Converts a URL into numeric features, including entropy and character-composition signals."""
    from urllib.parse import urlparse
    import math
    from collections import Counter

    parsed = urlparse(url)
    sensitive_words = ["login", "verify", "secure", "account", "update", "confirm", "signin"]

    features = {}
    features["url_length"] = len(url)
    features["valid_url"] = 1 if parsed.scheme and parsed.netloc else 0
    features["at_symbol"] = 1 if "@" in url else 0
    features["sensitive_words_count"] = sum(1 for word in sensitive_words if word in url.lower())
    features["path_length"] = len(parsed.path)
    features["isHttps"] = 1 if url.startswith("https") else 0
    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_and"] = url.count("&")
    features["nb_or"] = url.count("|")
    features["nb_www"] = url.lower().count("www")
    features["nb_com"] = url.lower().count(".com")
    features["nb_underscore"] = url.count("_")
    features["num_subdirs"] = url.count("/")
    features["digits_count"] = sum(1 for ch in url if ch.isdigit())
    features["special_char_count"] = sum(1 for ch in url if ch in "!#$%^&*()+=[]{};:,<>?")

    if len(url) > 0:
        counts = Counter(url)
        entropy = -sum((c / len(url)) * math.log2(c / len(url)) for c in counts.values())
        features["url_entropy"] = round(entropy, 3)
    else:
        features["url_entropy"] = 0.0

    return features


def build_combined_dataset(sample_size=15000):
    """Builds a balanced training dataset from PhiUSIIL only, avoiding the bare-domain artifact in the other source."""
    df2 = pd.read_csv("data/phiusiil_raw.csv")

    df2_urls = df2[["URL", "label"]].rename(columns={"URL": "url"})
    df2_urls["label"] = df2_urls["label"].apply(lambda x: 0 if x == 1 else 1)  # flip: phiusiil 1=legit -> our 0

    phishing = df2_urls[df2_urls["label"] == 1].sample(n=sample_size, random_state=42)
    legitimate = df2_urls[df2_urls["label"] == 0].sample(n=sample_size, random_state=42)

    balanced = pd.concat([phishing, legitimate], ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

    print("Extracting features from URLs, this may take a moment...")
    feature_rows = [extract_features(str(url)) for url in balanced["url"]]
    X = pd.DataFrame(feature_rows)
    y = balanced["label"]

    result = X.copy()
    result["target"] = y

    result.to_csv("data/combined_training_data.csv", index=False)
    print(f"Saved combined dataset: {len(result)} rows to data/combined_training_data.csv")

    return result
def train_model(csv_path):
    """Trains a phishing classifier from a CSV with pre-computed features and a target column."""
    data = pd.read_csv(csv_path)

    X = data.drop(columns=["target"])
    y = data["target"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()

    print(f"Model trained on {len(X_train)} examples, tested on {len(X_test)}.")
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}  (of URLs flagged as phishing, % that really were)")
    print(f"Recall:    {recall:.2%}  (of actual phishing URLs, % that were caught)")
    print(f"Confusion matrix -> True Negatives: {tn}, False Positives: {fp}, False Negatives: {fn}, True Positives: {tp}")

    return model 

def show_feature_importance(model, feature_names):
    """Prints which features the model relies on most heavily."""
    importances = model.feature_importances_
    ranked = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)

    print("\nFeature importance (highest impact first):")
    for name, importance in ranked:
        print(f"  {name}: {importance:.3f}")       

import joblib

MODEL_PATH = "data/phishing_model.pkl"


def save_model(model, path=MODEL_PATH):
    """Saves a trained model to disk so we don't need to retrain every time."""
    joblib.dump(model, path)


def load_model(path=MODEL_PATH):
    """Loads a previously trained model from disk."""
    return joblib.load(path)


def check_phishing_url(url, model):
    """Returns True if the model classifies this URL as phishing."""
    features = extract_features(url)
    X = pd.DataFrame([features])
    prediction = model.predict(X)[0]
    return prediction == 1    

if __name__ == "__main__":
    build_combined_dataset(sample_size=15000)

    model = train_model("data/combined_training_data.csv")
    save_model(model)

    feature_names = ["url_length", "valid_url", "at_symbol", "sensitive_words_count",
                      "path_length", "isHttps", "nb_dots", "nb_hyphens", "nb_and",
                      "nb_or", "nb_www", "nb_com", "nb_underscore", "num_subdirs",
                      "digits_count", "special_char_count", "url_entropy"]
    show_feature_importance(model, feature_names)

    test_url = "http://faceb00k-login-verify.tk/account"
    result = check_phishing_url(test_url, model)
    print(f"{test_url} -> Phishing: {result}")

    linkedin_url = "https://www.linkedin.com/in/jackson-karanja-6655b5303/"
    linkedin_result = check_phishing_url(linkedin_url, model)
    print(f"{linkedin_url} -> Phishing: {linkedin_result}")