import pandas as pd
from detection.ml_classifier import extract_features

df = pd.read_csv("data/phiusiil_raw.csv")
df_urls = df[["URL", "label"]].rename(columns={"URL": "url"})
df_urls["label"] = df_urls["label"].apply(lambda x: 0 if x == 1 else 1)

sample = df_urls.sample(n=3000, random_state=42)
feature_rows = [extract_features(str(u)) for u in sample["url"]]
features_df = pd.DataFrame(feature_rows)
features_df["label"] = sample["label"].values

legit_avg = features_df[features_df["label"] == 0].mean(numeric_only=True)
phish_avg = features_df[features_df["label"] == 1].mean(numeric_only=True)

linkedin_features = extract_features("https://jackpage1.onrender.com")
print(f"{'Feature':<22} {'LinkedIn':<12} {'Legit avg':<12} {'Phishing avg':<12}")
for key in linkedin_features:
    print(f"{key:<22} {linkedin_features[key]:<12} {round(legit_avg[key], 2):<12} {round(phish_avg[key], 2):<12}")