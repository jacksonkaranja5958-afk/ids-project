import pandas as pd

df1 = pd.read_csv("data/phishing_features_raw.csv")
df2 = pd.read_csv("data/phiusiil_raw.csv")

legit1 = df1[df1["label"] == 0]["url"].astype(str)
legit2 = df2[df2["label"] == 1]["URL"].astype(str)
phish1 = df1[df1["label"] == 1]["url"].astype(str)

print("phishing_features legit URLs with a path (contains /):", (legit1.str.contains("/")).mean())
print("phiusiil legit URLs with a path (contains /):", (legit2.str.contains("/")).mean())
print("phishing_features PHISHING URLs with a path (contains /):", (phish1.str.contains("/")).mean())
phish2 = df2[df2["label"] == 0]["URL"].astype(str)
print("phiusiil PHISHING URLs with a path (contains /):", (phish2.str.contains("/")).mean())

import pandas as pd

df2 = pd.read_csv("data/phiusiil_raw.csv")

legit = df2[df2["label"] == 1]["URL"].astype(str)
phish = df2[df2["label"] == 0]["URL"].astype(str)

print("PhiUSIIL legit URLs using https:", (legit.str.startswith("https")).mean())
print("PhiUSIIL phishing URLs using https:", (phish.str.startswith("https")).mean())