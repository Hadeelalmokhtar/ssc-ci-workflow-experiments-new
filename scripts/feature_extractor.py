import os
import re
import pandas as pd
import math

# Resolve root path safely
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
expected_path = os.path.join(BASE_DIR, "expected_features.txt")

with open(expected_path, "r") as f:
    expected_features = [line.strip() for line in f.readlines()]

# Shannon entropy
def shannon_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
    return -sum([p * math.log2(p) for p in prob])


def extract_features(file_path):

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
    except:
        content = ""

    lines = content.splitlines()
    feature_dict = {}

    # Numeric features
    feature_dict["file_size"] = len(content)
    feature_dict["num_lines"] = len(lines)
    feature_dict["num_chars"] = len(content)
    feature_dict["num_digits"] = sum(c.isdigit() for c in content)
    feature_dict["num_uppercase"] = sum(c.isupper() for c in content)
    feature_dict["num_special_chars"] = len(re.findall(r"[^\w\s]", content))

    suspicious_keywords = [
        "eval", "exec", "base64", "powershell",
        "wget", "curl", "chmod", "crypto",
        "wallet", "token", "hook"
    ]

    for keyword in suspicious_keywords:
        feature_dict[f"kw_{keyword}"] = content.lower().count(keyword)

    feature_dict["num_urls"] = len(re.findall(r"http[s]?://", content))
    feature_dict["num_ips"] = len(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", content))
    feature_dict["entropy"] = shannon_entropy(content[:5000])

    # IMPORTANT: ensure categorical column exists if model expects it
    if "Package Repository" in expected_features:
        feature_dict["Package Repository"] = "unknown"

    # Fill missing expected features
    for feature in expected_features:
        if feature not in feature_dict:
            feature_dict[feature] = 0

    # Create dataframe strictly ordered
    features_df = pd.DataFrame(
        [[feature_dict[col] for col in expected_features]],
        columns=expected_features
    )

    # Cast numeric only
    for col in features_df.columns:
        if col != "Package Repository":
            features_df[col] = features_df[col].astype("int64")

    return features_df


