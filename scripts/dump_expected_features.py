import joblib

# Load preprocessing pipeline
preprocess = joblib.load("ml/preprocess.pkl")

try:
    cols = preprocess.feature_names_in_
except:
    cols = preprocess.get_feature_names_out()

with open("expected_features.txt", "w") as f:
    for col in cols:
        f.write(col + "\n")

print("Saved expected_features.txt")
print("Number of features:", len(cols))

