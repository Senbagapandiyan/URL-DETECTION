import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_COLUMNS, extract_features

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "phishing_model.pkl"


def preprocess_dataset(df):
    """Clean the dataset and convert it into model-ready features."""
    df = df.copy()

    if set(FEATURE_COLUMNS).issubset(df.columns):
        feature_frame = df[FEATURE_COLUMNS].copy()
    else:
        feature_rows = []
        for value in df.get("url", []):
            feature_dict, _ = extract_features(value)
            feature_rows.append(feature_dict)
        feature_frame = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)

    feature_frame = feature_frame.apply(pd.to_numeric, errors="coerce")

    imputer = SimpleImputer(strategy="median")
    features = pd.DataFrame(imputer.fit_transform(feature_frame), columns=FEATURE_COLUMNS)

    labels = df["label"].astype(str).str.strip().fillna("Phishing")
    labels = labels.replace({"legitimate": "Legitimate", "phishing": "Phishing", "0": "Legitimate", "1": "Phishing"})
    encoded_labels = labels.map({"Legitimate": 0, "Phishing": 1}).fillna(1)

    return features, encoded_labels


def main():
    """Train the Random Forest model and export the trained artifact."""
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} rows from {DATASET_PATH}")

    X, y = preprocess_dataset(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"Model accuracy: {accuracy * 100:.2f}%")

    joblib.dump({"model": model, "feature_names": FEATURE_COLUMNS, "accuracy": round(float(accuracy * 100), 2)}, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
