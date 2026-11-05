from pathlib import Path

import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_FILE = BASE_DIR / "data" / "train.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_FILE = MODEL_DIR / "phishing_model.joblib"


def train_model():
    print("Loading training dataset...")

    df = pd.read_csv(TRAIN_FILE)

    X_train = df["Email Text"].fillna("")
    y_train = df["Email Type"].map({
        "Safe Email": 0,
        "Phishing Email": 1
    })

    if y_train.isna().any():
        raise ValueError("Unknown email label found")

    y_train = y_train.astype(int)

    print(f"Training samples: {len(df)}")

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                max_features=30000,
                min_df=2,
                ngram_range=(1, 2),
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=42
            )
        )
    ])

    print("Training model...")

    model.fit(X_train, y_train)

    MODEL_DIR.mkdir(exist_ok=True)

    joblib.dump(model, MODEL_FILE)

    print("Training completed successfully")
    print(f"Model saved: {MODEL_FILE}")


if __name__ == "__main__":
    train_model()
