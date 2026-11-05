from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = BASE_DIR / "models/phishing_model.joblib"
TEST_FILE = BASE_DIR / "data/test.csv"


def evaluate_model():
    print("Loading trained model...")

    model = joblib.load(MODEL_FILE)
    df = pd.read_csv(TEST_FILE)

    X_test = df["Email Text"].fillna("")
    y_test = df["Email Type"].map({
        "Safe Email": 0,
        "Phishing Email": 1
    })

    if y_test.isna().any():
        raise ValueError("Unknown email label found")

    y_test = y_test.astype(int)

    print(f"Testing samples: {len(df)}")
    print("Evaluating model...\n")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0

    print("========== MODEL RESULTS ==========")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")

    print("\n========== CONFUSION MATRIX ==========")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Positives:  {tp}")

    print("\n========== CLASSIFICATION REPORT ==========")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Safe Email", "Phishing Email"],
        zero_division=0
    ))


if __name__ == "__main__":
    evaluate_model()
