from pathlib import Path

import joblib

from app.email_parser import analyze_email


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models/phishing_model.joblib"


def predict_email(file_path):
    model = joblib.load(MODEL_PATH)

    email_data = analyze_email(file_path)

    text = (
        email_data["subject"]
        + "\n"
        + email_data["body"]
    ).strip()

    if not text:
        raise ValueError("Email has no text to analyze")

    probability = float(
        model.predict_proba([text])[0][1]
    )

    prediction = (
        "Phishing" if probability >= 0.5 else "Safe"
    )

    return {
        "prediction": prediction,
        "phishing_probability": round(probability, 4),
        "model": "TF-IDF + Logistic Regression"
    }
