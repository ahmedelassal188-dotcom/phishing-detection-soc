import csv
from pathlib import Path

from app.email_parser import analyze_email
from app.feature_extractor import extract_features


PROJECT_DIR = Path(__file__).resolve().parent.parent


def build_dataset():
    labels_file = PROJECT_DIR / "data/test_labels.csv"
    output_file = PROJECT_DIR / "data/features.csv"

    rows = []

    with open(labels_file, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for record in reader:
            email_path = PROJECT_DIR / record["file_path"]

            email_data = analyze_email(email_path)
            features = extract_features(email_data)

            features["label"] = record["label"]
            rows.append(features)

    if not rows:
        raise ValueError("No email samples found")

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"Dataset created: {output_file}")
    print(f"Total samples: {len(rows)}")


if __name__ == "__main__":
    build_dataset()
