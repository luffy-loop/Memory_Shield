
import json
from pathlib import Path
from collections import Counter

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from app.security.normalizer import TextNormalizer


BASE = Path(__file__).resolve().parent
DATASET = BASE / "data" / "training_dataset.json"
MODEL = BASE / "models" / "tfidf_classifier.joblib"
REPORT = BASE / "reports" / "tfidf_baseline.json"


def build_model():
    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                sublinear_tf=True
            )),
            ("char", TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                sublinear_tf=True
            ))
        ])),
        ("classifier", LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=42
        ))
    ])


def main():
    rows = json.loads(DATASET.read_text(encoding="utf-8"))

    normalizer = TextNormalizer()

    texts = [row["content"] for row in rows]
    labels = [row["label"] for row in rows]

    groups = [
        normalizer.normalize_for_detection(text)
        for text in texts
    ]

    splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=42
    )

    train_idx, val_idx = next(
        splitter.split(texts, labels, groups)
    )

    X_train = [texts[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]

    X_val = [texts[i] for i in val_idx]
    y_val = [labels[i] for i in val_idx]

    train_groups = {groups[i] for i in train_idx}
    val_groups = {groups[i] for i in val_idx}

    overlap = train_groups & val_groups

    assert not overlap, "Dataset leakage detected"

    model = build_model()
    model.fit(X_train, y_train)

    predictions = model.predict(X_val)

    accuracy = accuracy_score(y_val, predictions)

    metrics = classification_report(
        y_val,
        predictions,
        labels=["benign", "attack"],
        output_dict=True,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_val,
        predictions,
        labels=["benign", "attack"]
    )

    failures = [
        {
            "id": rows[i]["id"],
            "category": rows[i]["category"],
            "content": texts[i],
            "expected": labels[i],
            "predicted": prediction
        }
        for i, prediction in zip(val_idx, predictions)
        if labels[i] != prediction
    ]

    report = {
        "model": "TF-IDF + Logistic Regression",
        "evaluation_type": "grouped development validation",
        "total_samples": len(rows),
        "unique_normalized_texts": len(set(groups)),
        "training_samples": len(X_train),
        "validation_samples": len(X_val),
        "training_distribution": dict(Counter(y_train)),
        "validation_distribution": dict(Counter(y_val)),
        "normalized_overlap": len(overlap),
        "accuracy": accuracy,
        "classification_report": metrics,
        "confusion_matrix": matrix.tolist(),
        "failures": failures
    }

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL)

    REPORT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("=" * 60)
    print("MEMORYSHIELD ML BASELINE")
    print("=" * 60)

    print("Total samples:", len(rows))
    print("Training samples:", len(X_train))
    print("Validation samples:", len(X_val))
    print("Normalized overlap:", len(overlap))
    print("Accuracy:", f"{accuracy:.2%}")

    print("\nClassification report:")
    print(classification_report(
        y_val,
        predictions,
        zero_division=0
    ))

    print("Confusion matrix:")
    print(matrix)

    print("\nIncorrect predictions:", len(failures))
    print("Model saved:", MODEL)
    print("Report saved:", REPORT)


if __name__ == "__main__":
    main()
