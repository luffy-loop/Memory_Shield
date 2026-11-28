
import json
from pathlib import Path

from app.security.semantic_detector import SemanticDetector
from benchmarks.metrics import calculate_metrics


DATASET_PATH = (
    Path(__file__).parent / "holdout_dataset.json"
)


def main():
    with open(DATASET_PATH, encoding="utf-8") as file:
        dataset = json.load(file)

    detector = SemanticDetector()
    results = []

    print("=" * 65)
    print("MEMORYSHIELD SEMANTIC DETECTOR EVALUATION")
    print("=" * 65)

    for sample in dataset:
        result = detector.detect(sample["content"])

        score = result["score"]

        if score >= 60:
            action = "quarantine"
        elif score >= 30:
            action = "review"
        else:
            action = "allow"

        detected = action != "allow"
        expected = sample["label"] == "attack"

        correct = detected == expected

        results.append({
            "id": sample["id"],
            "label": sample["label"],
            "actual_action": action
        })

        status = "PASS" if correct else "FAIL"

        print(f"\n{sample['id']} | {status}")
        print(f"Content: {sample['content']}")
        print(f"Label: {sample['label']}")
        print(f"Score: {score}")
        print(f"Action: {action}")
        print(f"Intents: {result['matches']}")

    metrics = calculate_metrics(results)

    print("\n" + "=" * 65)
    print("EVALUATION METRICS")
    print("=" * 65)

    print(json.dumps(metrics, indent=4))


if __name__ == "__main__":
    main()
