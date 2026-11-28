
import json
import argparse
from pathlib import Path


def load_report(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def validate_comparison(old, new):
    fields = (
        "id", "content", "category",
        "label", "source", "expected_action"
    )

    def dataset_signature(report):
        results = report["results"]

        signature = {
            row["id"]: tuple(row[field] for field in fields)
            for row in results
        }

        if len(signature) != len(results):
            raise ValueError("Duplicate sample IDs found.")

        return signature

    if dataset_signature(old) != dataset_signature(new):
        raise ValueError("Reports use different datasets.")

    if old["evaluation_mode"] != new["evaluation_mode"]:
        raise ValueError("Evaluation modes do not match.")


def compare_metrics(old, new):
    metrics = [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "false_negative_rate",
        "specificity"
    ]

    print("\nDETECTION METRICS")
    print("-" * 75)

    print(
        f"{'Metric':25}"
        f"{'Baseline':>12}"
        f"{'Current':>12}"
        f"{'Change (pp)':>15}"
    )

    for metric in metrics:
        before = old["detection_metrics"][metric] * 100
        after = new["detection_metrics"][metric] * 100
        change = after - before

        print(
            f"{metric:25}"
            f"{before:11.2f}%"
            f"{after:11.2f}%"
            f"{change:14.2f}"
        )


def compare_policy(old, new):
    before = old["policy_accuracy"] * 100
    after = new["policy_accuracy"] * 100

    print("\nPOLICY ACCURACY")
    print("-" * 75)
    print(f"Baseline : {before:.2f}%")
    print(f"Current  : {after:.2f}%")
    print(f"Change   : {after - before:+.2f} pp")


def compare_latency(old, new):
    before = old["average_latency_ms"]
    after = new["average_latency_ms"]

    print("\nLATENCY COMPARISON")
    print("-" * 75)
    print(f"Baseline : {before:.4f} ms")
    print(f"Current  : {after:.4f} ms")
    print(f"Change   : {after - before:+.4f} ms")


def compare_cases(old, new):
    previous = {
        row["id"]: row
        for row in old["results"]
    }

    improved = []
    regressed = []
    newly_detected = []
    missed_attacks = []

    for current in new["results"]:
        before = previous[current["id"]]

        if not before["correct"] and current["correct"]:
            improved.append(current["id"])

        elif before["correct"] and not current["correct"]:
            regressed.append(current["id"])

        if current["label"] == "attack":
            old_detected = before["actual_action"] != "allow"
            new_detected = current["actual_action"] != "allow"

            if not old_detected and new_detected:
                newly_detected.append(current["id"])

            elif old_detected and not new_detected:
                missed_attacks.append(current["id"])

    print("\nCASE-LEVEL ANALYSIS")
    print("-" * 75)

    groups = {
        "Policy improvements": improved,
        "Policy regressions": regressed,
        "Newly detected attacks": newly_detected,
        "Lost attack detections": missed_attacks
    }

    for name, cases in groups.items():
        print(f"{name}: {len(cases)}")

        if cases:
            print("  " + ", ".join(cases))


def main():
    parser = argparse.ArgumentParser(
        description="Compare MemoryShield benchmark reports"
    )

    parser.add_argument("baseline", type=Path)
    parser.add_argument("current", type=Path)

    args = parser.parse_args()

    old = load_report(args.baseline)
    new = load_report(args.current)

    validate_comparison(old, new)

    print("=" * 75)
    print("MEMORYSHIELD BENCHMARK COMPARISON")
    print("=" * 75)

    compare_metrics(old, new)
    compare_policy(old, new)
    compare_latency(old, new)
    compare_cases(old, new)

    print("\n" + "=" * 75)


if __name__ == "__main__":
    main()
