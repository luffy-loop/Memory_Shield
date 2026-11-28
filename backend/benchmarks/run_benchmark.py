
import json
from pathlib import Path
from datetime import datetime, timezone

from benchmarks.evaluator import SecurityEvaluator


REPORT_DIR = Path(__file__).parent / "reports"


def print_summary(summary):
    metrics = summary["detection_metrics"]

    print("\n" + "=" * 60)
    print("       MEMORYSHIELD SECURITY BENCHMARK")
    print("=" * 60)

    print(f"Evaluation mode       : {summary['evaluation_mode']}")
    print(f"Total samples         : {summary['total_samples']}")
    print(f"Correct predictions   : {summary['correct_predictions']}")
    print(f"Incorrect predictions : {summary['incorrect_predictions']}")
    print(f"Policy accuracy       : {summary['policy_accuracy']:.2%}")
    print(f"Average latency       : {summary['average_latency_ms']:.4f} ms")

    print("\nDETECTION METRICS")
    print("-" * 60)

    for name in [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
        "false_negative_rate",
        "specificity"
    ]:
        print(f"{name.replace('_', ' ').title():25}: {metrics[name]:.2%}")

    print("\nCONFUSION MATRIX")
    print("-" * 60)

    for name, value in metrics["confusion_matrix"].items():
        print(f"{name.replace('_', ' ').title():25}: {value}")

    print("\nCATEGORY ANALYSIS")
    print("-" * 60)

    for name, category in summary["category_analysis"].items():
        print(
            f"{name:25}: "
            f"{category['correct']}/{category['total']} "
            f"({category['accuracy']:.2%})"
        )

    print("\nFAILED CASES")
    print("-" * 60)

    if not summary["failures"]:
        print("No failed cases.")

    for failure in summary["failures"]:
        print(f"\nCase ID  : {failure['id']}")
        print(f"Content  : {failure['content']}")
        print(f"Expected : {failure['expected_action']}")
        print(f"Actual   : {failure['actual_action']}")
        print(f"Risk     : {failure['risk_score']}")

    print("\n" + "=" * 60)


def save_report(summary):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)

    timestamp = now.strftime("%Y%m%d_%H%M%S_%f")

    summary["generated_at"] = now.isoformat()

    report_path = REPORT_DIR / f"benchmark_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    return report_path


def main():
    evaluator = SecurityEvaluator()

    summary = evaluator.generate_summary()

    print_summary(summary)

    report_path = save_report(summary)

    print(f"\nReport saved: {report_path}")


if __name__ == "__main__":
    main()
