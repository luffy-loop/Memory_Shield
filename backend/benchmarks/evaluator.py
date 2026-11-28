
import json
from pathlib import Path
from collections import defaultdict
from time import perf_counter

from app.security.guard import MemoryGuard
from benchmarks.metrics import calculate_metrics


DATASET_PATH = Path(__file__).parent / "dataset.json"


class OfflineMemoryGuard(MemoryGuard):
    def _learned_attack(self, content):
        return False


class SecurityEvaluator:

    def __init__(self, dataset_path=DATASET_PATH):
        self.dataset_path = Path(dataset_path)
        self.guard = OfflineMemoryGuard()

    def load_dataset(self):
        with self.dataset_path.open(encoding="utf-8") as file:
            return json.load(file)

    def evaluate(self):
        dataset = self.load_dataset()
        results = []

        for sample in dataset:
            start = perf_counter()

            prediction = self.guard.analyze(
                sample["content"],
                sample["source"]
            )

            latency = (perf_counter() - start) * 1000

            results.append({
                "id": sample["id"],
                "category": sample["category"],
                "label": sample["label"],
                "content": sample["content"],
                "source": sample["source"],
                "expected_action": sample["expected_action"],
                "actual_action": prediction["action"],
                "risk_score": prediction["score"],
                "findings": prediction["findings"],
                "correct": (
                    sample["expected_action"] == prediction["action"]
                ),
                "latency_ms": round(latency, 4)
            })

        return results

    def category_analysis(self, results):
        categories = defaultdict(
            lambda: {"total": 0, "correct": 0, "incorrect": 0}
        )

        for result in results:
            category = categories[result["category"]]

            category["total"] += 1

            if result["correct"]:
                category["correct"] += 1
            else:
                category["incorrect"] += 1

        for category in categories.values():
            category["accuracy"] = round(
                category["correct"] / category["total"], 4
            )

        return dict(categories)

    def generate_summary(self):
        results = self.evaluate()

        total = len(results)
        correct = sum(result["correct"] for result in results)

        failures = [
            result for result in results
            if not result["correct"]
        ]

        return {
            "evaluation_mode": "offline",
            "total_samples": total,
            "correct_predictions": correct,
            "incorrect_predictions": total - correct,
            "policy_accuracy": round(correct / total, 4) if total else 0,
            "average_latency_ms": round(
                sum(r["latency_ms"] for r in results) / total, 4
            ) if total else 0,
            "detection_metrics": calculate_metrics(results),
            "category_analysis": self.category_analysis(results),
            "failures": failures,
            "results": results
        }
