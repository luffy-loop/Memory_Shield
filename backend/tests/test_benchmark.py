
from benchmarks.metrics import calculate_metrics
from benchmarks.evaluator import SecurityEvaluator


def test_dataset_not_empty():
    dataset = SecurityEvaluator().load_dataset()
    assert len(dataset) > 0


def test_unique_sample_ids():
    dataset = SecurityEvaluator().load_dataset()
    ids = [sample["id"] for sample in dataset]

    assert len(ids) == len(set(ids))


def test_dataset_schema():
    dataset = SecurityEvaluator().load_dataset()

    required_fields = {
        "id",
        "category",
        "label",
        "content",
        "source",
        "expected_action"
    }

    for sample in dataset:
        assert required_fields.issubset(sample)
        assert sample["label"] in {
            "benign", "attack", "sensitive"
        }
        assert sample["expected_action"] in {
            "allow", "review", "quarantine"
        }


def test_confusion_matrix():
    results = [
        {"label": "attack", "actual_action": "quarantine"},
        {"label": "benign", "actual_action": "allow"},
        {"label": "benign", "actual_action": "review"},
        {"label": "attack", "actual_action": "allow"}
    ]

    metrics = calculate_metrics(results)

    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1
    }

    assert metrics["accuracy"] == 0.5
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.5


def test_perfect_detection():
    results = [
        {"label": "attack", "actual_action": "quarantine"},
        {"label": "benign", "actual_action": "allow"}
    ]

    metrics = calculate_metrics(results)

    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0


def test_complete_detection_failure():
    results = [
        {"label": "attack", "actual_action": "allow"},
        {"label": "benign", "actual_action": "quarantine"}
    ]

    metrics = calculate_metrics(results)

    assert metrics["accuracy"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate"] == 1.0
    assert metrics["false_negative_rate"] == 1.0


def test_empty_results():
    metrics = calculate_metrics([])

    assert metrics["total_samples"] == 0
    assert metrics["accuracy"] == 0.0
    assert metrics["f1_score"] == 0.0


def test_sensitive_samples_excluded():
    results = [
        {"label": "sensitive", "actual_action": "quarantine"},
        {"label": "attack", "actual_action": "review"},
        {"label": "benign", "actual_action": "allow"}
    ]

    metrics = calculate_metrics(results)

    assert metrics["total_samples"] == 2
    assert metrics["accuracy"] == 1.0


def test_evaluator_results():
    evaluator = SecurityEvaluator()
    dataset = evaluator.load_dataset()
    results = evaluator.evaluate()

    assert len(results) == len(dataset)

    for result in results:
        assert 0 <= result["risk_score"] <= 100
        assert result["latency_ms"] >= 0
        assert result["actual_action"] in {
            "allow", "review", "quarantine"
        }


def test_summary_consistency():
    summary = SecurityEvaluator().generate_summary()

    assert summary["total_samples"] == (
        summary["correct_predictions"]
        + summary["incorrect_predictions"]
    )

    assert len(summary["failures"]) == (
        summary["incorrect_predictions"]
    )


def test_category_analysis():
    evaluator = SecurityEvaluator()
    results = evaluator.evaluate()
    categories = evaluator.category_analysis(results)

    assert sum(
        category["total"]
        for category in categories.values()
    ) == len(results)

    for category in categories.values():
        assert category["total"] == (
            category["correct"] + category["incorrect"]
        )

        assert 0 <= category["accuracy"] <= 1
