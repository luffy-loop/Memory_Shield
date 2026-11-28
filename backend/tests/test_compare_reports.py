
import json
import pytest
from copy import deepcopy

from benchmarks.compare_reports import (
    load_report,
    validate_comparison,
    compare_cases
)


@pytest.fixture
def report():
    return {
        "evaluation_mode": "offline",
        "results": [
            {
                "id": "TEST-001",
                "content": "Synthetic attack example",
                "category": "direct_injection",
                "label": "attack",
                "source": "user",
                "expected_action": "quarantine",
                "actual_action": "allow",
                "correct": False
            }
        ]
    }


def test_load_report(tmp_path, report):
    path = tmp_path / "report.json"

    path.write_text(
        json.dumps(report),
        encoding="utf-8"
    )

    assert load_report(path) == report


def test_matching_datasets(report):
    validate_comparison(report, deepcopy(report))


def test_different_content_rejected(report):
    current = deepcopy(report)
    current["results"][0]["content"] = "Different content"

    with pytest.raises(ValueError):
        validate_comparison(report, current)


def test_different_labels_rejected(report):
    current = deepcopy(report)
    current["results"][0]["label"] = "benign"

    with pytest.raises(ValueError):
        validate_comparison(report, current)


def test_different_modes_rejected(report):
    current = deepcopy(report)
    current["evaluation_mode"] = "online"

    with pytest.raises(ValueError):
        validate_comparison(report, current)


def test_missing_sample_rejected(report):
    current = deepcopy(report)
    current["results"] = []

    with pytest.raises(ValueError):
        validate_comparison(report, current)


def test_duplicate_ids_rejected(report):
    current = deepcopy(report)

    current["results"].append(
        deepcopy(current["results"][0])
    )

    with pytest.raises(ValueError):
        validate_comparison(report, current)


def test_newly_detected_attack(report, capsys):
    current = deepcopy(report)
    current["results"][0]["actual_action"] = "review"

    compare_cases(report, current)

    output = capsys.readouterr().out

    assert "Newly detected attacks: 1" in output
    assert "Policy improvements: 0" in output


def test_policy_improvement(report, capsys):
    current = deepcopy(report)
    current["results"][0]["actual_action"] = "quarantine"
    current["results"][0]["correct"] = True

    compare_cases(report, current)

    output = capsys.readouterr().out

    assert "Policy improvements: 1" in output


def test_policy_regression(report, capsys):
    previous = deepcopy(report)
    previous["results"][0]["actual_action"] = "quarantine"
    previous["results"][0]["correct"] = True

    compare_cases(previous, report)

    output = capsys.readouterr().out

    assert "Policy regressions: 1" in output
    assert "Lost attack detections: 1" in output
