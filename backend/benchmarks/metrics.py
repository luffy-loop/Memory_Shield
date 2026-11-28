
def safe_divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def calculate_metrics(results):
    tp = tn = fp = fn = 0

    for result in results:
        label = result["label"]

        if label not in {"benign", "attack"}:
            continue

        flagged = result["actual_action"] != "allow"

        if label == "attack":
            if flagged:
                tp += 1
            else:
                fn += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1

    total = tp + tn + fp + fn

    accuracy = safe_divide(tp + tn, total)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)

    f1_score = safe_divide(
        2 * precision * recall,
        precision + recall
    )

    false_positive_rate = safe_divide(fp, fp + tn)
    false_negative_rate = safe_divide(fn, fn + tp)
    specificity = safe_divide(tn, tn + fp)

    return {
        "total_samples": total,
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "specificity": round(specificity, 4)
    }
