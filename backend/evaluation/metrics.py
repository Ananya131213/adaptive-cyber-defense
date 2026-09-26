"""Evaluation helpers for detection quality metrics."""


def calculate_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    """Calculate precision, recall, and false-positive rate."""
    from sklearn.metrics import confusion_matrix, precision_score, recall_score

    true_negative, false_positive, false_negative, true_positive = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()
    negatives = true_negative + false_positive
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(false_positive / negatives) if negatives else 0.0,
    }