# Security evaluation

The offline regression suite uses eight synthetic labelled examples: three benign, three attack, and two sensitive-memory cases. It checks exact allow/review/quarantine decisions. Learned Hindsight signals are disabled for reproducibility.

For the six benign/attack examples, review and quarantine count as flagged. True positives are flagged attacks, false negatives are allowed attacks, false positives are flagged benign examples, and true negatives are allowed benign examples.

- Detection rate (recall): TP / (TP + FN)
- False positive rate: FP / (FP + TN)
- Precision: TP / (TP + FP), when the denominator is nonzero

Run from backend:

```bash
python -m pip install -r requirements.txt
python -m pip install pytest httpx
python -m pytest tests/test_security_evaluation.py -v
```

The expected regression outcome is zero false positives and false negatives on these six examples. This is a test expectation, not a measured deployment result. The examples are small and selected for known policy behavior, so passing does not establish generalization. Future evaluation should use independently labelled, diverse examples, report per-category results and include unseen attacks, benign security discussions and Hindsight integration tests.

Never use real credentials or personal records as test fixtures.
