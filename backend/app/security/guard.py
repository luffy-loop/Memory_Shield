from app.security.detectors import (
    InjectionDetector,
    PiiDetector,
    InstructionDetector
)


class MemoryGuard:
    def __init__(self):
        self.detectors = [
            InjectionDetector(),
            PiiDetector(),
            InstructionDetector()
        ]

    def analyze(self, content, source="user"):
        findings = []

        for detector in self.detectors:
            result = detector.detect(content)

            if result["score"] > 0:
                findings.append(result)

        score = min(
            100,
            sum(item["score"] for item in findings)
        )

        if score >= 60:
            action = "quarantine"
        elif score >= 30:
            action = "review"
        else:
            action = "allow"

        return {
            "safe": action == "allow",
            "score": score,
            "findings": findings,
            "action": action,
            "source": source
        }