from app.security.detectors import (
    InjectionDetector,
    PiiDetector,
    InstructionDetector,
    TrustDetector,
    ProvenanceDetector,
    ContradictionDetector
)

class MemoryGuard:
    def __init__(self, memory_store=None):
        self.memory_store = memory_store
        self.detectors = [
            InjectionDetector(),
            PiiDetector(),
            InstructionDetector(),
            TrustDetector(),
            ProvenanceDetector(),
            ContradictionDetector(memory_store)
        ]

    def analyze(self, content, source="user"):
        findings = []

        for detector in self.detectors:
            if isinstance(
                detector,
                (TrustDetector, ProvenanceDetector, ContradictionDetector)
            ):
                result = detector.detect(content, source)
            else:
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
