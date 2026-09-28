import re

from app.security.detectors import (
    InjectionDetector,
    PiiDetector,
    InstructionDetector,
    TrustDetector,
    ProvenanceDetector,
    ContradictionDetector
)
from app.memory.hindsight import memory as hindsight_memory


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

    def _learned_attack(self, content):
        try:
            results = hindsight_memory.recall(
                f"previous memory poisoning attacks similar to: {content}",
                bank_id=hindsight_memory.security_bank_id
            )

            for result in results:
                text = getattr(result, "text", "").lower()

                if (
                    "memory poisoning" in text
                    and (
                        "detected" in text
                        or "quarantine" in text
                    )
                ):
                    return True

        except Exception:
            pass

        return False

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

        attack_signals = {
            "prompt_injection",
            "suspicious_instruction"
        }

        has_attack_signal = any(
            item["name"] in attack_signals
            for item in findings
        )

        score = min(
            100,
            sum(item["score"] for item in findings)
        )

        if score >= 20 and has_attack_signal:
            if self._learned_attack(content):
                findings.append({
                    "name": "learned_attack_pattern",
                    "score": 30,
                    "matches": [
                        "similar attack pattern found in Hindsight"
                    ]
                })

                score = min(100, score + 30)

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