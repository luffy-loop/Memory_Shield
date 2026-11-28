import re

from app.security.detectors import (
    InjectionDetector,
    PiiDetector,
    CredentialDetector,
    InstructionDetector,
    TrustDetector,
    ProvenanceDetector,
    ContradictionDetector
)

from app.security.normalizer import TextNormalizer
from app.security.semantic_detector import SemanticDetector
from app.security.intent_detector import IntentDetector
from app.security.memory_poisoning_detector import MemoryPoisoningDetector
from app.security.authority_detector import AuthorityDetector
from app.security.descriptive_context import DescriptiveContext
from app.memory.hindsight import memory as hindsight_memory


class MemoryGuard:

    def __init__(self, memory_store=None):
        self.memory_store = memory_store
        self.normalizer = TextNormalizer()
        self.semantic_detector = SemanticDetector()
        self.intent_detector = IntentDetector()
        self.memory_poisoning_detector = MemoryPoisoningDetector()
        self.authority_detector = AuthorityDetector()

        self.detectors = [
            InjectionDetector(),
            PiiDetector(),
            CredentialDetector(),
            InstructionDetector(),
            TrustDetector(),
            ProvenanceDetector(),
            ContradictionDetector(memory_store)
        ]

    def _remove_defensive_actions(self, content):
        pattern = (
            r"\b(?:(?:must|should|do|does|can)\s+not|never)"
            r"\s+(?:bypass|disable|skip|disclose|reveal|ignore)\b"
        )

        return re.sub(
            pattern,
            " [defensive action] ",
            content,
            flags=re.IGNORECASE
        )

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

        poisoning_result = self.memory_poisoning_detector.detect(content)
        authority_result = self.authority_detector.detect(content)

        attack_content = DescriptiveContext.remove_descriptions(
            content
        )

        normalized_content = (
            self.normalizer.normalize_for_detection(
                attack_content
            )
        )

        semantic_result = self.semantic_detector.detect(
            attack_content
        )

        intent_result = self.intent_detector.detect(
            content
        )

        original_attack_content = (
            self._remove_defensive_actions(
                attack_content
            )
        )

        normalized_attack_content = (
            self._remove_defensive_actions(
                normalized_content
            )
        )

        for detector in self.detectors:

            if isinstance(
                detector,
                (
                    TrustDetector,
                    ProvenanceDetector,
                    ContradictionDetector
                )
            ):
                result = detector.detect(content, source)

            elif isinstance(
                detector,
                (InjectionDetector, InstructionDetector)
            ):
                original_result = detector.detect(
                    original_attack_content
                )

                normalized_result = detector.detect(
                    normalized_attack_content
                )

                result = max(
                    (original_result, normalized_result),
                    key=lambda item: item["score"]
                )

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

        existing_threat_score = sum(
            item["score"]
            for item in findings
            if item["name"] in attack_signals
        )

        other_risk_score = sum(
            item["score"]
            for item in findings
            if item["name"] not in attack_signals
        )

        semantic_score = semantic_result["score"]

        if semantic_score > 0:
            findings.append(semantic_result)

        if intent_result["score"] > 0:
            findings.append(intent_result)

        if poisoning_result["score"] > 0:
            findings.append(poisoning_result)

        if authority_result["score"] > 0:
            findings.append(authority_result)

        combined_threat_score = max(
            authority_result["score"],
            poisoning_result["score"],
            intent_result["score"],
            existing_threat_score,
            semantic_score
        )

        score = min(
            100,
            combined_threat_score + other_risk_score
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

        credential_hit = any(
            item["name"] == "credential_exposure"
            for item in findings
        )

        critical_pii = any(
            item["name"] == "sensitive_data"
            and any(
                match in {
                    "aadhaar",
                    "pan",
                    "card",
                    "password",
                    "api_token"
                }
                for match in item["matches"]
            )
            for item in findings
        )

        if credential_hit or score >= 60 or critical_pii:
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