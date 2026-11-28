
import re

from app.security.normalizer import TextNormalizer
from app.security.context_detector import ContextDetector


class SemanticDetector:

    def __init__(self):
        self.normalizer = TextNormalizer()
        self.context_detector = ContextDetector()

        self.intent_rules = {
            "policy_manipulation": (
                r"\b(ignore|disable|remove|discard|replace|override|suspend|forget|bypass)\b",
                r"\b(rules?|polic(?:y|ies)|restrictions?|checks?|limitations?|safety|security|instructions?)\b"
            ),

            "authorization_bypass": (
                r"\b(skip|disable|remove|bypass|avoid|suspend|unnecessary|without)\b",
                r"\b(authorization|approval|verification|permissions?|validation|authentication)\b"
            ),

            "memory_poisoning": (
                r"\b(remember|store|save|persist|update)\b",
                r"\b(unrestricted|unverified|disable|bypass|anonymous|trusted|authorized|administrator)\b"
            ),

            "authority_impersonation": (
                r"\b(administrator|developer|system|supervisor|operator|officer|executive)\b",
                r"\b(directive|override|instruction|disable|bypass|unrestricted|remove|disclose)\b"
            ),

            "unauthorized_disclosure": (
                r"\b(reveal|disclose|expose|release|grant|retrieve)\b",
                r"\b(confidential|private|restricted|protected|unrestricted|records?|secrets?)\b"
            )
        }

    def detect(self, content):
        text = self.normalizer.normalize_for_detection(content)
        context = self.context_detector.detect(content)

        matches = []

        for intent, patterns in self.intent_rules.items():
            if all(
                re.search(pattern, text)
                for pattern in patterns
            ):
                matches.append(intent)

        original_score = min(60, len(matches) * 30)

        score = original_score

        if context["defensive_context"]:
            score = max(0, score - 15)

        return {
            "name": "semantic_threat",
            "score": score,
            "matches": matches,
            "original_score": original_score,
            "context": context
        }
