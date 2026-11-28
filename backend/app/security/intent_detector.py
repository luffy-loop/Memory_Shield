import re

from app.security.normalizer import TextNormalizer


class IntentDetector:

    def __init__(self):
        self.normalizer = TextNormalizer()

        self.rules = {
            "instruction_override": (
                r"(?:ignore|disregard|override|discard|forget|replace)"
                r"\b.{0,100}\b"
                r"(?:instructions?|rules?|polic(?:y|ies))\b",

                r"(?:follow|obey|accept|execute)\s+only\b"
                r".{0,80}\b(?:commands?|instructions?|orders?)\b",
            ),

            "security_bypass": (
                r"(?:bypass|disable|remove|skip|suspend|turn off)"
                r"\b.{0,100}\b"
                r"(?:security|authentication|authorization|"
                r"verification|validation|restrictions?|"
                r"access controls?|protective checks?|"
                r"protective mechanisms?)\b",

                r"do not verify\b",

                r"(?:execute|perform|respond|proceed)"
                r"\b.{0,100}\bwithout\b.{0,40}\b"
                r"(?:approval|authorization|verification|"
                r"security|safety checks?)\b",
            ),

            "unauthorized_disclosure": (
                r"(?:reveal|disclose|expose|release|retrieve)"
                r"\b.{0,80}\b"
                r"(?:confidential|private|restricted|"
                r"protected|secrets?|passwords?|credentials?)\b",

                r"grant\b.{0,60}\bunrestricted access\b",
            ),

            "unrestricted_role": (
                r"you are now\b.{0,60}\bunrestricted\b",

                r"(?:always|automatically)\s+trust\b",

                r"accept\b.{0,60}\bunverified\b",
            )
        }

    def detect(self, content):
        clauses = re.split(
            r"[!?;:\n]+|\.(?=\s|$)|"
            r"\b(?:but|however|instead|yet)\b",
            content,
            flags=re.IGNORECASE
        )

        matches = []

        for clause in clauses:
            clause = self.normalizer.normalize_for_detection(
                clause
            ).strip()

            clause = re.sub(
                r"^(?:please|kindly|now)\s+",
                "",
                clause
            )

            for intent, patterns in self.rules.items():
                if any(
                    re.match(pattern, clause)
                    for pattern in patterns
                ):
                    if intent not in matches:
                        matches.append(intent)

        return {
            "name": "high_confidence_intent",
            "score": 60 if matches else 0,
            "matches": matches
        }