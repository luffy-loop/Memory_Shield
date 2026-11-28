import re

from app.security.normalizer import TextNormalizer


class MemoryPoisoningDetector:

    def __init__(self):
        self.normalizer = TextNormalizer()

        self.persistence_pattern = (
            r"\b(?:remember|store|save|persist|"
            r"update your memory|from now on|"
            r"future requests?|future operations?)\b"
        )

        self.rules = {
            "privilege_escalation": (
                r"\b(?:all|every|any)\b.{0,60}"
                r"\b(?:administrator|admin privileges|"
                r"administrator privileges|authorized)\b",
            ),

            "security_control_removal": (
                r"\b(?:disable|disabling|skip|skipping|"
                r"bypass|bypassing|remove|removing)\b"
                r".{0,60}\b(?:security|authentication|"
                r"authorization|verification|validation|"
                r"approval|access controls?)\b",

                r"\b(?:exception|exemption)\b.{0,40}"
                r"\b(?:authentication|authorization|"
                r"verification|access controls?)\b",

                r"\b(?:approval|verification|validation|"
                r"authentication)\b.{0,40}"
                r"\b(?:unnecessary|optional|never required|"
                r"not required|no longer required)\b",
            ),

            "unrestricted_permissions": (
                r"\b(?:allow|allowing|grant|granting|"
                r"permit|permitting)\b.{0,60}"
                r"\b(?:unrestricted|unauthorized|restricted|"
                r"anonymous|full access|private records)\b",

                r"\bauthorization for all future operations\b",
            ),

            "untrusted_source_elevation": (
                r"\b(?:trust|accept)\b.{0,60}"
                r"\b(?:unknown users?|external requests?|"
                r"unverified identities|every command|"
                r"all commands?)\b",

                r"\b(?:all|every|external|future)\b.{0,60}"
                r"\b(?:trusted|authoritative)\b",
            ),

            "confidentiality_violation": (
                r"\b(?:confidential|private|protected)\b"
                r".{0,60}\b(?:publicly accessible|"
                r"publicly available|unrestricted)\b",

                r"\b(?:allow|allowing|permit|permitting)\b"
                r".{0,40}\bconfidential disclosure\b",
            ),

            "security_policy_invalidation": (
                r"\b(?:security warnings?|protective rules?|"
                r"security policies)\b.{0,40}"
                r"\b(?:irrelevant|ignored|expired|invalid)\b",

                r"\bignore\b.{0,40}\bsecurity warnings?\b",
            )
        }

    def detect(self, content):
        clauses = re.split(
            r"[!?;]+|\.(?=\s|$)|"
            r"\b(?:but|however|instead|yet)\b",
            content,
            flags=re.IGNORECASE
        )

        matches = []

        for clause in clauses:
            text = self.normalizer.normalize_for_detection(
                clause
            )

            if not re.search(
                self.persistence_pattern,
                text
            ):
                continue

            for name, patterns in self.rules.items():
                if any(
                    re.search(pattern, text)
                    for pattern in patterns
                ):
                    if name not in matches:
                        matches.append(name)

        return {
            "name": "memory_poisoning_intent",
            "score": 60 if matches else 0,
            "matches": matches
        }