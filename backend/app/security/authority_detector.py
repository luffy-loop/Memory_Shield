import re

from app.security.normalizer import TextNormalizer


class AuthorityDetector:

    def __init__(self):
        self.normalizer = TextNormalizer()

        self.authority_pattern = (
            r"^(?:security administrator|system administrator|"
            r"administrator|admin|developer|system|management|"
            r"executive|supervisor|compliance officer|"
            r"internal support|security officer|operator|"
            r"official policy)"
            r"(?:\s+(?:directive|instruction|override|"
            r"authorization|notice|message|update|order))*$"
        )

        self.rules = {
            "command_override": (
                r"^(?:accept|execute|obey|follow)\s+"
                r"(?:all|every|any|only)\b"
                r".{0,60}\b(?:commands?|instructions?|orders?)\b",
            ),

            "security_control_bypass": (
                r"^(?:disable|remove|skip|bypass|suspend|ignore)"
                r"\b.{0,80}\b"
                r"(?:approval|authentication|authorization|"
                r"verification|validation|security|"
                r"restrictions?|warnings?|access controls?)\b",
            ),

            "authorization_invalidation": (
                r"^(?:human\s+)?"
                r"(?:approval|authentication|authorization|"
                r"verification|validation)\b.{0,40}"
                r"\b(?:unnecessary|optional|never required|"
                r"not required|no longer required)\b",
            ),

            "unrestricted_access": (
                r"^(?:grant|allow|permit|enable)\b"
                r".{0,60}\b"
                r"(?:anonymous|unrestricted|unauthorized|"
                r"restricted operations|full access)\b",
            ),

            "unauthorized_execution": (
                r"^(?:execute|perform|run|authorize)\b"
                r".{0,60}\b"
                r"(?:restricted|unauthorized|privileged)\b",
            ),

            "unverified_trust": (
                r"^(?:always\s+)?(?:trust|accept)\b"
                r".{0,60}\b"
                r"(?:unknown|unverified|external|anonymous)\b",

                r"^(?:all|every|any)\b.{0,60}"
                r"\b(?:is|are)\s+(?:automatically\s+)?trusted\b",
            ),

            "confidential_disclosure": (
                r"^(?:disclose|reveal|expose|release|retrieve)"
                r"\b.{0,60}\b"
                r"(?:confidential|private|protected|"
                r"restricted|secrets?|credentials?)\b",
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

            parts = clause.split(":", 1)

            if len(parts) != 2:
                continue

            authority = self.normalizer.normalize_for_detection(
                parts[0]
            ).strip()

            instruction = self.normalizer.normalize_for_detection(
                parts[1]
            ).strip()

            if not re.fullmatch(
                self.authority_pattern,
                authority
            ):
                continue

            instruction = re.sub(
                r"^(?:please|kindly|now)\s+",
                "",
                instruction
            )

            for name, patterns in self.rules.items():

                if any(
                    re.search(pattern, instruction)
                    for pattern in patterns
                ):
                    if name not in matches:
                        matches.append(name)

        return {
            "name": "authority_impersonation_intent",
            "score": 60 if matches else 0,
            "matches": matches
        }