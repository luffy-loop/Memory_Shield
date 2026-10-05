import re

class InjectionDetector:
    patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?previous",
        r"system\s+instruction",
        r"developer\s+message",
        r"reveal\s+(any\s+)?secret",
        r"from\s+now\s+on",
        r"you\s+are\s+now",
        r"override\s+instructions",
        r"always\s+trust",
        r"ignore\s+(all\s+)?future\s+(security\s+)?warnings",
        r"ignore\s+.*security\s+warnings",
        r"bypass\s+(security|verification)",
        r"do\s+not\s+verify",
        r"treat\s+.*\s+as\s+trusted",
        r"automatically\s+trust",
        r"skip\s+(security\s+)?verification",
        r"trusted\s+automatically",
        r"skip\s+verification",
        r"bypass\s+.*\s+check"
    ]

    def detect(self, text):
        matches = [
            p for p in self.patterns
            if re.search(p, text, re.I)
        ]

        return {
            "name": "prompt_injection",
            "score": min(60, len(matches) * 20),
            "matches": matches
        }


class PiiDetector:
    patterns = [
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 20),
        ("phone", r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)", 15),
        ("aadhaar", r"(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)", 45),
        ("pan", r"\b[A-Z]{5}\d{4}[A-Z]\b", 35),
        ("card", r"\b(?:\d[ -]*?){13,16}\b", 25),
        ("date_of_birth", r"\b(?:date\s+of\s+birth|dob|birth\s*date)\b", 35),
        ("password", r"\b(?:password|passcode|pin|secret)\b", 40),
        ("api_token", r"\b(?:api\s*key|access\s*token|auth\s*token)\b", 45)
    ]

    def detect(self, text):
        matches = []
        score = 0

        for name, pattern, value in self.patterns:
            if re.search(pattern, text, re.I):
                matches.append(name)
                score += value

        return {
            "name": "sensitive_data",
            "score": min(100, score),
            "matches": matches
        }


class CredentialDetector:
    patterns = [
        ("private_key", r"-----BEGIN\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        ("aws_key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        ("generic_secret", r"\b(?:client_secret|client-secret|secret_key|secret-key)\s*[:=]\s*\S+"),
        ("connection_string", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s]+"),
        ("credential_assignment", r"\b(?:password|passwd|token|api[_ -]?key)\s*[:=]\s*\S+")
    ]

    def detect(self, text):
        matches = [
            name for name, pattern in self.patterns
            if re.search(pattern, text, re.I)
        ]

        return {
            "name": "credential_exposure",
            "score": min(100, len(matches) * 60),
            "matches": matches
        }


class InstructionDetector:
    patterns = [
        r"ignore\s+.*instruction",
        r"follow\s+only",
        r"do\s+not\s+follow",
        r"ignore\s+.*security",
        r"always\s+trust",
        r"do\s+not\s+verify",
        r"bypass\s+.*security",
        r"skip\s+verification",
        r"trusted\s+automatically"
    ]

    def detect(self, text):
        matches = [
            p for p in self.patterns
            if re.search(p, text, re.I)
        ]

        return {
            "name": "suspicious_instruction",
            "score": min(40, len(matches) * 15),
            "matches": matches
        }


class TrustDetector:
    untrusted_sources = {
        "web": 15,
        "document": 10,
        "file": 10,
        "tool": 15,
        "unknown": 20
    }

    def detect(self, text, source="user"):
        source = source.lower()

        if source in self.untrusted_sources:
            return {
                "name": "source_trust",
                "score": self.untrusted_sources[source],
                "matches": [
                    f"external or lower-trust source: {source}"
                ]
            }

        return {
            "name": "source_trust",
            "score": 0,
            "matches": []
        }


class ProvenanceDetector:
    def detect(self, text, source="user"):
        source = source.lower()

        if source in {"web", "document", "file", "tool"}:
            return {
                "name": "provenance",
                "score": 5,
                "matches": [
                    f"provenance requires validation: {source}"
                ]
            }

        if source == "unknown":
            return {
                "name": "provenance",
                "score": 15,
                "matches": [
                    "source provenance is unknown"
                ]
            }

        return {
            "name": "provenance",
            "score": 0,
            "matches": []
        }


class ContradictionDetector:
    def __init__(self, memory_store=None):
        self.memory_store = memory_store

    def detect(self, text, source="user"):
        if not self.memory_store:
            return {
                "name": "contradiction",
                "score": 0,
                "matches": []
            }

        text_low = text.lower()

        for item in self.memory_store.get_all():
            old = item["content"].lower()

            if "always " in old and "never " in text_low:
                return {
                    "name": "contradiction",
                    "score": 25,
                    "matches": [
                        f"conflicts with trusted memory: {item['content']}"
                    ]
                }

            if "never " in old and "always " in text_low:
                return {
                    "name": "contradiction",
                    "score": 25,
                    "matches": [
                        f"conflicts with trusted memory: {item['content']}"
                    ]
                }

        return {
            "name": "contradiction",
            "score": 0,
            "matches": []
        }
