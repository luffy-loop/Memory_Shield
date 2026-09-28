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
        matches = [p for p in self.patterns if re.search(p, text, re.I)]
        return {
            "name": "prompt_injection",
            "score": min(60, len(matches) * 20),
            "matches": matches
        }


class PiiDetector:
    patterns = [
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"\b\d{10}\b",
        r"\b(?:\d[ -]*?){13,16}\b"
    ]

    def detect(self, text):
        matches = [p for p in self.patterns if re.search(p, text)]
        return {
            "name": "sensitive_data",
            "score": min(30, len(matches) * 10),
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
        matches = [p for p in self.patterns if re.search(p, text, re.I)]
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
                "matches": [f"external or lower-trust source: {source}"]
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
                "matches": [f"provenance requires validation: {source}"]
            }

        if source == "unknown":
            return {
                "name": "provenance",
                "score": 15,
                "matches": ["source provenance is unknown"]
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
                    "matches": [f"conflicts with trusted memory: {item['content']}"]
                }

            if "never " in old and "always " in text_low:
                return {
                    "name": "contradiction",
                    "score": 25,
                    "matches": [f"conflicts with trusted memory: {item['content']}"]
                }

        return {
            "name": "contradiction",
            "score": 0,
            "matches": []
        }
