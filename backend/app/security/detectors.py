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
