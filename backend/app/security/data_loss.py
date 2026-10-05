import re


class DataLossGuard:
    patterns = [
        ("aadhaar", r"(?<!\d)(?:\d{4}[ -]?){2}\d{4}(?!\d)", "pii"),
        ("pan", r"\b[A-Z]{5}\d{4}[A-Z]\b", "pii"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "pii"),
        ("phone", r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)", "pii"),
        ("card", r"\b(?:\d[ -]*?){13,16}\b", "financial"),
        ("private_key", r"-----BEGIN\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "credential"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "credential"),
        ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", "credential"),
        ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "credential"),
        ("credential", r"\b(?:password|passwd|token|api[_ -]?key|client[_ -]?secret)\s*[:=]\s*\S+", "credential"),
        ("connection_string", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s]+", "credential")
    ]

    def scan(self, content):
        findings = []

        for name, pattern, kind in self.patterns:
            if re.search(pattern, content, re.I):
                findings.append({"name": name, "kind": kind})

        credential = any(item["kind"] == "credential" for item in findings)
        sensitive = any(item["kind"] in {"pii", "financial"} for item in findings)

        if credential:
            action = "block"
            score = 100
        elif len(findings) >= 2:
            action = "block"
            score = min(100, 70 + len(findings) * 10)
        elif sensitive:
            action = "redact"
            score = 60
        else:
            action = "allow"
            score = 0

        return {
            "safe": action == "allow",
            "score": score,
            "action": action,
            "findings": findings
        }

    def redact(self, content):
        value = content

        for name, pattern, kind in self.patterns:
            value = re.sub(
                pattern,
                lambda match: f"[REDACTED:{name.upper()}]",
                value,
                flags=re.I
            )

        return value


guard = DataLossGuard()
