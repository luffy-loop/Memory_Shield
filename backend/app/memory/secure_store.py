from app.memory.hindsight import memory as hindsight_memory

class SecureMemoryStore:
    def __init__(self, guard):
        self.guard = guard
        self.memories = []
        self.quarantine = []
        self.review = []

    def _learned_attack(self, content):
        try:
            results = hindsight_memory.recall(
                f"previous memory poisoning attacks similar to: {content}"
            )

            for r in results.results:
                text = getattr(r, "text", "").lower()

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

    def add(self, content, source="user"):
        result = self.guard.analyze(content, source)

        if self._learned_attack(content):
            result["findings"].append({
                "name": "learned_attack_pattern",
                "score": 30,
                "matches": ["similar attack pattern found in Hindsight"]
            })
            result["score"] = min(100, result["score"] + 30)

            if result["score"] >= 60:
                result["action"] = "quarantine"

        memory = {
            "content": content,
            "source": source,
            "risk_score": result["score"],
            "findings": result["findings"],
            "action": result["action"]
        }

        if result["action"] == "quarantine":
            self.quarantine.append(memory)

            findings = ", ".join(
                item["name"] for item in result["findings"]
            )

            hindsight_memory.retain(
                f"MemoryShield security event: "
                f"memory poisoning detected. "
                f"Detection patterns: {findings}. "
                f"Risk score: {result['score']}. "
                f"Action: quarantine. "
                f"Source: {source}."
            )

        elif result["action"] == "review":
            self.review.append(memory)

            findings = ", ".join(
                item["name"] for item in result["findings"]
            )

            hindsight_memory.retain(
                f"MemoryShield security event: suspicious memory requires review. "
                f"Detection patterns: {findings}. "
                f"Risk score: {result['score']}. "
                f"Action: review. "
                f"Source: {source}."
            )

        else:
            self.memories.append(memory)

            hindsight_memory.retain(
                f"Memory content: {content}\n"
                f"Source: {source}\n"
                f"Risk score: {result['score']}\n"
                f"Security findings: {result['findings']}\n"
                f"MemoryShield action: allowed"
            )

        return memory

    def get_all(self):
        return self.memories

    def get_quarantine(self):
        return self.quarantine

    def get_review(self):
        return self.review
