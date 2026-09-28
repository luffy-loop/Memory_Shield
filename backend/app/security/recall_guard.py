class RecallGuard:
    def __init__(self, guard):
        self.guard = guard

    def filter(self, memories):
        safe = []
        blocked = []

        for memory in memories:
            text = getattr(memory, "text", None)

            if text is None and isinstance(memory, dict):
                text = memory.get("content", "")

            if not text:
                continue

            result = self.guard.analyze(text, "hindsight")

            if result["action"] == "allow":
                safe.append({
                    "content": text,
                    "risk_score": result["score"],
                    "findings": result["findings"]
                })
            else:
                blocked.append({
                    "content": text,
                    "risk_score": result["score"],
                    "findings": result["findings"],
                    "action": result["action"]
                })

        return {
            "safe": safe,
            "blocked": blocked
        }
