from uuid import uuid4
from app.memory.hindsight import memory as hindsight_memory
from app.incidents.service import service
from app.incidents.incident import Incident

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

                if "memory poisoning" in text and (
                    "detected" in text or "quarantine" in text
                ):
                    return True

        except Exception:
            pass

        return False

    def add(self, content, source="user"):
        result = self.guard.analyze(content, source)

        attack_signals = {
            "prompt_injection",
            "suspicious_instruction"
        }

        has_attack_signal = any(
            f["name"] in attack_signals
            for f in result["findings"]
        )

        if result["score"] >= 20 and has_attack_signal:
            if self._learned_attack(content):
                result["findings"].append({
                    "name": "learned_attack_pattern",
                    "score": 30,
                    "matches": ["similar attack pattern found in Hindsight"]
                })
                result["score"] = min(100, result["score"] + 30)

        if result["score"] >= 60:
            result["action"] = "quarantine"
        elif result["score"] >= 30:
            result["action"] = "review"
        else:
            result["action"] = "allow"

        item = {
            "content": content,
            "source": source,
            "risk_score": result["score"],
            "findings": result["findings"],
            "action": result["action"]
        }

        if result["action"] == "quarantine":
            self.quarantine.append(item)

            findings = ", ".join(
                x["name"] for x in result["findings"]
            )

            incident = Incident(
                incident_id=f"INC-{uuid4().hex[:8].upper()}",
                title="Memory Poisoning Detected",
                description=content,
                severity="high",
                source=source,
                memory_content=content,
                risk_score=result["score"]
            )

            service.create(incident)

            hindsight_memory.retain(
                f"SECURITY_EVENT | "
                f"MemoryShield detected memory poisoning | "
                f"patterns={findings} | "
                f"risk={result['score']} | "
                f"action=quarantine | "
                f"source={source}"
            )

        elif result["action"] == "review":
            self.review.append(item)

            findings = ", ".join(
                x["name"] for x in result["findings"]
            )

            hindsight_memory.retain(
                f"SECURITY_EVENT | "
                f"MemoryShield detected suspicious memory | "
                f"patterns={findings} | "
                f"risk={result['score']} | "
                f"action=review | "
                f"source={source}"
            )

        else:
            self.memories.append(item)

            hindsight_memory.retain(
                f"AGENT_MEMORY | "
                f"content={content} | "
                f"source={source}"
            )

        return item

    def get_all(self):
        return self.memories

    def get_quarantine(self):
        return self.quarantine

    def get_review(self):
        return self.review
