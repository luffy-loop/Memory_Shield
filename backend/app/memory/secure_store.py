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

    def add(self, content, source="user"):
        result = self.guard.analyze(content, source)

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
                x["name"]
                for x in result["findings"]
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
                f"source={source}",
                bank_id=hindsight_memory.security_bank_id
            )

        elif result["action"] == "review":
            self.review.append(item)

            findings = ", ".join(
                x["name"]
                for x in result["findings"]
            )

            hindsight_memory.retain(
                f"SECURITY_EVENT | "
                f"MemoryShield detected suspicious memory | "
                f"patterns={findings} | "
                f"risk={result['score']} | "
                f"action=review | "
                f"source={source}",
                bank_id=hindsight_memory.security_bank_id
            )

        else:
            self.memories.append(item)

            hindsight_memory.retain(
                f"AGENT_MEMORY | "
                f"content={content} | "
                f"source={source}",
                bank_id=hindsight_memory.agent_bank_id
            )

        return item

    def get_all(self):
        return self.memories

    def get_quarantine(self):
        return self.quarantine

    def get_review(self):
        return self.review