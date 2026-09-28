from app.memory.hindsight import memory as hindsight_memory
from app.security.recall_guard import RecallGuard


class Agent:
    def __init__(self, memory, guard):
        self.memory = memory
        self.guard = guard
        self.recall_guard = RecallGuard(guard)

    def remember(self, content):
        return self.memory.add(content)

    def build_context(self, query=""):
        results = hindsight_memory.recall(
            query,
            bank_id=hindsight_memory.agent_bank_id
        )

        checked = self.recall_guard.filter(results)

        return "\n".join(
            dict.fromkeys(
                item["content"]
                for item in checked["safe"]
            )
        )

    def respond(self, message, source="user"):
        security = self.guard.analyze(message, source)

        if security["action"] == "quarantine":
            item = self.memory.add(message, source)

            return {
                "message": message,
                "blocked": True,
                "security": security,
                "memory": item,
                "memory_context": "",
                "response": "Memory write blocked and quarantined."
            }

        item = self.memory.add(message, source)

        context = self.build_context(message)

        return {
            "message": message,
            "blocked": False,
            "security": security,
            "memory": item,
            "memory_context": context,
            "response": "Memory accepted and protected."
        }