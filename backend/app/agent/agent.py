from app.memory.hindsight import memory as hindsight_memory

class Agent:
    def __init__(self, memory, guard):
        self.memory = memory
        self.guard = guard

    def remember(self, content):
        return self.memory.add(content)

    def build_context(self, query=""):
        results = hindsight_memory.recall(query)
        safe = []

        for r in results.results:
            text = getattr(r, "text", "")
            if not text:
                continue

            result = self.guard.analyze(text, "hindsight")

            if result["action"] == "allow":
                safe.append(text)

        return "\n".join(safe)

    def respond(self, message):
        context = self.build_context(message)

        return {
            "message": message,
            "memory_context": context
        }
