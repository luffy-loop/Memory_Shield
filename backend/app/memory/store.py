class MemoryStore:
    def __init__(self):
        self.memories = []

    def add(self, content, source="user"):
        self.memories.append({
            "content": content,
            "source": source
        })

    def get_all(self):
        return self.memories