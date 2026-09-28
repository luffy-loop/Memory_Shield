import os
from hindsight import HindsightEmbedded

class HindsightMemory:
    def __init__(self):
        self.client = HindsightEmbedded(
            profile="memshield",
            llm_provider=os.getenv("HINDSIGHT_API_LLM_PROVIDER", "groq"),
            llm_model=os.getenv("HINDSIGHT_API_LLM_MODEL", "llama-3.3-70b-versatile"),
            llm_api_key=os.getenv("HINDSIGHT_API_LLM_API_KEY")
        )
        self.bank_id = "memshield-v2"

    def retain(self, content: str):
        return self.client.retain(
            bank_id=self.bank_id,
            content=content,
            context="AI agent memory security"
        )

    def recall(self, query: str):
        try:
            return self.client.recall(
                bank_id=self.bank_id,
                query=query
            )
        except Exception as e:
            if "not found" in str(e).lower():
                return []
            raise

memory = HindsightMemory()
