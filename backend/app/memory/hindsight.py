import os
from hindsight import HindsightEmbedded

class HindsightMemory:
    def __init__(self):
        self.client = HindsightEmbedded(
            profile="memshield",
            llm_provider=os.getenv("HINDSIGHT_API_LLM_PROVIDER", "groq"),
            llm_model=os.getenv("HINDSIGHT_API_LLM_MODEL", "openai/gpt-oss-20b"),
            llm_api_key=os.getenv("HINDSIGHT_API_LLM_API_KEY")
        )
        self.bank_id = "memshield-v2"

    def retain(self, content: str):
        try:
            return self.client.retain(
                bank_id=self.bank_id,
                content=content,
                context="AI agent memory security"
            )
        except Exception as e:
            print(f"Hindsight retain skipped: {e}")
            return None

    def recall(self, query: str):
        try:
            return self.client.recall(
                bank_id=self.bank_id,
                query=query
            )
        except Exception as e:
            if "not found" in str(e).lower():
                return []
            print(f"Hindsight recall skipped: {e}")
            return []

memory = HindsightMemory()
