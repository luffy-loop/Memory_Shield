import os
from hindsight import HindsightEmbedded

class HindsightMemory:
    def __init__(self):
        self.client = HindsightEmbedded(
            profile="memshield",
            llm_provider=os.getenv("HINDSIGHT_API_LLM_PROVIDER", "groq"),
            llm_model=os.getenv(
                "HINDSIGHT_API_LLM_MODEL",
                "openai/gpt-oss-20b"
            ),
            llm_api_key=os.getenv("HINDSIGHT_API_LLM_API_KEY")
        )

        self.agent_bank_id = "memshield-agent-v1"
        self.security_bank_id = "memshield-security-v1"

    def retain(self, content: str, bank_id=None):
        bank = bank_id or self.agent_bank_id

        try:
            return self.client.retain(
                bank_id=bank,
                content=content,
                context="AI agent memory security"
            )
        except Exception as e:
            print(f"Hindsight retain skipped: {e}")
            return None

    def recall(self, query: str, bank_id=None):
        bank = bank_id or self.agent_bank_id

        try:
            return self.client.recall(
                bank_id=bank,
                query=query
            )
        except Exception as e:
            if "not found" in str(e).lower():
                return []

            print(f"Hindsight recall skipped: {e}")
            return []

memory = HindsightMemory()
