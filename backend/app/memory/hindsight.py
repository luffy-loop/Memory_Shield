import os

class HindsightMemory:
    def __init__(self):
        self.agent_bank_id = "memshield-agent-v1"
        self.security_bank_id = "memshield-security-v1"
        self.client = None

        base_url = os.getenv("HINDSIGHT_BASE_URL")
        api_key = os.getenv("HINDSIGHT_API_KEY")

        if base_url:
            try:
                from hindsight_client.hindsight_client import HindsightClient
                self.client = HindsightClient(
                    base_url=base_url,
                    api_key=api_key
                )
            except Exception as e:
                print(f"Hindsight disabled: {e}")

    @property
    def enabled(self):
        return self.client is not None

    def retain(self, content: str, bank_id=None):
        if not self.client:
            return None

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
        if not self.client:
            return []

        bank = bank_id or self.agent_bank_id

        try:
            result = self.client.recall(
                bank_id=bank,
                query=query
            )
            return getattr(result, "results", [])
        except Exception as e:
            print(f"Hindsight recall skipped: {e}")
            return []

    def reflect(self, query: str, bank_id=None):
        if not self.client:
            return None

        bank = bank_id or self.agent_bank_id

        try:
            return self.client.reflect(
                bank_id=bank,
                query=query
            )
        except Exception as e:
            print(f"Hindsight reflect skipped: {e}")
            return None

memory = HindsightMemory()
