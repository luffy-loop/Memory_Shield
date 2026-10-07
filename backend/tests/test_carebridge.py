from fastapi.testclient import TestClient
from app.main import app
from app.carebridge.credentials import credential_manager
from app.agent_security.service import engine

client = TestClient(app)

def setup_function():
    engine.audit.clear()
    engine.approvals.clear()
    credential_manager.leases.clear()

def test_pdf_prompt_injection_is_blocked():
    data = client.post("/carebridge/simulate").json()
    item = next(x for x in data["scenarios"] if x["scenario"] == "pdf_prompt_injection")
    assert item["result"]["decision"]["decision"] == "block"
    assert item["result"]["decision"]["risk_score"] == 100

def test_payment_requires_human_approval():
    data = client.post("/carebridge/simulate").json()
    item = next(x for x in data["scenarios"] if x["scenario"] == "payment_deepfake")
    assert item["result"]["decision"]["decision"] == "review"
    assert item["result"]["approval"]["status"] == "pending"

def test_credential_rotation_revokes_old_lease():
    data = client.post("/carebridge/simulate").json()
    item = next(x for x in data["scenarios"] if x["scenario"] == "credential_exposure")
    assert item["old_credential_valid_after_rotation"] is False
    assert item["new_credential_valid"] is True
    assert item["old_credential_revoked"] is True

def test_all_challenge_scenarios_are_present():
    data = client.post("/carebridge/simulate").json()
    assert set(data["summary"]) == {"pdf_prompt_injection","payment_deepfake","credential_rotation"}
