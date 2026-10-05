from fastapi.testclient import TestClient
from app.main import app
from app.agent_security.service import engine

client=TestClient(app)

def setup_function():
    engine.audit.clear()
    engine.approvals.clear()

def test_allowed_agent_action():
    r=client.post("/agents/evaluate",json={"agent_id":"patient_helper","tool":"patient_record_lookup","action":"read"})
    assert r.json()["decision"]["decision"]=="allow"

def test_unknown_tool_blocked():
    r=client.post("/agents/evaluate",json={"agent_id":"patient_helper","tool":"payment_gateway","action":"submit"})
    assert r.json()["decision"]["decision"]=="block"

def test_sensitive_action_review():
    r=client.post("/agents/evaluate",json={"agent_id":"billing_agent","tool":"payment_gateway","action":"submit","data_sensitivity":"financial"})
    assert r.json()["decision"]["decision"]=="review"
    assert r.json()["approval"]["status"]=="pending"

def test_audit_summary():
    client.post("/agents/evaluate",json={"agent_id":"patient_helper","tool":"chat","action":"use"})
    client.post("/agents/evaluate",json={"agent_id":"patient_helper","tool":"email","action":"send","data_sensitivity":"medical","destination":"external@example.com"})
    s=client.get("/agents/summary").json()["summary"]
    assert s["total_actions"]==2 and s["allowed"]==1 and s["review"]==1
