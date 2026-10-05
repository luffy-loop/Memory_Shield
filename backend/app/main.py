from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.agent.agent import Agent
from app.security.guard import MemoryGuard
from app.memory.secure_store import SecureMemoryStore
from app.incidents.api import router as incident_router
from app.incidents.service import service
from app.memory.hindsight import memory as hindsight_memory
from app.agent_security.models import ToolRequest
from app.agent_security.service import (
    get_agents,
    get_agent,
    evaluate,
    approvals,
    decide,
    audit,
    set_status
)

app = FastAPI(title="MemoryShield Agent Security")

BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)

memory = SecureMemoryStore(None)
guard = MemoryGuard(memory)
memory.guard = guard
agent = Agent(memory, guard)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE_DIR / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )


@app.post("/agent/chat")
def agent_chat(message: str):
    return agent.respond(message)


@app.post("/chat")
def chat(message: str):
    return agent.respond(message)


@app.post("/memory/check")
def memory_check(content: str, source: str = "user"):
    return guard.analyze(content, source)


@app.post("/memory/guard")
def memory_guard(content: str, source: str = "user"):
    return guard.analyze(content, source)


@app.post("/memory/retain")
def memory_retain(content: str, source: str = "user"):
    return memory.add(content, source)


@app.get("/memory/recall")
def memory_recall(query: str):
    results = hindsight_memory.recall(query)

    return {
        "query": query,
        "results": [
            getattr(item, "text", "")
            for item in results
            if getattr(item, "text", "")
        ]
    }


@app.post("/memory/reflect")
def memory_reflect(query: str, bank_id: str = None):
    result = hindsight_memory.reflect(query, bank_id=bank_id)

    if result is None:
        return {
            "query": query,
            "result": None
        }

    return {
        "query": query,
        "result": getattr(result, "text", result)
    }


@app.post("/memory")
def add_memory(content: str, source: str = "user"):
    return memory.add(content, source)


@app.get("/memory")
def get_memory():
    return memory.get_all()


@app.get("/quarantine")
def get_quarantine():
    return memory.get_quarantine()


@app.get("/review")
def get_review():
    return memory.get_review()


@app.get("/incidents/timeline")
def incident_timeline():
    incidents = service.all()

    return [
        {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "source": incident.source,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "created_at": incident.created_at,
            "resolved_at": incident.resolved_at
        }
        for incident in sorted(
            incidents,
            key=lambda x: x.created_at,
            reverse=True
        )
    ]


@app.get("/metrics")
def metrics():
    incidents = service.all()

    return {
        "trusted_memories": len(memory.get_all()),
        "review_items": len(memory.get_review()),
        "quarantined_memories": len(memory.get_quarantine()),
        "incidents": len(incidents),
        "open_incidents": sum(
            1 for i in incidents if i.status == "open"
        ),
        "quarantined_incidents": sum(
            1 for i in incidents if i.status == "quarantined"
        ),
        "recovered_incidents": sum(
            1 for i in incidents if i.status == "recovered"
        )
    }


@app.get("/learning")
def learning():
    results = hindsight_memory.recall(
        "previous memory poisoning attacks security incidents learned patterns",
        bank_id=hindsight_memory.security_bank_id
    )

    return {
        "patterns": [
            {
                "text": getattr(item, "text", ""),
                "type": getattr(item, "type", "unknown")
            }
            for item in results
            if getattr(item, "text", "")
        ]
    }


@app.get("/agents")
def agents():
    return [item.model_dump() for item in get_agents()]


@app.get("/agents/{agent_id}")
def agent_security_details(agent_id: str):
    item = get_agent(agent_id)

    if not item:
        raise HTTPException(status_code=404, detail="Agent not found")

    return item.model_dump()


@app.post("/agents/evaluate")
def evaluate_tool_request(request: ToolRequest):
    return evaluate(request)


@app.get("/agents/approvals")
def agent_approvals():
    return approvals()


@app.post("/agents/approvals/{request_id}")
def decide_agent_approval(
    request_id: str,
    approve: bool,
    decided_by: str = "operator"
):
    result = decide(request_id, approve, decided_by)

    if not result:
        raise HTTPException(status_code=404, detail="Approval request not found")

    return result


@app.get("/agents/audit")
def agent_audit():
    return audit()


@app.post("/agents/{agent_id}/status")
def update_agent_status(agent_id: str, status: str):
    if status not in {"active", "paused", "quarantined", "disabled"}:
        raise HTTPException(status_code=400, detail="Invalid agent status")

    result = set_status(agent_id, status)

    if not result:
        raise HTTPException(status_code=404, detail="Agent not found")

    return result.model_dump()


app.include_router(incident_router)
