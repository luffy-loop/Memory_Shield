from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.agent.agent import Agent
from app.security.guard import MemoryGuard
from app.memory.secure_store import SecureMemoryStore
from app.incidents.api import router as incident_router
from app.incidents.service import service

app = FastAPI(title="MemShield")

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

app.include_router(incident_router)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE_DIR / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )


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


@app.post("/chat")
def chat(message: str):
    return agent.respond(message)


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
