from fastapi import FastAPI
from app.agent.agent import Agent
from app.security.guard import MemoryGuard
from app.memory.secure_store import SecureMemoryStore
from app.incidents.api import router as incident_router

app = FastAPI(title="MemShield")

guard = MemoryGuard()
memory = SecureMemoryStore(guard)
agent = Agent(memory, guard)

app.include_router(incident_router)

@app.get("/")
def root():
    return {
        "name": "MemShield",
        "status": "running",
        "mode": "protected"
    }

@app.post("/memory")
def add_memory(content: str):
    return memory.add(content)

@app.get("/memory")
def get_memory():
    return memory.get_all()

@app.get("/quarantine")
def get_quarantine():
    return memory.get_quarantine()

@app.post("/chat")
def chat(message: str):
    return agent.respond(message)

@app.get("/review")
def get_review():
    return memory.get_review()
