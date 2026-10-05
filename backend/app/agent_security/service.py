from .engine import AgentSecurityEngine
from .registry import registry


engine = AgentSecurityEngine(registry)


def get_agents():
    return registry.all()


def get_agent(agent_id):
    return registry.get(agent_id)


def evaluate(request):
    decision = engine.evaluate(request)
    audit = engine.record(request, decision)

    approval = None

    if decision.requires_approval:
        approval = engine.request_approval(request, decision)

    return {
        "decision": decision.model_dump(),
        "audit": audit.model_dump(),
        "approval": approval.model_dump() if approval else None
    }


def approvals():
    return [item.model_dump() for item in engine.approval_list()]


def decide(request_id, approve, decided_by="operator"):
    result = engine.decide(request_id, approve, decided_by)

    if not result:
        return None

    return result.model_dump()


def audit():
    return [item.model_dump() for item in engine.audit_list()]


def set_status(agent_id, status):
    return engine.set_agent_status(agent_id, status)
