from uuid import uuid4
from datetime import datetime

from .models import AgentDefinition, ApprovalRequest, AuditEvent, PolicyDecision, ToolRequest


SENSITIVE_LEVELS = {
    "normal": 0,
    "personal": 15,
    "medical": 35,
    "financial": 35,
    "credential": 45,
    "critical": 50
}


class AgentSecurityEngine:
    def __init__(self, registry):
        self.registry = registry
        self.approvals = {}
        self.audit = []

    def _base_risk(self, request, agent):
        score = SENSITIVE_LEVELS.get(request.data_sensitivity.lower(), 20)

        if request.destination and not self._internal_destination(request.destination):
            score += 20

        if request.action in {"delete", "export", "send", "pay", "transfer"}:
            score += 15

        if request.tool == "payment_gateway":
            score += 20

        return min(100, score)

    def _internal_destination(self, destination):
        value = destination.lower()
        return (
            value.startswith("internal:")
            or value.endswith("@carebridge.local")
            or value in {"internal", "carebridge"}
        )

    def evaluate(self, request: ToolRequest):
        agent = self.registry.get(request.agent_id)

        if not agent:
            return PolicyDecision(
                decision="block",
                risk_score=100,
                reason="Unknown agent"
            )

        if agent.status in {"paused", "quarantined", "disabled"}:
            return PolicyDecision(
                decision="block",
                risk_score=100,
                reason=f"Agent is {agent.status}"
            )

        permission = f"{request.tool}:{request.action}"

        if permission not in agent.permissions:
            return PolicyDecision(
                decision="block",
                risk_score=95,
                reason=f"Permission denied: {permission}"
            )

        score = self._base_risk(request, agent)

        if score >= 80:
            return PolicyDecision(
                decision="review",
                risk_score=score,
                reason="High-risk action requires human approval",
                requires_approval=True
            )

        if score >= 50:
            return PolicyDecision(
                decision="review",
                risk_score=score,
                reason="Sensitive action requires review",
                requires_approval=True
            )

        return PolicyDecision(
            decision="allow",
            risk_score=score,
            reason="Policy checks passed"
        )

    def record(self, request, decision):
        event = AuditEvent(
            event_id=f"ACT-{uuid4().hex[:8].upper()}",
            agent_id=request.agent_id,
            tool=request.tool,
            action=request.action,
            decision=decision.decision,
            risk_score=decision.risk_score,
            reason=decision.reason,
            data_sensitivity=request.data_sensitivity,
            destination=request.destination
        )
        self.audit.append(event)
        return event

    def request_approval(self, request, decision):
        approval = ApprovalRequest(
            request_id=f"APR-{uuid4().hex[:8].upper()}",
            agent_id=request.agent_id,
            tool=request.tool,
            action=request.action,
            risk_score=decision.risk_score,
            reason=decision.reason
        )
        self.approvals[approval.request_id] = approval
        return approval

    def decide(self, request_id, approve, decided_by="operator"):
        approval = self.approvals.get(request_id)

        if not approval:
            return None

        approval.status = "approved" if approve else "blocked"
        approval.decided_by = decided_by
        approval.decided_at = datetime.utcnow()

        return approval

    def approval_list(self):
        return list(self.approvals.values())

    def audit_list(self):
        return list(reversed(self.audit))

    def set_agent_status(self, agent_id, status):
        return self.registry.set_status(agent_id, status)


engine = AgentSecurityEngine(None)
