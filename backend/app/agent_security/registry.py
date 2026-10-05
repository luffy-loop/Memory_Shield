from copy import deepcopy

from .models import AgentDefinition


class AgentRegistry:
    def __init__(self):
        self._agents = {
            "patient_helper": AgentDefinition(
                agent_id="patient_helper",
                name="Patient Helper",
                description="Answers patient questions and accesses patient records.",
                tools=["chat", "patient_record_lookup", "email"],
                permissions=[
                    "chat:use",
                    "patient_record_lookup:read",
                    "email:send"
                ]
            ),
            "scheduler": AgentDefinition(
                agent_id="scheduler",
                name="Scheduler",
                description="Books appointments and communicates through SMS.",
                tools=["doctor_calendar", "sms"],
                permissions=[
                    "doctor_calendar:read",
                    "doctor_calendar:book",
                    "sms:send"
                ]
            ),
            "billing_agent": AgentDefinition(
                agent_id="billing_agent",
                name="Billing Agent",
                description="Handles invoices and payment gateway actions.",
                tools=["invoices", "payment_gateway"],
                permissions=[
                    "invoices:read",
                    "invoices:reconcile",
                    "payment_gateway:submit"
                ]
            )
        }

    def all(self):
        return [agent.model_copy(deep=True) for agent in self._agents.values()]

    def get(self, agent_id):
        agent = self._agents.get(agent_id)
        return agent.model_copy(deep=True) if agent else None

    def set_status(self, agent_id, status):
        agent = self._agents.get(agent_id)

        if not agent:
            return None

        agent.status = status
        return agent.model_copy(deep=True)

    def set_risk(self, agent_id, score):
        agent = self._agents.get(agent_id)

        if not agent:
            return None

        agent.risk_score = max(0, min(100, score))
        return agent.model_copy(deep=True)


registry = AgentRegistry()
