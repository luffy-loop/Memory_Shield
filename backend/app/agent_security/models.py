from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime


class AgentDefinition(BaseModel):
    agent_id: str
    name: str
    description: str
    status: str = "active"
    tools: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    risk_score: int = 0


class ToolRequest(BaseModel):
    agent_id: str
    tool: str
    action: str
    data_sensitivity: str = "normal"
    destination: Optional[str] = None
    source: str = "agent"
    payload_keys: List[str] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    decision: str
    risk_score: int
    reason: str
    requires_approval: bool = False


class ApprovalRequest(BaseModel):
    request_id: str
    agent_id: str
    tool: str
    action: str
    risk_score: int
    reason: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None


class AuditEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str
    tool: str
    action: str
    decision: str
    risk_score: int
    reason: str
    data_sensitivity: str = "normal"
    destination: Optional[str] = None
