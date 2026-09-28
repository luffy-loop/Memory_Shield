from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class Incident(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str
    source: str = "unknown"
    memory_content: Optional[str] = None
    risk_score: int = 0
    status: str = "open"
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
