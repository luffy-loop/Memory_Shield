from pydantic import BaseModel
from typing import Optional

class Incident(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: str
    root_cause: Optional[str] = None
    resolution: Optional[str] = None
    status: str = "open"
