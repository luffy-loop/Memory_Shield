from fastapi import APIRouter, HTTPException
from app.incidents.incident import Incident
from app.incidents.service import service

router = APIRouter(prefix="/incidents", tags=["incidents"])

@router.post("/")
def create_incident(incident: Incident):
    return service.create(incident)

@router.get("/")
def get_incidents():
    return service.all()

@router.get("/{incident_id}")
def get_incident(incident_id: str):
    incident = service.get(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident

@router.post("/{incident_id}/quarantine")
def quarantine_incident(incident_id: str):
    incident = service.quarantine(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident

@router.post("/{incident_id}/recover")
def recover_incident(incident_id: str, resolution: str):
    incident = service.recover(incident_id, resolution)

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident

@router.post("/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    root_cause: str,
    resolution: str
):
    incident = service.resolve(
        incident_id,
        root_cause,
        resolution
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident
