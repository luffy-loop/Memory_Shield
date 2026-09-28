from .incident import Incident

class IncidentService:
    def __init__(self):
        self.incidents = {}

    def create(self, incident: Incident):
        self.incidents[incident.incident_id] = incident
        return incident

    def get(self, incident_id: str):
        return self.incidents.get(incident_id)

    def resolve(self, incident_id: str, root_cause: str, resolution: str):
        incident = self.incidents.get(incident_id)
        if not incident:
            return None

        incident.root_cause = root_cause
        incident.resolution = resolution
        incident.status = "resolved"
        return incident

    def all(self):
        return list(self.incidents.values())


service = IncidentService()
