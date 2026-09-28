import os
import sqlite3
from datetime import datetime

from .incident import Incident


class IncidentService:
    def __init__(self, db_path=None):
        self.db_path = db_path or (
            "/tmp/memoryshield.db"
            if os.getenv("VERCEL")
            else "memoryshield.db"
        )
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT,
                    memory_content TEXT,
                    risk_score INTEGER,
                    status TEXT,
                    root_cause TEXT,
                    resolution TEXT,
                    created_at TEXT,
                    resolved_at TEXT
                )
            """)
            conn.commit()

    def _to_incident(self, row):
        return Incident(
            incident_id=row[0],
            title=row[1],
            description=row[2],
            severity=row[3],
            source=row[4],
            memory_content=row[5],
            risk_score=row[6],
            status=row[7],
            root_cause=row[8],
            resolution=row[9],
            created_at=datetime.fromisoformat(row[10]),
            resolved_at=datetime.fromisoformat(row[11])
            if row[11]
            else None
        )

    def create(self, incident):
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.title,
                incident.description,
                incident.severity,
                incident.source,
                incident.memory_content,
                incident.risk_score,
                incident.status,
                incident.root_cause,
                incident.resolution,
                incident.created_at.isoformat(),
                incident.resolved_at.isoformat()
                if incident.resolved_at
                else None
            ))
            conn.commit()

        return incident

    def get(self, incident_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,)
            ).fetchone()

        return self._to_incident(row) if row else None

    def quarantine(self, incident_id):
        incident = self.get(incident_id)

        if not incident:
            return None

        incident.status = "quarantined"
        return self.create(incident)

    def recover(self, incident_id, resolution):
        incident = self.get(incident_id)

        if not incident:
            return None

        incident.status = "recovered"
        incident.resolution = resolution
        incident.resolved_at = datetime.utcnow()

        return self.create(incident)

    def resolve(self, incident_id, root_cause, resolution):
        incident = self.get(incident_id)

        if not incident:
            return None

        incident.root_cause = root_cause
        incident.resolution = resolution
        incident.status = "resolved"
        incident.resolved_at = datetime.utcnow()

        return self.create(incident)

    def all(self):
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT *
                FROM incidents
                ORDER BY created_at DESC
            """).fetchall()

        return [self._to_incident(row) for row in rows]


service = IncidentService()