from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe

@dataclass
class CredentialLease:
    agent_id: str
    scope: str
    token: str
    expires_at: datetime
    active: bool = True

class CredentialManager:
    """Demo credential broker: scoped, short-lived, revocable leases."""
    def __init__(self, ttl_seconds=300):
        self.ttl_seconds = ttl_seconds
        self.leases = {}

    def issue(self, agent_id, scope):
        now = datetime.now(timezone.utc)
        lease = CredentialLease(agent_id, scope, token_urlsafe(18),
                                now + timedelta(seconds=self.ttl_seconds))
        self.leases[lease.token] = lease
        return lease

    def revoke(self, token):
        lease = self.leases.get(token)
        if not lease:
            return False
        lease.active = False
        return True

    def validate(self, token, agent_id, scope):
        lease = self.leases.get(token)
        if not lease or not lease.active:
            return False
        if lease.agent_id != agent_id or lease.scope != scope:
            return False
        return datetime.now(timezone.utc) < lease.expires_at

    def rotate(self, agent_id, scope):
        for lease in self.leases.values():
            if lease.agent_id == agent_id and lease.scope == scope and lease.active:
                lease.active = False
        return self.issue(agent_id, scope)

    def snapshot(self):
        return [{"agent_id": x.agent_id, "scope": x.scope,
                 "expires_at": x.expires_at.isoformat(), "active": x.active}
                for x in self.leases.values()]

credential_manager = CredentialManager()
