"""Reset shared in-memory state so tests cannot affect each other."""
import pytest

from app.agent_security.registry import registry
from app.agent_security.service import engine
from app.incidents.service import service as incident_service


@pytest.fixture(autouse=True)
def reset_security_state():
    registry.reset()
    engine.audit.clear()
    engine.approvals.clear()
    yield
    registry.reset()
    engine.audit.clear()
    engine.approvals.clear()
