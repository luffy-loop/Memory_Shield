import pytest

from app.security.guard import MemoryGuard


@pytest.fixture
def guard(monkeypatch):
    guard = MemoryGuard()

    monkeypatch.setattr(
        guard,
        "_learned_attack",
        lambda _: False
    )

    return guard


@pytest.mark.parametrize("content", [
    "Password managers improve account security.",
    "Never share your password with strangers.",
    "A secret should be stored in a secure vault.",
    "Password hashing protects stored credentials.",
    "A PIN is commonly used for authentication.",
    "An API key provides application authentication.",
    "Access tokens should be rotated regularly.",
    "Developers should protect their API keys.",
    "Never expose your authentication token.",
    "Strong passwords improve application security."
])
def test_benign_security_discussion(guard, content):
    result = guard.analyze(content)

    assert result["action"] == "allow"


@pytest.mark.parametrize("content", [
    "My password is demo123",
    "password=FAKE_TEST_VALUE",
    "api_key=FAKE_TEST_KEY",
    "My PIN is 1234",
    "My passcode is 5678",
    "Access token: FAKE_TEST_TOKEN",
    "My secret is FAKE_SECRET_VALUE"
])
def test_actual_credential_exposure(guard, content):
    result = guard.analyze(content)

    assert result["action"] == "quarantine"


@pytest.mark.parametrize("content", [
    "Email: demo@example.invalid",
    "Contact: sample@example.invalid",
    "My email is user@example.invalid"
])
def test_email_requires_review(guard, content):
    result = guard.analyze(content)

    assert result["action"] == "review"


@pytest.mark.parametrize("content", [
    "Never share passwords. password=FAKE_TEST_VALUE",
    "API keys should be protected. api_key=FAKE_KEY",
    "Never disclose credentials. My PIN is 1234"
])
def test_defensive_text_preserves_credential_detection(
    guard, content
):
    result = guard.analyze(content)

    assert result["action"] == "quarantine"

@pytest.mark.parametrize("content", [
    "My PIN is FAKE_PIN.",
    "PIN: TEST_1234",
    "PIN=9876"
])
def test_pin_value_detection(guard, content):
    result = guard.analyze(content)

    assert result["action"] == "quarantine"
