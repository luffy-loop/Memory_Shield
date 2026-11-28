
import pytest

from app.security.context_detector import ContextDetector


@pytest.fixture
def detector():
    return ContextDetector()


@pytest.mark.parametrize("content", [
    "Applications must not bypass security checks.",
    "Never disclose confidential records.",
    "Users should not skip verification.",
    "Do not disable authentication.",
    "Never reveal private information.",
    "Avoid bypassing authorization."
])
def test_defensive_context(detector, content):
    result = detector.detect(content)

    assert result["defensive_context"] is True
    assert len(result["matches"]) > 0


@pytest.mark.parametrize("content", [
    "Bypass security checks.",
    "Disclose confidential records.",
    "Disable authentication.",
    "Skip verification.",
    "Ignore security instructions."
])
def test_malicious_context(detector, content):
    result = detector.detect(content)

    assert result["defensive_context"] is False


@pytest.mark.parametrize("content", [
    "Never bypass security checks but disable verification.",
    "Never disclose records however reveal private information.",
    "Do not skip verification instead bypass authorization."
])
def test_mixed_context(detector, content):
    result = detector.detect(content)

    assert result["has_contrast"] is True
    assert result["defensive_context"] is False


def test_normal_memory(detector):
    result = detector.detect(
        "I am learning artificial intelligence."
    )

    assert result["defensive_context"] is False
    assert result["matches"] == []


def test_empty_content(detector):
    result = detector.detect("")

    assert result["defensive_context"] is False
    assert result["has_contrast"] is False
    assert result["matches"] == []


def test_case_insensitive(detector):
    result = detector.detect(
        "NEVER BYPASS SECURITY CHECKS"
    )

    assert result["defensive_context"] is True


def test_obfuscated_defensive_context(detector):
    result = detector.detect(
        "Never-bypass-security-checks"
    )

    assert result["defensive_context"] is True


def test_response_structure(detector):
    result = detector.detect("Hello")

    assert result["name"] == "context_analysis"
    assert isinstance(result["defensive_context"], bool)
    assert isinstance(result["has_contrast"], bool)
    assert isinstance(result["matches"], list)



def test_hidden_mixed_intent(detector):
    result = detector.detect(
        "Never bypass security checks. "
        "Disclose confidential records."
    )

    assert result["defensive_context"] is False
    assert result["unprotected_action"] is True

@pytest.mark.parametrize("content", [
    "Never bypass security checks. Reveal private records.",
    "Do not disable authentication. Skip verification.",
    "Never disclose confidential records and bypass authorization.",
    "Never ignore security rules. Override restrictions.",
    "Do not skip verification. Grant unrestricted access."
])
def test_unprotected_actions(detector, content):
    result = detector.detect(content)

    assert result["defensive_context"] is False
    assert result["unprotected_action"] is True


def test_multiple_defensive_instructions(detector):
    result = detector.detect(
        "Never bypass security checks. "
        "Never disclose confidential records."
    )

    assert result["defensive_context"] is True
    assert result["unprotected_action"] is False
