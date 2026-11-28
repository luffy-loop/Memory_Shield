
import pytest
from app.security.normalizer import TextNormalizer


@pytest.fixture
def normalizer():
    return TextNormalizer()


def test_case_normalization(normalizer):
    assert normalizer.normalize("HELLO World") == "hello world"


def test_unicode_normalization(normalizer):
    assert normalizer.normalize("Ｈｅｌｌｏ") == "hello"


def test_whitespace_normalization(normalizer):
    assert normalizer.normalize("hello     world") == "hello world"


def test_newline_normalization(normalizer):
    assert normalizer.normalize("hello\nworld") == "hello world"


def test_tab_normalization(normalizer):
    assert normalizer.normalize("hello\tworld") == "hello world"


def test_separator_normalization(normalizer):
    assert normalizer.normalize("hello-world_example") == "hello world example"


def test_spaced_letters(normalizer):
    assert normalizer.normalize("H E L L O world") == "hello world"


def test_invisible_characters(normalizer):
    assert normalizer.normalize("hel\u200blo") == "hello"


def test_empty_string(normalizer):
    assert normalizer.normalize("") == ""


def test_whitespace_only(normalizer):
    assert normalizer.normalize("    ") == ""


def test_normal_text_preserved(normalizer):
    text = "python is a programming language"
    assert normalizer.normalize(text) == text


def test_idempotency(normalizer):
    text = "H E L L O-WORLD"
    normalized = normalizer.normalize(text)

    assert normalizer.normalize(normalized) == normalized


def test_analysis_metadata(normalizer):
    result = normalizer.analyze("HELLO-WORLD")

    assert result["original"] == "HELLO-WORLD"
    assert result["normalized"] == "hello world"
    assert result["changed"] is True
    assert result["original_length"] == 11
    assert result["normalized_length"] == 11


def test_unchanged_metadata(normalizer):
    result = normalizer.analyze("hello world")

    assert result["changed"] is False
