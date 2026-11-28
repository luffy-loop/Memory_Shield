
import re
import unicodedata


class TextNormalizer:

    @staticmethod
    def normalize_unicode(text: str) -> str:
        return unicodedata.normalize("NFKC", text)

    @staticmethod
    def remove_invisible_characters(text: str) -> str:
        return "".join(
            char for char in text
            if unicodedata.category(char) != "Cf"
        )

    @staticmethod
    def normalize_case(text: str) -> str:
        return text.casefold()

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def normalize_separators(text: str) -> str:
        return re.sub(r"[-_.]+", " ", text)

    @staticmethod
    def collapse_spaced_letters(text: str) -> str:
        pattern = r"\b(?:[a-z]\s+){2,}[a-z]\b"

        return re.sub(
            pattern,
            lambda match: re.sub(
                r"\s+", "", match.group()
            ),
            text
        )

    def normalize(self, text: str) -> str:
        text = self.normalize_unicode(text)
        text = self.remove_invisible_characters(text)
        text = self.normalize_case(text)
        text = self.normalize_separators(text)
        text = self.normalize_whitespace(text)
        text = self.collapse_spaced_letters(text)

        return self.normalize_whitespace(text)

    def analyze(self, text: str) -> dict:
        normalized = self.normalize(text)

        return {
            "original": text,
            "normalized": normalized,
            "changed": text != normalized,
            "original_length": len(text),
            "normalized_length": len(normalized)
        }
