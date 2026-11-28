
import re

from app.security.normalizer import TextNormalizer


class ContextDetector:

    def __init__(self):
        self.normalizer = TextNormalizer()

        self.defensive_patterns = [
            r"\b(?:must|should|do|does|can)\s+not\s+"
            r"(?:bypass|disable|skip|disclose|reveal|ignore)\b",

            r"\bnever\s+"
            r"(?:bypass|disable|skip|disclose|reveal|ignore)\b",

            r"\b(?:prevent|avoid)\s+"
            r"(?:bypassing|disabling|skipping|disclosing|revealing)\b"
        ]

        self.contrast_pattern = (
            r"\b(?:but|however|instead|except|although|yet)\b"
        )

        self.action_pattern = r'\b(?:bypass|disable|skip|disclose|reveal|ignore|override|remove|expose|release|grant|retrieve|discard|suspend|replace|forget)\b|\b(?:follow|obey|execute|accept)\s+only\b|\balways\s+trust\b'

    def detect(self, content):
        text = self.normalizer.normalize(content)

        matches = [
            match.group()
            for pattern in self.defensive_patterns
            for match in re.finditer(pattern, text)
        ]

        has_contrast = bool(
            re.search(self.contrast_pattern, text)
        )

        remaining_text = text

        for pattern in self.defensive_patterns:
            remaining_text = re.sub(
                pattern, " ", remaining_text
            )

        unprotected_action = bool(
            re.search(self.action_pattern, remaining_text)
        )

        defensive_context = (
            bool(matches)
            and not has_contrast
            and not unprotected_action
        )

        return {
            "name": "context_analysis",
            "defensive_context": defensive_context,
            "has_contrast": has_contrast,
            "unprotected_action": unprotected_action,
            "matches": matches
        }
