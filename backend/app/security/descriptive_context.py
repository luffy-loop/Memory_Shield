import re


class DescriptiveContext:

    patterns = (
        r"(?:a|an|the)?\s*"
        r"(?:system instructions?|developer messages?)\s+"
        r"(?:defines?|describes?|explains?)\s+"
        r"(?:application|software|operating)\s+"
        r"(?:behavior|behaviour|requirements|rules|policies)",

        r"(?:the\s+)?(?:phrase|expression|statement)\s+"
        r"[\"']?"
        r"(?:ignore|override|bypass|disable|disregard)\s+"
        r"(?:(?:all|previous|existing)\s+)*"
        r"(?:instructions?|security|rules?|security checks)"
        r"[\"']?\s+"
        r"is\s+(?:an?\s+)?"
        r"(?:attack example|example of prompt injection|"
        r"example of an attack|prompt injection example)"
    )

    @classmethod
    def remove_descriptions(cls, content):
        clauses = re.split(
            r"([.!?](?=\s|$)|[;\n])",
            content
        )

        cleaned = []

        for clause in clauses:
            candidate = clause.strip()

            descriptive = any(
                re.fullmatch(
                    pattern,
                    candidate,
                    flags=re.IGNORECASE
                )
                for pattern in cls.patterns
            )

            if descriptive:
                cleaned.append(" ")
            else:
                cleaned.append(clause)

        return "".join(cleaned)