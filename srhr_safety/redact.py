"""Remove direct identifiers from chat text before it is stored or analysed.

Pattern-based and intentionally conservative: it is better to over-redact a
number than to store someone's phone number next to an SRH question.
"""

import re

_PATTERNS = [
    # Emails
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # Nigerian phone numbers: +234 / 234 / 0 followed by 70x, 80x, 81x, 90x, 91x...
    ("PHONE", re.compile(r"(?<!\d)(?:\+?234[\s-]?|0)[789][01]\d(?:[\s-]?\d){7}(?!\d)")),
    # 11-digit identifiers (NIN, BVN) and other long digit runs
    ("ID_NUMBER", re.compile(r"(?<!\d)\d{10,}(?!\d)")),
    # Street addresses: "No. 12 Adeola Street", "12b Allen Avenue"
    ("ADDRESS", re.compile(
        r"\b(?:no\.?\s*)?\d+[a-z]?,?\s+(?:[A-Za-z]+\s+){1,4}"
        r"(?:street|st|road|rd|avenue|ave|close|crescent|cres|way|lane|drive|estate)\b",
        re.IGNORECASE)),
]

# Self-introductions in English and Pidgin: "my name is Ada", "na me be Chidi"
_NAME_INTRO = re.compile(
    r"\b((?i:my name is|my name na|i am called|call me|na me be|this is))\s+(?!(?i:on|at)\b)"
    r"((?i:[a-z]+)(?:\s+[A-Z][a-z]+|\s+[a-z]+(?=\s*(?:[,.!?]|$)))?)")


def redact(text: str) -> tuple[str, list[str]]:
    """Return (redacted_text, list_of_redacted_categories)."""
    found: list[str] = []
    out = text or ""
    for label, pattern in _PATTERNS:
        out, n = pattern.subn(f"[{label}]", out)
        if n:
            found.append(label)

    def _name(m: re.Match) -> str:
        return f"{m.group(1)} [NAME]"

    out, n = _NAME_INTRO.subn(_name, out)
    if n:
        found.append("NAME")
    return out, found
