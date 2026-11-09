"""Detect signals that a user may be under 18.

A signal never proves age. It switches the conversation to a protective
pathway (no product sales, age-appropriate information, human handover offer)
until a human reviews it.
"""

import re

from .text import normalise

ADULT_AGE = 18

_AGE_STATEMENTS = [
    # "I am 16", but not "I am 5 months pregnant" or "I am 2 weeks late"
    re.compile(r"\b(?:i am|i'm|i m|im|i be|my age is|my age na|age)\s+(\d{1,2})\b"
               r"(?!\s*(?:months?|weeks?|days?|hours?|minutes?|times?|kg|tablets?|pills?))"),
    re.compile(r"\b(\d{1,2})\s*(?:years old|year old|yrs old|yrs|yo|years)\b"),
]

# Nigerian school levels that almost always mean a minor.
_SCHOOL_SIGNALS = [
    re.compile(r"\b(?:jss|jss ?[1-3]|js ?[1-3]|sss ?[1-3]|ss ?[1-3])\b"),
    re.compile(r"\b(?:secondary school|junior secondary|senior secondary|primary school)\b"),
    re.compile(r"\b(?:waec|neco|bece)\b"),
]


def minor_signal(text: str) -> str | None:
    """Return a short reason string if the text suggests the user is under 18."""
    norm = normalise(text)
    for pattern in _AGE_STATEMENTS:
        for m in pattern.finditer(norm):
            age = int(m.group(1))
            if 9 <= age < ADULT_AGE:
                return f"stated_age_{age}"
    for pattern in _SCHOOL_SIGNALS:
        if pattern.search(norm):
            return "school_level"
    return None
