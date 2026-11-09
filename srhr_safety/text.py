"""Text normalisation and simple language detection (Nigerian English / Pidgin)."""

import re
import unicodedata

_NON_WORD = re.compile(r"[^a-z0-9']+")
_REPEATS = re.compile(r"(.)\1{2,}")  # "pleaseeee" -> "pleasee"

# Common Nigerian Pidgin markers. Deliberately small and transparent; extend with
# native-speaker review rather than guessing.
PIDGIN_MARKERS = {
    "dey", "abeg", "wetin", "una", "wan", "sabi", "comot", "pikin", "oga",
    "abi", "shey", "sef", "dem", "wahala", "e don", "how far", "no be",
    "make i", "i go", "na im", "belle",
}


def normalise(text: str) -> str:
    """Lowercase, strip accents and punctuation, collapse repeats and spaces."""
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    text = text.replace("’", "'")
    text = _REPEATS.sub(r"\1\1", text)
    text = _NON_WORD.sub(" ", text)
    return " ".join(text.split())


def contains_phrase(norm_text: str, phrase: str) -> bool:
    """Whole-word phrase match on already-normalised text."""
    p = normalise(phrase)
    if not p:
        return False
    return f" {p} " in f" {norm_text} "


def detect_language(text: str) -> str:
    """Return 'pcm' (Nigerian Pidgin) or 'en'. Heuristic; defaults to English."""
    norm = normalise(text)
    hits = sum(1 for m in PIDGIN_MARKERS if contains_phrase(norm, m))
    return "pcm" if hits >= 1 else "en"
