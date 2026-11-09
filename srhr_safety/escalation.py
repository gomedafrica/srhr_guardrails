"""Rule-based escalation engine.

Rules live in a JSON file that clinicians can review without reading code.
The engine runs BEFORE any language model, and a triggered handover cannot be
cleared by anything the user or the model says; only a human with a
permitted role can resolve it (see SafetyLayer.resolve_handover).
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .text import contains_phrase, normalise

# Highest first. The most severe matching rule decides the response.
SEVERITY_ORDER = ["emergency", "safeguarding", "urgent", "pharmacist"]


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    response: str
    any_of: list[str] = field(default_factory=list)
    all_of: list[list[str]] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    review_status: str = "draft"
    description: str = ""

    def matches(self, norm_text: str) -> bool:
        if any(contains_phrase(norm_text, p) for p in self.any_of):
            return True
        if self.all_of and all(
            any(contains_phrase(norm_text, p) for p in group) for group in self.all_of
        ):
            return True
        return any(re.search(rx, norm_text) for rx in self.regex)


@dataclass
class Match:
    rule_id: str
    category: str
    severity: str
    response: str


class RuleSet:
    def __init__(self, rules: list[Rule], version: str, sha256: str):
        for r in rules:
            if r.severity not in SEVERITY_ORDER:
                raise ValueError(f"Rule {r.id}: unknown severity '{r.severity}'")
        self.rules = rules
        self.version = version
        self.sha256 = sha256

    @classmethod
    def load(cls, path: str | Path, expected_sha256: str | None = None) -> "RuleSet":
        raw = Path(path).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 and digest != expected_sha256:
            raise ValueError("Rule file hash mismatch: refusing to load unreviewed rules")
        data = json.loads(raw)
        rules = [
            Rule(
                id=r["id"],
                category=r["category"],
                severity=r["severity"],
                response=r["response"],
                any_of=r.get("match", {}).get("any_of", []),
                all_of=r.get("match", {}).get("all_of", []),
                regex=r.get("match", {}).get("regex", []),
                review_status=r.get("review_status", "draft"),
                description=r.get("description", ""),
            )
            for r in data["rules"]
        ]
        return cls(rules, data.get("version", "unversioned"), digest)

    def evaluate(self, text: str) -> list[Match]:
        """Return all matching rules, most severe first."""
        norm = normalise(text)
        hits = [
            Match(r.id, r.category, r.severity, r.response)
            for r in self.rules
            if r.matches(norm)
        ]
        hits.sort(key=lambda m: SEVERITY_ORDER.index(m.severity))
        return hits
