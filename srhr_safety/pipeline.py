"""SafetyLayer: the single entry point a chatbot calls for every incoming message.

Order of checks (by design):
  1. Data-rights commands (delete / stop) are honoured immediately.
  2. Safety rules run on EVERY message, even before consent, so an emergency
     always gets an emergency reply. Nothing is stored without consent.
  3. An active handover locks the conversation until a human resolves it.
  4. Consent gate.
  5. Under-18 signals switch to the protective pathway.
  6. Only then may the message reach the AI assistant, in redacted form.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .age import minor_signal
from .consent import ConsentManager, MemoryStore, pseudonymise
from .escalation import RuleSet
from .redact import redact
from .text import contains_phrase, detect_language, normalise

PACKAGE_ROOT = Path(__file__).resolve().parent

# Actions returned to the host chatbot
ALLOW = "allow"                  # pass redacted text to the AI assistant
HANDOVER = "handover"            # route to a human; AI must not reply
ASK_CONSENT = "ask_consent"      # send consent prompt, do not process further
REPLY_ONLY = "reply_only"        # send the reply, nothing else
MINOR_PATHWAY = "minor_pathway"  # AI may give age-appropriate info only; no sales

DELETE_COMMANDS = ["delete my data", "erase my data", "remove my data",
                   "comot my data", "clear my data", "/delete"]
STOP_COMMANDS = ["withdraw consent", "stop using my data", "/stop", "i no gree again"]
CONSENT_YES = ["yes", "i agree", "agree", "i consent", "ok", "okay", "i gree",
               "yes i agree", "/agree"]

RESOLVER_ROLES = {"pharmacist", "clinician", "safeguarding_officer"}


@dataclass
class Decision:
    action: str
    reply: str | None = None
    language: str = "en"
    redacted_text: str | None = None
    triggered: list[str] = field(default_factory=list)
    severity: str | None = None
    allow_commerce: bool = True
    notes: list[str] = field(default_factory=list)


class SafetyLayer:
    def __init__(self, secret: bytes, store: MemoryStore | None = None,
                 rules_path: str | Path | None = None,
                 messages_dir: str | Path | None = None,
                 policy_version: str = "2026-11-v1",
                 expected_rules_sha256: str | None = None,
                 contacts: dict[str, str] | None = None):
        if not secret or len(secret) < 16:
            raise ValueError("Provide a secret of at least 16 bytes for pseudonymisation")
        self.secret = secret
        # Local referral contacts that fill {placeholders} in messages, e.g.
        # {"emergency_number": "112", "gbv_referral": "...", "crisis_line": "..."}
        self.contacts = contacts or {}
        self.consent = ConsentManager(store or MemoryStore(), policy_version)
        self.rules = RuleSet.load(
            rules_path or PACKAGE_ROOT / "rules" / "escalation_rules.json",
            expected_sha256=expected_rules_sha256)
        mdir = Path(messages_dir or PACKAGE_ROOT / "messages")
        self.messages = {
            p.stem: json.loads(p.read_text(encoding="utf-8")) for p in mdir.glob("*.json")
        }

    # ---------------------------------------------------------------- helpers
    def _msg(self, key: str, lang: str) -> str:
        table = self.messages.get(lang) or self.messages["en"]
        text = table.get(key) or self.messages["en"].get(key, key)
        return text.format_map(_Defaults(self.contacts))

    @staticmethod
    def _is(norm: str, phrases: list[str]) -> bool:
        return any(norm == normalise(p) or contains_phrase(norm, p) for p in phrases)

    # ------------------------------------------------------------------- main
    def process(self, user_id: str, text: str) -> Decision:
        pid = pseudonymise(user_id, self.secret)
        lang = detect_language(text)
        norm = normalise(text)
        rec = self.consent.record(pid)

        # 1. Data rights
        if self._is(norm, DELETE_COMMANDS):
            self.consent.erase(pid)
            return Decision(REPLY_ONLY, self._msg("data_deleted", lang), lang)
        if self._is(norm, STOP_COMMANDS):
            self.consent.withdraw(pid)
            return Decision(REPLY_ONLY, self._msg("consent_withdrawn", lang), lang)

        # 2. Safety rules on every message
        hits = self.rules.evaluate(text)
        redacted, _ = redact(text)
        has_consent = self.consent.has_consent(pid)

        if hits:
            top = hits[0]
            decision = Decision(
                HANDOVER, self._msg(top.response, lang), lang,
                redacted_text=redacted, triggered=[h.rule_id for h in hits],
                severity=top.severity, allow_commerce=False)
            if has_consent:
                rec.handover = {"rule": top.rule_id, "severity": top.severity,
                                "at": _now(), "resolved": False}
                self._log(rec, redacted, decision)
                self.consent.store.put(rec)
            else:
                decision.notes.append("not_stored_no_consent")
            return decision

        # 3. Handover lock: user text cannot unlock it
        if rec.handover and not rec.handover.get("resolved"):
            return Decision(HANDOVER, self._msg("handover_pending", lang), lang,
                            redacted_text=redacted, triggered=[rec.handover["rule"]],
                            severity=rec.handover["severity"], allow_commerce=False)

        # 4. Consent gate
        if not has_consent:
            # Exact replies only: "ok, which pill?" must not count as consent
            if norm in {normalise(p) for p in CONSENT_YES}:
                self.consent.grant(pid)
                return Decision(REPLY_ONLY, self._msg("consent_thanks", lang), lang)
            return Decision(ASK_CONSENT, self._msg("consent_prompt", lang), lang)

        # 5. Under-18 signals (sticky until a human reviews)
        reason = minor_signal(text)
        if reason and not rec.minor_flag:
            rec.minor_flag = reason
        if rec.minor_flag:
            decision = Decision(MINOR_PATHWAY, self._msg("minor_pathway", lang), lang,
                                redacted_text=redacted, allow_commerce=False,
                                notes=[f"minor_signal:{rec.minor_flag}"])
            self._log(rec, redacted, decision)
            self.consent.store.put(rec)
            return decision

        # 6. Safe to pass on
        decision = Decision(ALLOW, None, lang, redacted_text=redacted)
        self._log(rec, redacted, decision)
        self.consent.store.put(rec)
        return decision

    def resolve_handover(self, user_id: str, resolver_role: str, note: str = "") -> bool:
        """Only a human with a permitted role can release a handover lock."""
        if resolver_role not in RESOLVER_ROLES:
            raise PermissionError(f"Role '{resolver_role}' cannot resolve handovers")
        pid = pseudonymise(user_id, self.secret)
        rec = self.consent.store.get(pid)
        if not rec or not rec.handover:
            return False
        rec.handover.update(resolved=True, resolved_by=resolver_role,
                            resolved_at=_now(), note=redact(note)[0])
        rec.messages.append({"at": _now(), "event": "handover_resolved",
                             "by": resolver_role})
        rec.handover = None
        self.consent.store.put(rec)
        return True

    def clear_minor_flag(self, user_id: str, resolver_role: str) -> bool:
        if resolver_role not in RESOLVER_ROLES:
            raise PermissionError(f"Role '{resolver_role}' cannot clear age flags")
        pid = pseudonymise(user_id, self.secret)
        rec = self.consent.store.get(pid)
        if not rec:
            return False
        rec.minor_flag = None
        self.consent.store.put(rec)
        return True

    @staticmethod
    def _log(rec, redacted: str, d: Decision) -> None:
        rec.messages.append({"at": _now(), "text": redacted, "action": d.action,
                             "rules": d.triggered})


class _Defaults(dict):
    """Leave unknown {placeholders} visible so missing contacts are noticed."""

    def __missing__(self, key):
        return "{" + key + "}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
