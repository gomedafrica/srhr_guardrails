"""Check data rights, escalation, consent and age before forwarding chat text."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

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
        self._lock = Lock()
        # Keep only safety signals in process memory until consent is granted.
        self._pending_handovers: dict[str, dict] = {}
        self._pending_minors: dict[str, str] = {}
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
        with self._lock:
            return self._process(user_id, text)

    def _process(self, user_id: str, text: str) -> Decision:
        pid = pseudonymise(user_id, self.secret)
        lang = detect_language(text)
        norm = normalise(text)
        rec = self.consent.record(pid)
        hits = self.rules.evaluate(text)

        # Honor data rights and still deliver any safety response.
        rights_reply = None
        deleting = self._is(norm, DELETE_COMMANDS)
        if deleting:
            self.consent.erase(pid)
            self._pending_handovers.pop(pid, None)
            self._pending_minors.pop(pid, None)
            rights_reply = self._msg("data_deleted", lang)
        elif self._is(norm, STOP_COMMANDS):
            self.consent.withdraw(pid)
            rights_reply = self._msg("consent_withdrawn", lang)

        if rights_reply and not hits:
            return Decision(REPLY_ONLY, rights_reply, lang, allow_commerce=False)

        redacted, _ = redact(text)
        has_consent = rights_reply is None and self.consent.has_consent(pid)
        reason = minor_signal(text)
        if reason and not rights_reply:
            self._pending_minors.setdefault(pid, reason)
        if has_consent:
            rec.minor_flag = rec.minor_flag or self._pending_minors.get(pid)

        if hits:
            top = hits[0]
            handover = {"rule": top.rule_id, "severity": top.severity,
                        "at": _now(), "resolved": False}
            reply = self._msg(top.response, lang)
            decision = Decision(
                HANDOVER, reply if rights_reply is None else f"{reply}\n\n{rights_reply}",
                lang, redacted_text=redacted if rights_reply is None else None,
                triggered=[h.rule_id for h in hits], severity=top.severity,
                allow_commerce=False)
            if has_consent:
                rec.handover = handover
                self._log(rec, redacted, decision)
                self.consent.store.put(rec)
                self._pending_minors.pop(pid, None)
            else:
                if not deleting:
                    self._pending_handovers[pid] = handover
                decision.notes.append("not_stored_no_consent")
            return decision

        handover = self._pending_handovers.get(pid) or rec.handover
        if handover and not handover.get("resolved"):
            return Decision(HANDOVER, self._msg("handover_pending", lang), lang,
                            redacted_text=redacted, triggered=[handover["rule"]],
                            severity=handover["severity"], allow_commerce=False)

        if not has_consent:
            if norm in {normalise(p) for p in CONSENT_YES}:
                self.consent.grant(pid, minor_flag=self._pending_minors.get(pid))
                self._pending_minors.pop(pid, None)
                return Decision(REPLY_ONLY, self._msg("consent_thanks", lang), lang,
                                allow_commerce=False)
            return Decision(ASK_CONSENT, self._msg("consent_prompt", lang), lang,
                            allow_commerce=False)

        if rec.minor_flag:
            decision = Decision(MINOR_PATHWAY, self._msg("minor_pathway", lang), lang,
                                redacted_text=redacted, allow_commerce=False,
                                notes=[f"minor_signal:{rec.minor_flag}"])
            self._log(rec, redacted, decision)
            self.consent.store.put(rec)
            self._pending_minors.pop(pid, None)
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
        with self._lock:
            rec = self.consent.store.get(pid)
            if not rec or not rec.handover:
                return self._pending_handovers.pop(pid, None) is not None
            rec.messages.append({"at": _now(), "event": "handover_resolved",
                                 "by": resolver_role})
            rec.handover = None
            self.consent.store.put(rec)
            self._pending_handovers.pop(pid, None)
            return True

    def clear_minor_flag(self, user_id: str, resolver_role: str) -> bool:
        if resolver_role not in RESOLVER_ROLES:
            raise PermissionError(f"Role '{resolver_role}' cannot clear age flags")
        pid = pseudonymise(user_id, self.secret)
        with self._lock:
            rec = self.consent.store.get(pid)
            if not rec:
                return self._pending_minors.pop(pid, None) is not None
            rec.minor_flag = None
            self.consent.store.put(rec)
            self._pending_minors.pop(pid, None)
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
