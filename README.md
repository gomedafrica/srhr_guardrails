# SRHR Safety Kit

An open-source safety layer for sexual and reproductive health (SRHR) chatbots, built for low-resource settings and tested first in Nigeria.

It sits between a messaging channel (Telegram, WhatsApp, SMS, web chat) and any AI assistant, and it runs on **every** message before the AI sees it:

| Check | What it does |
|---|---|
| **Escalation rules** | Detects danger signs, gender-based violence disclosures, time-sensitive needs and out-of-scope requests (diagnosis, prescribing). It hands the conversation to a human. The AI cannot clear a handover; only a pharmacist, clinician or safeguarding officer can. |
| **Consent** | Asks for plain-language consent before anything is stored. Emergencies still get an emergency reply without consent. Only a temporary handover flag is kept in memory. |
| **Privacy filter** | Removes phone numbers, emails, ID numbers (NIN/BVN), street addresses and self-introduced names before storage. Platform user IDs are replaced by a keyed hash. |
| **Data rights** | "delete my data", "withdraw consent" (and Pidgin equivalents) work at any point in the chat. |
| **Under-18 pathway** | Age statements and school-level signals (JSS, SS2, WAEC...) switch to a protective pathway: no product sales, general information only, offer of a trained person. Only a human can clear it. |
| **Language** | Replies in Nigerian English or Nigerian Pidgin, detected per message. |

Rules and messages are plain JSON files, so clinicians and language reviewers can check and change them without touching code.

> **Status: v0.1, draft.** The code is tested. The clinical rules and the Pidgin wording are **examples that have not yet been clinically validated or reviewed by native speakers**. Read [SAFETY.md](SAFETY.md) before using this with real users.

## Quick start

Python 3.10+, no dependencies.

```bash
git clone <repo-url> && cd srhr-safety-kit
python -m unittest discover -s tests
python examples/cli_demo.py            # try it in a terminal
```

## Using it in your chatbot

```python
from srhr_safety import SafetyLayer, ALLOW, HANDOVER

safety = SafetyLayer(
    secret=SECRET_KEY_BYTES,                 # keep out of source control
    contacts={"emergency_number": "112",
              "crisis_line": "...", "gbv_referral": "..."},
)

def on_message(user_id, text):
    d = safety.process(user_id, text)
    if d.action == ALLOW:
        return my_ai_assistant(d.redacted_text, language=d.language,
                               allow_commerce=d.allow_commerce)
    if d.action == HANDOVER:
        notify_pharmacist_queue(user_id, d.severity, d.triggered)
    return d.reply                           # consent prompt, safety message, etc.

# Later, from the pharmacist dashboard:
safety.resolve_handover(user_id, resolver_role="pharmacist")
```

### Actions returned

| `action` | Meaning for the host app |
|---|---|
| `allow` | Pass `redacted_text` to your AI. Respect `allow_commerce`. |
| `handover` | Send `reply`, alert a human. The AI must not answer. |
| `ask_consent` | Send `reply` (the consent prompt). Process nothing else. |
| `minor_pathway` | Send `reply`. The AI may give general, age-appropriate information only. No sales. |
| `reply_only` | Send `reply` (for example, confirming deletion). |

### Integrity of the rules

`SafetyLayer(..., expected_rules_sha256="...")` refuses to start if the rule file differs from the version your clinical reviewer signed off. Changing a rule then requires a new review and a new hash.

## Project layout

```
srhr_safety/
  pipeline.py        SafetyLayer: order of checks, handover lock
  escalation.py      rule engine (any_of / all_of / regex, severity ordering)
  consent.py         consent records, pseudonymisation, delete/withdraw/export, stores
  redact.py          identifier removal
  age.py             under-18 signals
  text.py            normalisation, English/Pidgin detection
  rules/escalation_rules.json   DRAFT rules for clinical review
  messages/en.json, pcm.json    DRAFT user-facing wording
tests/               unit tests
examples/cli_demo.py
```

## Contributing

Most needed: clinical review of the rules, native-speaker review of Pidgin, and new languages (Hausa, Yoruba, Igbo). Add a `messages/<code>.json` file and the matching phrases in the rules. See [ROADMAP.md](ROADMAP.md).

## Licence

- Code: [MIT](LICENSE)
- Rules and message content: [CC BY 4.0](LICENSE-CONTENT)

Developed by FinnBlue Technologies (GoMed).
