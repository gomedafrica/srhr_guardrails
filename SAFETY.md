# Safety design and known limits

## Principles

1. **The AI does not diagnose or prescribe.** Requests for diagnosis, dosing or prescriptions go to a licensed pharmacist.
2. **Safety checks come first.** Rules run on every message, before consent and before any AI model, so an emergency always gets an emergency reply.
3. **Handovers cannot be talked out of.** Once a rule triggers, nothing the user or the AI says releases the conversation. Only a human with a permitted role (`pharmacist`, `clinician`, `safeguarding_officer`) can resolve it.
4. **Store as little as possible.** Chat text is saved only with consent and after redaction. Before consent, the layer keeps only pseudonymous handover and age signals in process memory. These signals are lost on restart. A deletion request clears saved records and these in-memory signals. User IDs are keyed hashes. Withdrawal erases conversation content, and deletion erases the record.
5. **Protect possible minors.** An under-18 signal blocks product sales and stays in place until a human reviews it.
6. **When unsure, escalate.** Rules are written to prefer false alarms over missed danger signs.

These follow the data minimisation and data-subject-rights principles of the Nigeria Data Protection Act 2023. Using this kit does not by itself make a service compliant.

## Review status

| Component | Status |
|---|---|
| Code (engine, consent, redaction, pipeline) | Unit tested |
| Escalation rules (`rules/escalation_rules.json`) | **Draft: requires sign-off by a licensed clinician or pharmacist** |
| English messages | **Draft: requires clinical review and user testing** |
| Pidgin messages and phrases | **Draft: requires native-speaker review** |
| Referral contacts | **Must be configured per deployment** (`contacts=`) |

Record reviewers and dates in the `review` block of the rule file, then pin its hash with `expected_rules_sha256`.

## Known limitations

- **Keyword matching, not understanding.** Rules miss phrasings they don't list, and they don't handle negation ("I'm *not* bleeding heavily" still triggers). This is deliberate (fail safe), but rules must be tested with real, anonymised conversations.
- **Redaction is pattern-based.** It catches common Nigerian phone, ID, email and address formats and self-introduced names. It won't catch every name or location mentioned in free text.
- **Age detection is a signal, not verification.** Users can misstate their age. The pathway reduces risk; it does not remove it.
- **Language detection is a simple heuristic** that leans towards Pidgin when common markers appear.
- **Concurrency protection applies within one SafetyLayer instance.** Deployments with multiple workers need shared safety state and atomic updates.
- **The included stores are for pilots.** Production use needs an encrypted database, access control and retention limits.
