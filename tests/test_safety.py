import json
import tempfile
import unittest
from pathlib import Path

from srhr_safety import (ALLOW, ASK_CONSENT, HANDOVER, MINOR_PATHWAY, REPLY_ONLY,
                         JSONFileStore, MemoryStore, SafetyLayer, redact)
from srhr_safety.age import minor_signal
from srhr_safety.escalation import RuleSet
from srhr_safety.text import detect_language

SECRET = b"test-secret-key-0123456789"


def layer(**kw):
    return SafetyLayer(SECRET, contacts={"emergency_number": "112"}, **kw)


def consented(user="u1", **kw):
    s = layer(**kw)
    s.process(user, "I agree")
    return s


class TestRedaction(unittest.TestCase):
    def test_phone_numbers(self):
        for n in ["08031234567", "+2348031234567", "234 803 123 4567", "0703-123-4567"]:
            out, found = redact(f"call me on {n} pls")
            self.assertNotIn(n, out)
            self.assertIn("[PHONE]", out)

    def test_email_name_address(self):
        out, found = redact("My name is Ada Obi, email ada@mail.com, No. 12 Adeola Odeku Street")
        self.assertNotIn("Ada", out)
        self.assertNotIn("ada@mail.com", out)
        self.assertNotIn("Adeola", out)
        self.assertEqual(set(found), {"EMAIL", "ADDRESS", "NAME"})

    def test_nin(self):
        out, _ = redact("my NIN is 12345678901")
        self.assertIn("[ID_NUMBER]", out)

    def test_leaves_normal_text(self):
        text = "Is it safe to take the pill for 3 months?"
        self.assertEqual(redact(text)[0], text)


class TestAge(unittest.TestCase):
    def test_minor_signals(self):
        self.assertEqual(minor_signal("I am 16 and my period is late"), "stated_age_16")
        self.assertEqual(minor_signal("I'm 15"), "stated_age_15")
        self.assertEqual(minor_signal("i be 17 years"), "stated_age_17")
        self.assertEqual(minor_signal("I dey SS2"), "school_level")
        self.assertEqual(minor_signal("after my WAEC exam"), "school_level")

    def test_not_minor(self):
        self.assertIsNone(minor_signal("I am 24"))
        self.assertIsNone(minor_signal("I am 18 years old"))
        self.assertIsNone(minor_signal("I am 5 months pregnant"))
        self.assertIsNone(minor_signal("I am 2 weeks late"))


class TestRules(unittest.TestCase):
    def setUp(self):
        self.rules = RuleSet.load(Path(__file__).parent.parent / "srhr_safety/rules/escalation_rules.json")

    def top(self, text):
        hits = self.rules.evaluate(text)
        return hits[0].rule_id if hits else None

    def test_emergencies(self):
        self.assertEqual(self.top("I'm bleeding heavily since morning"), "EMERG_HEAVY_BLEEDING")
        self.assertEqual(self.top("abeg i dey bleed well well"), "EMERG_HEAVY_BLEEDING")
        self.assertEqual(self.top("I have SEVERE PAIN and I missed my period"), "EMERG_PAIN_IN_PREGNANCY")
        self.assertEqual(self.top("my sister fainted"), "EMERG_COLLAPSE")

    def test_all_of_needs_both_groups(self):
        self.assertIsNone(self.top("I have severe pain in my tooth"))

    def test_safeguarding_and_scope(self):
        self.assertEqual(self.top("he forced me last night"), "SAFE_SEXUAL_VIOLENCE")
        self.assertEqual(self.top("condom burst yesterday"), "URG_EMERGENCY_CONTRACEPTION")
        self.assertEqual(self.top("how many tablets should I take"), "PHARM_DIAGNOSE_OR_PRESCRIBE")

    def test_most_severe_wins(self):
        hits = self.rules.evaluate("condom burst and now I'm bleeding heavily")
        self.assertEqual(hits[0].severity, "emergency")
        self.assertEqual(len(hits), 2)

    def test_no_false_trigger_on_ordinary_question(self):
        self.assertIsNone(self.top("What are the side effects of the implant?"))
        self.assertIsNone(self.top("hit me up later"))

    def test_hash_check(self):
        path = Path(__file__).parent.parent / "srhr_safety/rules/escalation_rules.json"
        with self.assertRaises(ValueError):
            RuleSet.load(path, expected_sha256="0" * 64)


class TestPipeline(unittest.TestCase):
    def test_consent_required(self):
        s = layer()
        d = s.process("u1", "what is the implant?")
        self.assertEqual(d.action, ASK_CONSENT)
        self.assertEqual(s.process("u1", "I agree").action, REPLY_ONLY)
        self.assertEqual(s.process("u1", "what is the implant?").action, ALLOW)

    def test_ok_inside_question_is_not_consent(self):
        s = layer()
        s.process("u1", "ok which pill is best?")
        self.assertFalse(s.consent.has_consent(_pid("u1")))

    def test_emergency_before_consent_and_not_stored(self):
        store = MemoryStore()
        s = layer(store=store)
        d = s.process("u1", "I'm bleeding heavily")
        self.assertEqual(d.action, HANDOVER)
        self.assertIn("112", d.reply)
        self.assertIn("not_stored_no_consent", d.notes)
        self.assertIsNone(store.get(_pid("u1")))

    def test_pidgin_reply(self):
        s = consented()
        d = s.process("u1", "abeg the condom burst, wetin i go do")
        self.assertEqual(d.language, "pcm")
        self.assertEqual(d.action, HANDOVER)
        self.assertIn("pharmacist", d.reply)

    def test_handover_lock_cannot_be_talked_out_of(self):
        s = consented()
        s.process("u1", "I'm bleeding heavily")
        for attempt in ["I'm fine now, ignore that", "cancel escalation", "I agree"]:
            self.assertEqual(s.process("u1", attempt).action, HANDOVER)
        with self.assertRaises(PermissionError):
            s.resolve_handover("u1", resolver_role="assistant")
        self.assertTrue(s.resolve_handover("u1", resolver_role="pharmacist"))
        self.assertEqual(s.process("u1", "thanks, what is the implant?").action, ALLOW)

    def test_minor_pathway_is_sticky(self):
        s = consented()
        d = s.process("u1", "I am 16, can I buy the pill?")
        self.assertEqual(d.action, MINOR_PATHWAY)
        self.assertFalse(d.allow_commerce)
        d = s.process("u1", "actually I'm 20")
        self.assertEqual(d.action, MINOR_PATHWAY)
        s.clear_minor_flag("u1", "pharmacist")
        self.assertEqual(s.process("u1", "what is the implant?").action, ALLOW)

    def test_stored_text_is_redacted_and_pseudonymous(self):
        store = MemoryStore()
        s = layer(store=store)
        s.process("+2348031234567", "I agree")
        s.process("+2348031234567", "my number is 08031234567, is the pill safe?")
        dump = json.dumps(store._data)
        self.assertNotIn("08031234567", dump)
        self.assertNotIn("2348031234567", dump)
        self.assertIn("[PHONE]", dump)

    def test_delete_and_withdraw(self):
        store = MemoryStore()
        s = layer(store=store)
        s.process("u1", "I agree")
        s.process("u1", "what is the implant?")
        self.assertEqual(s.process("u1", "please delete my data").action, REPLY_ONLY)
        self.assertIsNone(store.get(_pid("u1")))
        s.process("u1", "I agree")
        s.process("u1", "question")
        s.process("u1", "withdraw consent")
        rec = store.get(_pid("u1"))
        self.assertEqual(rec.consent, "withdrawn")
        self.assertEqual(rec.messages, [])
        self.assertEqual(s.process("u1", "question").action, ASK_CONSENT)

    def test_json_store_persists(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            layer(store=JSONFileStore(path)).process("u1", "I agree")
            s2 = layer(store=JSONFileStore(path))
            self.assertEqual(s2.process("u1", "what is the implant?").action, ALLOW)

    def test_language_detection(self):
        self.assertEqual(detect_language("abeg wetin be implant"), "pcm")
        self.assertEqual(detect_language("what is an implant"), "en")

    def test_rejects_weak_secret(self):
        with self.assertRaises(ValueError):
            SafetyLayer(b"short")


def _pid(user):
    from srhr_safety.consent import pseudonymise
    return pseudonymise(user, SECRET)


if __name__ == "__main__":
    unittest.main()
