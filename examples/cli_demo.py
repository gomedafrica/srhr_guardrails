"""Try the safety layer in a terminal: python examples/cli_demo.py

Type messages as a user would. Commands: /pharmacist (resolve a handover as a
pharmacist), /quit.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from srhr_safety import ALLOW, SafetyLayer  # noqa: E402

layer = SafetyLayer(
    secret=os.environ.get("SRHR_SECRET", "demo-secret-change-me-123").encode(),
    contacts={"emergency_number": "112",
              "crisis_line": "[configure crisis line]",
              "gbv_referral": "[configure GBV referral]"},
)
USER = "demo-user"

print("SRHR Safety Kit demo. Type a message (or /pharmacist, /quit).\n")
while True:
    try:
        text = input("you > ").strip()
    except EOFError:
        break
    if text == "/quit":
        break
    if text == "/pharmacist":
        print("[handover resolved]" if layer.resolve_handover(USER, "pharmacist")
              else "[no active handover]")
        continue
    d = layer.process(USER, text)
    print(f"  action={d.action} lang={d.language} rules={d.triggered} "
          f"commerce={'yes' if d.allow_commerce else 'no'}")
    if d.redacted_text and d.redacted_text != text:
        print(f"  stored as: {d.redacted_text}")
    if d.action == ALLOW:
        print("bot > (message passed to your AI assistant)\n")
    else:
        print(f"bot > {d.reply}\n")
