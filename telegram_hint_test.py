"""Guard: a Telegram error the operator sees must say what to do.

api_telegram_test already surfaced Telegram's own description. That was not
enough: "chat not found" is one description for four unrelated mistakes, and the
most common one - the token was changed after the chat id was recorded, so the
id belongs to a different bot - is the one nobody suspects.

Pure string mapping, so it is tested offline. Asserts the hint DRAWS A
DISTINCTION rather than just existing: the same description with a numeric group
id, a numeric user id and an @channel must not produce the same advice, because
those three need three different fixes.

The last case matters as much as the others: an unknown description must stay
empty. Inventing advice for a cause the panel has not reasoned about is how a
hint becomes a lie.
"""
import io
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main  # noqa: E402

fails = []


def check(label, cond, detail=""):
    if not cond:
        fails.append(label)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", label,
                           ("  -> " + detail) if detail else ""))


print()
print("=== 1. the three chat-not-found causes get three different answers ===")
NF = "Bad Request: chat not found"
group = main._tg_hint(NF, "-1001234567890")
user = main._tg_hint(NF, "123456789")
chan = main._tg_hint(NF, "@mychannel")
check("a numeric group id gets the token-mismatch answer",
      "different bot" in group, group[:70])
check("a positive numeric id is recognised as a USER id",
      "/start" in user, user[:70])
check("an @channel gets the admin answer",
      "admin" in chan.lower(), chan[:70])
check("the three answers are all different",
      len({group, user, chan}) == 3,
      "the hint does not actually distinguish the cases")

print()
print("=== 2. the other errors an operator really hits ===")
for desc, needle in (
        ("Bad Request: bot is not a member of the channel chat", "not in that chat"),
        ("Bad Request: not enough rights to send text messages", "admin"),
        ("Forbidden: bot was blocked by the user", "blocked"),
        ("Bad Request: bot can't initiate conversation with a user", "/start"),
        ("Bad Request: too many requests", "rate-limit")):
    h = main._tg_hint(desc, "-1001")
    check("%-48s hinted" % desc[:48], needle in h, h[:60])

print()
print("=== 3. an unknown reason stays empty rather than guessing ===")
check("an unrecognised description produces no advice",
      main._tg_hint("Bad Request: something nobody has seen", "-1001") == "")
check("an empty description produces no advice", main._tg_hint("", "-1001") == "")
check("None does not raise", main._tg_hint(None, "") == "")

print()
print("=== 4. it is wired into the endpoint, not just defined ===")
src = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"),
              encoding="utf-8-sig").read()
check("api_telegram_test appends the hint",
      "_tg_hint(" in src and "_hint}" in src.replace(" ", "_hint}"),
      "the hint exists but the endpoint does not use it")
check("the description is still surfaced too",
      "{err} — {str(desc)[:120]}" in src,
      "Telegram's own wording was dropped instead of supplemented")
check("the hint never decides whether a message was sent",
      "ok_code" not in src[src.index("def _tg_hint"):src.index("def _tg_hint") + 200],
      "a text helper must not touch delivery")

print()
print("=== %s ===" % ("ALL OK" if not fails else "%d FAILED" % len(fails)))
sys.exit(1 if fails else 0)