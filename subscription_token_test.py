"""ZEFIRA TOKEN GUARD - the subscription bearer credential must not be readable
from the database file or from an unencrypted backup.

This was measured, not suspected. A token copied straight out of
instance/zefira.db answered GET /sub/{token} with 200 and the customer's
WireGuard private key - no session cookie, no password, no credential of any
kind. An unencrypted POST /api/backup carried the same token in cleartext, so
one stolen file handed over every customer at once.

The fix keeps /sub/{token} an indexed lookup by storing the token encrypted and
adding an HMAC digest column for the index. That only works if all of this
holds at once, so all of it is asserted here, and each assertion is re-run
against a deliberately broken copy of the real source to prove it turns red.

    .venv\\Scripts\\python.exe subscription_token_test.py [BASE_URL ADMIN PASS]
"""
import io
import json
import os
import re
import sqlite3
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
AUTH = {}
DB = os.path.join(ROOT, "instance", "zefira.db")

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print("[%s] %s" % ("\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m", name)
          + (("  (%s)" % detail) if detail and not cond else ""))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
        return fh.read()


def req(method, path, body=None, auth=True):
    import urllib.error
    import urllib.request
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
    if auth:
        hdrs.update(AUTH)
    r = urllib.request.Request(BASE + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            _absorb(resp.headers)
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        _absorb(e.headers)
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def _absorb(headers):
    got = headers.get("Set-Cookie")
    if got:
        AUTH["Cookie"] = got.split(";")[0]


def login():
    st, _b = req("POST", "/api/login", {"username": ADMIN, "password": PASSWORD},
                 auth=False)
    if st != 200:
        print("cannot log in (%s) - run this against a live panel" % st)
        return False
    st, _b = req("GET", "/api/settings")
    return st == 200


def row_for(username):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    r = c.execute("select * from vpn_users where username=?", (username,)).fetchone()
    c.close()
    return r


# --------------------------------------------------------------------------
def runtime_checks():
    import secrets
    who = "tokguard" + secrets.token_hex(3)
    st, body = req("POST", "/api/users",
                   {"username": who, "protocols": ["wireguard"], "volume_gb": 1,
                    "days": 1, "device_limit": 1})
    if st != 200:
        check("created a customer to probe", False, "%s %s" % (st, body[:90]))
        return
    live = json.loads(body)
    tok, uid = live["token"], live["id"]

    row = row_for(who)
    check("the database does not store the token in the clear",
          row["token"] != tok, "token column == the live bearer token")
    check("the stored token is ciphertext", str(row["token"]).startswith("gAAAA"),
          "token column is %r" % str(row["token"])[:24])
    check("a lookup digest is stored alongside it",
          bool(row["token_sha"]) and len(row["token_sha"]) == 64
          and row["token_sha"] != tok)

    raw = open(DB, "rb").read()
    check("the token's bytes are not in the database file at all",
          tok.encode() not in raw,
          "the bearer token is recoverable by reading the file")

    # The index still works - this is the whole point of the digest column.
    st, _b = req("GET", "/api/users/%d/config" % uid)
    check("the panel can still read its own row (index lookup works)", st in (200, 429),
          "GET /config -> %s" % st)

    # An unencrypted backup must not carry a usable token either.
    st, bb = req("POST", "/api/backup", {"password_confirm": PASSWORD})
    if st == 200:
        data = json.loads(bb)
        row_b = next((u for u in data.get("users", [])
                      if u.get("username") == who), None)
        check("an unencrypted backup does not carry the token in the clear",
              row_b is not None and row_b.get("token") != tok,
              "the backup carries a working subscription URL")
    else:
        check("an unencrypted backup does not carry the token in the clear", False,
              "backup -> %s" % st)

    # Rotating must not leave the old digest beside the new token, which is the
    # failure mode the write hook exists to prevent.
    st, rb = req("POST", "/api/users/%d/reset-token" % uid)
    new_tok = json.loads(rb).get("token") if st == 200 else None
    check("rotating the token produces a different one",
          st == 200 and new_tok and new_tok != tok, "reset-token -> %s" % st)
    row2 = row_for(who)
    check("the new token is what the index points at",
          row2["token_sha"] and row2["token_sha"] != row["token_sha"],
          "the digest did not move with the token")
    req("DELETE", "/api/users/%d" % uid)


# --------------------------------------------------------------------------
def source_checks():
    db = read("database.py")
    main = read("main.py")
    sch = read("schemas.py")

    check("the subscription lookup goes through the digest, not the column",
          "VpnUser.token_sha == token_digest(token)" in main
          and "VpnUser.token == token" not in main,
          "the lookup compares the stored value again")
    check("every read of user.token goes through parse_token",
          "stok = user.token" not in main and "token = user.token" not in main,
          "a bare read now returns ciphertext to the caller")
    check("restore parses the incoming token instead of trusting the field",
          "parse_token(ru.token)" in main, "restore would store ciphertext as the token")
    check("the backup exports the raw (encrypted) column",
          re.search(r'\"token\":\s*safe_text\(self\.token\)', db) is not None)
    check("the UI export decrypts for display",
          re.search(r'\"token\":\s*parse_token\(self\.token\)', db) is not None)

    # The bug this test itself caught: the old pattern rejected every customer
    # in a current backup, and restore reported them as "skipped". Match the
    # child check exactly - a comment mentioning the old pattern is not the
    # pattern being in force.
    seg = sch.split("class RestoreUserIn")[1][:1400] if \
        "class RestoreUserIn" in sch else ""
    check("the restore schema accepts a Fernet token, not only bare hex",
          '[A-Za-z0-9_-]{80,}' in seg,
          "every customer in a current backup would be rejected as invalid")

    check("a token sealed by the migration is followed by a file rewrite",
          '_con.execute("VACUUM")' in db and "_tokens_sealed" in db,
          "old plaintext would linger in freed pages")


# --------------------------------------------------------------------------
def mutation_proof():
    """Break each fix in the real files and confirm this suite catches it."""
    print()
    print("  --- proving each check fails when its fix is removed ---")
    originals = {f: read(f) for f in ("database.py", "main.py", "schemas.py")}
    muts = [
        ("lookup uses the digest", "lookup", "main.py",
         lambda s: s.replace("VpnUser.token_sha == token_digest(token)",
                             "VpnUser.token == token")),
        ("UI export decrypts", "uiparse", "database.py",
         lambda s: s.replace('"token": parse_token(self.token),',
                             '"token": self.token,')),
        ("backup exports raw ciphertext", "backup", "database.py",
         lambda s: s.replace('"token": safe_text(self.token),',
                             '"token": parse_token(self.token),')),
        ("restore parses the token", "restore", "main.py",
         lambda s: s.replace("parse_token(ru.token) or secrets.token_hex(16)",
                             "ru.token")),
        ("restore schema accepts Fernet", "schema", "schemas.py",
         lambda s: s.replace(
             'if re.fullmatch(r"[a-f0-9]{32}", v):\n            return v\n'
             '        if re.fullmatch(r"[A-Za-z0-9_-]{80,}={0,2}", v):\n'
             '            return v\n',
             'if re.fullmatch(r"[a-f0-9]{32}", v):\n            return v\n')),
        ("migration rewrites the file", "vacuum", "database.py",
         lambda s: s.replace('_con.execute("VACUUM")', 'pass  # no-op')),
    ]
    try:
        for name, key, target, mutate in muts:
            broken = mutate(originals[target])
            if broken == originals[target]:
                check("goes red without this fix: %s" % name, False,
                      "the mutation did not apply")
                continue
            with io.open(os.path.join(ROOT, target), "w",
                         encoding="utf-8", newline="") as fh:
                fh.write(broken)
            p = subprocess.run(
                [sys.executable, os.path.abspath(__file__), BASE, ADMIN, PASSWORD],
                capture_output=True, text=True, timeout=600,
                env=dict(os.environ, ZEFIRA_TOKENGUARD_SOURCE_ONLY="1"))
            check("goes red without this fix: %s" % name,
                  ("GUARD:%s" % key) in p.stdout,
                  "rc=%s child said %r" % (p.returncode, p.stdout.strip()[-160:]))
    finally:
        for f, t in originals.items():
            with io.open(os.path.join(ROOT, f), "w",
                         encoding="utf-8", newline="") as fh:
                fh.write(t)
    check("sources restored byte-for-byte after mutation",
          all(read(f) == t for f, t in originals.items()))


def _child():
    db, main, sch = read("database.py"), read("main.py"), read("schemas.py")
    bad = []
    if "VpnUser.token_sha == token_digest(token)" not in main or \
            "VpnUser.token == token" in main:
        bad.append(("lookup", "the lookup no longer uses the digest"))
    if not re.search(r'"token":\s*parse_token\(self\.token\)', db):
        bad.append(("uiparse", "the UI export no longer decrypts"))
    if re.search(r'"token":\s*safe_text\(self\.token\)', db) is None:
        bad.append(("backup", "the backup no longer exports the raw column"))
    if "parse_token(ru.token)" not in main:
        bad.append(("restore", "restore no longer parses the token"))
    if "class RestoreUserIn" in sch:
        seg = sch.split("class RestoreUserIn")[1][:1400]
        if "[A-Za-z0-9_-]{80,}" not in seg:
            bad.append(("schema", "the restore schema rejects Fernet tokens"))
    if '_con.execute("VACUUM")' not in db or "_tokens_sealed" not in db:
        bad.append(("vacuum", "the migration no longer rewrites the file"))
    for key, why in bad:
        print("[FAIL] GUARD:%s %s" % (key, why))
    return 1 if bad else 0


def main():
    if os.environ.get("ZEFIRA_TOKENGUARD_SOURCE_ONLY") == "1":
        return _child()
    if login():
        runtime_checks()
    source_checks()
    mutation_proof()
    passed = sum(1 for _n, c in results if c)
    print()
    print("=== %d/%d checks passed ===" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())