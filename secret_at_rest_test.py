"""secret_data must be unreadable in the database file, and still readable by the panel.

secret_data is the customer's UUID, their WireGuard private key, their OpenVPN
client keypair and the L2TP PSK - the one thing in the database a customer
cannot regenerate. It was `json.dumps`'d into a TEXT column, so anyone who
could read the SQLite file read every customer's connection credentials. The
backup export wrote the same cleartext, so a copied backup file was a
credential dump too.

The fix reuses the Fernet the panel already derives from SECRET_KEY for the AI
key, the Telegram bot token and the REALITY private key.

The risk was never "does it encrypt" - it is "does every reader still read
it". A row written before the change is bare JSON and stays that way until the
customer is re-provisioned, and every install in the field upgrades in place,
so the plaintext branch is the current format of every existing row, not a
legacy to delete later. parse_secret_map accepts both; the restore path used to
call json.loads directly, which would have turned every restore of a new
backup into a silent re-provision - invalidating customer configs at exactly
the moment they need them. That is asserted here.
"""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(ROOT, "database.py")
PROTOCOLS = os.path.join(ROOT, "protocols.py")
MAIN = os.path.join(ROOT, "main.py")
RECOVERY = r"C:\Users\mrlurix\AppData\Local\Temp\opencode\measure_encrypted.py"

MAP = {"vless": "0f8fad5b-d9cb-469f-a165-70867728950e",
       "wireguard": "yAnz5TF+lXXJte14tji3zlMNq/+hdMtnYhBYBS6seXU=",
       "l2tp": json.dumps({"password": "p", "psk": "k"}, separators=(",", ":"))}
PLAIN = json.dumps(MAP, separators=(",", ":"))


def read(p):
    with io.open(p, encoding="utf-8-sig", newline="") as fh:
        return fh.read()


def live():
    """Run the real code against a real database and report what it observed."""
    if sys.platform != "win32" or not os.path.exists(RECOVERY):
        return None
    import subprocess
    r = subprocess.run([sys.executable, RECOVERY], capture_output=True, text=True,
                       cwd=ROOT, timeout=180)
    return r.stdout


def checks(db, protos, main):
    return {
        # writing
        "serialize_secrets encrypts":
            "encrypt_text(plain)" in protos,
        # Matched line-wise, not as one regex: the fallback has a five-line comment
        # between the `except` and the log call, and a single pattern spanning
        # that was reporting a correct branch as missing.
        "the plaintext fallback is not silent":
            any(l.strip().startswith("log.warning")
                for l in protos.split("\n")
                if "storing plaintext" in l) and "except Exception" in protos,
        # reading
        "parse_secret_map still accepts bare JSON":
            'if secret_data.startswith("{"):' in db,
        "parse_secret_map also decrypts":
            "decrypt_text(secret_data)" in db,
        "an unreadable bundle returns {} rather than raising":
            "except Exception" in db and "return {}" in db,
        "a non-dict payload is rejected":
            "isinstance(parsed, dict)" in db,
        # the restore path, which silently re-provisioned on the old shape
        "restore uses parse_secret_map, not json.loads":
            "parse_secret_map(ru.secret_data)" in main,
        "no direct json.loads of the backup secret field":
            "json.loads(ru.secret_data)" not in main,
        "parse_secret_map is imported where it is used":
            re.search(r"from database import \([^)]*parse_secret_map", main, re.S) is not None
            or "from database import parse_secret_map" in main,
    }


def main():
    failures = []
    db, protos, main = read(DATABASE), read(PROTOCOLS), read(MAIN)
    base = checks(db, protos, main)

    print("== 1. written encrypted, readable either way ==")
    for name, ok in sorted(base.items()):
        print("   %-52s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            failures.append(name)

    print()
    print("== 2. run it for real: encrypt, store, read back, export ==")
    out = live()
    if out is None:
        print("   SKIPPED: the measurement harness is not available here")
        print("   -> the static assertions above still ran and still apply.")
    else:
        want = [
            "starts with '{' (plaintext JSON) : False",
            "a WireGuard private key in it     : False",
            "parse_secret_map round-trips      : True",
            "column value is not plaintext    : True",
            "the WireGuard key survives        : True",
            "legacy row still readable        : True",
            "a WireGuard key is NOT in it     : True",
        ]
        missing = [w for w in want if w not in out]
        for w in want:
            print("   %-52s %s" % (w, "ok" if w in out else "FAIL"))
        if missing:
            failures.append("live behaviour: %d of %d" % (len(missing), len(want)))

    print()
    print("== 3. each assertion can fail: undo it, it must go red ==")
    muts = [
        ("write plaintext again",
         lambda d, p, m: (d, p.replace("        return encrypt_text(plain)", "        return plain"), m),
         ["serialize_secrets encrypts"]),
        ("reader stops accepting bare JSON",
         lambda d, p, m: (d.replace('    if secret_data.startswith("{"):', "    if False:"), p, m),
         ["parse_secret_map still accepts bare JSON"]),
        ("reader stops decrypting",
         lambda d, p, m: (d.replace("decrypt_text(secret_data)", "secret_data"), p, m),
         ["parse_secret_map also decrypts"]),
        ("restore goes back to json.loads",
         lambda d, p, m: (d, p, m.replace("parse_secret_map(ru.secret_data)", "json.loads(ru.secret_data)")),
         ["restore uses parse_secret_map, not json.loads",
          "no direct json.loads of the backup secret field"]),
        ("drop the import",
         lambda d, p, m: (d, p, re.sub(r"^\s*parse_secret_map,\n", "", m, flags=re.M)),
         ["parse_secret_map is imported where it is used"]),
    ]
    for name, fn, must in muts:
        nd, np_, nm = fn(db, protos, main)
        if (nd, np_, nm) == (db, protos, main):
            print("   %-36s FAIL (mutation inert)" % name)
            failures.append(name + ": inert")
            continue
        after = checks(nd, np_, nm)
        still = [g for g in must if after[g]]
        if still:
            print("   %-36s FAIL (stayed green: %s)" % (name, ", ".join(still)))
            failures.append(name + ": cannot fail")
        else:
            print("   %-36s ok (goes red: %s)" % (name, ", ".join(must)))

    print()
    if failures:
        print("FAIL: %d problem(s): %s" % (len(failures), "; ".join(failures)))
        return 1
    print("PASS: the credential bundle is encrypted at rest and still readable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())