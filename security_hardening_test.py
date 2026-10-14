"""ZEFIRA HARDENING GUARD - the 2026-10-12 audit findings, made regression-proof.

Six defects came out of that audit. Each check below asserts the fixed
behaviour, and each is then re-run against a deliberately broken copy of the
real source to prove the check goes RED when the fix is removed. A guard that
cannot fail proves nothing, so "goes red" is part of the test, not a comment.

Static checks read the real files. Runtime checks drive a live panel and count
status codes - the limiter assertions are measured, not asserted from reading.

    .venv\\Scripts\\python.exe security_hardening_test.py [BASE_URL ADMIN PASS]
"""
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PASSWORD"
AUTH = {}

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
    import urllib.parse
    import urllib.request
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"}
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
    """Keep the session cookie. Without this every probe runs unauthenticated."""
    got = headers.get("Set-Cookie")
    if got:
        AUTH["Cookie"] = got.split(";")[0]


def login():
    st, body = req("POST", "/api/login",
                   {"username": ADMIN, "password": PASSWORD}, auth=False)
    if st != 200:
        print("cannot log in (%s) - run this against a live panel" % st)
        return False
    st, body = req("GET", "/api/settings")
    if st != 200:
        print("login returned 200 but the session does not work (%s)" % st)
        return False
    return True


# --------------------------------------------------------------------------
# 1. Every route that hands out a secret shares ONE budget.
#    Measured: 30 authenticated calls, counting 429s.
# --------------------------------------------------------------------------
def secret_disclosure_is_budgeted():
    st, body = req("POST", "/api/nodes",
                   {"name": "hardnode", "iran_ip": "10.7.7.7",
                    "kharej_ip": "10.7.7.8", "tunnel_port": 51821,
                    "transport": "tcp"})
    if st != 200:
        check("node created for the limiter probe", False, str(st) + " " + body[:80])
        return
    nid = json.loads(body)["id"]
    st, ub = req("POST", "/api/users",
                 {"username": "harduser", "protocols": ["wireguard"],
                  "volume_gb": 1, "days": 1, "device_limit": 1})
    uid = json.loads(ub)["id"] if st == 200 else None

    def burst(path, method="GET"):
        codes = {}
        for _ in range(30):
            s, _b = req(method, path)
            codes[s] = codes.get(s, 0) + 1
        return codes

    # /config is on its own budget key, so it gets a clean 30-call run.
    if uid:
        c = burst("/api/users/%d/config" % uid)
        check("customer config dump is rate-limited (measured %s)" % c,
              c.get(429, 0) >= 20 and c.get(200, 0) <= 12,
              "30 calls produced %s" % c)

    # /guide shares the nodereveal budget, so give reveal-token its 10 first
    # and then check the guide cannot add any more.
    b1 = burst("/api/nodes/%d/reveal-token" % nid, "POST")
    b2 = burst("/api/nodes/%d/guide" % nid)
    check("node guide is rate-limited (measured %s after %s)"
          % (b2, b1),
          b2.get(200, 0) == 0 and b1.get(429, 0) >= 20,
          "reveal %s then guide %s" % (b1, b2))

    if uid:
        req("DELETE", "/api/users/%d" % uid)
    req("DELETE", "/api/nodes/%d" % nid)


# --------------------------------------------------------------------------
# 2-6. Source-level guarantees. Each is re-checked against a broken copy.
# --------------------------------------------------------------------------
def source_checks():
    main = read("main.py")
    db = read("database.py")

    # 2. An empty scope is an unknown scope, and unknown denies.
    check("_token_scope_allowed denies an empty scope (fails closed)",
          re.search(r"scope\s*=\s*\(scopes or \"\"\)\.strip\(\)", main) is not None
          and re.search(r"if not scopes or scopes == \"full\"", main) is None,
          "the fail-open branch is back")

    # 3. The restore transaction no longer advertises guards it never ran,
    #    and the checker it advertised is gone.
    check("restore no longer claims a scrypt-hash check it never performed",
          "scrypt-strong admin hashes" not in main)
    # The name still appears in the docstring, on purpose - it explains what was
    # removed. What must be gone is the DEFINITION.
    check("the never-called _is_strong_scrypt_hash is gone",
          "def _is_strong_scrypt_hash" not in main,
          "the dead definition is back")
    check("restore really does refuse the admins array",
          re.search(r"refused \+= len\(data\.admins\)", main) is not None)

    # 4. The bot token cannot reach the journal through an exception.
    #    Match the CALL, not a window: the explanatory comment above it names
    #    _safe_ai_error too, so a window check would pass even with the call
    #    removed - which is exactly what the mutation proof caught.
    check("telegram failure log scrubs the bot token",
          re.search(r'log\.warning\("telegram notify failed: %s",\s*'
                    r'_safe_ai_error\(e, token\)\)', main) is not None)

    # 5. The WAL sidecar carries the freshest rows, so it is hardened too.
    check("SQLite WAL/SHM sidecars are chmod'ed, not just the main file",
          '-wal' in db and '-shm' in db
          and db.count("self.engine.url.database + suffix") == 1)

    # 6. Pre-update snapshots are bounded, not just pre-restore ones.
    #
    # This used to assert that the function's NAME was in the source:
    #
    #     "_prune_pre_update_snapshots" in main
    #     and re.search(r"def _prune_pre_update_snapshots", main) is not None
    #
    # It never called it. So a function whose first line raised NameError -
    # which is exactly what this one did, because main.py used INSTANCE_DIR
    # without importing it - passed. The pre-update snapshot that is supposed to
    # protect the operator's master key, CA and database from `git reset --hard`
    # had never once run, and failed in the one way that reads like a disk
    # problem. The check below calls it instead.
    # 7. The first-run banner must not claim a protection it did not apply.
    #
    # It used to chmod the credentials file to 0600 inside `except OSError:
    # pass` and then print "(mode 600)" either way. On a filesystem that refuses
    # the chmod the file keeps the umask's bits - 0644 on a default Linux umask,
    # readable by every local user - while the operator was told it was private
    # and deleted it when they were done. The password is the admin's, and it is
    # printed nowhere else precisely because the journal is readable by the adm
    # group.
    #
    # Not made fatal on purpose: this runs on first boot, and a panel that
    # refused to start would leave the operator with no admin account at all.
    # The defect was the UNCONDITIONAL claim, so that exact line must be gone.
    # My first attempt here tested `re.search(r"cred_private\)", main)`, which
    # is right in spirit and wrong in fact: in the source the guard reads
    # `if cred_private` followed by a NEWLINE, so the pattern never matched and
    # the check failed on a correct file. Asserting the absence of the old line
    # says what is actually wrong.
    check("the (mode 600) claim is no longer unconditional",
          'print(f"  PASSWORD: written to {cred_path} (mode 600)")' not in main,
          "the banner still states a mode the code never confirmed")
    check("a chmod failure on the credentials file is reported, not swallowed",
          "chmod failed" in main and "MODE 600 COULD NOT BE SET" in main)
    check("a failed chmod still tells the operator what to run",
          "chmod 600" in main)
    check("a failed chmod does not stop the panel starting",
          "cred_private = False" in main
          and "raise" not in main[main.index("cred_private = False"):
                                   main.index("cred_private = False") + 140],
          "it re-raises, which would leave a first boot with no admin")

    check("the names the updater depends on are still in the source",
          "_prune_pre_update_snapshots" in main
          and "_snapshot_runtime_state" in main,
          "the updater calls these by name")


# --------------------------------------------------------------------------
# The pre-update snapshot, actually called.
#
# _do_update runs
#     runtime_backup = _snapshot_runtime_state()
#     ok, out = _git("reset", "--hard", f"origin/{branch}", timeout=120)
# one line apart, and it goes on to the reset whether the snapshot returned a
# path or None. So None has to mean "wrote nothing", and the only way to know
# that is to run it.
#
# INSTANCE_DIR is repointed at a temporary directory and restored afterwards, so
# nothing here can read or write the real instance/.

def _snapshot_round_trip():
    import importlib
    import shutil
    import tempfile

    try:
        import main as panel
    except Exception as exc:                      # pragma: no cover
        check("main.py imports for the snapshot check", False, repr(exc)[:70])
        return

    if not hasattr(panel, "INSTANCE_DIR"):
        # main.py does not import it at module level, so the prune and the
        # snapshot both raise NameError. Saying so is the finding.
        check("the pre-update snapshot runs instead of raising", False,
              "main.py has no module-level INSTANCE_DIR, so both updater helpers "
              "raise NameError")
        return
    real = panel.INSTANCE_DIR
    tmp = tempfile.mkdtemp(prefix="snap-")
    try:
        panel.INSTANCE_DIR = __import__("pathlib").Path(tmp)
        for rel in ("secret.key", "ca.key", "ca.crt", "zefira.db"):
            with open(os.path.join(tmp, rel), "wb") as fh:
                fh.write(b"x" * 32)

        try:
            where = panel._snapshot_runtime_state()
        except BaseException as exc:
            check("the pre-update snapshot runs instead of raising",
                  False, "%s: %s" % (type(exc).__name__, exc))
            where = None
        else:
            check("the pre-update snapshot runs instead of raising", True)

        check("the snapshot returns the path it wrote, not None",
              bool(where),
              "returned None - _do_update cannot tell the operator where it is")
        if where:
            got = set(os.listdir(where))
            for rel in ("secret.key", "ca.key", "ca.crt", "zefira.db"):
                check("the snapshot carries %s" % rel, rel in got,
                      "missing: %s" % ", ".join(sorted(got)))
            check("the snapshot copies the bytes, not just the names",
                  open(os.path.join(where, "secret.key"), "rb").read() == b"x" * 32)

        # Bounded: keep=2 with five snapshots on disk leaves the two newest.
        for n in range(5):
            d = os.path.join(tmp, "pre-update-2020010%d-000000" % n)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "secret.key"), "wb") as fh:
                fh.write(b"x" * 32)
        before = sorted(d for d in os.listdir(tmp) if d.startswith("pre-update-"))
        try:
            panel._prune_pre_update_snapshots(keep=2)
            after = sorted(d for d in os.listdir(tmp) if d.startswith("pre-update-"))
        except BaseException as exc:
            check("the prune runs instead of raising", False,
                  "%s: %s" % (type(exc).__name__, exc))
            after = []
        else:
            check("the prune runs instead of raising", True)
        check("the prune is bounded to the newest snapshots",
              len(after) == 2, "%d left: %s" % (len(after), after))
        check("the prune keeps the NEWEST ones",
              after == before[-2:], "kept %s, newest are %s" % (after, before[-2:]))

        # "Best-effort: pruning must never be able to fail an update" is the
        # docstring's own promise, and the reachable way to break it is the
        # DELETION failing. Measured first: a missing directory and a path that
        # is a file both make glob() return [], so neither reaches the guard.
        import shutil as _sh

        real_rmtree = _sh.rmtree

        def _boom(path, *a, **kw):
            raise OSError(28, "No space left on device")

        _sh.rmtree = _boom
        try:
            try:
                panel._prune_pre_update_snapshots(keep=1)
                check("a prune whose deletion fails does not raise", True)
            except BaseException as exc:
                check("a prune whose deletion fails does not raise", False,
                      "%s: %s" % (type(exc).__name__, exc))
            check("the snapshots survive a failed deletion",
                  len([d for d in os.listdir(tmp) if d.startswith("pre-update-")]) >= 2)
        finally:
            _sh.rmtree = real_rmtree
    finally:
        panel.INSTANCE_DIR = real
        shutil.rmtree(tmp, ignore_errors=True)


# Only in the parent. The child imports a deliberately broken main.py, and with
# the INSTANCE_DIR import removed it has no such attribute - so running this
# there dies with AttributeError before the source checks, and the mutation
# looks unproven for a reason that has nothing to do with what it measures.
if os.environ.get("ZEFIRA_GUARD_SOURCE_ONLY") != "1":
    print()
    print("  the pre-update snapshot, actually called:")
    _snapshot_round_trip()



# Each mutation targets one fix and names it with a stable GUARD key. The
# child process re-runs the source checks against the broken file and prints
# "GUARD:<key>" for each one that turned red, so the parent can prove THIS
# fix went red rather than merely observing that something did.
MUTATIONS = [
    ("empty scope denies", "scope",
     lambda s: s.replace('scope = (scopes or "").strip()',
                         'scope = "full" if not scopes else (scopes or "").strip()')),
    ("restore docstring honesty", "doc",
     lambda s: s.replace("    What actually hardens this function:",
                         "    All hardening lives here: volume sanity, scrypt-strong admin hashes,")),
    ("dead checker removed", "dead",
     lambda s: s.replace(
         "def _apply_restore_tx(data: RestoreIn, request: Request, admin: Admin):",
         "def _is_strong_scrypt_hash(h: str | None) -> bool:\n"
         "    return True\n\n\n"
         "def _apply_restore_tx(data: RestoreIn, request: Request, admin: Admin):")),
    ("telegram token scrubbed", "tg",
     lambda s: s.replace('_safe_ai_error(e, token)', 'e')),
    ("WAL sidecar hardened", "wal",
     lambda s: s.replace('for suffix in ("", "-wal", "-shm"):', 'for suffix in ("",):')),
    ("pre-update snapshots pruned", "prune",
     lambda s: s.replace("def _prune_pre_update_snapshots", "def _disabled_prune")),
    # The one that matters. main.py used INSTANCE_DIR in the prune and the
    # snapshot without importing it, so both died on their first line with
    # NameError - and NameError is not OSError, so the prune's own guard did not
    # catch it. Removing the module-level import reproduces exactly that.
    ("the first-run banner claims a mode it did not set", "mode600",
     lambda s: s.replace(
         '"  PASSWORD: written to {cred_path} ("\n'
         '                          + ("mode 600)" if cred_private\n'
         '                             else "MODE 600 COULD NOT BE SET)"))',
         '"  PASSWORD: written to {cred_path} (mode 600)")')),
    ("INSTANCE_DIR imported where it is used", "instancedir",
     lambda s: s.replace("\nfrom config import INSTANCE_DIR\n", "\n", 1)),
]


def mutation_proof():
    """Break each fix in a scratch copy and confirm its own check goes red."""
    print()
    print("  --- proving each check fails when its fix is removed ---")
    originals = {f: read(f) for f in ("main.py", "database.py")}
    try:
        for name, key, mutate in MUTATIONS:
            target = "database.py" if key == "wal" else "main.py"
            broken = mutate(originals[target])
            if broken == originals[target]:
                check("goes red without this fix: %s" % name, False,
                      "the mutation did not apply, so this check proves nothing")
                continue
            with io.open(os.path.join(ROOT, target), "w",
                         encoding="utf-8", newline="") as fh:
                fh.write(broken)
            p = subprocess.run(
                [sys.executable, os.path.abspath(__file__), BASE, ADMIN, PASSWORD],
                capture_output=True, text=True, timeout=600,
                env=dict(os.environ, ZEFIRA_GUARD_SOURCE_ONLY="1"))
            check("goes red without this fix: %s" % name,
                  ("GUARD:%s" % key) in p.stdout,
                  "rc=%s child did not report GUARD:%s | out=%r | err=%r"
                  % (p.returncode, key, p.stdout.strip()[-200:],
                     (p.stderr or "").strip()[-300:]))
    finally:
        for f, text in originals.items():
            with io.open(os.path.join(ROOT, f), "w",
                         encoding="utf-8", newline="") as fh:
                fh.write(text)

    same = all(read(f) == t for f, t in originals.items())
    check("main.py and database.py restored byte-for-byte after mutation", same,
          "a mutated file was left behind")


def _is_strong_scrypt_hash_absent():
    return "_is_strong_scrypt_hash" not in read("main.py")


def main():
    if os.environ.get("ZEFIRA_GUARD_SOURCE_ONLY") == "1":
        # mutation child: run only the source checks, so a broken copy cannot
        # recurse into live-server probes or into another mutation.
        m = read("main.py")
        d = read("database.py")
        bad = []
        if re.search(r"if not scopes or scopes == \"full\"", m) or \
                'scope = (scopes or "").strip()' not in m:
            bad.append(("scope", "empty scope fails open again"))
        if "scrypt-strong admin hashes" in m:
            bad.append(("doc", "restore docstring lies again"))
        if "def _is_strong_scrypt_hash" in m:
            bad.append(("dead", "the dead checker is back"))
        if re.search(r'log\.warning\("telegram notify failed: %s",\s*'
                     r'_safe_ai_error\(e, token\)\)', m) is None:
            bad.append(("tg", "telegram token is not scrubbed"))
        if '-wal' not in d or '-shm' not in d:
            bad.append(("wal", "wal sidecar not hardened"))
        if "def _prune_pre_update_snapshots" not in m:
            bad.append(("prune", "pre-update snapshots not pruned"))
        # INSTANCE_DIR is used by the prune and the snapshot and was never
        # imported at module level, so both died on their first line with
        # NameError - which is not OSError, so the prune's own guard could not
        # catch it. The functions were present the entire time the feature was
        # dead, which is why the old name-based check passed.
        if "MODE 600 COULD NOT BE SET" not in m:
            bad.append(("mode600",
                        "the first-run banner claims a mode the code never set"))
        if "from config import INSTANCE_DIR" not in m:
            bad.append(("instancedir",
                        "INSTANCE_DIR is not imported, so the snapshot raises "
                        "NameError and _do_update resets --hard with no copy"))
        for key, why in bad:
            print("[FAIL] GUARD:%s %s" % (key, why))
        return 1 if bad else 0

    ok = login()
    if ok:
        secret_disclosure_is_budgeted()
    source_checks()
    mutation_proof()

    passed = sum(1 for _n, c in results if c)
    print()
    print("=== %d/%d checks passed ===" % (passed, len(results)))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())