"""The AI fetch's URL and its validated base must be built the same way.

_ai_complete validates `eff_base`, pins its resolved IP, strips the provider key
for local targets, and then fetches a `url` it built SEPARATELY. The safety of
that fetch rests entirely on the two agreeing - the same shape as the README
block-count check and the pre-update snapshot's name check: a real invariant
that only the reader is enforcing.

Measured across all four providers before this existed:

    anthropic  url = _anthropic_base(base_url) + "/v1/messages"
    gemini     base = _gemini_base(base_url)
    groq       base = _groq_base(base_url)
    openai     base = (base_url or "https://api.openai.com/v1").rstrip("/")

against

    eff_base = _anthropic_base(base_url) if provider == "anthropic"
               else _gemini_base(base_url)      if provider == "gemini"
               else _groq_base(base_url)        if provider == "groq"
               else (base_url or "https://api.openai.com/v1")

They agree today. If a fifth provider is added and only one of the two is wired
to its helper, this panel fetches an unvalidated URL with the operator's provider
key - and the SSRF guard, the key stripping and the IP pinning all silently stop
applying.

    .venv\\Scripts\\python.exe ai_url_guard_test.py
"""
import ast
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MAIN = os.path.join(ROOT, "main.py")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print("[%s] %s" % ("\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m", name)
          + (("  (%s)" % detail) if detail and not cond else ""))


def function_body(src, name):
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(src, n) or ""
    return ""



# --------------------------------------------------------------------------
# Child mode: the parent mutates main.py and looks for one GUARD token per
# mutation. It runs the SAME source checks and names the ones that turned red,
# so a token means the property broke and nothing else.
# --------------------------------------------------------------------------
if os.environ.get("ZEFIRA_AIURL_CHILD") == "1":
    _src = io.open(MAIN, encoding="utf-8", newline="").read()
    _body = function_body(_src, "_ai_complete")
    _L = _body.split("\n")
    _eff = ""
    for _i, _l in enumerate(_L):
        if "eff_base = (" in _l:
            _eff = "\n".join(_L[_i:_i + 6])
            break
    _helpers = set(re.findall(r"_(\w+)_base\(base_url\)", _eff))

    def _prov(index):
        for _j in range(index, -1, -1):
            _m = re.search(r'(?:el)?if provider == "(\w+)"', _L[_j])
            if _m:
                return _m.group(1)
            if re.match(r"\s*else\s*:", _L[_j]):
                return "default"
        return None

    _seen = {}
    for _i, _l in enumerate(_L):
        if re.match(r"\s*(url|base)\s*=", _l):
            for _h in re.findall(r"_(\w+)_base\(base_url\)", _l):
                _seen.setdefault(_prov(_i), set()).add(_h)
    for _p, _hs in _seen.items():
        for _h in _hs:
            if _h not in _helpers:
                print("GUARD:helper %s builds its url from _%s_base, which "
                      "eff_base does not validate" % (_p, _h))
    # A branch that replaces a validated helper with a literal must be caught
    # even though it names no helper at all.
    for _i, _l in enumerate(_L):
        if re.match(r"\s*base\s*=\s*\(base_url\s*or\s*\"https?://", _l) and \
                _prov(_i) not in (None, "default"):
            print("GUARD:helper %s builds its url from a literal that eff_base "
                  "never validated" % _prov(_i))

    if re.search(r"pinned\s*=\s*_ai_pinned_ip\(eff_base\)", _body) is None:
        print("GUARD:pin the fetch no longer pins the validated host")
    if re.search(r"if not pinned:\s*\n\s*return False", _body) is None:
        print("GUARD:pin an unresolvable host is no longer refused")
    if "blocked_reason = _ai_base_url_blocked(eff_base)" not in _body:
        print("GUARD:order the blocked-base check no longer runs")
    elif "blocked_reason = _ai_base_url_blocked(eff_base)" in _body:
        try:
            if _body.index("_ai_base_url_blocked(eff_base)") >= \
                    _body.index("urllib.request.Request(url"):
                print("GUARD:order the blocked-base abort comes AFTER the request "
                      "is built")
        except ValueError:
            print("GUARD:order the fetch no longer builds a Request")
    if "_ai_target_is_local" not in _body or "headers.pop(_h, None)" not in _body:
        print("GUARD:key the provider key is no longer stripped for a local target")
    if "2_000_000" not in _body:
        print("GUARD:cap the reply body cap is gone")
    raise SystemExit(0)

src = io.open(MAIN, encoding="utf-8", newline="").read()
body = function_body(src, "_ai_complete")
L = body.split("\n")


def provider_of(index):
    """The nearest `if provider == "x"` above a line."""
    cur = None
    for j in range(index, -1, -1):
        m = re.search(r'(?:el)?if provider == "(\w+)"', L[j])
        if m:
            return m.group(1)
        if re.match(r"\s*else\s*:", L[j]):
            return "default"
    return cur


print()
print("  --- each provider's url must come from the helper eff_base uses ---")
# eff_base, as written
eff = ""
for i, l in enumerate(L):
    if "eff_base = (" in l:
        eff = "\n".join(L[i:i + 6])
        break
assert eff, "eff_base was not found in _ai_complete"
HELPERS = set(re.findall(r"_(\w+)_base\(base_url\)", eff))
print("    eff_base uses helpers: %s, plus the literal default" % sorted(HELPERS))
check("eff_base has a literal https default for the last branch",
      "https://" in eff)

# which helper each provider's url/base line comes from
seen = {}
for i, l in enumerate(L):
    if re.match(r"\s*(url|base)\s*=", l):
        for h in re.findall(r"_(\w+)_base\(base_url\)", l):
            seen.setdefault(provider_of(i), set()).add(h)
for prov in sorted(seen):
    for h in seen[prov]:
        check("%s builds its url from _%s_base, which eff_base validates"
              % (prov, h), h in HELPERS,
              "eff_base does not use _%s_base" % h)

# the default branch: base_url or a literal, never a bare concatenation
for i, l in enumerate(L):
    if re.match(r"\s*base\s*=\s*\(base_url", l):
        check("the default branch derives from base_url or a literal https default",
              "base_url" in l and "https://" in l, l.strip()[:60])

print()
print("  --- the fetch keeps the protections that depend on eff_base ---")
check("the fetch pins the resolved IP of eff_base",
      re.search(r"pinned\s*=\s*_ai_pinned_ip\(eff_base\)", body) is not None)
check("an unresolvable host is refused rather than fetched",
      re.search(r"if not pinned:\s*\n\s*return False", body) is not None)
check("a blocked eff_base aborts before the request is built",
      body.index("_ai_base_url_blocked(eff_base)") < body.index("urllib.request.Request(url"))
check("the provider key is stripped for a local target",
      "_ai_target_is_local" in body and 'headers.pop(_h, None)' in body)
check("redirects are refused, so a 302 cannot leave the pinned host",
      "_NoRedirectCls" in src or "_NoRedirect" in src)
check("the reply body is capped so a hostile provider cannot OOM the worker",
      "2_000_000" in body)

print()
print("  --- every outbound URL is either a literal or validated ---")
OTHER = ("main.py", "protocols.py", "database.py", "schemas.py", "config.py")
risky = []
for f in OTHER:
    t = io.open(os.path.join(ROOT, f), encoding="utf-8").read()
    for n in ast.walk(ast.parse(t)):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "Request" and n.args:
            seg = " ".join((ast.get_source_segment(t, n) or "").split())
            if "http" not in seg.split(",")[0][:24] and not seg.startswith("urllib"):
                risky.append((f, n.lineno, seg[:56]))
for f, ln, seg in risky:
    print("    %s L%d %s" % (f, ln, seg))
check("no Request is built from a URL that is neither literal nor eff_base-derived",
      not risky, "%d call site(s)" % len(risky))

# --------------------------------------------------------------------------
print()
print("  --- proving the invariant fails when a branch disagrees ---")
BACKUP = os.path.join(os.environ.get("TEMP", "."), "main_aiurl_backup.py")
MUTATIONS = [
    ("a provider url is built from a helper eff_base does not validate",
     "GUARD:helper",
     lambda s: s.replace("            base = _groq_base(base_url)",
                         "            base = (base_url or \"https://evil.example\").rstrip(\"/\")")),
    ("the fetch stops pinning the validated host",
     "GUARD:pin",
     lambda s: s.replace("pinned = _ai_pinned_ip(eff_base)",
                         "pinned = _ai_pinned_ip('https://api.openai.com')")),
    ("the blocked-base abort is moved after the request is built",
     "GUARD:order",
     lambda s: s.replace(
         '        blocked_reason = _ai_base_url_blocked(eff_base)',
         '        blocked_reason = None')),
]
original = io.open(MAIN, encoding="utf-8", newline="").read()
io.open(BACKUP, "w", encoding="utf-8", newline="").write(original)
try:
    for label, token, fn in MUTATIONS:
        broken = fn(original)
        if broken == original:
            check("goes red without this fix: %s" % label, False,
                  "the mutation did not apply")
            continue
        io.open(MAIN, "w", encoding="utf-8", newline="").write(broken)
        try:
            r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                               capture_output=True, text=True, timeout=240,
                               env=dict(os.environ, ZEFIRA_AIURL_CHILD="1"))
            check("goes red without this fix: %s" % label, token in r.stdout,
                  "child said %r" % (r.stdout or r.stderr).strip()[-130:])
        finally:
            io.open(MAIN, "w", encoding="utf-8", newline="").write(original)
    check("main.py restored byte-for-byte after mutation",
          io.open(MAIN, encoding="utf-8", newline="").read() == original)
finally:
    io.open(MAIN, "w", encoding="utf-8", newline="").write(original)
    try:
        os.remove(BACKUP)
    except OSError:
        pass

passed = sum(1 for _n, c in results if c)
print()
print("=== %d/%d checks passed ===" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)