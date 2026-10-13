"""BackPack v1.8.5 in the tunnel section - enforced, and proved red.

The panel pinned BackPack v1.8.2 while upstream shipped v1.8.3, v1.8.4 and
v1.8.5. Three releases of new capability, and the guide kept describing the
wizard those releases retired: it told the operator to invent the kharej's token
by hand (upstream now refuses a link whose two ends disagree), pointed at
Link Test (replaced by Connection Test in v1.8.5), and offered nothing for the
per-tunnel cap, the restart schedule, the backup addresses or the sni carrier
that v1.8.4 and v1.8.5 added.

So this checks both halves: that the pin is the version the guide was written
against, and that every capability it claims to carry is actually wired through
the model, the schema, the route, the guide and all four locales. A guide that
describes a feature the panel cannot store is worse than a guide that is merely
old, because the operator finds out at the far end of a tunnel.

    .venv\\Scripts\\python.exe backpack_tunnel_test.py
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

P_MAIN = os.path.join(ROOT, "main.py")
P_PROTO = os.path.join(ROOT, "protocols.py")
P_SCHEM = os.path.join(ROOT, "schemas.py")
P_DB = os.path.join(ROOT, "database.py")
P_HTML = os.path.join(ROOT, "templates", "panel.html")
P_JS = os.path.join(ROOT, "static", "app.js")
P_I18N = os.path.join(ROOT, "static", "i18n.js")

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print("[%s] %s" % ("\033[92mPASS\033[0m" if cond else "\033[91mFAIL\033[0m", name)
          + (("  (%s)" % detail) if detail and not cond else ""))


def src(p):
    return io.open(p, encoding="utf-8", newline="").read()


MAIN, PROTO, SCHEM, DB, HTML, JS, I18N = (src(p) for p in
                                          (P_MAIN, P_PROTO, P_SCHEM, P_DB,
                                           P_HTML, P_JS, P_I18N))

NODE = {"name": "n1", "transport": "tcp", "iran_ip": "5.61.9.10",
        "kharej_ip": "2.33.4.5", "tunnel_port": 443,
        "forwarded_ports": "", "udp_forward": False}
FULL = dict(NODE, transport="tcp-pck", preset="aggressive",
            traffic_limit_gb=500, restart_hours=12,
            backup_hosts="5.61.9.11, edge.example.com")

# --------------------------------------------------------------------------
if os.environ.get("ZEFIRA_BP_CHILD") != "1":
    import protocols
    import schemas

    print()
    print("  --- the pin ---")
    v = protocols.BACKPACK_VERSION
    c = protocols.BACKPACK_PIN_COMMIT
    h = protocols.BACKPACK_PIN_SHA256
    check("the pin is v1.8.5, not the v1.8.2 it sat on for three releases",
          v == "v1.8.5", v)
    check("the pinned commit is a full 40-hex sha", bool(re.fullmatch(r"[0-9a-f]{40}", c)), c)
    check("the pinned installer hash is a full 64-hex sha256",
          bool(re.fullmatch(r"[0-9a-f]{64}", h)), h)
    check("the guide tells the operator which release it is written for",
          v in protocols.backpack_guide(NODE, "T"))
    check("the guide hands out the pinned commit, not a floating branch",
          c in protocols.backpack_guide(NODE, "T"))
    check("the guide hands out the pinned hash",
          h in protocols.backpack_guide(NODE, "T"))
    check("the pin is not the v1.8.2 pair that was there before",
          c != "5e1d15734550c7133fe512ab62475ce1482cf1da"
          and h != "478789edc3ca702724ca643bfc3785123da0d4983e80f060726d8e258d82ab18")

    print()
    print("  --- the sni carrier, added upstream in v1.8.4 ---")
    check("sni is an accepted transport", "sni" in protocols.TUNNEL_TRANSPORTS)
    check("sni is in the schema's transport list", '"sni"' in SCHEM)
    check("sni is in the form", 'value="sni"' in HTML)
    check("sni has a label in the guide",
          '"sni":' in PROTO and "SNI Spoofing" in PROTO)
    check("sni reaches the guide as a transport name",
          "SNI Spoofing" in protocols.backpack_guide(
              dict(NODE, transport="sni"), "T"))

    print()
    print("  --- the four new options, end to end ---")
    FIELDS = ("preset", "traffic_limit_gb", "restart_hours", "backup_hosts")
    for f in FIELDS:
        check("%s is a column on TunnelNode" % f,
              re.search(r"\n    %s = Column\(" % f, DB) is not None)
        check("%s is in the migration list" % f,
              '_add("tunnel_nodes", "%s"' % f in DB)
        check("%s is a field on TunnelNodeIn" % f,
              re.search(r"\n    %s: " % f, SCHEM) is not None)
        check("%s is returned by to_dict" % f,
              '"%s"' % f in DB)
        check("%s is passed to the model by POST /api/nodes" % f,
              "%s=data.%s" % (f, f) in MAIN or
              ("backup_hosts" == f and "backup_hosts=_bp_join_hosts(data.backup_hosts)" in MAIN))
    check("the form has an input or select for each",
          all(x in HTML for x in ('id="node-preset"', 'id="node-limit"',
                                  'id="node-restart"', 'id="node-backup"')))
    check("app.js sends each",
          all(x in JS for x in ('$("#node-preset").value', '"#node-limit"',
                                '"#node-restart"', '"#node-backup"')))

    print()
    print("  --- defaults equal upstream's own ---")
    m = schemas.TunnelNodeIn(name="n", iran_ip="1.2.3.4", kharej_ip="5.6.7.8",
                             tunnel_port=443)
    check("a node created with no new fields keeps turbo / no cap / off / none",
          (m.preset, m.traffic_limit_gb, m.restart_hours, m.backup_hosts)
          == ("turbo", 0, 0, ""),
          str((m.preset, m.traffic_limit_gb, m.restart_hours, m.backup_hosts)))
    check("sni validates end to end",
          schemas.TunnelNodeIn(name="n", iran_ip="1.2.3.4", kharej_ip="5.6.7.8",
                               tunnel_port=443, transport="sni").transport == "sni")
    for bad, why in (({"preset": "turboo"}, "a preset upstream has no such thing"),
                     ({"traffic_limit_gb": -1}, "a negative cap"),
                     ({"backup_hosts": "9.9.9.9;rm -rf /"}, "a shell metacharacter"),
                     ({"backup_hosts": "9.9.9.9\nx"}, "an embedded newline")):
        try:
            schemas.TunnelNodeIn(name="n", iran_ip="1.2.3.4", kharej_ip="5.6.7.8",
                                 tunnel_port=443, **bad)
            check("refused: %s" % why, False, "it was accepted")
        except Exception:
            check("refused: %s" % why, True)

    print()
    print("  --- every route decorator is on a handler, not on a helper ---")
    # This is not a hypothetical. Adding a module-level helper by inserting
    # it just above `def api_nodes_create(` left it sitting between the
    # decorator and the handler, so the decorator registered the helper,
    # FastAPI turned its `raw` argument into a required query parameter,
    # and every POST /api/nodes answered 422 with loc=[query, raw] - tunnel
    # creation broken outright, and invisible to any check that only reads
    # source. The check below looks at what FOLLOWS each decorator.
    stray = []
    for m in re.finditer(r"^@app\.(get|post|put|patch|delete)\(", MAIN, re.M):
        tail = MAIN[m.start():]
        nl = tail.index(chr(10))
        nxt = tail[nl + 1:].split(chr(10))[0]
        if not (nxt.startswith("def ") or nxt.startswith("async def ")):
            stray.append((MAIN[:m.start()].count(chr(10)) + 1, nxt[:48]))
    check("no @app decorator is separated from its handler",
          not stray, str(stray[:3]))
    check("the helper sits ABOVE the decorator, not between",
          MAIN.index("def _bp_join_hosts(") < MAIN.index('@app.post("/api/nodes")'))

    print()
    print("  --- backup addresses are held to the SSRF rule ---")
    # Indentation, not offset. The previous check compared the guard's position
    # with the primary's raise line and reported True for a guard that sat
    # directly beneath it - unreachable, because the raise ends that branch, and
    # looking perfectly healthy. Dedenting is what makes the block run at all.
    _L = MAIN.split(chr(10))
    _i = next(k for k, l in enumerate(_L) if l.strip().startswith("for label, host in"))
    _g = next(k for k, l in enumerate(_L) if "for _i, _host in enumerate(" in l)

    def _ind(n):
        return len(_L[n]) - len(_L[n].lstrip())

    check("the backup_hosts guard is dedented to the loop's own column, so it runs",
          _ind(_g) == _ind(_i),
          "guard at column %d, loop at %d" % (_ind(_g), _ind(_i)))
    check("the guard sits after the loop, not before it", _g > _i)
    # Reach is settled by the column check above. What a column cannot see is
    # whether the guard examines the address at all - a guard that iterates the
    # list and never looks at an entry is at the right indentation and does
    # nothing whatsoever.
    _body = chr(10).join(_L[_g:_g + 8])
    check("the guard tests each backup address",
          "_hostname_is_ssrf_blocked(_host)" in _body, _body[:70])
    check("the guard refuses when one is blocked",
          "raise HTTPException(" in _body and "backup_hosts[{_i}]" in _body)
    check("it refuses with the index of the offending entry",
          "backup_hosts[{_i}]" in MAIN)

    print()
    print("  --- the guide speaks v1.8.5 ---")
    out = protocols.backpack_guide(NODE, "T")
    for label, probe in (
            ("the setup link is the supported path",
             "sudo backpack link apply '<paste the setup link from STEP 1>'"),
            ("a kharej with no BackPack is set up by one command",
             'bash <(curl -fsSL "$BP") link apply'),
            ("applying the same link again updates the tunnel",
             # The guide wraps at 66 columns, so "UPDATES that tunnel in place"
             # spans a newline and never matched. The probe has to stop at the
             # wrap.
             "UPDATES that tunnel in"),
            ("the kharej must not invent its own token",
             "must NOT be given a token of its own"),
            ("Connection Test replaces Link Test", "option 0"),
            ("the removed speed tests are named as removed",
             "Speed Test and Game Latency Test are gone"),
            ("only WSS proves the far end", "X-Backpack-Proof"),
            ("plain tcp/ws/udp are said not to authenticate the server",
             "authenticate nothing"),
    ):
        check("the guide says %s" % label, probe in out, "missing: %r" % probe[:44])
    fout = protocols.backpack_guide(FULL, "T")
    check("the guide no longer tells the operator to invent the kharej token",
          "same as Iran!" not in out and "TOKEN          : {token}   (same" not in out)
    check("the guide no longer points at the retired Link Test",
          "Manage -> Link Test" not in out)

    # Each of these only appears on a node that sets the option, which is the
    # point: a node that sets none of them must read as it always did. Checking
    # them against `out` was checking a guide that cannot contain them.
    print()
    print("  --- each option explains itself where it appears ---")
    for label, probe in (
            ("the cap names the file the engine reads",
             "<name>.quota.json beside the config"),
            ("the cap says what happens when it is reached",
             "goes offline the moment the"),
            ("the restart schedule says why UTC matters",
             "+03:30 and a kharej on UTC still line up"),
            ("the restart schedule says what 0 means", "0 is off"),
            ("the restart schedule is not confused with Auto Refresh",
             "Auto Refresh is different"),
            ("backup addresses say they ride in the setup link",
             "these ride in the setup link"),
            ("backup addresses say what the kharej does with them",
             "fails over to them on its own")):
        check("the guide explains %s" % label, probe in fout,
              "missing: %r" % probe[:44])
    # The option BLOCK, not the NOTES: the NOTES bullet explaining that a tunnel
    # CAN be capped belongs on every guide, on purpose. What must not appear on a
    # node that sets nothing is the block itself.
    check("none of the option lines or their explanations appear on a node that sets none of them",
          not any(x in out for x in ("  Traffic limit :", "  Restart both  :",
                                     "  Backup hosts  :",
                                     "+03:30 and a kharej on UTC still line up",
                                     "these ride in the setup link",
                                     "goes offline the moment the")),
          "the block leaked onto a plain node")

    print()
    print("  --- optional lines appear only when the node sets them ---")
    check("a node with no options shows no cap line",
          "Traffic limit :" not in out)
    check("a node with no options shows no restart line",
          "Restart both  :" not in out)
    check("a node with no options shows no backup line",
          "Backup hosts  :" not in out)
    check("a node that sets all of them shows all of them",
          "Traffic limit : 500 GB" in fout and "Restart both  : every 12 h" in fout
          and "Backup hosts  : 5.61.9.11, edge.example.com" in fout)
    check("the preset is named in the guide", "Preset      : aggressive" in fout)

    print()
    print("  --- the rendered guide is pasteable ---")
    longest = max(len(l) for l in out.splitlines())
    check("no line runs away past 120 columns", longest <= 120, "%d" % longest)
    check("the one-command install is split so it can be pasted",
          any(l.strip().startswith("bash <(curl -fsSL") for l in out.splitlines()))
    check("a stray line continuation cannot join two commands",
          "install.sh) \\" not in out and "install.sh)  " not in out)

    print()
    print("  --- every tunnels.* key the panel uses exists in all four locales ---")
    need = set(re.findall(r'data-i18n="(tunnels\.[a-zA-Z]+)"', HTML))
    need |= set(re.findall(r't\("(tunnels\.[a-zA-Z]+)"\)', JS))

    def block_end(text, brace_open):
        depth, i, n = 0, brace_open, len(text)
        while i < n:
            c = text[i]
            if c in "\"'`":
                q, i = c, i + 1
                while i < n:
                    if text[i] == "\\":
                        i += 2
                        continue
                    if text[i] == q:
                        break
                    i += 1
                i += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise AssertionError("unbalanced")

    spans = {}
    for m in re.finditer(r"Object\.assign\(Z_STRINGS\.(\w+),\s*\{", I18N):
        spans.setdefault(m.group(1), []).append(
            (m.start(), block_end(I18N, m.end() - 1)))
    for loc in ("en", "fa", "zh", "ru"):
        have = set()
        for a, b in spans.get(loc, []):
            have |= set(re.findall(r'"([\w.]+)"\s*:', I18N[a:b]))
        miss = sorted(k for k in need if k not in have)
        check("every tunnels.* key exists in %s (%d keys)" % (loc, len(need)),
              not miss, "missing %s" % ", ".join(miss[:4]))

# --------------------------------------------------------------------------
# Child mode: the parent mutates one file at a time and looks for one token.
# --------------------------------------------------------------------------
else:
    import protocols

    if protocols.BACKPACK_VERSION != "v1.8.5":
        print("GUARD:pin version=%s" % protocols.BACKPACK_VERSION)
    if not re.fullmatch(r"[0-9a-f]{40}", protocols.BACKPACK_PIN_COMMIT or ""):
        print("GUARD:pincommit %r" % protocols.BACKPACK_PIN_COMMIT)
    if not re.fullmatch(r"[0-9a-f]{64}", protocols.BACKPACK_PIN_SHA256 or ""):
        print("GUARD:pinsha %r" % protocols.BACKPACK_PIN_SHA256)
    if "sni" not in protocols.TUNNEL_TRANSPORTS:
        print("GUARD:sni not in TUNNEL_TRANSPORTS")

    node = {"name": "n1", "transport": "tcp", "iran_ip": "5.61.9.10",
            "kharej_ip": "2.33.4.5", "tunnel_port": 443,
            "forwarded_ports": "", "udp_forward": False}
    full = dict(node, preset="aggressive", traffic_limit_gb=500,
                restart_hours=12, backup_hosts="5.61.9.11")
    plain = protocols.backpack_guide(node, "T")
    rich = protocols.backpack_guide(full, "T")

    for probe, token in (("sudo backpack link apply", "GUARD:link"),
                         ('bash <(curl -fsSL "$BP") link apply', "GUARD:onecmd"),
                         ("UPDATES that tunnel in", "GUARD:update"),
                         ("X-Backpack-Proof", "GUARD:proof"),
                         ("option 0", "GUARD:conntest")):
        if probe not in plain:
            print("%s the guide no longer says %r" % (token, probe[:34]))
    if "Traffic limit : 500 GB" not in rich:
        print("GUARD:cap the cap line does not render")
    if "Traffic limit :" in plain:
        print("GUARD:optional a node with no options still shows a cap line")
    if "Restart both  : every 12 h" not in rich:
        print("GUARD:restart the restart line does not render")
    if "Backup hosts  : 5.61.9.11" not in rich:
        print("GUARD:backup the backup line does not render")
    for probe, token in (("+03:30 and a kharej on UTC still line up", "GUARD:explrestart"),
                         ("these ride in the setup link", "GUARD:explbackup"),
                         ("<name>.quota.json beside the config", "GUARD:explcap")):
        if probe not in rich:
            print("%s the guide no longer explains %r" % (token, probe[:30]))
    if "Preset      : aggressive" not in rich:
        print("GUARD:preset the preset is not named")
    if max(len(l) for l in plain.splitlines()) > 120:
        print("GUARD:width a line ran away past 120 columns")
    raise SystemExit(0)

# --------------------------------------------------------------------------
if os.environ.get("ZEFIRA_BP_CHILD") != "1":
    print()
    print("  --- proving each check fails when its fix is removed ---")
    FILES = {"protocols.py": P_PROTO, "schemas.py": P_SCHEM, "database.py": P_DB,
             "main.py": P_MAIN, "panel.html": P_HTML, "app.js": P_JS,
             "i18n.js": P_I18N}
    MUTATIONS = [
        ("the pin is rolled back to v1.8.2", "GUARD:pin", "protocols.py",
         lambda s: s.replace('BACKPACK_VERSION = "v1.8.5"',
                             'BACKPACK_VERSION = "v1.8.2"')),
        ("the pinned commit is truncated", "GUARD:pincommit", "protocols.py",
         lambda s: re.sub(r'BACKPACK_PIN_COMMIT = "[0-9a-f]+"',
                          'BACKPACK_PIN_COMMIT = "abc"', s)),
        ("the pinned installer hash is emptied", "GUARD:pinsha", "protocols.py",
         lambda s: re.sub(r'BACKPACK_PIN_SHA256 = "[0-9a-f]+"',
                          'BACKPACK_PIN_SHA256 = ""', s)),
        ("the sni carrier is dropped", "GUARD:sni", "protocols.py",
         lambda s: s.replace(', "sni"]', "]")),
        ("the setup link step is removed", "GUARD:link", "protocols.py",
         lambda s: s.replace("sudo backpack link apply", "sudo backpack join")),
        ("the one-command install is removed", "GUARD:onecmd", "protocols.py",
         lambda s: s.replace('bash <(curl -fsSL "$BP") link apply', "backpack join")),
        ("the link-updates-in-place note is removed", "GUARD:update", "protocols.py",
         lambda s: s.replace("UPDATES that tunnel in", "refuses, as before")),
        ("the wss server-proof note is removed", "GUARD:proof", "protocols.py",
         lambda s: s.replace("X-Backpack-Proof", "the usual handshake")),
        ("Connection Test is replaced by the retired Link Test", "GUARD:conntest",
         "protocols.py", lambda s: s.replace("option 0", "Manage -> Link Test")),
        ("the cap line stops rendering", "GUARD:cap", "protocols.py",
         lambda s: s.replace("Traffic limit : %d GB", "Traffic cap was %d GB")),
        ("a node with no options is shown a cap line", "GUARD:optional", "protocols.py",
         lambda s: s.replace("if limit:", "if True:")),
        ("the restart line stops rendering", "GUARD:restart", "protocols.py",
         lambda s: s.replace("Restart both  : every %d h", "Restarts : %d h")),
        ("the backup line stops rendering", "GUARD:backup", "protocols.py",
         lambda s: s.replace("Backup hosts  : %s", "Hosts: %s")),
        ("the preset is no longer named", "GUARD:preset", "protocols.py",
         lambda s: s.replace("Preset      : {preset}", "Preset")),
        ("the guide grows an un-pasteable line", "GUARD:width", "protocols.py",
         lambda s: s.replace("ZEFIRA x BACKPACK - Tunnel Setup Guide",
                             "ZEFIRA x BACKPACK - Tunnel Setup Guide "
                             + "and a great deal more text to push it over the limit "
                             * 3)),
    ]
    originals = {}
    for _f, _p in FILES.items():
        originals[_f] = src(_p)
    try:
        for label, token, fname, fn in MUTATIONS:
            broken = fn(originals[fname])
            if broken == originals[fname]:
                check("goes red without this fix: %s" % label, False,
                      "the mutation did not apply, so it proves nothing")
                continue
            for f, _p in FILES.items():
                io.open(_p, "w", encoding="utf-8", newline="").write(
                    broken if f == fname else originals[f])
            try:
                r = subprocess.run([sys.executable, os.path.abspath(__file__)],
                                   capture_output=True, text=True, timeout=240,
                                   env=dict(os.environ, ZEFIRA_BP_CHILD="1"))
                check("goes red without this fix: %s" % label, token in r.stdout,
                      "child said %r" % (r.stdout or r.stderr).strip()[-140:])
            finally:
                for f, _p in FILES.items():
                    io.open(_p, "w", encoding="utf-8", newline="").write(originals[f])
        for f, _p in FILES.items():
            check("%s restored byte-for-byte after mutation" % f,
                  src(_p) == originals[f])
    finally:
        for f, _p in FILES.items():
            io.open(_p, "w", encoding="utf-8", newline="").write(originals[f])

    passed = sum(1 for _n, c in RESULTS if c)
    print()
    print("=== %d/%d checks passed ===" % (passed, len(RESULTS)))
    raise SystemExit(0 if passed == len(RESULTS) else 1)